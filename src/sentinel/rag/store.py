from __future__ import annotations

import json
from pathlib import Path
import shutil
import warnings

from sentinel.config import Settings
from sentinel.errors import RAGIndexIncompatibleError
from sentinel.rag.canonical import CANONICAL_TEXT_VERSION, CHUNKING_VERSION, NORMALIZED_CORPUS_VERSION, build_finding_documents, source_cache_hash
from sentinel.rag.embeddings import LangChainEmbeddingAdapter, SentenceTransformerEmbeddingClient, get_embedding_model_info, safe_collection_name
from sentinel.schemas.rag import HistoricalFinding, HistoricalFindingQuery, RAGIndexMetadata


def _finding_matches_terms(finding: HistoricalFinding, terms: list[str]) -> bool:
    """True if a finding's protocol/source identifies it with an excluded project.

    Matches on protocol_name, source/github links, slug, and title (lowercased) —
    enough to drop a target project's own published findings without nuking
    unrelated findings that merely mention the term in prose.
    """
    haystack = " ".join(
        str(getattr(finding, attr, "") or "")
        for attr in ("protocol_name", "source_link", "github_link", "slug", "title")
    ).lower()
    return any(term in haystack for term in terms)


def rag_paths(settings: Settings, root: Path | None = None) -> dict[str, Path]:
    root = root or settings.rag_dir
    return {
        "root": root,
        "raw": root / "solodit_raw_cache.jsonl",
        "normalized": root / "solodit_normalized_findings.jsonl",
        "chroma": root / "chroma",
        "sync_state": root / "sync_state.json",
        "index_metadata": root / "index_metadata.json",
    }


def write_findings(settings: Settings, raw_findings: list[dict], findings: list[HistoricalFinding], root: Path | None = None) -> None:
    paths = rag_paths(settings, root)
    paths["root"].mkdir(parents=True, exist_ok=True)
    with paths["raw"].open("w", encoding="utf-8") as handle:
        for finding in raw_findings:
            handle.write(json.dumps(finding) + "\n")
    with paths["normalized"].open("w", encoding="utf-8") as handle:
        for finding in findings:
            handle.write(json.dumps(finding.model_dump(mode="json")) + "\n")


def load_findings(settings: Settings, root: Path | None = None) -> list[HistoricalFinding]:
    path = rag_paths(settings, root)["normalized"]
    if not path.exists():
        return []
    findings = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            findings.append(HistoricalFinding.model_validate_json(line))
    return findings


class HistoricalFindingStore:
    """Persistent Chroma-backed store, with JSON fallback when Chroma is not installed."""

    def __init__(self, settings: Settings, root: Path | None = None) -> None:
        self.settings = settings
        self.root = root

    def _collection_name(self) -> str:
        prefix = "solodit_global" if self.root is None else "solodit_repo"
        return safe_collection_name(prefix, self.settings.rag_embed_model)

    def _write_metadata(self, findings: list[HistoricalFinding], document_count: int, model_info) -> RAGIndexMetadata:
        paths = rag_paths(self.settings, self.root)
        metadata = RAGIndexMetadata(
            embedding_model=model_info.model_name,
            embedding_dim=model_info.dimension,
            embedding_provider=model_info.provider,
            normalized_corpus_version=NORMALIZED_CORPUS_VERSION,
            chunking_version=CHUNKING_VERSION,
            canonical_text_version=CANONICAL_TEXT_VERSION,
            finding_count=len(findings),
            document_count=document_count,
            source_cache_hash=source_cache_hash(findings),
            chroma_collection_name=self._collection_name(),
        )
        paths["index_metadata"].write_text(json.dumps(metadata.model_dump(mode="json"), indent=2) + "\n", encoding="utf-8")
        return metadata

    def load_metadata(self) -> RAGIndexMetadata | None:
        path = rag_paths(self.settings, self.root)["index_metadata"]
        if not path.exists():
            return None
        return RAGIndexMetadata.model_validate_json(path.read_text(encoding="utf-8"))

    def validate_index(self) -> RAGIndexMetadata:
        metadata = self.load_metadata()
        if metadata is None:
            raise RAGIndexIncompatibleError("RAG index metadata is missing; run `sentinel rag rebuild` or enable SENTINEL_RAG_AUTO_REBUILD=true.")
        model_info = get_embedding_model_info(self.settings.rag_embed_model, local_files_only=True)
        mismatches = []
        if metadata.embedding_model != self.settings.rag_embed_model:
            mismatches.append(f"embedding_model index={metadata.embedding_model!r} current={self.settings.rag_embed_model!r}")
        if metadata.embedding_dim != model_info.dimension:
            mismatches.append(f"embedding_dim index={metadata.embedding_dim} current={model_info.dimension}")
        if metadata.canonical_text_version != CANONICAL_TEXT_VERSION:
            mismatches.append(f"canonical_text_version index={metadata.canonical_text_version!r} current={CANONICAL_TEXT_VERSION!r}")
        if metadata.chunking_version != CHUNKING_VERSION:
            mismatches.append(f"chunking_version index={metadata.chunking_version!r} current={CHUNKING_VERSION!r}")
        if mismatches:
            raise RAGIndexIncompatibleError("RAG index is incompatible: " + "; ".join(mismatches))
        return metadata

    def rebuild(self) -> str:
        paths = rag_paths(self.settings, self.root)
        if paths["chroma"].exists():
            archive = paths["root"] / f"chroma.archive"
            if archive.exists():
                shutil.rmtree(archive)
            paths["chroma"].rename(archive)
        return self.build(load_findings(self.settings, self.root))

    def build(self, findings: list[HistoricalFinding]) -> str:
        paths = rag_paths(self.settings, self.root)
        paths["chroma"].mkdir(parents=True, exist_ok=True)
        documents = [doc for finding in findings for doc in build_finding_documents(finding)]
        try:
            from langchain_chroma import Chroma
        except Exception:
            (paths["chroma"] / "UNAVAILABLE").write_text("Install langchain-chroma and chromadb to build the vector index.\n", encoding="utf-8")
            model_info = get_embedding_model_info(self.settings.rag_embed_model, local_files_only=True)
            self._write_metadata(findings, len(documents), model_info)
            return str(paths["chroma"])
        try:
            client = SentenceTransformerEmbeddingClient(self.settings.rag_embed_model)
            model_info = client.get_model_info()
            Chroma.from_texts(
                texts=[doc["text"] for doc in documents],
                embedding=LangChainEmbeddingAdapter(client),
                metadatas=[doc["metadata"] for doc in documents],
                ids=[doc["id"] for doc in documents],
                persist_directory=str(paths["chroma"]),
                collection_name=self._collection_name(),
            )
        except Exception as exc:
            (paths["chroma"] / "UNAVAILABLE").write_text(f"Vector index build unavailable: {type(exc).__name__}: {exc}\n", encoding="utf-8")
            model_info = get_embedding_model_info(self.settings.rag_embed_model, local_files_only=True)
        self._write_metadata(findings, len(documents), model_info)
        return str(paths["chroma"])

    def search(self, query: HistoricalFindingQuery, candidate_k: int = 25) -> list[tuple[HistoricalFinding, float]]:
        return [(item["finding"], item["score"]) for item in self.search_documents(query, candidate_k)]

    def search_documents(self, query: HistoricalFindingQuery, candidate_k: int = 25) -> list[dict]:
        findings_by_id = {finding.id: finding for finding in load_findings(self.settings, self.root)}
        # Blind RAG: drop the target project's own published findings so the eval
        # measures discovery, not retrieval of the answer. A dropped finding's id is
        # absent from the map, so any candidate referencing it is skipped below.
        exclude_terms = [t.lower() for t in getattr(self.settings, "rag_exclude_terms", []) if t]
        if exclude_terms:
            findings_by_id = {
                fid: f for fid, f in findings_by_id.items() if not _finding_matches_terms(f, exclude_terms)
            }
        if not findings_by_id:
            return []
        try:
            self.validate_index()
        except RAGIndexIncompatibleError:
            if self.settings.rag_auto_rebuild:
                self.rebuild()
                self.validate_index()
            else:
                raise
        try:
            from langchain_chroma import Chroma

            client = SentenceTransformerEmbeddingClient(self.settings.rag_embed_model, local_files_only=True)
            db = Chroma(
                persist_directory=str(rag_paths(self.settings, self.root)["chroma"]),
                embedding_function=LangChainEmbeddingAdapter(client),
                collection_name=self._collection_name(),
            )
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", message="Relevance scores must be between 0 and 1.*")
                raw = db.similarity_search_with_relevance_scores(query.query, k=candidate_k)
            candidates = []
            for doc, score in raw:
                finding_id = str(doc.metadata.get("finding_id") or doc.metadata.get("id"))
                finding = findings_by_id.get(finding_id)
                if finding:
                    candidates.append(
                        {
                            "finding": finding,
                            "score": max(0.0, min(1.0, float(score))),
                            "view_type": str(doc.metadata.get("view_type") or "unknown"),
                            "metadata": dict(doc.metadata),
                        }
                    )
            if candidates:
                return candidates
        except Exception:
            pass
        query_terms = set(query.query.lower().split())
        candidates = []
        for finding in findings_by_id.values():
            for doc in build_finding_documents(finding):
                text = doc["text"].lower()
                hits = sum(1 for term in query_terms if term and term in text)
                if hits:
                    candidates.append(
                        {
                            "finding": finding,
                            "score": min(1.0, hits / max(4, len(query_terms))),
                            "view_type": str(doc["metadata"].get("view_type") or "unknown"),
                            "metadata": doc["metadata"],
                        }
                    )
        return sorted(candidates, key=lambda item: item["score"], reverse=True)[:candidate_k]
