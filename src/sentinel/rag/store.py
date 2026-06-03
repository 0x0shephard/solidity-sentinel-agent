from __future__ import annotations

import json
from pathlib import Path
import warnings

from sentinel.config import Settings
from sentinel.schemas.rag import HistoricalFinding, HistoricalFindingQuery


def rag_paths(settings: Settings) -> dict[str, Path]:
    root = settings.rag_dir
    return {
        "root": root,
        "raw": root / "solodit_raw_cache.jsonl",
        "normalized": root / "solodit_normalized_findings.jsonl",
        "chroma": root / "chroma",
        "sync_state": root / "sync_state.json",
    }


def write_findings(settings: Settings, raw_findings: list[dict], findings: list[HistoricalFinding]) -> None:
    paths = rag_paths(settings)
    paths["root"].mkdir(parents=True, exist_ok=True)
    with paths["raw"].open("w", encoding="utf-8") as handle:
        for finding in raw_findings:
            handle.write(json.dumps(finding) + "\n")
    with paths["normalized"].open("w", encoding="utf-8") as handle:
        for finding in findings:
            handle.write(json.dumps(finding.model_dump(mode="json")) + "\n")


def load_findings(settings: Settings) -> list[HistoricalFinding]:
    path = rag_paths(settings)["normalized"]
    if not path.exists():
        return []
    findings = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            findings.append(HistoricalFinding.model_validate_json(line))
    return findings


class HistoricalFindingStore:
    """Persistent Chroma-backed store, with JSON fallback when Chroma is not installed."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def build(self, findings: list[HistoricalFinding]) -> str:
        paths = rag_paths(self.settings)
        paths["chroma"].mkdir(parents=True, exist_ok=True)
        try:
            from langchain_chroma import Chroma
            from langchain_huggingface import HuggingFaceEmbeddings
        except Exception:
            (paths["chroma"] / "UNAVAILABLE").write_text("Install langchain-chroma and chromadb to build the vector index.\n", encoding="utf-8")
            return str(paths["chroma"])
        embeddings = HuggingFaceEmbeddings(model_name=self.settings.rag_embed_model)
        texts = [finding.search_text for finding in findings]
        metadatas = [
            {
                "id": finding.id,
                "title": finding.title,
                "impact": finding.impact or "",
                "vulnerability_class": finding.vulnerability_class,
                "tags": ",".join(finding.tags),
            }
            for finding in findings
        ]
        ids = [finding.id for finding in findings]
        Chroma.from_texts(texts=texts, embedding=embeddings, metadatas=metadatas, ids=ids, persist_directory=str(paths["chroma"]))
        return str(paths["chroma"])

    def search(self, query: HistoricalFindingQuery, candidate_k: int = 25) -> list[tuple[HistoricalFinding, float]]:
        findings_by_id = {finding.id: finding for finding in load_findings(self.settings)}
        if not findings_by_id:
            return []
        try:
            from langchain_chroma import Chroma
            from langchain_huggingface import HuggingFaceEmbeddings

            embeddings = HuggingFaceEmbeddings(model_name=self.settings.rag_embed_model, model_kwargs={"local_files_only": True})
            db = Chroma(persist_directory=str(rag_paths(self.settings)["chroma"]), embedding_function=embeddings)
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", message="Relevance scores must be between 0 and 1.*")
                raw = db.similarity_search_with_relevance_scores(query.query, k=candidate_k)
            candidates = []
            for doc, score in raw:
                finding_id = str(doc.metadata.get("id"))
                finding = findings_by_id.get(finding_id)
                if finding:
                    candidates.append((finding, max(0.0, min(1.0, float(score)))))
            if candidates:
                return candidates
        except Exception:
            pass
        query_terms = set(query.query.lower().split())
        candidates = []
        for finding in findings_by_id.values():
            text = finding.search_text.lower()
            hits = sum(1 for term in query_terms if term and term in text)
            if hits:
                candidates.append((finding, min(1.0, hits / max(4, len(query_terms)))))
        return sorted(candidates, key=lambda item: item[1], reverse=True)[:candidate_k]
