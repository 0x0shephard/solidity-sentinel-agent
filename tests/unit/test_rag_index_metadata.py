import json

import pytest

from sentinel.config import Settings
from sentinel.errors import RAGIndexIncompatibleError
from sentinel.rag.canonical import build_canonical_finding_text, build_canonical_query_text, build_finding_documents
from sentinel.rag.store import HistoricalFindingStore, load_findings, rag_paths, write_findings
from sentinel.schemas.rag import HistoricalFinding, RAGIndexMetadata
from sentinel.schemas.research import VulnerabilityHypothesis
from sentinel.schemas.static import SourceEvidence
from sentinel.tools.research import _record_retrieval_telemetry
from sentinel.schemas.rag import HistoricalFindingQuery


def _finding() -> HistoricalFinding:
    return HistoricalFinding(
        id="finding-1",
        title="UUPS upgrade flow is incomplete",
        content="The contract calls _authorizeUpgrade but never calls upgradeToAndCall. Storage layout also diverges.",
        summary="Incomplete UUPS upgrade flow",
        impact="HIGH",
        protocol_name="Example",
        tags=["Upgradeability"],
        vulnerability_class="upgradeability",
        root_cause_terms=["authorizeUpgrade", "upgradeToAndCall", "storage layout"],
        quality_score=4,
        source_link="https://example.test/report",
        search_text="UUPS upgrade authorizeUpgrade upgradeToAndCall storage layout",
    )


class FakeEmbeddingClient:
    def __init__(self, model_name, local_files_only=False):
        self.model_name = model_name

    def get_model_info(self):
        from sentinel.schemas.rag import EmbeddingModelInfo

        return EmbeddingModelInfo(model_name=self.model_name, dimension=3, provider="sentence_transformers")

    def embed_documents(self, texts):
        return [[1.0, 0.0, 0.0] for _ in texts]

    def embed_query(self, text):
        return [1.0, 0.0, 0.0]


def test_index_metadata_is_written_after_build(tmp_path, monkeypatch):
    settings = Settings(rag_dir=tmp_path / "rag")
    write_findings(settings, [], [_finding()])
    captured = {}

    class FakeChroma:
        @classmethod
        def from_texts(cls, texts, embedding, metadatas, ids, persist_directory, collection_name):
            captured.update({"texts": texts, "metadatas": metadatas, "ids": ids, "collection_name": collection_name})

    monkeypatch.setattr("sentinel.rag.store.SentenceTransformerEmbeddingClient", FakeEmbeddingClient)
    monkeypatch.setattr("langchain_chroma.Chroma", FakeChroma)

    HistoricalFindingStore(settings).build(load_findings(settings))

    metadata_path = rag_paths(settings)["index_metadata"]
    metadata = RAGIndexMetadata.model_validate_json(metadata_path.read_text())
    assert metadata.embedding_model == settings.rag_embed_model
    assert metadata.embedding_dim == 3
    assert metadata.finding_count == 1
    assert metadata.document_count == 5
    assert len(captured["texts"]) == 5
    assert captured["metadatas"][0]["finding_id"] == "finding-1"


def test_metadata_mismatch_raises_rag_index_incompatible(tmp_path):
    settings = Settings(rag_dir=tmp_path / "rag")
    write_findings(settings, [], [_finding()])
    paths = rag_paths(settings)
    paths["root"].mkdir(parents=True, exist_ok=True)
    paths["index_metadata"].write_text(
        json.dumps(
            {
                "embedding_model": "different-model",
                "embedding_dim": 384,
                "embedding_provider": "sentence_transformers",
                "normalized_corpus_version": "solodit-normalized-v1",
                "chunking_version": "finding-semantic-units-v1",
                "canonical_text_version": "canonical-finding-text-v1",
                "finding_count": 1,
                "document_count": 5,
                "source_cache_hash": "abc",
                "chroma_collection_name": "old",
            }
        )
    )

    with pytest.raises(RAGIndexIncompatibleError):
        HistoricalFindingStore(settings).search(HistoricalFindingQuery(query="upgrade bug"))


def test_auto_rebuild_path_is_triggered(tmp_path, monkeypatch):
    settings = Settings(rag_dir=tmp_path / "rag", rag_auto_rebuild=True)
    write_findings(settings, [], [_finding()])
    calls = {"rebuild": 0, "validate": 0}

    def fake_validate(self):
        calls["validate"] += 1
        if calls["validate"] == 1:
            raise RAGIndexIncompatibleError("bad")
        return None

    def fake_rebuild(self):
        calls["rebuild"] += 1
        return "rebuilt"

    monkeypatch.setattr(HistoricalFindingStore, "validate_index", fake_validate)
    monkeypatch.setattr(HistoricalFindingStore, "rebuild", fake_rebuild)

    matches = HistoricalFindingStore(settings).search(HistoricalFindingQuery(query="upgrade authorizeUpgrade"))

    assert calls["rebuild"] == 1
    assert matches


def test_canonical_finding_text_and_multiview_documents():
    text = build_canonical_finding_text(_finding())
    docs = build_finding_documents(_finding())

    assert "[Title]" in text
    assert "[Vulnerability Class]" in text
    assert "[Root Cause Terms]" in text
    assert "[Impact]" in text
    assert "[Recommendation / Fix Pattern]" in text
    assert {doc["metadata"]["view_type"] for doc in docs} == {
        "summary_view",
        "root_cause_view",
        "impact_view",
        "recommendation_view",
        "exploit_precondition_view",
    }


def test_canonical_query_includes_class_and_root_terms():
    hypothesis = VulnerabilityHypothesis(
        id="hyp-1",
        title="Broken upgrade",
        vulnerability_class="upgradeability",
        evidence_summary="authorize only",
        confidence=0.5,
        affected_functions=["graduateAndUpgrade"],
        root_cause_terms=["authorizeUpgrade", "missing upgradeToAndCall"],
        evidence_lines=[
            SourceEvidence(
                file_path="src/LevelOne.sol",
                line_start=1,
                line_end=1,
                function_name="graduateAndUpgrade",
                source_text="_authorizeUpgrade(_levelTwo);",
                reason="upgrade authorization without execution",
            )
        ],
    )

    query = build_canonical_query_text(hypothesis, "root_cause")

    assert "upgradeability" in query
    assert "authorizeUpgrade" in query
    assert "missing upgradeToAndCall" in query
    assert "_authorizeUpgrade" in query


def test_retrieval_telemetry_redacts_raw_documents(tmp_path):
    state = {"run_id": "run-1", "run_dir": str(tmp_path), "hypothesis_id": "hyp-1", "query_intent": "root_cause"}

    _record_retrieval_telemetry(
        state,
        query=HistoricalFindingQuery(query="very long raw source should be hashed only"),
        raw_candidate_count=10,
        final_candidate_count=3,
        top_score=0.4,
        used_targeted_cache=True,
        used_global_cache=False,
    )

    record = json.loads((tmp_path / "retrieval_telemetry.jsonl").read_text().splitlines()[0])
    assert "query_text_hash" in record
    assert "very long raw source" not in json.dumps(record)
