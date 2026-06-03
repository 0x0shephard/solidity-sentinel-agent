from pathlib import Path

from sentinel.evals.rag_embeddings import (
    RAGEvalFixture,
    RAGEvalQuery,
    _mrr,
    _relevance_labels,
    balanced_score,
    evaluate_query_mode,
)
from sentinel.schemas.rag import HistoricalFinding, HistoricalFindingMatch
from sentinel.schemas.rag import RetrievalQualityGrade
from sentinel.evals.rag_embeddings import RetrievalMetrics


def _finding(finding_id: str, vuln_class: str = "upgradeability") -> HistoricalFinding:
    return HistoricalFinding(
        id=finding_id,
        title="UUPS authorizeUpgrade missing upgradeTo",
        content="upgradeTo implementation slot UUPS authorizeUpgrade",
        summary="upgrade bug",
        vulnerability_class=vuln_class,
        root_cause_terms=["authorizeUpgrade", "upgradeTo"],
        tags=["Upgradeability"],
        search_text="UUPS authorizeUpgrade upgradeTo implementation slot",
    )


def _match(finding_id: str) -> HistoricalFindingMatch:
    return HistoricalFindingMatch(
        finding=_finding(finding_id),
        semantic_score=0.8,
        keyword_score=0.8,
        class_protocol_score=0.8,
        quality_recency_score=0.8,
        final_score=0.8,
        matched_terms=["upgradeTo"],
        relevance_reason="test",
    )


def test_recall_relevance_with_exact_ids():
    query = RAGEvalQuery(
        query_id="q1",
        hypothesis_class="upgradeability",
        query="upgrade bug",
        relevant_finding_ids=["finding-2"],
    )

    labels, strict = _relevance_labels(query, [_match("finding-1"), _match("finding-2")])

    assert strict is True
    assert labels == [0, 1]


def test_weak_label_relevance_scoring():
    query = RAGEvalQuery(
        query_id="q1",
        hypothesis_class="upgradeability",
        query="upgrade bug",
        expected_vulnerability_classes=["upgradeability"],
        expected_terms=["authorizeUpgrade", "upgradeTo"],
    )

    labels, strict = _relevance_labels(query, [_match("finding-1")])

    assert strict is False
    assert labels == [1]


def test_mrr_and_balanced_score():
    assert _mrr([0, 0, 1], 10) == 1 / 3

    metrics = RetrievalMetrics(recall_at_10=1.0, class_match_rate=1.0, safe_to_cite_rate=0.5, average_latency_ms=500)
    assert balanced_score(metrics) > 0.7


class FakeStore:
    def search_documents(self, query, candidate_k=25):
        return [{"finding": _finding("finding-1"), "score": 0.9, "view_type": "root_cause_view", "metadata": {"view_type": "root_cause_view"}}]


def test_raw_and_canonical_query_modes_both_run():
    fixture = RAGEvalFixture(
        fixture_name="tiny",
        queries=[
            RAGEvalQuery(
                query_id="q1",
                hypothesis_class="upgradeability",
                query="upgrade bug",
                root_cause_terms=["authorizeUpgrade"],
                expected_vulnerability_classes=["upgradeability"],
                expected_terms=["upgradeTo"],
            )
        ],
    )

    raw = evaluate_query_mode(FakeStore(), fixture, "raw_query")
    canonical = evaluate_query_mode(FakeStore(), fixture, "canonical_query")

    assert raw.metrics.recall_at_10 == 1.0
    assert canonical.metrics.recall_at_10 == 1.0
    assert raw.top_view_type == "root_cause_view"
    assert canonical.root_cause_view_hit_rate == 1.0


def test_exact_id_metrics_skip_gracefully_without_ids():
    query = RAGEvalQuery(query_id="q1", hypothesis_class="manual_review", query="x")
    labels, strict = _relevance_labels(query, [])

    assert strict is False
    assert labels == []
