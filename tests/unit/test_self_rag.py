from sentinel.schemas.common import ToolStatus
from sentinel.schemas.rag import HistoricalFinding, HistoricalFindingMatch, RetrievalQualityGrade
from sentinel.schemas.research import VulnerabilityHypothesis
from sentinel.schemas.static import SourceEvidence
from sentinel.tools.research import (
    BuildRAGContextBundleInput,
    CritiqueHistoricalMatchesInput,
    MergeRAGResultsInput,
    RAGQueriesInput,
    RepairRAGQueryInput,
    RetrievalGradeInput,
    build_rag_context_bundle,
    critique_historical_matches,
    expand_rag_queries,
    grade_retrieval_quality,
    merge_rag_results,
    repair_rag_query,
)


def _hypothesis() -> VulnerabilityHypothesis:
    return VulnerabilityHypothesis(
        id="hyp-1",
        title="External call before accounting",
        vulnerability_class="external_call_before_accounting",
        affected_files=["src/Vault.sol"],
        affected_functions=["withdraw"],
        evidence_summary="hook before burn",
        confidence=0.8,
        root_cause_terms=["external call before state update", "reentrancy"],
        exploit_precondition_terms=["callback", "stale balance"],
        evidence_lines=[
            SourceEvidence(
                file_path="src/Vault.sol",
                line_start=10,
                line_end=10,
                function_name="withdraw",
                source_text="hook.beforeWithdraw();",
                reason="external call before accounting",
            )
        ],
    )


def _match(finding_id: str, score: float, vuln_class: str = "external_call_before_accounting") -> HistoricalFindingMatch:
    finding = HistoricalFinding(
        id=finding_id,
        title="External call before state update causes reentrancy",
        content="callback can observe stale balance before accounting update",
        summary="same root cause",
        vulnerability_class=vuln_class,
        root_cause_terms=["external call before state update", "reentrancy"],
        search_text="external call before state update callback stale balance",
    )
    return HistoricalFindingMatch(
        finding=finding,
        semantic_score=score,
        keyword_score=score,
        class_protocol_score=score,
        quality_recency_score=score,
        final_score=score,
        matched_terms=["reentrancy"],
        relevance_reason="same root cause",
    )


def test_expand_rag_queries_returns_multiple_intents():
    output = expand_rag_queries(RAGQueriesInput(hypothesis=_hypothesis(), objective="Find bugs"), {})

    assert output.status == ToolStatus.OK
    assert len(output.queries) >= 3
    assert {query.intent for query in output.queries} >= {"root_cause", "exploit_preconditions", "code_indicators"}


def test_merge_rag_results_deduplicates_by_finding_id():
    first = _match("hist-1", 0.2)
    better = _match("hist-1", 0.7)

    output = merge_rag_results(MergeRAGResultsInput(matches_by_query={"a": [first], "b": [better]}), {})

    assert len(output.matches) == 1
    assert output.matches[0].final_score == 0.7


def test_grade_retrieval_quality_good_weak_bad():
    hyp = _hypothesis()

    good = grade_retrieval_quality(RetrievalGradeInput(hypothesis=hyp, matches=[_match("a", 0.4), _match("b", 0.35)]), {})
    weak = grade_retrieval_quality(RetrievalGradeInput(hypothesis=hyp, matches=[_match("c", 0.2, "manual_review")]), {})
    bad = grade_retrieval_quality(RetrievalGradeInput(hypothesis=hyp, matches=[]), {})

    assert good.grade.grade == "good"
    assert weak.grade.grade == "weak"
    assert bad.grade.grade == "bad"


def test_repair_rag_query_returns_single_repair_query():
    output = repair_rag_query(
        RepairRAGQueryInput(
            hypothesis=_hypothesis(),
            grade=RetrievalQualityGrade(grade="weak", score=0.2, reason="thin", repair_hint="use callback terms"),
        ),
        {},
    )

    assert len(output.queries) == 1
    assert output.queries[0].intent == "repair"
    assert "callback" in output.queries[0].query


def test_critique_rejects_irrelevant_and_accepts_shared_root_cause():
    hyp = _hypothesis()
    relevant = _match("rel", 0.4)
    irrelevant = _match("irr", 0.4, "oracle_staleness_logic")
    irrelevant.finding.root_cause_terms = ["oracle", "stale price"]
    irrelevant.finding.title = "Stale oracle price accepted"
    irrelevant.finding.summary = "oracle freshness issue"
    irrelevant.finding.search_text = "oracle stale price freshness"
    irrelevant.matched_terms = []

    output = critique_historical_matches(CritiqueHistoricalMatchesInput(hypothesis=hyp, matches=[relevant, irrelevant]), {})

    assert output.critiques[0].safe_to_cite is True
    assert output.critiques[1].safe_to_cite is False


def test_rag_bundle_keeps_only_safe_matches():
    hyp = _hypothesis()
    critiques = critique_historical_matches(CritiqueHistoricalMatchesInput(hypothesis=hyp, matches=[_match("rel", 0.4)]), {}).critiques

    output = build_rag_context_bundle(
        BuildRAGContextBundleInput(
            hypothesis=hyp,
            matches=[_match("rel", 0.4)],
            grade=RetrievalQualityGrade(grade="good", score=0.4, reason="ok"),
            critiques=critiques,
        ),
        {},
    )

    bundle = output.data["bundle"]
    assert bundle["safe_matches"]
    assert not bundle["rejected_matches"]
