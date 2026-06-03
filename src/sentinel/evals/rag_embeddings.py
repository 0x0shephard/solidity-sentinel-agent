from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
import json
import math
from pathlib import Path
import re
import time

from pydantic import BaseModel, Field

from sentinel.artifacts import write_json, write_text
from sentinel.config import Settings, get_settings
from sentinel.rag.canonical import build_canonical_query_text
from sentinel.rag.embeddings import get_embedding_model_info, safe_collection_name
from sentinel.rag.ranking import rank_matches
from sentinel.rag.store import HistoricalFindingStore, load_findings, write_findings
from sentinel.schemas.common import ToolStatus
from sentinel.schemas.rag import HistoricalFindingMatch, HistoricalFindingQuery, RetrievalQualityGrade
from sentinel.schemas.research import VulnerabilityHypothesis
from sentinel.tools.research import CritiqueHistoricalMatchesInput, RetrievalGradeInput, critique_historical_matches, grade_retrieval_quality


DEFAULT_MODELS = [
    "sentence-transformers/all-MiniLM-L6-v2",
    "sentence-transformers/all-mpnet-base-v2",
    "BAAI/bge-base-en-v1.5",
]


class RAGEvalQuery(BaseModel):
    query_id: str
    hypothesis_class: str
    query: str
    root_cause_terms: list[str] = Field(default_factory=list)
    expected_vulnerability_classes: list[str] = Field(default_factory=list)
    expected_terms: list[str] = Field(default_factory=list)
    relevant_finding_ids: list[str] = Field(default_factory=list)


class RAGEvalFixture(BaseModel):
    fixture_name: str
    queries: list[RAGEvalQuery]


class RetrievalMetrics(BaseModel):
    recall_at_5: float = 0.0
    recall_at_10: float = 0.0
    precision_at_5: float = 0.0
    precision_at_10: float = 0.0
    mrr_at_10: float = 0.0
    ndcg_at_10: float = 0.0
    class_match_rate: float = 0.0
    root_cause_term_overlap: float = 0.0
    safe_to_cite_rate: float = 0.0
    average_top_score: float = 0.0
    average_latency_ms: float = 0.0
    strict_metrics_available: bool = False
    weak_label_metrics_available: bool = True
    rejected_match_rate: float = 0.0


class QueryModeResult(BaseModel):
    mode: str
    metrics: RetrievalMetrics
    grade_distribution: dict[str, int] = Field(default_factory=dict)
    top_view_type: str = "unknown"
    root_cause_view_hit_rate: float = 0.0
    recommendation_view_hit_rate: float = 0.0


class ModelRAGEvalResult(BaseModel):
    model: str
    dimension: int
    provider: str
    raw_query: QueryModeResult
    canonical_query: QueryModeResult
    balanced_score: float


class RAGEvalReport(BaseModel):
    fixture_name: str
    models: list[ModelRAGEvalResult]
    best_model_by_recall: str | None = None
    best_model_by_latency: str | None = None
    best_balanced_model: str | None = None
    output_dir: str


def _terms(text: str) -> set[str]:
    return {term.lower() for term in re.findall(r"[a-zA-Z][a-zA-Z0-9_-]{2,}", text)}


def load_rag_fixture(name: str) -> RAGEvalFixture:
    path = Path("evals/rag") / f"{name}.json"
    if not path.exists():
        path = Path("evals/rag") / f"{name}-rag-eval.json"
    return RAGEvalFixture.model_validate_json(path.read_text(encoding="utf-8"))


def list_rag_fixtures() -> list[str]:
    root = Path("evals/rag")
    if not root.exists():
        return []
    return sorted(path.stem for path in root.glob("*.json") if not path.name.endswith(".generated.json"))


def _weak_relevant(query: RAGEvalQuery, match: HistoricalFindingMatch) -> bool:
    finding = match.finding
    expected_classes = {item.lower() for item in query.expected_vulnerability_classes}
    finding_classes = {finding.vulnerability_class.lower(), *[tag.lower() for tag in finding.tags]}
    if expected_classes.intersection(finding_classes):
        return True
    expected_terms = _terms(" ".join([*query.expected_terms, *query.root_cause_terms]))
    finding_text = _terms(f"{finding.title} {finding.search_text[:2000]} {' '.join(finding.root_cause_terms)}")
    return len(expected_terms.intersection(finding_text)) >= min(2, max(1, len(expected_terms)))


def _relevance_labels(query: RAGEvalQuery, matches: list[HistoricalFindingMatch]) -> tuple[list[int], bool]:
    if query.relevant_finding_ids:
        relevant_ids = set(query.relevant_finding_ids)
        return [1 if match.finding.id in relevant_ids else 0 for match in matches], True
    return [1 if _weak_relevant(query, match) else 0 for match in matches], False


def _precision(labels: list[int], k: int) -> float:
    window = labels[:k]
    return sum(window) / k if window else 0.0


def _recall(labels: list[int], k: int, relevant_total: int | None = None) -> float:
    total = relevant_total if relevant_total is not None else max(1, 1 if any(labels) else 0)
    if total == 0:
        return 0.0
    return min(1.0, sum(labels[:k]) / total)


def _mrr(labels: list[int], k: int = 10) -> float:
    for index, label in enumerate(labels[:k], start=1):
        if label:
            return 1.0 / index
    return 0.0


def _dcg(labels: list[int], k: int = 10) -> float:
    return sum(label / math.log2(index + 2) for index, label in enumerate(labels[:k]))


def _ndcg(labels: list[int], k: int = 10) -> float:
    ideal = sorted(labels, reverse=True)
    denom = _dcg(ideal, k)
    return _dcg(labels, k) / denom if denom else 0.0


def _term_overlap(query: RAGEvalQuery, matches: list[HistoricalFindingMatch]) -> float:
    expected = _terms(" ".join([*query.expected_terms, *query.root_cause_terms]))
    if not expected or not matches:
        return 0.0
    scores = []
    for match in matches[:10]:
        got = _terms(f"{match.finding.title} {' '.join(match.finding.root_cause_terms)} {match.finding.search_text[:2000]}")
        scores.append(len(expected.intersection(got)) / len(expected))
    return sum(scores) / len(scores) if scores else 0.0


def balanced_score(metrics: RetrievalMetrics) -> float:
    normalized_latency = min(1.0, metrics.average_latency_ms / 5000.0)
    return max(
        0.0,
        (0.45 * metrics.recall_at_10)
        + (0.25 * metrics.class_match_rate)
        + (0.20 * metrics.safe_to_cite_rate)
        - (0.10 * normalized_latency),
    )


def _hypothesis_for_query(query: RAGEvalQuery) -> VulnerabilityHypothesis:
    return VulnerabilityHypothesis(
        id=query.query_id,
        title=query.query,
        vulnerability_class=query.hypothesis_class,
        evidence_summary=query.query,
        confidence=0.5,
        root_cause_terms=query.root_cause_terms,
        exploit_precondition_terms=query.expected_terms,
        affected_functions=[],
    )


def _canonical_query(query: RAGEvalQuery) -> str:
    return build_canonical_query_text(
        _hypothesis_for_query(query),
        "rag_eval",
        root_cause_terms=query.root_cause_terms,
        exploit_precondition_terms=query.expected_terms,
    )


def _run_query(store: HistoricalFindingStore, query: RAGEvalQuery, text: str) -> tuple[list[HistoricalFindingMatch], list[str], float]:
    started = time.perf_counter()
    hf_query = HistoricalFindingQuery(
        query=text,
        vulnerability_class=query.hypothesis_class,
        tags=query.root_cause_terms,
        top_k=10,
    )
    docs = store.search_documents(hf_query, candidate_k=25)
    matches = rank_matches(hf_query, [(doc["finding"], doc["score"]) for doc in docs])
    view_by_id = {doc["finding"].id: doc["view_type"] for doc in docs}
    views = [view_by_id.get(match.finding.id, "unknown") for match in matches]
    latency_ms = (time.perf_counter() - started) * 1000
    return matches, views, latency_ms


def evaluate_query_mode(store: HistoricalFindingStore, fixture: RAGEvalFixture, mode: str) -> QueryModeResult:
    recall5 = []
    recall10 = []
    precision5 = []
    precision10 = []
    mrr10 = []
    ndcg10 = []
    class_rates = []
    overlaps = []
    top_scores = []
    latencies = []
    safe_rates = []
    reject_rates = []
    grade_counts: Counter[str] = Counter()
    view_counts: Counter[str] = Counter()
    root_hits = []
    rec_hits = []
    strict_available = False
    for query in fixture.queries:
        text = query.query if mode == "raw_query" else _canonical_query(query)
        matches, views, latency = _run_query(store, query, text)
        labels, strict = _relevance_labels(query, matches)
        strict_available = strict_available or strict
        relevant_total = len(query.relevant_finding_ids) if query.relevant_finding_ids else None
        recall5.append(_recall(labels, 5, relevant_total))
        recall10.append(_recall(labels, 10, relevant_total))
        precision5.append(_precision(labels, 5))
        precision10.append(_precision(labels, 10))
        mrr10.append(_mrr(labels, 10))
        ndcg10.append(_ndcg(labels, 10))
        class_rates.append(sum(labels[:10]) / max(1, len(labels[:10])))
        overlaps.append(_term_overlap(query, matches))
        top_scores.append(matches[0].final_score if matches else 0.0)
        latencies.append(latency)
        view_counts.update(views[:5])
        root_hits.append(1.0 if "root_cause_view" in views[:5] else 0.0)
        rec_hits.append(1.0 if "recommendation_view" in views[:5] else 0.0)
        grade = grade_retrieval_quality(RetrievalGradeInput(hypothesis=_hypothesis_for_query(query), matches=matches), {})
        grade_counts[grade.grade.grade] += 1
        critiques = critique_historical_matches(CritiqueHistoricalMatchesInput(hypothesis=_hypothesis_for_query(query), matches=matches), {})
        if critiques.critiques:
            safe = sum(1 for item in critiques.critiques if item.safe_to_cite)
            safe_rates.append(safe / len(critiques.critiques))
            reject_rates.append(1.0 - (safe / len(critiques.critiques)))
        else:
            safe_rates.append(0.0)
            reject_rates.append(0.0)
    count = max(1, len(fixture.queries))

    def avg(values: list[float]) -> float:
        return round(sum(values) / count, 4)

    metrics = RetrievalMetrics(
        recall_at_5=avg(recall5),
        recall_at_10=avg(recall10),
        precision_at_5=avg(precision5),
        precision_at_10=avg(precision10),
        mrr_at_10=avg(mrr10),
        ndcg_at_10=avg(ndcg10),
        class_match_rate=avg(class_rates),
        root_cause_term_overlap=avg(overlaps),
        safe_to_cite_rate=avg(safe_rates),
        average_top_score=avg(top_scores),
        average_latency_ms=round(sum(latencies) / count, 2),
        strict_metrics_available=strict_available,
        rejected_match_rate=avg(reject_rates),
    )
    return QueryModeResult(
        mode=mode,
        metrics=metrics,
        grade_distribution=dict(grade_counts),
        top_view_type=view_counts.most_common(1)[0][0] if view_counts else "unknown",
        root_cause_view_hit_rate=avg(root_hits),
        recommendation_view_hit_rate=avg(rec_hits),
    )


def _model_root(out_dir: Path, model: str) -> Path:
    return out_dir / "indexes" / safe_collection_name("model", model)


def evaluate_embedding_models(
    fixture: RAGEvalFixture,
    models: list[str],
    rebuild: bool = False,
    settings: Settings | None = None,
    output_dir: Path | None = None,
) -> RAGEvalReport:
    cfg = settings or get_settings()
    out_dir = output_dir or Path("runs/rag_eval") / datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    out_dir.mkdir(parents=True, exist_ok=True)
    corpus = load_findings(cfg)
    if not corpus:
        raise ValueError("Global Solodit normalized cache is empty; run `sentinel rag sync` first.")

    results = []
    for model in models:
        model_settings = cfg.model_copy(update={"rag_embed_model": model, "rag_auto_rebuild": True})
        root = _model_root(out_dir, model)
        write_findings(model_settings, [], corpus, root=root)
        store = HistoricalFindingStore(model_settings, root=root)
        if rebuild or store.load_metadata() is None:
            store.rebuild()
        metadata = store.validate_index()
        raw_result = evaluate_query_mode(store, fixture, "raw_query")
        canonical_result = evaluate_query_mode(store, fixture, "canonical_query")
        combined = canonical_result.metrics
        results.append(
            ModelRAGEvalResult(
                model=model,
                dimension=metadata.embedding_dim,
                provider=metadata.embedding_provider,
                raw_query=raw_result,
                canonical_query=canonical_result,
                balanced_score=round(balanced_score(combined), 4),
            )
        )
    report = RAGEvalReport(
        fixture_name=fixture.fixture_name,
        models=results,
        best_model_by_recall=max(results, key=lambda item: item.canonical_query.metrics.recall_at_10).model if results else None,
        best_model_by_latency=min(results, key=lambda item: item.canonical_query.metrics.average_latency_ms).model if results else None,
        best_balanced_model=max(results, key=lambda item: item.balanced_score).model if results else None,
        output_dir=str(out_dir),
    )
    write_json(out_dir / "results.json", report.model_dump(mode="json"))
    write_text(out_dir / "results.md", render_rag_eval_markdown(report))
    return report


def render_rag_eval_markdown(report: RAGEvalReport) -> str:
    lines = [
        f"# RAG Embedding Evaluation: {report.fixture_name}",
        "",
        "| Model | Dim | Recall@5 | Recall@10 | MRR@10 | Class Match | Term Overlap | Safe-to-Cite | Avg Latency |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in report.models:
        metrics = item.canonical_query.metrics
        lines.append(
            f"| {item.model} | {item.dimension} | {metrics.recall_at_5:.2f} | {metrics.recall_at_10:.2f} | "
            f"{metrics.mrr_at_10:.2f} | {metrics.class_match_rate:.2f} | {metrics.root_cause_term_overlap:.2f} | "
            f"{metrics.safe_to_cite_rate:.2f} | {metrics.average_latency_ms:.0f} |"
        )
    lines.extend(
        [
            "",
            "## Query Mode Comparison",
            "",
            "| Model | Mode | Recall@10 | MRR@10 | Safe-to-Cite | Grade Distribution |",
            "|---|---|---:|---:|---:|---|",
        ]
    )
    for item in report.models:
        for mode_result in [item.raw_query, item.canonical_query]:
            metrics = mode_result.metrics
            lines.append(
                f"| {item.model} | {mode_result.mode} | {metrics.recall_at_10:.2f} | {metrics.mrr_at_10:.2f} | "
                f"{metrics.safe_to_cite_rate:.2f} | {mode_result.grade_distribution} |"
            )
    lines.extend(
        [
            "",
            "## Multi-View Retrieval",
            "",
            "| Model | Top View Type | Root-Cause View Hit Rate | Recommendation View Hit Rate |",
            "|---|---|---:|---:|",
        ]
    )
    for item in report.models:
        view = item.canonical_query
        lines.append(
            f"| {item.model} | {view.top_view_type} | {view.root_cause_view_hit_rate:.2f} | {view.recommendation_view_hit_rate:.2f} |"
        )
    lines.extend(
        [
            "",
            "## Recommendation",
            "",
            f"- Best model by Recall@10: `{report.best_model_by_recall}`",
            f"- Best model by latency: `{report.best_model_by_latency}`",
            f"- Best balanced model: `{report.best_balanced_model}`",
            "",
            "Keep MiniLM if the stronger models do not materially improve Recall@10 or balanced score enough to justify latency and local model cost.",
        ]
    )
    return "\n".join(lines) + "\n"


def generate_eval_queries(fixture_name: str) -> Path:
    root = Path("evals/rag")
    root.mkdir(parents=True, exist_ok=True)
    canned = {
        "hawk-high": RAGEvalFixture(
            fixture_name="hawk-high-rag-eval",
            queries=[
                RAGEvalQuery(
                    query_id="q1",
                    hypothesis_class="upgradeability",
                    query="UUPS upgrade flow calls _authorizeUpgrade but does not execute upgradeTo or upgradeToAndCall implementation slot unchanged",
                    root_cause_terms=["UUPS", "_authorizeUpgrade", "upgradeTo", "implementation slot"],
                    expected_vulnerability_classes=["upgradeability", "proxy-upgrade", "access-control"],
                    expected_terms=["authorizeUpgrade", "upgradeTo", "implementation", "UUPS"],
                ),
                RAGEvalQuery(
                    query_id="q2",
                    hypothesis_class="accounting",
                    query="percentage distribution math pays amount to every recipient without dividing by recipient count total payout exceeds configured share",
                    root_cause_terms=["percentage", "distribution", "recipient count", "overpayment"],
                    expected_vulnerability_classes=["accounting", "reward-distribution"],
                    expected_terms=["distribution", "percentage", "overpayment", "accounting"],
                ),
                RAGEvalQuery(
                    query_id="q3",
                    hypothesis_class="storage_layout",
                    query="upgradeable implementation storage layout mismatch between old and new implementation corrupts proxy state",
                    root_cause_terms=["storage layout", "upgradeable", "proxy state"],
                    expected_vulnerability_classes=["storage_layout", "upgradeability"],
                    expected_terms=["storage", "layout", "upgrade", "proxy"],
                ),
                RAGEvalQuery(
                    query_id="q4",
                    hypothesis_class="business_logic",
                    query="configured cutoff score is written but not enforced during graduation lifecycle allowing ineligible users to pass",
                    root_cause_terms=["cutoff", "not enforced", "lifecycle"],
                    expected_vulnerability_classes=["business_logic", "access-control"],
                    expected_terms=["cutoff", "score", "enforced", "lifecycle"],
                ),
            ],
        )
    }
    fixture = canned.get(fixture_name)
    if fixture is None:
        fixture = RAGEvalFixture(
            fixture_name=f"{fixture_name}-rag-eval",
            queries=[
                RAGEvalQuery(
                    query_id="q1",
                    hypothesis_class="manual_review",
                    query=f"{fixture_name} Solidity audit root cause exploit precondition fix pattern",
                    root_cause_terms=[fixture_name],
                    expected_vulnerability_classes=["manual_review"],
                    expected_terms=[fixture_name, "solidity", "audit"],
                )
            ],
        )
    path = root / f"{fixture_name}-rag-eval.generated.json"
    path.write_text(json.dumps(fixture.model_dump(mode="json"), indent=2) + "\n", encoding="utf-8")
    return path
