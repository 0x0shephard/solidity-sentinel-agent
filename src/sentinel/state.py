from __future__ import annotations

from typing import TypedDict

from sentinel.schemas.common import ArtifactRef, CompletedStep, PlanStep, ToolCallRecord
from sentinel.schemas.rag import RAGContextBundle
from sentinel.schemas.report import Finding
from sentinel.schemas.research import ResearchRefinement, ResearchSubgraphResult, VulnerabilityHypothesis


class AuditState(TypedDict, total=False):
    """LangGraph parent graph state.

    LangGraph nodes will receive this mapping, compute one focused update, and
    return a partial state update. Keeping this explicit makes the graph easy
    to inspect and prevents hidden conversation-state dependencies.
    """

    run_id: str
    repo: str
    repo_path: str
    objective: str
    run_dir: str
    plan: list[PlanStep]
    completed_steps: list[CompletedStep]
    open_questions: list[str]
    current_focus: str
    tool_call_count: int
    tool_ledger: list[ToolCallRecord]
    compressed_context: str
    repo_facts: dict
    build_facts: dict
    static_facts: dict
    hypotheses: list[VulnerabilityHypothesis]
    subgraph_results: list[ResearchSubgraphResult]
    findings: list[Finding]
    artifacts: list[ArtifactRef]
    errors: list[str]
    warnings: list[str]
    historical_findings: list[dict]
    rag_context_bundles: dict[str, RAGContextBundle]
    last_outputs: dict[str, dict]
    use_llm_refiner: bool


class ResearchState(TypedDict, total=False):
    """Isolated LangGraph research subgraph state."""

    subgraph_run_id: str
    parent_run_id: str
    objective: str
    hypothesis: VulnerabilityHypothesis
    selected_snippets: list[dict]
    allowed_tool_names: list[str]
    use_llm_refiner: bool
    notes: list[str]
    evidence_records: list[dict]
    historical_findings: list[dict]
    rag_context_bundle: RAGContextBundle | None
    subagent_tool_ledger: list[ToolCallRecord]
    llm_refinement: ResearchRefinement
    result: ResearchSubgraphResult


def initial_audit_state(run_id: str, repo: str, objective: str, run_dir: str) -> AuditState:
    """Create the minimum complete parent graph state for a new audit run."""

    return {
        "run_id": run_id,
        "repo": repo,
        "repo_path": repo,
        "objective": objective,
        "run_dir": run_dir,
        "plan": [],
        "completed_steps": [],
        "open_questions": [],
        "current_focus": "initialize",
        "tool_call_count": 0,
        "tool_ledger": [],
        "compressed_context": "",
        "repo_facts": {},
        "build_facts": {},
        "static_facts": {},
        "hypotheses": [],
        "subgraph_results": [],
        "findings": [],
        "artifacts": [],
        "errors": [],
        "warnings": [],
        "historical_findings": [],
        "rag_context_bundles": {},
        "last_outputs": {},
        "use_llm_refiner": False,
    }


def initial_research_state(
    subgraph_run_id: str,
    parent_run_id: str,
    objective: str,
    hypothesis: VulnerabilityHypothesis,
    selected_snippets: list[dict],
    allowed_tool_names: list[str],
    use_llm_refiner: bool = False,
) -> ResearchState:
    """Create isolated state for the research subgraph.

    Notice what is absent: repo path, parent tool ledger, parent artifacts,
    parent static facts, and parent errors. The subgraph receives only scoped
    research context.
    """

    return {
        "subgraph_run_id": subgraph_run_id,
        "parent_run_id": parent_run_id,
        "objective": objective,
        "hypothesis": hypothesis,
        "selected_snippets": selected_snippets,
        "allowed_tool_names": allowed_tool_names,
        "use_llm_refiner": use_llm_refiner,
        "notes": [],
        "historical_findings": [],
        "rag_context_bundle": None,
        "subagent_tool_ledger": [],
    }
