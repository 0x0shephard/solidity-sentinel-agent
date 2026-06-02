from __future__ import annotations

from typing import TypedDict

from sentinel.schemas.common import ArtifactRef, CompletedStep, PlanStep, ToolCallRecord
from sentinel.schemas.report import Finding
from sentinel.schemas.research import ResearchSubgraphResult, VulnerabilityHypothesis


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
    last_outputs: dict[str, dict]


class ResearchState(TypedDict, total=False):
    """Isolated LangGraph research subgraph state."""

    subgraph_run_id: str
    parent_run_id: str
    objective: str
    hypothesis: VulnerabilityHypothesis
    selected_snippets: list[dict]
    allowed_tool_names: list[str]
    notes: list[str]
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
        "last_outputs": {},
    }
