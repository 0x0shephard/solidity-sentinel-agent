from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from sentinel.schemas.common import ToolStatus
from sentinel.schemas.research import ResearchSubgraphResult
from sentinel.state import ResearchState


DEFAULT_RESEARCH_TOOLS = [
    "research.summarize_known_pattern",
]


def validate_scope(state: ResearchState) -> ResearchState:
    allowed = set(state.get("allowed_tool_names", []))
    forbidden = [name for name in allowed if not name.startswith("research.")]
    if forbidden:
        state.setdefault("notes", []).append(f"Rejected non-research tools from scope: {', '.join(forbidden)}")
        state["allowed_tool_names"] = [name for name in state["allowed_tool_names"] if name.startswith("research.")]
    state.setdefault("notes", []).append("Research subgraph received scoped state only.")
    return state


def analyze_hypothesis(state: ResearchState) -> ResearchState:
    hypothesis = state["hypothesis"]
    snippets = state.get("selected_snippets", [])
    if snippets:
        state.setdefault("notes", []).append(f"Reviewed {len(snippets)} selected snippet(s) for {hypothesis.id}.")
    else:
        state.setdefault("notes", []).append(f"No snippets were provided for {hypothesis.id}; confidence remains conservative.")
    state.setdefault("notes", []).append(f"Mapped hypothesis class: {hypothesis.vulnerability_class}.")
    return state


def create_result(state: ResearchState) -> ResearchState:
    hypothesis = state["hypothesis"]
    functions = hypothesis.affected_functions
    files = hypothesis.affected_files
    result = ResearchSubgraphResult(
        status=ToolStatus.OK,
        subgraph_run_id=state["subgraph_run_id"],
        hypothesis_id=hypothesis.id,
        refined_title=hypothesis.title,
        vulnerability_class=hypothesis.vulnerability_class,
        exploit_preconditions=["Attacker can reach the affected function"] if functions else [],
        likely_impact="Requires manual validation; evidence should be tied to file/function facts.",
        evidence_to_collect=[*files, *functions],
        recommended_tests=[f"Add a regression test around {function}" for function in functions] or ["Add a targeted regression test for the suspected behavior."],
        confidence=min(0.95, hypothesis.confidence + 0.1),
        limitations=["Research subgraph is deterministic in Phase 7; LLM-assisted refinement can be added later."],
        notes=state.get("notes", []),
    )
    state["result"] = result
    return state


def build_research_graph():
    graph = StateGraph(ResearchState)
    graph.add_node("validate_scope", validate_scope)
    graph.add_node("analyze_hypothesis", analyze_hypothesis)
    graph.add_node("create_result", create_result)

    graph.add_edge(START, "validate_scope")
    graph.add_edge("validate_scope", "analyze_hypothesis")
    graph.add_edge("analyze_hypothesis", "create_result")
    graph.add_edge("create_result", END)
    return graph.compile()


def run_research_subgraph(state: ResearchState) -> ResearchSubgraphResult:
    result_state = build_research_graph().invoke(state)
    return result_state["result"]

