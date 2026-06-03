from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from sentinel.schemas.common import ToolStatus
from sentinel.schemas.research import ResearchSubgraphResult
from sentinel.state import ResearchState


DEFAULT_RESEARCH_TOOLS = [
    "research.summarize_known_pattern",
]


def _impact_for_class(vulnerability_class: str, functions: list[str]) -> str:
    function_text = f" `{functions[0]}`" if functions else ""
    if vulnerability_class == "reentrancy":
        return f"External control flow before finalized state in{function_text} can allow repeated withdrawal or inconsistent accounting."
    if vulnerability_class == "unchecked_transfer":
        return f"Ignoring an ERC20 transfer return value in{function_text} can make accounting continue after a token transfer failed."
    if vulnerability_class == "missing_access_control":
        return f"An unauthorized caller may be able to execute sensitive behavior in{function_text}."
    return "The evidence supports a manual security review before reporting exploitability."


def _tests_for_class(vulnerability_class: str, functions: list[str]) -> list[str]:
    target = functions[0] if functions else "the affected function"
    if vulnerability_class == "reentrancy":
        return [f"Add an attacker-contract regression test that re-enters {target} before accounting is finalized."]
    if vulnerability_class == "unchecked_transfer":
        return [f"Add a mock ERC20 that returns false and assert {target} reverts or handles the failure."]
    if vulnerability_class == "missing_access_control":
        return [f"Add a non-authorized caller regression test for {target}."]
    return [f"Add a targeted regression test for {target}."]


def _evidence_message(snippet: dict) -> str:
    if snippet.get("description"):
        return str(snippet["description"]).strip()
    if snippet.get("text"):
        return str(snippet["text"]).strip()
    if snippet.get("function"):
        return f"Function declaration: {snippet['function']}"
    if snippet.get("check"):
        return f"Slither detector: {snippet['check']}"
    return "Selected evidence snippet."


def _evidence_records(snippets: list[dict]) -> list[dict]:
    records: list[dict] = []
    seen: set[tuple] = set()
    for snippet in snippets:
        file_path = snippet.get("file_path")
        if not file_path and snippet.get("source_files"):
            file_path = snippet["source_files"][0]
        message = _evidence_message(snippet)
        key = (file_path, snippet.get("line"), snippet.get("function") or tuple(snippet.get("functions") or []), message)
        if key in seen:
            continue
        seen.add(key)
        records.append(
            {
                "kind": str(snippet.get("kind", "selected_evidence")),
                "file_path": file_path,
                "line_start": snippet.get("line"),
                "line_end": snippet.get("line"),
                "function": snippet.get("function") or (snippet.get("functions") or [None])[0],
                "message": message,
            }
        )
    return records[:6]


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
        state["evidence_records"] = _evidence_records(snippets)
    else:
        state.setdefault("notes", []).append(f"No snippets were provided for {hypothesis.id}; confidence remains conservative.")
        state["evidence_records"] = []
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
        evidence=state.get("evidence_records", []),
        exploit_preconditions=["Attacker can reach the affected function"] if functions else [],
        likely_impact=_impact_for_class(hypothesis.vulnerability_class, functions),
        evidence_to_collect=[*files, *functions],
        recommended_tests=_tests_for_class(hypothesis.vulnerability_class, functions),
        confidence=min(0.95, hypothesis.confidence + 0.1),
        limitations=["Research subgraph is deterministic; exploitability still requires targeted validation on the full project."],
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
