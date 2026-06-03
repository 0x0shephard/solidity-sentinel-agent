from __future__ import annotations

from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from sentinel.schemas.common import ToolStatus
from sentinel.schemas.rag import RAGContextBundle, RetrievalQualityGrade
from sentinel.schemas.research import VulnerabilityHypothesis
from sentinel.tools import build_default_registry
from sentinel.tools.executor import ToolExecutor


RAG_TOOL_NAMES = [
    "research.expand_rag_queries",
    "research.retrieve_multi_query",
    "research.merge_rag_results",
    "research.grade_retrieval_quality",
    "research.repair_rag_query",
    "research.critique_historical_matches",
    "research.build_rag_context_bundle",
]


class RAGState(TypedDict, total=False):
    subgraph_run_id: str
    parent_run_id: str
    hypothesis: VulnerabilityHypothesis
    queries: list
    matches_by_query: dict
    matches: list
    grade: RetrievalQualityGrade
    critiques: list
    used_repair: bool
    targeted_rag: dict
    notes: list[str]
    subagent_tool_ledger: list
    bundle: RAGContextBundle


def initial_rag_state(subgraph_run_id: str, parent_run_id: str, hypothesis: VulnerabilityHypothesis, targeted_rag: dict | None = None) -> RAGState:
    return {
        "subgraph_run_id": subgraph_run_id,
        "parent_run_id": parent_run_id,
        "hypothesis": hypothesis,
        "queries": [],
        "matches_by_query": {},
        "matches": [],
        "critiques": [],
        "used_repair": False,
        "targeted_rag": targeted_rag or {},
        "notes": [],
        "subagent_tool_ledger": [],
    }


def _executor() -> ToolExecutor:
    return ToolExecutor(build_default_registry().scoped(RAG_TOOL_NAMES))


def _tool_state(state: RAGState) -> dict:
    return {
        "run_id": state["subgraph_run_id"],
        "run_dir": "",
        "tool_call_count": 0,
        "tool_ledger": [],
        "last_outputs": {},
        "historical_findings": [],
        "targeted_rag": state.get("targeted_rag", {}),
    }


def expand_queries(state: RAGState) -> RAGState:
    tool_state = _tool_state(state)
    output = _executor().execute("research.expand_rag_queries", {"hypothesis": state["hypothesis"].model_dump(mode="json")}, tool_state)
    state["queries"] = output.queries
    state["subagent_tool_ledger"] = tool_state.get("tool_ledger", [])
    return state


def retrieve_and_merge(state: RAGState) -> RAGState:
    tool_state = _tool_state(state)
    executor = _executor()
    retrieved = executor.execute("research.retrieve_multi_query", {"queries": [query.model_dump(mode="json") for query in state.get("queries", [])]}, tool_state)
    merged = executor.execute("research.merge_rag_results", {"matches_by_query": retrieved.model_dump(mode="json")["matches_by_query"]}, tool_state)
    grade = executor.execute(
        "research.grade_retrieval_quality",
        {"hypothesis": state["hypothesis"].model_dump(mode="json"), "matches": [match.model_dump(mode="json") for match in merged.matches]},
        tool_state,
    )
    state["matches_by_query"] = retrieved.matches_by_query
    state["matches"] = merged.matches
    state["grade"] = grade.grade
    state["subagent_tool_ledger"] = [*state.get("subagent_tool_ledger", []), *tool_state.get("tool_ledger", [])]
    return state


def maybe_repair(state: RAGState) -> RAGState:
    grade = state.get("grade")
    if not grade or grade.grade != "weak":
        return state
    tool_state = _tool_state(state)
    executor = _executor()
    repaired = executor.execute(
        "research.repair_rag_query",
        {"hypothesis": state["hypothesis"].model_dump(mode="json"), "grade": grade.model_dump(mode="json")},
        tool_state,
    )
    retrieved = executor.execute("research.retrieve_multi_query", {"queries": [query.model_dump(mode="json") for query in repaired.queries]}, tool_state)
    merged = executor.execute("research.merge_rag_results", {"matches_by_query": retrieved.model_dump(mode="json")["matches_by_query"]}, tool_state)
    repaired_grade = executor.execute(
        "research.grade_retrieval_quality",
        {"hypothesis": state["hypothesis"].model_dump(mode="json"), "matches": [match.model_dump(mode="json") for match in merged.matches]},
        tool_state,
    )
    if repaired_grade.grade.score >= grade.score:
        state["queries"] = [*state.get("queries", []), *repaired.queries]
        state["matches"] = merged.matches
        state["grade"] = repaired_grade.grade
        state["used_repair"] = True
    state["subagent_tool_ledger"] = [*state.get("subagent_tool_ledger", []), *tool_state.get("tool_ledger", [])]
    return state


def critique_matches(state: RAGState) -> RAGState:
    if state.get("grade") and state["grade"].grade == "bad":
        state["critiques"] = []
        return state
    tool_state = _tool_state(state)
    output = _executor().execute(
        "research.critique_historical_matches",
        {"hypothesis": state["hypothesis"].model_dump(mode="json"), "matches": [match.model_dump(mode="json") for match in state.get("matches", [])]},
        tool_state,
    )
    state["critiques"] = output.critiques
    state["subagent_tool_ledger"] = [*state.get("subagent_tool_ledger", []), *tool_state.get("tool_ledger", [])]
    return state


def build_bundle(state: RAGState) -> RAGState:
    tool_state = _tool_state(state)
    grade = state.get("grade") or RetrievalQualityGrade(grade="bad", score=0.0, reason="Retrieval did not run.")
    output = _executor().execute(
        "research.build_rag_context_bundle",
        {
            "hypothesis": state["hypothesis"].model_dump(mode="json"),
            "queries": [query.model_dump(mode="json") for query in state.get("queries", [])],
            "matches": [match.model_dump(mode="json") for match in state.get("matches", [])],
            "grade": grade.model_dump(mode="json"),
            "critiques": [critique.model_dump(mode="json") for critique in state.get("critiques", [])],
            "used_repair": state.get("used_repair", False),
        },
        tool_state,
    )
    state["bundle"] = RAGContextBundle.model_validate(output.data["bundle"])
    state["subagent_tool_ledger"] = [*state.get("subagent_tool_ledger", []), *tool_state.get("tool_ledger", [])]
    return state


def build_rag_graph():
    graph = StateGraph(RAGState)
    graph.add_node("expand_queries", expand_queries)
    graph.add_node("retrieve_and_merge", retrieve_and_merge)
    graph.add_node("maybe_repair", maybe_repair)
    graph.add_node("critique_matches", critique_matches)
    graph.add_node("build_bundle", build_bundle)
    graph.add_edge(START, "expand_queries")
    graph.add_edge("expand_queries", "retrieve_and_merge")
    graph.add_edge("retrieve_and_merge", "maybe_repair")
    graph.add_edge("maybe_repair", "critique_matches")
    graph.add_edge("critique_matches", "build_bundle")
    graph.add_edge("build_bundle", END)
    return graph.compile()


def empty_bundle(hypothesis: VulnerabilityHypothesis, reason: str) -> RAGContextBundle:
    return RAGContextBundle(
        hypothesis_id=hypothesis.id,
        quality_grade=RetrievalQualityGrade(grade="bad", score=0.0, reason=reason),
        notes=[reason],
    )


def run_rag_subgraph(state: RAGState) -> RAGContextBundle:
    try:
        result = build_rag_graph().invoke(state)
        return result["bundle"]
    except Exception as exc:
        return empty_bundle(state["hypothesis"], f"RAG subgraph unavailable: {type(exc).__name__}: {exc}")
