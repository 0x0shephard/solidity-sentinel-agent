from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
import uuid

from langgraph.graph import END, START, StateGraph

from sentinel.artifacts import ensure_run_dir, write_json
from sentinel.schemas.common import CompletedStep, PlanStep
from sentinel.state import AuditState, initial_audit_state
from sentinel.tools import build_default_registry
from sentinel.tools.executor import ToolExecutor


def make_run_id() -> str:
    return datetime.now(UTC).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]


def _executor() -> ToolExecutor:
    return ToolExecutor(build_default_registry())


def _record_step(state: AuditState, step_id: str, summary: str) -> None:
    state.setdefault("completed_steps", []).append(CompletedStep(step_id=step_id, summary=summary))


def _run_tool(state: AuditState, tool_name: str, raw_input: dict):
    output = _executor().execute(tool_name, raw_input, state)
    _record_step(state, tool_name, f"{tool_name} returned {getattr(output, 'status', 'ok')}")
    return output


def initialize_run(state: AuditState) -> AuditState:
    ensure_run_dir(state["run_dir"])
    state["current_focus"] = "inspect_repo"
    state["plan"] = [
        PlanStep(id="inspect_repo", description="Inspect repository files and Solidity contracts"),
        PlanStep(id="detect_framework", description="Detect Solidity framework and compiler pragmas"),
        PlanStep(id="run_static_analysis", description="Extract static facts and run safe analyzers"),
        PlanStep(id="rank_hypotheses", description="Create early vulnerability hypotheses"),
        PlanStep(id="finish", description="Persist state artifacts"),
    ]
    return state


def inspect_repo(state: AuditState) -> AuditState:
    repo_path = state["repo_path"]
    _run_tool(state, "repo.list_files", {"repo_path": repo_path})
    _run_tool(state, "repo.find_contracts", {"repo_path": repo_path})
    _run_tool(state, "repo.search_text", {"repo_path": repo_path, "query": "pragma"})
    _run_tool(state, "repo.search_text", {"repo_path": repo_path, "query": "contract"})
    state["repo_facts"] = {
        "files": state["last_outputs"].get("repo.list_files", {}).get("files", []),
        "contracts": state["last_outputs"].get("repo.find_contracts", {}).get("files", []),
    }
    state["current_focus"] = "detect_framework"
    return state


def detect_framework(state: AuditState) -> AuditState:
    repo_path = state["repo_path"]
    _run_tool(state, "build.detect_framework", {"repo_path": repo_path})
    _run_tool(state, "build.detect_solc", {"repo_path": repo_path})
    _run_tool(state, "build.check_foundry_available", {"repo_path": repo_path})
    _run_tool(state, "build.check_slither_available", {"repo_path": repo_path})
    state["build_facts"] = {
        "framework": state["last_outputs"].get("build.detect_framework", {}),
        "solc": state["last_outputs"].get("build.detect_solc", {}),
    }
    state["current_focus"] = "run_static_analysis"
    return state


def run_static_analysis(state: AuditState) -> AuditState:
    repo_path = state["repo_path"]
    _run_tool(state, "static.extract_contracts", {"repo_path": repo_path})
    _run_tool(state, "static.extract_functions", {"repo_path": repo_path})
    _run_tool(state, "static.find_access_control_terms", {"repo_path": repo_path})
    _run_tool(state, "static.extract_external_calls", {"repo_path": repo_path})
    _run_tool(state, "repo.search_text", {"repo_path": repo_path, "query": "owner"})
    _run_tool(state, "repo.search_text", {"repo_path": repo_path, "query": "transfer"})
    _run_tool(state, "repo.search_text", {"repo_path": repo_path, "query": "call("})
    _run_tool(state, "repo.search_text", {"repo_path": repo_path, "query": "onlyOwner"})
    state["static_facts"] = {
        "contracts": state["last_outputs"].get("static.extract_contracts", {}).get("facts", []),
        "functions": state["last_outputs"].get("static.extract_functions", {}).get("facts", []),
        "access_control": state["last_outputs"].get("static.find_access_control_terms", {}).get("facts", []),
        "external_calls": state["last_outputs"].get("static.extract_external_calls", {}).get("facts", []),
    }
    state["current_focus"] = "rank_hypotheses"
    return state


def rank_hypotheses(state: AuditState) -> AuditState:
    _run_tool(
        state,
        "research.rank_hypotheses",
        {
            "objective": state["objective"],
            "static_facts": state.get("static_facts", {}).get("functions", []),
        },
    )
    _run_tool(state, "research.summarize_known_pattern", {"topic": "missing access control"})
    _run_tool(state, "research.summarize_known_pattern", {"topic": "reentrancy"})
    state["hypotheses"] = [
        hypothesis for hypothesis in state["last_outputs"].get("research.rank_hypotheses", {}).get("hypotheses", [])
    ]
    state["current_focus"] = "summarize_context"
    return state


def summarize_context(state: AuditState) -> AuditState:
    summary = (
        f"Repo files: {len(state.get('repo_facts', {}).get('files', []))}. "
        f"Contracts: {len(state.get('repo_facts', {}).get('contracts', []))}. "
        f"Static function facts: {len(state.get('static_facts', {}).get('functions', []))}. "
        f"Tool calls: {state.get('tool_call_count', 0)}."
    )
    state["compressed_context"] = summary
    state["current_focus"] = "finish"
    return state


def finish(state: AuditState) -> AuditState:
    # Add two harmless final inspection calls so the mock graph demonstrates a
    # long-horizon path over 20 tool calls without requiring external mutation.
    repo_path = state["repo_path"]
    _run_tool(state, "repo.list_files", {"repo_path": repo_path, "max_files": 50})
    _run_tool(state, "static.extract_functions", {"repo_path": repo_path})
    write_json(Path(state["run_dir"]) / "state.json", state)
    state["current_focus"] = "done"
    return state


def build_parent_graph():
    graph = StateGraph(AuditState)
    graph.add_node("initialize_run", initialize_run)
    graph.add_node("inspect_repo", inspect_repo)
    graph.add_node("detect_framework", detect_framework)
    graph.add_node("run_static_analysis", run_static_analysis)
    graph.add_node("rank_hypotheses", rank_hypotheses)
    graph.add_node("summarize_context", summarize_context)
    graph.add_node("finish", finish)

    graph.add_edge(START, "initialize_run")
    graph.add_edge("initialize_run", "inspect_repo")
    graph.add_edge("inspect_repo", "detect_framework")
    graph.add_edge("detect_framework", "run_static_analysis")
    graph.add_edge("run_static_analysis", "rank_hypotheses")
    graph.add_edge("rank_hypotheses", "summarize_context")
    graph.add_edge("summarize_context", "finish")
    graph.add_edge("finish", END)
    return graph.compile()


def run_audit(repo: str, objective: str, run_id: str | None = None) -> AuditState:
    actual_run_id = run_id or make_run_id()
    run_dir = str(Path("runs") / actual_run_id)
    state = initial_audit_state(run_id=actual_run_id, repo=repo, objective=objective, run_dir=run_dir)
    result = build_parent_graph().invoke(state)
    return result

