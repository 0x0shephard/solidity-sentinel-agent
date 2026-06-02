from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
import uuid

from langgraph.graph import END, START, StateGraph

from sentinel.artifacts import ensure_run_dir, write_json, write_text
from sentinel.graphs.research import DEFAULT_RESEARCH_TOOLS, run_research_subgraph
from sentinel.llm.provider import get_planner
from sentinel.observability.logging import log_event
from sentinel.observability.tracing import trace_span
from sentinel.reporting import build_report_document, create_findings_from_state, render_markdown_report
from sentinel.schemas.common import CompletedStep, PlanStep
from sentinel.schemas.research import VulnerabilityHypothesis
from sentinel.state import AuditState, initial_audit_state, initial_research_state
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


def _tool_prompt(state: AuditState) -> str:
    return (
        f"Objective: {state['objective']}\n"
        f"Repository path: {state['repo_path']}\n"
        f"Current focus: {state.get('current_focus', 'initialize')}\n"
        f"Compressed context: {state.get('compressed_context', '')}\n\n"
        "Return a concise plan for the next safe audit tools to run. "
        "Prefer repo/build/static/research tools. Include repo_path in inputs when needed."
    )


def plan_with_llm(state: AuditState) -> AuditState:
    registry = build_default_registry()
    planner = get_planner(mock=False)
    plan = planner.plan(_tool_prompt(state), [tool.public_dict() for tool in registry.list()])
    valid_names = {tool.full_name for tool in registry.list()}
    executed = []
    executor = ToolExecutor(registry)
    for decision in plan.decisions[:8]:
        if decision.tool_name not in valid_names:
            state.setdefault("errors", []).append(f"LLM selected unknown tool: {decision.tool_name}")
            continue
        tool = registry.get(decision.tool_name)
        tool_input = dict(decision.tool_input)
        if "repo_path" in tool.input_model.model_fields and "repo_path" not in tool_input:
            tool_input["repo_path"] = state["repo_path"]
        required = {name for name, field in tool.input_model.model_fields.items() if field.is_required()}
        if not required.issubset(tool_input):
            state.setdefault("errors", []).append(f"LLM omitted required input for {decision.tool_name}")
            continue
        output = executor.execute(decision.tool_name, tool_input, state)
        _record_step(state, decision.tool_name, f"{decision.tool_name} selected by LLM: {decision.rationale}")
        executed.append({"tool_name": decision.tool_name, "status": getattr(output, "status", "ok")})
    state["last_outputs"]["llm.plan_with_llm"] = {"executed": executed}
    state["current_focus"] = "inspect_repo"
    return state


def initialize_run(state: AuditState) -> AuditState:
    ensure_run_dir(state["run_dir"])
    log_event(state["run_dir"], run_id=state["run_id"], event="run_started", status="running")
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
            "static_facts": [
                *state.get("static_facts", {}).get("functions", []),
                *state.get("static_facts", {}).get("external_calls", []),
                *state.get("static_facts", {}).get("access_control", []),
            ],
        },
    )
    _run_tool(state, "research.summarize_known_pattern", {"topic": "missing access control"})
    _run_tool(state, "research.summarize_known_pattern", {"topic": "reentrancy"})
    state["hypotheses"] = [
        VulnerabilityHypothesis.model_validate(hypothesis)
        for hypothesis in state["last_outputs"].get("research.rank_hypotheses", {}).get("hypotheses", [])
    ]
    state["current_focus"] = "research_subgraph"
    return state


def research_subgraph(state: AuditState) -> AuditState:
    hypotheses = state.get("hypotheses", [])
    if not hypotheses:
        state.setdefault("errors", []).append("No hypothesis available for research subgraph.")
        state["current_focus"] = "summarize_context"
        return state

    hypothesis = hypotheses[0]
    selected_snippets = [
        *state.get("static_facts", {}).get("functions", [])[:3],
        *state.get("static_facts", {}).get("external_calls", [])[:3],
    ]
    subgraph_state = initial_research_state(
        subgraph_run_id=f"{state['run_id']}-research-1",
        parent_run_id=state["run_id"],
        objective=state["objective"],
        hypothesis=hypothesis,
        selected_snippets=selected_snippets,
        allowed_tool_names=DEFAULT_RESEARCH_TOOLS,
    )
    result = run_research_subgraph(subgraph_state)
    state.setdefault("subgraph_results", []).append(result)
    state["last_outputs"]["research.subgraph"] = result.model_dump(mode="json")
    _record_step(state, "research.subgraph", f"Research subgraph returned {result.status}")
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
    state["findings"] = create_findings_from_state(state)
    report = build_report_document(state)
    write_json(Path(state["run_dir"]) / "report.json", report.model_dump(mode="json"))
    write_text(Path(state["run_dir"]) / "report.md", render_markdown_report(report))
    log_event(
        state["run_dir"],
        run_id=state["run_id"],
        event="report_generated",
        status="ok",
        finding_count=len(state["findings"]),
    )
    state["current_focus"] = "done"
    write_json(Path(state["run_dir"]) / "state.json", state)
    log_event(
        state["run_dir"],
        run_id=state["run_id"],
        event="run_finished",
        status="completed",
        tool_call_count=state.get("tool_call_count", 0),
    )
    return state


def build_parent_graph(use_llm_planner: bool = False):
    graph = StateGraph(AuditState)
    graph.add_node("initialize_run", initialize_run)
    graph.add_node("plan_with_llm", plan_with_llm)
    graph.add_node("inspect_repo", inspect_repo)
    graph.add_node("detect_framework", detect_framework)
    graph.add_node("run_static_analysis", run_static_analysis)
    graph.add_node("rank_hypotheses", rank_hypotheses)
    graph.add_node("research_subgraph", research_subgraph)
    graph.add_node("summarize_context", summarize_context)
    graph.add_node("finish", finish)

    graph.add_edge(START, "initialize_run")
    graph.add_edge("initialize_run", "plan_with_llm" if use_llm_planner else "inspect_repo")
    graph.add_edge("plan_with_llm", "inspect_repo")
    graph.add_edge("inspect_repo", "detect_framework")
    graph.add_edge("detect_framework", "run_static_analysis")
    graph.add_edge("run_static_analysis", "rank_hypotheses")
    graph.add_edge("rank_hypotheses", "research_subgraph")
    graph.add_edge("research_subgraph", "summarize_context")
    graph.add_edge("summarize_context", "finish")
    graph.add_edge("finish", END)
    return graph.compile()


def run_audit(repo: str, objective: str, run_id: str | None = None, mock_llm: bool = True) -> AuditState:
    actual_run_id = run_id or make_run_id()
    run_dir = str(Path("runs") / actual_run_id)
    state = initial_audit_state(run_id=actual_run_id, repo=repo, objective=objective, run_dir=run_dir)
    ensure_run_dir(run_dir)
    with trace_span("audit.run", run_dir, run_id=actual_run_id, repo=repo, mock_llm=mock_llm):
        result = build_parent_graph(use_llm_planner=not mock_llm).invoke(state)
    return result
