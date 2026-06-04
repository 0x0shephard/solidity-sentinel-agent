from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
import uuid

from langgraph.graph import END, START, StateGraph

from sentinel.artifacts import ensure_run_dir, write_json, write_text
from sentinel.analysis.invariants import build_protocol_model as build_protocol_model_from_facts, mine_invariant_candidates
from sentinel.config import get_settings
from sentinel.graphs.research import DEFAULT_RESEARCH_TOOLS, run_research_subgraph
from sentinel.graphs.rag_subgraph import initial_rag_state, run_rag_subgraph
from sentinel.llm.provider import get_ollama_fallback_planner, get_planner
from sentinel.observability.logging import log_event
from sentinel.observability.tracing import trace_span
from sentinel.rag.sync import sync_solodit
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


def _evidence_snippets_for_hypothesis(state: AuditState, hypothesis: VulnerabilityHypothesis) -> list[dict]:
    if hypothesis.evidence_lines:
        return [
            {
                "kind": "source_evidence",
                "file_path": item.file_path,
                "line": item.line_start,
                "line_start": item.line_start,
                "line_end": item.line_end,
                "function": item.function_name,
                "text": item.source_text,
                "message": item.reason,
            }
            for item in hypothesis.evidence_lines
        ][:8]
    affected_files = set(hypothesis.affected_files)
    affected_functions = set(hypothesis.affected_functions)
    grouped_snippets: dict[str, list[dict]] = {}
    for fact_group, facts in state.get("static_facts", {}).items():
        for fact in facts:
            fact_files = set()
            if fact.get("file_path"):
                fact_files.add(fact["file_path"])
            fact_files.update(fact.get("source_files") or [])
            if affected_files and fact_files and not affected_files.intersection(fact_files):
                continue
            fact_functions = set()
            if fact.get("function"):
                fact_functions.add(fact["function"])
            fact_functions.update(fact.get("functions") or [])
            if affected_functions and fact_functions and not affected_functions.intersection(fact_functions):
                continue
            snippet = {"kind": fact_group, **fact}
            grouped_snippets.setdefault(fact_group, []).append(snippet)
    if hypothesis.vulnerability_class == "reentrancy":
        snippets = [
            *grouped_snippets.get("slither_findings", []),
            *grouped_snippets.get("external_calls", []),
            *grouped_snippets.get("storage_writes", []),
            *grouped_snippets.get("functions", []),
        ]
    elif hypothesis.vulnerability_class == "unchecked_transfer":
        snippets = [
            *grouped_snippets.get("slither_findings", []),
            *grouped_snippets.get("token_transfers", []),
            *grouped_snippets.get("functions", []),
            *grouped_snippets.get("storage_writes", []),
        ]
    elif hypothesis.vulnerability_class == "missing_access_control":
        snippets = [
            *grouped_snippets.get("slither_findings", []),
            *grouped_snippets.get("external_calls", []),
            *grouped_snippets.get("access_control", []),
            *grouped_snippets.get("functions", []),
        ]
    else:
        snippets = [snippet for group in grouped_snippets.values() for snippet in group]
    if not snippets:
        snippets.append(
            {
                "kind": "hypothesis",
                "file_path": hypothesis.affected_files[0] if hypothesis.affected_files else None,
                "function": hypothesis.affected_functions[0] if hypothesis.affected_functions else None,
                "text": hypothesis.evidence_summary,
            }
        )
    return snippets[:8]


def _tool_prompt(state: AuditState) -> str:
    remaining_budget = max(0, get_settings().max_tool_calls - state.get("tool_call_count", 0))
    rag_context = state.get("last_outputs", {}).get("research.retrieve_historical_findings", {})
    return (
        f"Objective: {state['objective']}\n"
        f"Repository path: {state['repo_path']}\n"
        f"Current focus: {state.get('current_focus', 'initialize')}\n"
        f"Compressed context: {state.get('compressed_context', '')}\n\n"
        f"Remaining approximate tool budget: {remaining_budget}\n"
        f"Available RAG context: {rag_context}\n\n"
        "Return a concise plan for the next safe audit tools to run. "
        "Prefer repo/build/static/research tools. Include repo_path in inputs when needed. "
        "Use output_references when one tool output should feed another input."
    )


def _resolve_output_references(state: AuditState, tool_input: dict, references: list[dict]) -> dict:
    resolved = dict(tool_input)
    for ref in references:
        from_tool = ref.get("from_tool")
        path = str(ref.get("path", ""))
        target_input = ref.get("target_input")
        if not from_tool or not path or not target_input:
            continue
        value = state.get("last_outputs", {}).get(from_tool)
        for part in path.split("."):
            if isinstance(value, dict):
                value = value.get(part)
            else:
                value = None
                break
        if value is not None:
            resolved[target_input] = value
    return resolved


def _model_or_mapping_json(value) -> dict:
    if not value:
        return {}
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return value
    return {}


def plan_with_llm(state: AuditState) -> AuditState:
    registry = build_default_registry()
    tool_catalog = [tool.public_dict() for tool in registry.list()]
    planner_source = "primary"
    try:
        planner = get_planner(mock=False)
        plan = planner.plan(_tool_prompt(state), tool_catalog)
    except Exception as exc:
        primary_error = f"{type(exc).__name__}: {exc}"
        state.setdefault("warnings", []).append(f"Primary LLM planner unavailable; trying Ollama fallback: {primary_error}")
        try:
            planner = get_ollama_fallback_planner()
            planner_source = "ollama_fallback"
            plan = planner.plan(_tool_prompt(state), tool_catalog)
            state.setdefault("warnings", []).append("Ollama fallback planner succeeded after primary LLM failure.")
        except Exception as fallback_exc:
            state.setdefault("warnings", []).append(
                f"Ollama fallback planner unavailable; continuing with deterministic graph path: {type(fallback_exc).__name__}: {fallback_exc}"
            )
            state["last_outputs"]["llm.plan_with_llm"] = {
                "executed": [],
                "fallback": "deterministic_graph",
                "primary_error": primary_error[:500],
                "fallback_error_type": type(fallback_exc).__name__,
                "fallback_message": str(fallback_exc)[:500],
            }
            state["current_focus"] = "inspect_repo"
            return state
    valid_names = {tool.full_name for tool in registry.list()}
    executed = []
    executor = ToolExecutor(registry)
    for decision in plan.decisions[:8]:
        if decision.tool_name not in valid_names:
            state.setdefault("errors", []).append(f"LLM selected unknown tool: {decision.tool_name}")
            continue
        tool = registry.get(decision.tool_name)
        tool_input = _resolve_output_references(state, dict(decision.tool_input), decision.output_references)
        if "repo_path" in tool.input_model.model_fields and "repo_path" not in tool_input:
            tool_input["repo_path"] = state["repo_path"]
        required = {name for name, field in tool.input_model.model_fields.items() if field.is_required()}
        if not required.issubset(tool_input):
            state.setdefault("errors", []).append(f"LLM omitted required input for {decision.tool_name}")
            continue
        output = executor.execute(decision.tool_name, tool_input, state)
        _record_step(state, decision.tool_name, f"{decision.tool_name} selected by LLM: {decision.rationale}")
        executed.append({"tool_name": decision.tool_name, "status": getattr(output, "status", "ok")})
    state["last_outputs"]["llm.plan_with_llm"] = {"executed": executed, "planner_source": planner_source}
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
        PlanStep(id="build_protocol_model", description="Summarize protocol roles, assets, lifecycle, accounting, and upgrade surfaces"),
        PlanStep(id="mine_invariant_candidates", description="Mine protocol invariant candidates from production source evidence"),
        PlanStep(id="build_targeted_rag_context", description="Build repo profile and targeted Solodit context"),
        PlanStep(id="rank_hypotheses", description="Create early vulnerability hypotheses"),
        PlanStep(id="finish", description="Persist state artifacts"),
    ]
    return state


def maybe_sync_solodit_rag(state: AuditState) -> AuditState:
    result = sync_solodit(stale_ok=True)
    state["last_outputs"]["research.solodit_sync"] = {"status": result.status.value, "state": result.model_dump(mode="json")}
    if result.message:
        state.setdefault("warnings", []).append(result.message)
    state["current_focus"] = "inspect_repo"
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
    framework = state["last_outputs"].get("build.detect_framework", {}).get("framework")
    foundry_status = state["last_outputs"].get("build.check_foundry_available", {}).get("status")
    if framework in {"foundry", "mixed"} and str(foundry_status).lower().endswith("ok"):
        _run_tool(state, "build.foundry_build", {"repo_path": repo_path})
    state["build_facts"] = {
        "framework": state["last_outputs"].get("build.detect_framework", {}),
        "solc": state["last_outputs"].get("build.detect_solc", {}),
        "foundry_build": state["last_outputs"].get("build.foundry_build", {}),
    }
    state["current_focus"] = "run_static_analysis"
    return state


def run_static_analysis(state: AuditState) -> AuditState:
    repo_path = state["repo_path"]
    _run_tool(state, "static.extract_contracts", {"repo_path": repo_path})
    _run_tool(state, "static.extract_functions", {"repo_path": repo_path})
    _run_tool(state, "static.map_function_ranges", {"repo_path": repo_path})
    _run_tool(state, "static.find_access_control_terms", {"repo_path": repo_path})
    _run_tool(state, "static.extract_external_calls", {"repo_path": repo_path})
    _run_tool(state, "static.extract_token_transfers", {"repo_path": repo_path})
    _run_tool(state, "static.extract_storage_writes", {"repo_path": repo_path})
    detector_names = [
        "static.detect_tx_origin_auth",
        "static.detect_unguarded_initializer",
        "static.detect_oracle_staleness_logic",
        "static.detect_unchecked_erc20_returns",
        "static.detect_dangerous_delegatecall",
        "static.detect_unsafe_or_guards",
        "static.detect_external_call_before_accounting",
        "static.detect_strategy_accounting_trust",
    ]
    for detector_name in detector_names:
        _run_tool(state, detector_name, {"repo_path": repo_path})
    slither_output = _run_tool(state, "static.run_slither", {"repo_path": repo_path})
    if getattr(slither_output, "raw_json_path", None):
        _run_tool(state, "static.parse_slither", {"raw_json_path": slither_output.raw_json_path})
    _run_tool(state, "repo.search_text", {"repo_path": repo_path, "query": "owner"})
    _run_tool(state, "repo.search_text", {"repo_path": repo_path, "query": "transfer"})
    _run_tool(state, "repo.search_text", {"repo_path": repo_path, "query": "call("})
    _run_tool(state, "repo.search_text", {"repo_path": repo_path, "query": "onlyOwner"})
    state["static_facts"] = {
        "contracts": state["last_outputs"].get("static.extract_contracts", {}).get("facts", []),
        "functions": state["last_outputs"].get("static.extract_functions", {}).get("facts", []),
        "function_ranges": state["last_outputs"].get("static.map_function_ranges", {}).get("ranges", []),
        "access_control": state["last_outputs"].get("static.find_access_control_terms", {}).get("facts", []),
        "external_calls": state["last_outputs"].get("static.extract_external_calls", {}).get("facts", []),
        "token_transfers": state["last_outputs"].get("static.extract_token_transfers", {}).get("facts", []),
        "storage_writes": state["last_outputs"].get("static.extract_storage_writes", {}).get("facts", []),
        "slither_findings": state["last_outputs"].get("static.parse_slither", {}).get("findings", []),
        "detections": [
            detection
            for detector_name in detector_names
            for detection in state["last_outputs"].get(detector_name, {}).get("detections", [])
        ],
    }
    state["current_focus"] = "rank_hypotheses"
    return state


def build_protocol_model(state: AuditState) -> AuditState:
    model = build_protocol_model_from_facts(state.get("static_facts", {}))
    state["protocol_model"] = model
    state["last_outputs"]["analysis.build_protocol_model"] = {"status": "ok", "protocol_model": model.model_dump(mode="json")}
    _record_step(state, "analysis.build_protocol_model", f"Protocol model terms: roles={len(model.roles)}, accounting={len(model.accounting_terms)}")
    state["current_focus"] = "mine_invariant_candidates"
    return state


def mine_invariants(state: AuditState) -> AuditState:
    candidates = mine_invariant_candidates(state["repo_path"], state.get("static_facts", {}))
    state["invariant_candidates"] = candidates
    state["last_outputs"]["analysis.mine_invariant_candidates"] = {
        "status": "ok",
        "candidates": [candidate.model_dump(mode="json") for candidate in candidates],
    }
    _record_step(state, "analysis.mine_invariant_candidates", f"Mined {len(candidates)} protocol invariant candidates")
    state["current_focus"] = "build_targeted_rag_context"
    return state


def build_targeted_rag_context(state: AuditState) -> AuditState:
    repo_path = state["repo_path"]
    profile = _run_tool(
        state,
        "research.build_repo_profile",
        {"repo_path": repo_path, "static_facts": state.get("static_facts", {})},
    )
    state["repo_rag_profile"] = getattr(profile, "profile", None)
    targeted = _run_tool(
        state,
        "research.targeted_solodit_context",
        {"repo_path": repo_path, "static_facts": state.get("static_facts", {})},
    )
    state["targeted_rag"] = getattr(targeted, "state", None)
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
                *state.get("static_facts", {}).get("token_transfers", []),
                *state.get("static_facts", {}).get("storage_writes", []),
                *state.get("static_facts", {}).get("slither_findings", []),
                *state.get("static_facts", {}).get("access_control", []),
                *state.get("static_facts", {}).get("detections", []),
                *[
                    {"invariant_candidate": candidate.model_dump(mode="json")}
                    for candidate in state.get("invariant_candidates", [])
                ],
                _model_or_mapping_json(state.get("repo_rag_profile")),
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


def rag_retrieve_context(state: AuditState) -> AuditState:
    hypotheses = state.get("hypotheses", [])
    if not hypotheses:
        return state
    state.setdefault("rag_context_bundles", {})
    for hypothesis in hypotheses[:5]:
        bundle = run_rag_subgraph(
            initial_rag_state(
                subgraph_run_id=f"{state['run_id']}-rag-{hypothesis.id}",
                parent_run_id=state["run_id"],
                hypothesis=hypothesis,
                targeted_rag=_model_or_mapping_json(state.get("targeted_rag")),
                run_dir=state["run_dir"],
            )
        )
        state["rag_context_bundles"][hypothesis.id] = bundle
        hypothesis.historical_matches = [critique.model_dump(mode="json") for critique in bundle.safe_matches]
        _record_step(state, "rag.subgraph", f"RAG bundle for {hypothesis.id}: {bundle.quality_grade.grade}, safe={len(bundle.safe_matches)}")
    state["current_focus"] = "research_subgraph"
    return state


def research_subgraph(state: AuditState) -> AuditState:
    hypotheses = state.get("hypotheses", [])
    if not hypotheses:
        state.setdefault("errors", []).append("No hypothesis available for research subgraph.")
        state["current_focus"] = "summarize_context"
        return state

    for index, hypothesis in enumerate(hypotheses[:5], start=1):
        selected_snippets = _evidence_snippets_for_hypothesis(state, hypothesis)
        subgraph_state = initial_research_state(
            subgraph_run_id=f"{state['run_id']}-research-{index}",
            parent_run_id=state["run_id"],
            objective=state["objective"],
            hypothesis=hypothesis,
            selected_snippets=selected_snippets,
            allowed_tool_names=DEFAULT_RESEARCH_TOOLS,
            use_llm_refiner=state.get("use_llm_refiner", False),
        )
        subgraph_state["rag_context_bundle"] = state.get("rag_context_bundles", {}).get(hypothesis.id)
        result = run_research_subgraph(subgraph_state)
        state.setdefault("subgraph_results", []).append(result)
        state["last_outputs"][f"research.subgraph.{hypothesis.id}"] = result.model_dump(mode="json")
        state["last_outputs"]["research.subgraph"] = result.model_dump(mode="json")
        _record_step(state, "research.subgraph", f"Research subgraph returned {result.status} for {hypothesis.id}")
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
    hypotheses = state.get("hypotheses", [])
    if hypotheses:
        for hypothesis in hypotheses[:5]:
            _run_tool(
                state,
                "dynamic.generate_validation_artifacts",
                {"repo_path": repo_path, "hypothesis": hypothesis.model_dump(mode="json")},
            )
    else:
        _run_tool(state, "dynamic.generate_validation_artifacts", {"repo_path": repo_path})
    _run_tool(state, "dynamic.compile_validation_artifacts", {"repo_path": repo_path})
    _run_tool(state, "dynamic.run_validation_artifacts", {"repo_path": repo_path})
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
    graph.add_node("maybe_sync_solodit_rag", maybe_sync_solodit_rag)
    graph.add_node("plan_with_llm", plan_with_llm)
    graph.add_node("inspect_repo", inspect_repo)
    graph.add_node("detect_framework", detect_framework)
    graph.add_node("run_static_analysis", run_static_analysis)
    graph.add_node("build_protocol_model", build_protocol_model)
    graph.add_node("mine_invariant_candidates", mine_invariants)
    graph.add_node("build_targeted_rag_context", build_targeted_rag_context)
    graph.add_node("rank_hypotheses", rank_hypotheses)
    graph.add_node("rag_retrieve_context", rag_retrieve_context)
    graph.add_node("research_subgraph", research_subgraph)
    graph.add_node("summarize_context", summarize_context)
    graph.add_node("finish", finish)

    graph.add_edge(START, "initialize_run")
    graph.add_edge("initialize_run", "maybe_sync_solodit_rag")
    graph.add_edge("maybe_sync_solodit_rag", "plan_with_llm" if use_llm_planner else "inspect_repo")
    graph.add_edge("plan_with_llm", "inspect_repo")
    graph.add_edge("inspect_repo", "detect_framework")
    graph.add_edge("detect_framework", "run_static_analysis")
    graph.add_edge("run_static_analysis", "build_protocol_model")
    graph.add_edge("build_protocol_model", "mine_invariant_candidates")
    graph.add_edge("mine_invariant_candidates", "build_targeted_rag_context")
    graph.add_edge("build_targeted_rag_context", "rank_hypotheses")
    graph.add_edge("rank_hypotheses", "rag_retrieve_context")
    graph.add_edge("rag_retrieve_context", "research_subgraph")
    graph.add_edge("research_subgraph", "summarize_context")
    graph.add_edge("summarize_context", "finish")
    graph.add_edge("finish", END)
    return graph.compile()


def run_audit(repo: str, objective: str, run_id: str | None = None, mock_llm: bool = True) -> AuditState:
    actual_run_id = run_id or make_run_id()
    run_dir = str(Path("runs") / actual_run_id)
    state = initial_audit_state(run_id=actual_run_id, repo=repo, objective=objective, run_dir=run_dir)
    state["use_llm_refiner"] = not mock_llm
    ensure_run_dir(run_dir)
    with trace_span("audit.run", run_dir, run_id=actual_run_id, repo=repo, mock_llm=mock_llm):
        result = build_parent_graph(use_llm_planner=not mock_llm).invoke(state)
    return result
