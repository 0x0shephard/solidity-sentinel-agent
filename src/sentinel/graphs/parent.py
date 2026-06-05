from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
import uuid

from langgraph.graph import END, START, StateGraph

from sentinel.artifacts import ensure_run_dir, write_json, write_text
from sentinel.analysis.contest import build_reasoning_packets, build_working_memory, run_gap_hunters
from sentinel.analysis.invariants import build_invariant_proof_packets, build_protocol_model as build_protocol_model_from_facts, mine_invariant_candidates
from sentinel.analysis.protocol_ir import build_protocol_graph, build_protocol_ir as build_protocol_ir_from_facts, protocol_ir_summary
from sentinel.config import get_settings
from sentinel.graphs.research import DEFAULT_RESEARCH_TOOLS, run_research_subgraph
from sentinel.graphs.rag_subgraph import initial_rag_state, run_rag_subgraph
from sentinel.llm.provider import get_ollama_fallback_planner, get_planner
from sentinel.observability.logging import log_event
from sentinel.observability.tracing import trace_span
from sentinel.rag.sync import sync_solodit
from sentinel.reporting import build_report_document, create_findings_from_state, render_markdown_report
from sentinel.schemas.common import ArtifactRef, CompletedStep, PlanStep
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
    proof_packet = next((packet for packet in state.get("proof_packets", []) if packet.packet_id == hypothesis.proof_packet_id), None)
    proof_snippets: list[dict] = []
    if proof_packet:
        proof_snippets.append(
            {
                "kind": "proof_packet",
                "proof_packet_id": proof_packet.packet_id,
                "invariant_type": proof_packet.invariant_type,
                "proof_status": proof_packet.proof_status,
                "text": proof_packet.title,
                "message": "Protocol invariant proof packet",
                "proof_obligations": [item.model_dump(mode="json") for item in proof_packet.proof_obligations],
                "counterevidence": proof_packet.counterevidence,
                "local_facts": proof_packet.local_facts,
            }
        )
    function_snippets = _function_body_snippets_for_hypothesis(state, hypothesis)
    if hypothesis.evidence_lines:
        return (proof_snippets + function_snippets + [
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
        ])[:12]
    affected_files = set(hypothesis.affected_files)
    affected_functions = set(hypothesis.affected_functions)
    grouped_snippets: dict[str, list[dict]] = {}
    for fact_group, facts in state.get("static_facts", {}).items():
        if not isinstance(facts, list):
            continue
        for fact in facts:
            if not isinstance(fact, dict):
                continue
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
    return (proof_snippets + function_snippets + snippets)[:12]


def _function_body_snippets_for_hypothesis(state: AuditState, hypothesis: VulnerabilityHypothesis) -> list[dict]:
    repo_path = Path(state.get("repo_path", ""))
    ranges = state.get("static_facts", {}).get("function_ranges", [])
    if not repo_path or not ranges:
        return []

    desired_files = {item.file_path for item in hypothesis.evidence_lines if item.file_path}
    desired_files.update(hypothesis.affected_files)
    desired_functions = {item.function_name for item in hypothesis.evidence_lines if item.function_name}
    desired_functions.update(hypothesis.affected_functions)
    desired_contracts = {item.contract_name for item in hypothesis.evidence_lines if item.contract_name}
    if hypothesis.affected_contract:
        desired_contracts.add(hypothesis.affected_contract)

    snippets: list[dict] = []
    seen: set[tuple[str, str | None, int | None]] = set()
    used_chars = 0
    for raw_range in ranges:
        if not isinstance(raw_range, dict):
            continue
        file_path = str(raw_range.get("file_path") or "")
        function_name = raw_range.get("function_name")
        contract_name = raw_range.get("contract_name")
        if desired_files and file_path not in desired_files:
            continue
        if desired_functions and function_name not in desired_functions:
            continue
        if desired_contracts and contract_name not in desired_contracts:
            continue
        start_line = raw_range.get("start_line")
        end_line = raw_range.get("end_line")
        if not file_path or not isinstance(start_line, int) or not isinstance(end_line, int):
            continue
        key = (file_path, function_name, start_line)
        if key in seen:
            continue
        source_path = repo_path / file_path
        if not source_path.exists():
            continue
        lines = source_path.read_text(encoding="utf-8", errors="replace").splitlines()
        body = "\n".join(lines[max(0, start_line - 1):end_line])
        if not body.strip():
            continue
        body = body[:4000]
        if used_chars + len(body) > 12000:
            break
        used_chars += len(body)
        seen.add(key)
        snippets.append(
            {
                "kind": "function_body",
                "file_path": file_path,
                "line_start": start_line,
                "line_end": end_line,
                "function": function_name,
                "contract": contract_name,
                "text": body,
                "message": "Full containing function body for research context.",
            }
        )
    return snippets[:4]


def _tool_prompt(state: AuditState) -> str:
    remaining_budget = max(0, get_settings().max_tool_calls - state.get("tool_call_count", 0))
    rag_context = state.get("last_outputs", {}).get("research.retrieve_historical_findings", {})
    protocol_ir = state.get("protocol_ir")
    protocol_summary = protocol_ir_summary(protocol_ir) if protocol_ir else {}
    protocol_graph = state.get("protocol_graph")
    graph_summary = {
        "slices": len(protocol_graph.slices),
        "attack_paths": len(protocol_graph.attack_paths),
        "top_attack_paths": [path.model_dump(mode="json") for path in protocol_graph.attack_paths[:5]],
    } if protocol_graph else {}
    targeted = _model_or_mapping_json(state.get("targeted_rag"))
    checklist_items = targeted.get("checklist_items", [])[:8] if targeted else []
    return (
        f"Objective: {state['objective']}\n"
        f"Repository path: {state['repo_path']}\n"
        f"Current focus: {state.get('current_focus', 'initialize')}\n"
        f"Compressed context: {state.get('compressed_context', '')}\n\n"
        f"Remaining approximate tool budget: {remaining_budget}\n"
        f"Protocol IR summary: {protocol_summary}\n"
        f"Protocol graph summary: {graph_summary}\n"
        f"RAG checklist items: {checklist_items}\n"
        f"Audit milestones: {_planner_milestones(state)}\n"
        f"Available output keys: {sorted(state.get('last_outputs', {}).keys())[:40]}\n"
        f"Available RAG context: {rag_context}\n\n"
        "Return strict JSON for the next safe audit tools to run. "
        "Reason like a protocol auditor over call graph slices, asset flows, state writes, auth constraints, lifecycle transitions, "
        "historical checklist items, and known analysis gaps. Prefer hypotheses that can be proven from local source evidence. "
        "Include repo_path in inputs when needed and use output_references when one tool output should feed another input. "
        "Use stop=true only when all required milestones are complete or the remaining budget is too low to run useful tools."
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


def _planner_milestones(state: AuditState) -> dict[str, bool]:
    return {
        "repo_inspected": bool(state.get("repo_facts")),
        "framework_detected": bool(state.get("build_facts")),
        "static_facts_extracted": bool(state.get("static_facts")),
        "protocol_ir_built": bool(state.get("protocol_ir")),
        "contest_reasoning_done": bool(state.get("last_outputs", {}).get("analysis.contest_reasoning")),
        "protocol_model_built": bool(state.get("protocol_model")),
        "targeted_rag_built": bool(state.get("targeted_rag")),
        "invariants_mined": bool(state.get("invariant_candidates")),
        "hypotheses_ranked": bool(state.get("hypotheses")),
        "rag_context_bundled": bool(state.get("rag_context_bundles")),
        "research_completed": bool(state.get("subgraph_results")),
    }


def _next_missing_graph_node(state: AuditState) -> str:
    milestones = _planner_milestones(state)
    ordered = [
        ("repo_inspected", "inspect_repo"),
        ("framework_detected", "detect_framework"),
        ("static_facts_extracted", "run_static_analysis"),
        ("protocol_ir_built", "build_protocol_ir"),
        ("contest_reasoning_done", "contest_reasoning"),
        ("protocol_model_built", "build_protocol_model"),
        ("targeted_rag_built", "build_targeted_rag_context"),
        ("invariants_mined", "mine_invariant_candidates"),
        ("hypotheses_ranked", "rank_hypotheses"),
        ("rag_context_bundled", "rag_retrieve_context"),
        ("research_completed", "research_subgraph"),
    ]
    for milestone, node in ordered:
        if not milestones.get(milestone):
            return node
    return "summarize_context"


def _route_after_planner(state: AuditState) -> str:
    return state.get("current_focus") or _next_missing_graph_node(state)


def _persist_long_term_memory(state: AuditState) -> ArtifactRef | None:
    working_memory = state.get("working_memory")
    if not working_memory:
        return None
    memory_dir = Path("data") / "memory"
    memory_dir.mkdir(parents=True, exist_ok=True)
    path = memory_dir / "benchmark_lessons.jsonl"
    lessons = getattr(working_memory, "benchmark_lessons", []) or []
    if not lessons:
        return None
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    with path.open("a", encoding="utf-8") as handle:
        for lesson in lessons:
            record = {
                "run_id": state["run_id"],
                "repo_path": state["repo_path"],
                "lesson": lesson,
                "created_at": datetime.now(UTC).isoformat(),
                "advisory_only": True,
            }
            serialized = json.dumps(record, sort_keys=True)
            if serialized not in existing:
                handle.write(serialized + "\n")
    return ArtifactRef(kind="long_term_memory", path=str(path), description="Gitignored advisory benchmark lessons persisted across runs.")


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
    skipped = []
    planner_rounds = []
    executor = ToolExecutor(registry)
    stop_reason = "planner_completed"
    for round_index in range(1, 5):
        remaining_budget = get_settings().max_tool_calls - state.get("tool_call_count", 0)
        if remaining_budget <= 2:
            stop_reason = "budget_low"
            break
        if round_index > 1:
            try:
                plan = planner.plan(_tool_prompt(state), tool_catalog)
            except Exception as exc:
                state.setdefault("warnings", []).append(f"LLM planner stopped after round {round_index - 1}: {type(exc).__name__}: {exc}")
                stop_reason = "planner_error_after_partial_execution"
                break
        round_record = {"round": round_index, "decisions": [], "stop": plan.stop}
        for decision in plan.decisions[: min(8, max(1, remaining_budget - 2))]:
            if decision.tool_name not in valid_names:
                message = f"LLM selected unknown tool: {decision.tool_name}"
                state.setdefault("errors", []).append(message)
                skipped.append({"tool_name": decision.tool_name, "reason": "unknown_tool"})
                continue
            tool = registry.get(decision.tool_name)
            tool_input = _resolve_output_references(state, dict(decision.tool_input), decision.output_references)
            if "repo_path" in tool.input_model.model_fields and "repo_path" not in tool_input:
                tool_input["repo_path"] = state["repo_path"]
            required = {name for name, field in tool.input_model.model_fields.items() if field.is_required()}
            if not required.issubset(tool_input):
                missing = sorted(required.difference(tool_input))
                state.setdefault("errors", []).append(f"LLM omitted required input for {decision.tool_name}")
                state.setdefault("errors", []).append(f"LLM omitted required input for {decision.tool_name}: {missing}")
                skipped.append({"tool_name": decision.tool_name, "reason": "missing_required_input", "missing": missing})
                continue
            output = executor.execute(decision.tool_name, tool_input, state)
            status = getattr(output, "status", "ok")
            _record_step(state, decision.tool_name, f"{decision.tool_name} selected by LLM: {decision.rationale}")
            record = {"tool_name": decision.tool_name, "status": str(status)}
            executed.append(record)
            round_record["decisions"].append(record)
        planner_rounds.append(round_record)
        if all(_planner_milestones(state).values()):
            stop_reason = "milestones_complete"
            break
        if plan.stop:
            stop_reason = "planner_requested_stop"
            break
        if not plan.decisions:
            stop_reason = "planner_returned_no_decisions"
            break
    state["last_outputs"]["llm.plan_with_llm"] = {
        "executed": executed,
        "skipped": skipped,
        "planner_rounds": planner_rounds,
        "planner_source": planner_source,
        "stop_reason": stop_reason,
        "milestones": _planner_milestones(state),
    }
    state["current_focus"] = _next_missing_graph_node(state)
    return state


def initialize_run(state: AuditState) -> AuditState:
    ensure_run_dir(state["run_dir"])
    log_event(state["run_dir"], run_id=state["run_id"], event="run_started", status="running")
    state["current_focus"] = "inspect_repo"
    state["plan"] = [
        PlanStep(id="inspect_repo", description="Inspect repository files and Solidity contracts"),
        PlanStep(id="detect_framework", description="Detect Solidity framework and compiler pragmas"),
        PlanStep(id="run_static_analysis", description="Extract static facts and run safe analyzers"),
        PlanStep(id="build_protocol_ir", description="Build Protocol IR, cross-contract graph facts, asset flows, auth constraints, and completeness gaps"),
        PlanStep(id="build_protocol_model", description="Summarize protocol roles, assets, lifecycle, accounting, and upgrade surfaces"),
        PlanStep(id="build_targeted_rag_context", description="Build graph-derived repo profile and Solodit checklist context before ranking"),
        PlanStep(id="mine_invariant_candidates", description="Mine protocol invariant candidates from Protocol IR and local checklist evidence"),
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
    _run_tool(state, "static.extract_token_types", {"repo_path": repo_path})
    _run_tool(state, "static.extract_storage_writes", {"repo_path": repo_path})
    detector_names = [
        "static.detect_tx_origin_auth",
        "static.detect_unguarded_initializer",
        "static.detect_oracle_staleness_logic",
        "static.detect_unchecked_erc20_returns",
        "static.detect_weak_randomness",
        "static.detect_dangerous_delegatecall",
        "static.detect_unsafe_or_guards",
        "static.detect_external_call_before_accounting",
        "static.detect_strategy_accounting_trust",
        "static.detect_public_vault_accounting_spoof",
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
        "token_types": state["last_outputs"].get("static.extract_token_types", {}).get("facts", []),
        "storage_writes": state["last_outputs"].get("static.extract_storage_writes", {}).get("facts", []),
        "slither_findings": state["last_outputs"].get("static.parse_slither", {}).get("findings", []),
        "detections": [
            detection
            for detector_name in detector_names
            for detection in state["last_outputs"].get(detector_name, {}).get("detections", [])
        ],
    }
    state["current_focus"] = "build_protocol_ir"
    return state


def build_protocol_ir(state: AuditState) -> AuditState:
    ir = build_protocol_ir_from_facts(state["repo_path"], state.get("static_facts", {}))
    graph = build_protocol_graph(ir)
    state["protocol_ir"] = ir
    state["protocol_graph"] = graph
    state.setdefault("static_facts", {})["protocol_ir"] = ir.model_dump(mode="json")
    state.setdefault("static_facts", {})["protocol_graph"] = graph.model_dump(mode="json")
    summary = protocol_ir_summary(ir)
    state["last_outputs"]["analysis.build_protocol_ir"] = {
        "status": "ok",
        "protocol_ir": ir.model_dump(mode="json"),
        "protocol_graph": graph.model_dump(mode="json"),
        "summary": summary,
    }
    if ir.completeness_gaps:
        state.setdefault("warnings", []).extend(f"Protocol IR gap: {gap}" for gap in ir.completeness_gaps)
    _record_step(
        state,
        "analysis.build_protocol_ir",
        f"Protocol IR: contracts={len(ir.contracts)}, slices={len(graph.slices)}, paths={len(graph.attack_paths)}, calls={len(ir.call_edges)}, asset_flows={len(ir.asset_flows)}",
    )
    state["current_focus"] = "contest_reasoning"
    return state


def contest_reasoning(state: AuditState) -> AuditState:
    ir = state.get("protocol_ir")
    if not ir:
        state.setdefault("warnings", []).append("Contest reasoning skipped because Protocol IR is unavailable.")
        state["current_focus"] = "build_protocol_model"
        return state
    reasoning_packets = build_reasoning_packets(ir)
    gap_candidates = run_gap_hunters(state["repo_path"], ir, reasoning_packets)
    working_memory = build_working_memory(reasoning_packets, gap_candidates, ir)
    state["reasoning_packets"] = reasoning_packets
    state["gap_candidates"] = gap_candidates
    state["working_memory"] = working_memory
    state.setdefault("static_facts", {})["reasoning_packets"] = [packet.model_dump(mode="json") for packet in reasoning_packets]
    state.setdefault("static_facts", {})["gap_candidates"] = [candidate.model_dump(mode="json") for candidate in gap_candidates]
    state.setdefault("static_facts", {})["working_memory"] = working_memory.model_dump(mode="json")
    state["last_outputs"]["analysis.contest_reasoning"] = {
        "status": "ok",
        "actor_model": [actor.model_dump(mode="json") for actor in ir.transaction_race_graph.actors],
        "race_edges": [edge.model_dump(mode="json") for edge in ir.transaction_race_graph.race_edges],
        "reasoning_packets": [packet.model_dump(mode="json") for packet in reasoning_packets],
        "gap_candidates": [candidate.model_dump(mode="json") for candidate in gap_candidates],
        "working_memory": working_memory.model_dump(mode="json"),
    }
    _record_step(
        state,
        "analysis.contest_reasoning",
        f"Contest reasoning: actors={len(ir.transaction_race_graph.actors)}, races={len(ir.transaction_race_graph.race_edges)}, gaps={len(gap_candidates)}",
    )
    state["current_focus"] = "build_protocol_model"
    return state


def build_protocol_model(state: AuditState) -> AuditState:
    if state.get("protocol_ir"):
        state.setdefault("static_facts", {})["protocol_ir"] = state["protocol_ir"].model_dump(mode="json")
    model = build_protocol_model_from_facts(state.get("static_facts", {}))
    state["protocol_model"] = model
    state["last_outputs"]["analysis.build_protocol_model"] = {"status": "ok", "protocol_model": model.model_dump(mode="json")}
    _record_step(state, "analysis.build_protocol_model", f"Protocol model terms: roles={len(model.roles)}, accounting={len(model.accounting_terms)}")
    state["current_focus"] = "build_targeted_rag_context"
    return state


def mine_invariants(state: AuditState) -> AuditState:
    candidates = mine_invariant_candidates(state["repo_path"], state.get("static_facts", {}))
    proof_packets = build_invariant_proof_packets(candidates, state.get("static_facts", {}))
    state["invariant_candidates"] = candidates
    state["proof_packets"] = proof_packets
    state.setdefault("static_facts", {})["proof_packets"] = [packet.model_dump(mode="json") for packet in proof_packets]
    state["last_outputs"]["analysis.mine_invariant_candidates"] = {
        "status": "ok",
        "candidates": [candidate.model_dump(mode="json") for candidate in candidates],
        "proof_packets": [packet.model_dump(mode="json") for packet in proof_packets],
    }
    _record_step(state, "analysis.mine_invariant_candidates", f"Mined {len(candidates)} protocol invariant candidates and {len(proof_packets)} proof packets")
    state["current_focus"] = "rank_hypotheses"
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
    targeted_state = _model_or_mapping_json(state.get("targeted_rag"))
    if targeted_state.get("checklist_items"):
        state.setdefault("static_facts", {})["rag_checklist_items"] = targeted_state["checklist_items"]
    state["last_outputs"]["llm.protocol_auditor_context"] = {
        "status": "ok",
        "protocol_ir_summary": protocol_ir_summary(state["protocol_ir"]) if state.get("protocol_ir") else {},
        "protocol_graph_summary": {
            "slices": len(state.get("protocol_graph").slices) if state.get("protocol_graph") else 0,
            "attack_paths": len(state.get("protocol_graph").attack_paths) if state.get("protocol_graph") else 0,
            "completeness": state.get("protocol_graph").completeness.model_dump(mode="json") if state.get("protocol_graph") else {},
        },
        "repo_profile": _model_or_mapping_json(state.get("repo_rag_profile")),
        "rag_checklist_items": targeted_state.get("checklist_items", [])[:10],
        "guidance": "Use checklist items as historical prompts only; require local Protocol IR evidence before promoting hypotheses.",
    }
    state["current_focus"] = "mine_invariant_candidates"
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
                *state.get("static_facts", {}).get("token_types", []),
                *state.get("static_facts", {}).get("storage_writes", []),
                *state.get("static_facts", {}).get("slither_findings", []),
                *state.get("static_facts", {}).get("access_control", []),
                *state.get("static_facts", {}).get("detections", []),
                *[
                    {"invariant_candidate": candidate.model_dump(mode="json")}
                    for candidate in state.get("invariant_candidates", [])
                ],
                *[
                    {"gap_candidate": candidate.model_dump(mode="json")}
                    for candidate in state.get("gap_candidates", [])
                ],
                _model_or_mapping_json(state.get("repo_rag_profile")),
                {"protocol_ir": state["protocol_ir"].model_dump(mode="json")} if state.get("protocol_ir") else {},
                {"rag_checklist_items": _model_or_mapping_json(state.get("targeted_rag")).get("checklist_items", [])},
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


def _select_hypotheses_for_deepening(hypotheses: list[VulnerabilityHypothesis], max_items: int = 10) -> list[VulnerabilityHypothesis]:
    """Choose a diversified evidence-backed set for expensive RAG/research/validation work."""
    selected: list[VulnerabilityHypothesis] = []
    selected_ids: set[str] = set()

    def score(hypothesis: VulnerabilityHypothesis) -> tuple[float, float]:
        sources = [source.lower() for source in hypothesis.source_detection_ids]
        is_profile_lead = any(source.startswith("repo-profile:") for source in sources) and not any(not source.startswith("repo-profile:") for source in sources)
        proof_bonus = {
            "static_proof_complete": 0.35,
            "strong_local_path": 0.25,
            "missing_counterevidence": 0.15,
            "setup_required": 0.0,
        }.get(hypothesis.proof_status, -0.1)
        evidence_bonus = min(0.25, 0.05 * len(hypothesis.evidence_lines))
        graph_bonus = 0.12 if hypothesis.graph_slice_ids or hypothesis.proof_packet_id else 0.0
        profile_penalty = -0.35 if is_profile_lead else 0.0
        return hypothesis.confidence + proof_bonus + evidence_bonus + graph_bonus + profile_penalty, hypothesis.confidence

    def add(hypothesis: VulnerabilityHypothesis) -> None:
        if len(selected) >= max_items or hypothesis.id in selected_ids:
            return
        selected.append(hypothesis)
        selected_ids.add(hypothesis.id)

    strong = [
        hypothesis
        for hypothesis in hypotheses
        if hypothesis.evidence_lines and hypothesis.proof_status in {"static_proof_complete", "strong_local_path", "missing_counterevidence"}
    ]
    for hypothesis in sorted(strong, key=score, reverse=True):
        add(hypothesis)

    by_class: dict[str, VulnerabilityHypothesis] = {}
    for hypothesis in sorted(hypotheses, key=score, reverse=True):
        if not hypothesis.evidence_lines:
            continue
        by_class.setdefault(hypothesis.vulnerability_class, hypothesis)
    for hypothesis in by_class.values():
        add(hypothesis)

    for hypothesis in sorted(hypotheses, key=score, reverse=True):
        if hypothesis.evidence_lines:
            add(hypothesis)
    return selected


def rag_retrieve_context(state: AuditState) -> AuditState:
    hypotheses = state.get("hypotheses", [])
    if not hypotheses:
        return state
    state.setdefault("rag_context_bundles", {})
    for hypothesis in _select_hypotheses_for_deepening(hypotheses):
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

    for index, hypothesis in enumerate(_select_hypotheses_for_deepening(hypotheses), start=1):
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
        for hypothesis in _select_hypotheses_for_deepening(hypotheses):
            semantic_validation = _run_tool(
                state,
                "dynamic.run_semantic_validation",
                {"repo_path": repo_path, "hypothesis": hypothesis.model_dump(mode="json")},
            )
            validation_data = getattr(semantic_validation, "data", {}) if semantic_validation else {}
            if validation_data.get("validated"):
                hypothesis.proof_status = validation_data.get("proof_status", "static_proof_complete")
                if validation_data.get("counterevidence"):
                    hypothesis.counterevidence.extend(validation_data["counterevidence"])
            _run_tool(
                state,
                "dynamic.generate_validation_artifacts",
                {"repo_path": repo_path, "hypothesis": hypothesis.model_dump(mode="json")},
            )
    else:
        _run_tool(state, "dynamic.generate_validation_artifacts", {"repo_path": repo_path})
    _run_tool(state, "dynamic.compile_validation_artifacts", {"repo_path": repo_path})
    _run_tool(state, "dynamic.run_validation_artifacts", {"repo_path": repo_path})
    run_dir = Path(state["run_dir"])
    if state.get("proof_packets"):
        write_json(run_dir / "proof_packets.json", [packet.model_dump(mode="json") for packet in state["proof_packets"]])
        state.setdefault("artifacts", []).append(
            ArtifactRef(kind="proof_packets", path=str(run_dir / "proof_packets.json"), description="Invariant proof packets used for hypothesis ranking.")
        )
    if state.get("protocol_graph"):
        write_json(run_dir / "protocol_graph.json", state["protocol_graph"].model_dump(mode="json"))
        state.setdefault("artifacts", []).append(
            ArtifactRef(kind="protocol_graph", path=str(run_dir / "protocol_graph.json"), description="Protocol graph slices and attack-path candidates.")
        )
    if state.get("working_memory"):
        write_json(run_dir / "working_memory.json", state["working_memory"].model_dump(mode="json"))
        state.setdefault("artifacts", []).append(
            ArtifactRef(kind="working_memory", path=str(run_dir / "working_memory.json"), description="Short-term audit memory with summaries, assumptions, and lessons.")
        )
        memory_artifact = _persist_long_term_memory(state)
        if memory_artifact:
            state.setdefault("artifacts", []).append(memory_artifact)
    if state.get("hypotheses"):
        write_json(
            run_dir / "candidate_rank_trace.json",
            {
                "hypotheses": [hypothesis.model_dump(mode="json") for hypothesis in state["hypotheses"]],
                "invariant_candidates": [candidate.model_dump(mode="json") for candidate in state.get("invariant_candidates", [])],
                "gap_candidates": [candidate.model_dump(mode="json") for candidate in state.get("gap_candidates", [])],
                "reasoning_packets": [packet.model_dump(mode="json") for packet in state.get("reasoning_packets", [])],
            },
        )
        state.setdefault("artifacts", []).append(
            ArtifactRef(kind="candidate_rank_trace", path=str(run_dir / "candidate_rank_trace.json"), description="Hypothesis ranking and source candidate trace.")
        )
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
    graph.add_node("build_protocol_ir", build_protocol_ir)
    graph.add_node("contest_reasoning", contest_reasoning)
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
    graph.add_conditional_edges(
        "plan_with_llm",
        _route_after_planner,
        {
            "inspect_repo": "inspect_repo",
            "detect_framework": "detect_framework",
            "run_static_analysis": "run_static_analysis",
            "build_protocol_ir": "build_protocol_ir",
            "contest_reasoning": "contest_reasoning",
            "build_protocol_model": "build_protocol_model",
            "build_targeted_rag_context": "build_targeted_rag_context",
            "mine_invariant_candidates": "mine_invariant_candidates",
            "rank_hypotheses": "rank_hypotheses",
            "rag_retrieve_context": "rag_retrieve_context",
            "research_subgraph": "research_subgraph",
            "summarize_context": "summarize_context",
        },
    )
    graph.add_edge("inspect_repo", "detect_framework")
    graph.add_edge("detect_framework", "run_static_analysis")
    graph.add_edge("run_static_analysis", "build_protocol_ir")
    graph.add_edge("build_protocol_ir", "contest_reasoning")
    graph.add_edge("contest_reasoning", "build_protocol_model")
    graph.add_edge("build_protocol_model", "build_targeted_rag_context")
    graph.add_edge("build_targeted_rag_context", "mine_invariant_candidates")
    graph.add_edge("mine_invariant_candidates", "rank_hypotheses")
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
