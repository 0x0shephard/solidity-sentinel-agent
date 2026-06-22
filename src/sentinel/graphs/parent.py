from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
import functools
import json
from pathlib import Path
import re
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
from sentinel.observability.progress import console_sink, emit as emit_progress, set_progress_sink
from sentinel.observability.tracing import configure_tracing, trace_span
from sentinel.rag.sync import sync_solodit
from sentinel.reporting import build_report_document, create_findings_from_state, render_markdown_report
from sentinel.schemas.common import ArtifactRef, CompletedStep, PlanStep, RiskLevel, SideEffect, ToolStatus
from sentinel.schemas.research import VulnerabilityHypothesis
from sentinel.schemas.static import SourceEvidence
from sentinel.state import AuditState, initial_audit_state, initial_research_state
from sentinel.tools import build_default_registry
from sentinel.tools.executor import ToolExecutor, _json_hash


def make_run_id() -> str:
    """Generate a unique, sortable run identifier.

    Args:
        (none)
    Returns:
        A string like ``20260606-143005-a1b2c3`` (UTC timestamp + short uuid),
        used to name the run directory and tag every artifact/log line.
    """
    return datetime.now(UTC).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]


def _executor() -> ToolExecutor:
    """Build a tool executor over the full default tool registry.

    Args:
        (none)
    Returns:
        A fresh ``ToolExecutor`` wrapping the 100+ tool registry — the single
        enforcement boundary through which every deterministic-node tool call runs.
    """
    return ToolExecutor(build_default_registry())


def _record_step(state: AuditState, step_id: str, summary: str) -> None:
    """Append a completed-step record to the audit's plan trace.

    Args:
        state: The mutable audit state.
        step_id: Identifier of the step/tool that ran (e.g. a tool name).
        summary: Human-readable one-line description of what happened.
    Returns:
        None. Mutates ``state['completed_steps']`` in place.
    """
    state.setdefault("completed_steps", []).append(CompletedStep(step_id=step_id, summary=summary))


def _run_tool(state: AuditState, tool_name: str, raw_input: dict):
    """Execute one registered tool and record it on the plan trace.

    Args:
        state: The mutable audit state (the executor records the call on it).
        tool_name: Fully-qualified tool name (``namespace.name``).
        raw_input: Raw input dict, validated against the tool's input schema.
    Returns:
        The tool's validated, typed output model (also stored in
        ``state['last_outputs'][tool_name]`` by the executor).
    """
    output = _executor().execute(tool_name, raw_input, state)
    _record_step(state, tool_name, f"{tool_name} returned {getattr(output, 'status', 'ok')}")
    return output


def _evidence_snippets_for_hypothesis(state: AuditState, hypothesis: VulnerabilityHypothesis) -> list[dict]:
    """Gather the evidence snippets to hand a hypothesis to the research subagent.

    Assembles (in priority order) the invariant proof packet, full function
    bodies, explicit evidence lines, and class-relevant static facts (reentrancy
    → external calls/state writes, unchecked_transfer → token transfers, etc.).

    Args:
        state: The audit state (reads proof_packets and static_facts).
        hypothesis: The hypothesis to collect supporting evidence for.
    Returns:
        Up to 12 snippet dicts (each with kind/file/line/text) used as the
        subagent's scoped evidence context.
    """
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
    """Read the full source bodies of a hypothesis's affected functions.

    Uses the static-analysis ``function_ranges`` to slice real source out of the
    repo for the affected files/functions/contracts, so the subagent reasons over
    actual code rather than summaries. Bounded to ~12K chars / 4 snippets.

    Args:
        state: The audit state (reads repo_path and static_facts.function_ranges).
        hypothesis: The hypothesis whose functions' bodies are wanted.
    Returns:
        Up to 4 ``function_body`` snippet dicts with real source text.
    """
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


def _caller_context_snippets(state: AuditState, hypothesis: VulnerabilityHypothesis) -> list[dict]:
    """Cross-contract callers of the hypothesis's affected function(s).

    Adversarial deepening needs to see who calls the affected function to decide
    whether a precondition is satisfied atomically (mitigation) or reachable by
    an attacker (confirmation) — e.g. a factory/configurator that initializes and
    wires a manager in the same transaction. Matching is whole-word so indirect
    sites (e.g. ``abi.encodeCall(Iface.initialize, ...)``) are captured.

    Args:
        state: The audit state (reads repo_path and static_facts.function_ranges).
        hypothesis: The hypothesis whose affected functions' callers are wanted.
    Returns:
        Up to 4 target-scoped ``caller_context`` snippet dicts (lib/test/script
        excluded), each with the caller's real source body.
    """

    from sentinel.evidence import classify_source_path

    repo_path = Path(state.get("repo_path", ""))
    ranges = state.get("static_facts", {}).get("function_ranges", [])
    targets = {name for name in [*hypothesis.affected_functions, hypothesis.affected_function] if name}
    if not str(repo_path) or not ranges or not targets:
        return []

    file_lines: dict[str, list[str]] = {}

    def _lines(rel_path: str) -> list[str]:
        if rel_path not in file_lines:
            source = repo_path / rel_path
            file_lines[rel_path] = source.read_text(encoding="utf-8", errors="replace").splitlines() if source.exists() else []
        return file_lines[rel_path]

    snippets: list[dict] = []
    seen: set[tuple] = set()
    used = 0
    for raw_range in ranges:
        if not isinstance(raw_range, dict):
            continue
        file_path = str(raw_range.get("file_path") or "")
        function_name = raw_range.get("function_name")
        if function_name in targets:
            continue  
        if classify_source_path(file_path) not in {"production", "unknown"}:
            continue  
        start_line, end_line = raw_range.get("start_line"), raw_range.get("end_line")
        if not isinstance(start_line, int) or not isinstance(end_line, int):
            continue
        body = "\n".join(_lines(file_path)[max(0, start_line - 1):end_line])
        if not any(re.search(rf"(?<![A-Za-z0-9_]){re.escape(target)}(?![A-Za-z0-9_])", body) for target in targets):
            continue
        key = (file_path, function_name, start_line)
        if key in seen:
            continue
        seen.add(key)
        block = body[:2200]
        if used + len(block) > 8000:
            break
        used += len(block)
        snippets.append(
            {
                "kind": "caller_context",
                "file_path": file_path,
                "line_start": start_line,
                "line_end": end_line,
                "function": function_name,
                "contract": raw_range.get("contract_name"),
                "text": block,
                "message": f"Cross-contract caller of {sorted(targets)} — use to judge atomic mitigation vs. attacker reachability.",
            }
        )
        if len(snippets) >= 4:
            break
    return snippets


def _cross_contract_neighbor_evidence(state: AuditState, hypothesis: VulnerabilityHypothesis, existing_files: set[str]) -> SourceEvidence | None:
    """A callee/caller of the affected function in a different target file, from the call graph.

    Fallback to ``_caller_context_snippets`` for cross-contract evidence: walks
    the Protocol IR ``call_edges`` for graph neighbours of the affected function
    and reads one neighbour's real source from a file not already cited.

    Args:
        state: The audit state (reads protocol_ir, static_facts, repo_path).
        hypothesis: The hypothesis to broaden evidence for.
        existing_files: Files already cited (so the neighbour adds a new file).
    Returns:
        A ``SourceEvidence`` for a cross-contract neighbour, or None if none
        exists in target (production/unknown) source.
    """

    from sentinel.evidence import classify_source_path

    ir = state.get("protocol_ir")
    ranges = state.get("static_facts", {}).get("function_ranges", [])
    repo_path = Path(state.get("repo_path", ""))
    targets = {name for name in [*hypothesis.affected_functions, hypothesis.affected_function] if name}
    if ir is None or not ranges or not targets:
        return None
    neighbors: set[str] = set()
    for edge in getattr(ir, "call_edges", []):
        if edge.to_function in targets and edge.from_function:
            neighbors.add(edge.from_function)
        if edge.from_function in targets and edge.to_function:
            neighbors.add(edge.to_function)
    neighbors -= targets
    if not neighbors:
        return None
    for raw_range in ranges:
        if not isinstance(raw_range, dict):
            continue
        name = raw_range.get("function_name")
        file_path = str(raw_range.get("file_path") or "")
        if name not in neighbors or file_path in existing_files:
            continue
        if classify_source_path(file_path) not in {"production", "unknown"}:
            continue
        start, end = raw_range.get("start_line"), raw_range.get("end_line")
        if not isinstance(start, int) or not isinstance(end, int):
            continue
        source = repo_path / file_path
        if not source.exists():
            continue
        body = "\n".join(source.read_text(encoding="utf-8", errors="replace").splitlines()[max(0, start - 1):end])
        if not body.strip():
            continue
        return SourceEvidence(
            file_path=file_path,
            line_start=start,
            line_end=end,
            contract_name=raw_range.get("contract_name"),
            function_name=name,
            source_text=body[:1200],
            reason=f"Cross-contract call path: {name} in {file_path} is on the call graph of the affected function.",
        )
    return None


# Math/economic bug classes whose root cause often lives in a leaf helper (e.g.
# FeeManager.calculateFee) but whose trigger/impact is an entry point that calls it
# (e.g. ShareModule.handleReport). For these we anchor the hypothesis on the entry
# point too, so the bug is attributed where it manifests — not just the leaf.
_ENTRY_POINT_ENRICH_CLASSES = {
    "accounting",
    "accounting_invariant",
    "business_logic",
    "fee",
    "share_accounting",
    "rounding",
}


def _count_fallback_usage(state: AuditState) -> int:
    """Count LLM calls that downgraded to the fallback model (for run integrity).

    Scans accumulated notes across the state and research subgraph results for the
    "Ollama fallback … applied" markers the provider paths emit on downgrade.
    """
    count = 0
    note_pools: list = list(state.get("notes", []) or [])
    for result in state.get("subgraph_results", []) or []:
        note_pools.extend(getattr(result, "notes", None) or [])
    for note in note_pools:
        if isinstance(note, str) and "fallback" in note.lower() and "applied" in note.lower():
            count += 1
    return count


def _add_entry_point_functions(hypothesis: VulnerabilityHypothesis, caller_functions: list[str], max_added: int = 2) -> None:
    """Anchor an accounting/economic hypothesis on the entry points that reach its
    affected function, so it points at where the bug is triggered (and is matched
    against the contest's entry-point function), not only the leaf math helper.
    """
    if (hypothesis.vulnerability_class or "") not in _ENTRY_POINT_ENRICH_CLASSES:
        return
    existing = set(hypothesis.affected_functions)
    added = 0
    for fn in caller_functions:
        if added >= max_added:
            break
        if fn and fn not in existing:
            hypothesis.affected_functions.append(fn)
            existing.add(fn)
            added += 1


def _attach_cross_contract_evidence(state: AuditState) -> None:
    """Phase 2.3: broaden each hypothesis's evidence to span >=2 contracts.

    Findings should cite the cross-contract call path, not just the single
    affected function. We attach one real, target-scoped caller or callee from a
    different file (via the call graph) so reports and the cross-contract metric
    reflect the protocol structure that already exists in the IR. If no genuine
    cross-contract neighbour exists, nothing is attached (no fabrication).

    Args:
        state: The audit state; iterates and mutates ``state['hypotheses']``.
    Returns:
        None. Appends at most one cross-file ``SourceEvidence`` per hypothesis.
    """

    for hypothesis in state.get("hypotheses", []):
        existing_files = {item.file_path for item in hypothesis.evidence_lines if item.file_path}
        if not existing_files:
            continue
        snippets = _caller_context_snippets(state, hypothesis)
        # Promote entry-point callers from evidence-only to affected functions for
        # math/economic classes (e.g. handleReport reaching calculateFee).
        _add_entry_point_functions(hypothesis, [s.get("function") for s in snippets if s.get("function")])
        added = False
        for snippet in snippets:
            file_path = snippet.get("file_path")
            if not file_path or file_path in existing_files:
                continue
            hypothesis.evidence_lines.append(
                SourceEvidence(
                    file_path=file_path,
                    line_start=snippet.get("line_start") or 1,
                    line_end=snippet.get("line_end") or (snippet.get("line_start") or 1),
                    contract_name=snippet.get("contract"),
                    function_name=snippet.get("function"),
                    source_text=str(snippet.get("text", ""))[:1200],
                    reason=f"Cross-contract call path: {snippet.get('function')} in {file_path} reaches the affected function.",
                )
            )
            added = True
            break
        if not added:
            neighbor = _cross_contract_neighbor_evidence(state, hypothesis, existing_files)
            if neighbor is not None:
                hypothesis.evidence_lines.append(neighbor)


def _tool_prompt(state: AuditState) -> str:
    """Build the LLM planner's prompt for the next round of tool selection.

    Compresses the current audit state into planner guidance: objective, budget,
    Protocol IR / graph summaries, RAG checklist, milestone progress, the next
    required milestone and how to advance it, already-executed tools (anti-repeat),
    and recent results. This is the in-code context-management strategy for the
    long-horizon planner loop.

    Args:
        state: The audit state to summarize.
    Returns:
        A prompt string (paired with the tool catalog when calling the planner).
    """
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
    milestones = _planner_milestones(state)
    next_milestone = next((name for name, done in milestones.items() if not done), None)
    ledger = state.get("tool_ledger", [])
    executed_counts = Counter(getattr(record, "tool_name", "") for record in ledger)
    repeated_tools = {name: count for name, count in executed_counts.items() if count > 1}
    recent_results = [
        {"tool": getattr(record, "tool_name", ""), "status": str(getattr(record, "status", ""))}
        for record in ledger[-6:]
    ]
    return (
        f"Objective: {state['objective']}\n"
        f"Repository path: {state['repo_path']}\n"
        f"Current focus: {state.get('current_focus', 'initialize')}\n"
        f"Compressed context: {state.get('compressed_context', '')}\n\n"
        f"Remaining approximate tool budget: {remaining_budget}\n"
        f"Protocol IR summary: {protocol_summary}\n"
        f"Protocol graph summary: {graph_summary}\n"
        f"RAG checklist items: {checklist_items}\n"
        f"Audit milestones: {milestones}\n"
        f"Next required milestone to complete: {next_milestone}\n"
        f"How to advance it: {_next_milestone_tool_hint(next_milestone)}\n"
        f"Tools already executed this session (tool -> count): {dict(executed_counts)}\n"
        f"Tools already repeated (avoid these unless inputs genuinely differ): {repeated_tools}\n"
        f"Most recent tool results: {recent_results}\n"
        f"Available output keys: {sorted(state.get('last_outputs', {}).keys())[:40]}\n"
        f"Available RAG context: {rag_context}\n\n"
        "Return strict JSON for the next safe audit tools to run. "
        "Reason like a protocol auditor over call graph slices, asset flows, state writes, auth constraints, lifecycle transitions, "
        "historical checklist items, and known analysis gaps. Prefer hypotheses that can be proven from local source evidence. "
        "Each decision MUST make progress toward the next required milestone; do NOT call a tool with inputs identical to a "
        "previous call this session, and do not repeat a tool that already succeeded unless you are passing genuinely new inputs. "
        "Include repo_path in inputs when needed and use output_references when one tool output should feed another input. "
        "Use stop=true only when all required milestones are complete or the remaining budget is too low to run useful tools."
    )


def _resolve_output_references(state: AuditState, tool_input: dict, references: list[dict]) -> dict:
    """Wire one tool's prior output into another tool's input (composability).

    Each reference is ``{from_tool, path, target_input}``: the dotted ``path`` is
    read from ``state['last_outputs'][from_tool]`` and injected into the new
    tool's input under ``target_input`` — this is what lets the model chain tools.

    Args:
        state: The audit state (reads ``last_outputs``).
        tool_input: The base input dict for the tool about to run.
        references: List of output-reference specs from the planner decision.
    Returns:
        A new input dict with resolved references merged in (originals preserved
        when a reference can't be resolved).
    """
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
    """Normalize a Pydantic model or mapping (or None) into a plain dict.

    Args:
        value: A Pydantic model, a dict, or None.
    Returns:
        ``value.model_dump(mode="json")`` for models, the dict itself for dicts,
        or ``{}`` for None/other — a safe accessor for optional state fields.
    """
    if not value:
        return {}
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return value
    return {}


_PIPELINE: list[tuple[str, str, str]] = [
    ("repo_inspected", "inspect_repo", "audit.inspect_repo"),
    ("framework_detected", "detect_framework", "audit.detect_framework"),
    ("static_facts_extracted", "run_static_analysis", "audit.run_static_analysis"),
    ("protocol_ir_built", "build_protocol_ir", "audit.build_protocol_ir"),
    ("contest_reasoning_done", "contest_reasoning", "audit.contest_reasoning"),
    ("protocol_model_built", "build_protocol_model", "audit.build_protocol_model"),
    ("targeted_rag_built", "build_targeted_rag_context", "audit.build_targeted_rag_context"),
    ("invariants_mined", "mine_invariant_candidates", "audit.mine_invariants"),
    ("hypotheses_ranked", "rank_hypotheses", "audit.rank_hypotheses"),
    ("rag_context_bundled", "rag_retrieve_context", "audit.retrieve_rag_context"),
    ("research_completed", "research_subgraph", "audit.research_hypotheses"),
]
_PIPELINE_MILESTONES = [milestone for milestone, _node, _tool in _PIPELINE]
_MILESTONE_TO_NODE = {milestone: node for milestone, node, _tool in _PIPELINE}
_MILESTONE_TOOL_HINTS = {milestone: [tool] for milestone, _node, tool in _PIPELINE}


def _stage(milestone: str, next_focus: str):
    """Make a graph node idempotent and milestone-tracked.

    The node is skipped if its milestone is already complete (so model-selected
    composite tools and the deterministic chain never redo the same stage), and
    completion is recorded in ``state['completed_stages']`` on success. This is
    what turns the deterministic chain into a guarded gap-filler behind the
    model-driven planner.

    Args:
        milestone: The milestone key this node completes (e.g. ``protocol_ir_built``).
        next_focus: The node to route to when this stage is skipped as already-done.
    Returns:
        A decorator that wraps a ``(state) -> state`` node with the skip/mark logic.
    """

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(state: AuditState) -> AuditState:
            if milestone in state.get("completed_stages", []):
                state["current_focus"] = next_focus
                return state
            emit_progress(f"▶ {milestone.replace('_', ' ')}")
            result = fn(state)
            result.setdefault("completed_stages", [])
            if milestone not in result["completed_stages"]:
                result["completed_stages"].append(milestone)
            return result

        wrapper.__sentinel_milestone__ = milestone
        return wrapper

    return decorator


def _next_milestone_tool_hint(next_milestone: str | None) -> str:
    """Tell the planner which composite tool advances the next milestone.

    Args:
        next_milestone: The first incomplete milestone, or None if all are done.
    Returns:
        A one-line instruction naming the ``audit.*`` composite tool to call
        next (or to stop), injected into the planner prompt.
    """

    if not next_milestone:
        return "All milestones complete; set stop=true."
    tools = _MILESTONE_TOOL_HINTS.get(next_milestone)
    if tools:
        return (
            f"Call {tools[0]} next. It runs (or resumes) the audit pipeline through this stage and "
            "records the milestone. Composite audit.* tools are self-healing: they run any missing "
            "prerequisite stages in order, so prefer them to advance milestones."
        )
    return "Set stop=true; remaining milestones are finalized by the graph."


def _planner_milestones(state: AuditState) -> dict[str, bool]:
    """Report which audit pipeline milestones are complete.

    Completion is authoritative — keyed off ``state['completed_stages']`` (set by
    the ``_stage`` decorator), not loose state-key presence.

    Args:
        state: The audit state.
    Returns:
        An ordered ``{milestone: bool}`` map over the 11 pipeline stages.
    """
    done = set(state.get("completed_stages", []))
    return {milestone: (milestone in done) for milestone in _PIPELINE_MILESTONES}


def _ensure_pipeline_through(state: AuditState, target_milestone: str) -> AuditState:
    """Run audit stages in dependency order up to ``target_milestone``.

    Each stage node is idempotent (see ``_stage``), so already-completed stages
    are skipped. This lets a single composite tool call resume the pipeline from
    wherever the model left it, guaranteeing prerequisites without redoing work.

    Args:
        state: The audit state, mutated in place as stages run.
        target_milestone: The milestone to ensure completion through (inclusive).
    Returns:
        The same ``state`` object, with all stages up to the target completed.
    """

    node_fns = _pipeline_node_fns()
    for milestone, _node_name, _tool in _PIPELINE:
        node_fns[milestone](state)
        if milestone == target_milestone:
            break
    return state


def _pipeline_node_fns() -> dict[str, "Callable[[AuditState], AuditState]"]:
    """Map each milestone to the (decorated) node function that completes it.

    Resolved lazily at call time to avoid a forward-reference problem (the node
    functions are defined later in this module).

    Args:
        (none)
    Returns:
        A ``{milestone: node_fn}`` dict used by ``_ensure_pipeline_through``.
    """
    return {
        "repo_inspected": inspect_repo,
        "framework_detected": detect_framework,
        "static_facts_extracted": run_static_analysis,
        "protocol_ir_built": build_protocol_ir,
        "contest_reasoning_done": contest_reasoning,
        "protocol_model_built": build_protocol_model,
        "targeted_rag_built": build_targeted_rag_context,
        "invariants_mined": mine_invariants,
        "hypotheses_ranked": rank_hypotheses,
        "rag_context_bundled": rag_retrieve_context,
        "research_completed": research_subgraph,
    }


def _next_missing_graph_node(state: AuditState) -> str:
    """Find the first incomplete pipeline stage's graph node name.

    Used after the planner runs to route the deterministic chain to the first
    gap the model left, so it only fills what's missing.

    Args:
        state: The audit state.
    Returns:
        The graph node name to run next, or ``"summarize_context"`` if every
        stage is complete.
    """
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
    """Conditional-edge router from the planner node into the stage chain.

    Args:
        state: The audit state (the planner sets ``current_focus`` on exit).
    Returns:
        The next node name — the planner's chosen focus, or the first missing
        milestone's node as a fallback.
    """
    return state.get("current_focus") or _next_missing_graph_node(state)


def _persist_long_term_memory(state: AuditState) -> ArtifactRef | None:
    """Append this run's advisory lessons to cross-run long-term memory.

    Writes de-duplicated ``benchmark_lessons`` from working memory to a gitignored
    JSONL under ``data/memory/`` so knowledge accumulates across audits.

    Args:
        state: The audit state (reads working_memory, run_id, repo_path).
    Returns:
        An ``ArtifactRef`` to the memory file, or None if there are no lessons.
    """
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


# The real-LLM planner may directly select only read/analysis tools. Tools that
# write, reach the network, install dependencies, or clean/mutate the workspace
# are blocked unless explicitly approved — the model never autonomously performs
# a side effect on the target or the host.
_PLANNER_BLOCKED_SIDE_EFFECTS = {SideEffect.WRITE_FILES, SideEffect.EXTERNAL_NETWORK}
# Matched against underscore/dot-delimited name segments (not substrings), so
# read tools like ``find_access_control_terms`` are not caught by "rm" in "terms".
_PLANNER_BLOCKED_NAME_SEGMENTS = {"install", "clean", "clone", "checkout", "snapshot", "write", "patch", "delete", "remove"}


def _planner_tool_allowed(tool) -> tuple[bool, str]:
    """Decide whether the LLM planner may directly select a tool.

    Args:
        tool: The ``RegisteredTool`` the planner chose.
    Returns:
        ``(allowed, reason)`` — blocks write/network/install/cleanup and HIGH-risk
        tools unless ``SENTINEL_PLANNER_ALLOW_SIDE_EFFECTS`` is set. Read/analysis
        tools (incl. composite ``audit.*`` and ``static`` runs) pass.
    """
    if get_settings().planner_allow_side_effects:
        return True, ""
    if tool.risk_level == RiskLevel.HIGH:
        return False, "high_risk"
    if any(effect in _PLANNER_BLOCKED_SIDE_EFFECTS for effect in tool.side_effects):
        return False, "side_effect"
    if set(re.split(r"[_.]", tool.name.lower())) & _PLANNER_BLOCKED_NAME_SEGMENTS:
        return False, "name_denylist"
    return True, ""


def plan_with_llm(state: AuditState) -> AuditState:
    """Model-driven planner spine: let the LLM select and run tools in a loop.

    Each round builds the planner prompt + full tool catalog, asks the model for
    tool decisions, and executes them through the enforcement executor with
    schema validation, required-input checks, anti-repeat de-duplication, and
    per-call exception isolation. Loops until milestones complete / budget low /
    no new actions / the model stops. Falls back to the Ollama planner, then to
    the deterministic graph, if the primary planner is unavailable.

    Args:
        state: The audit state, mutated as tools run (ledger, last_outputs,
            completed_stages, errors/warnings).
    Returns:
        The same ``state``, with ``last_outputs['llm.plan_with_llm']`` (executed/
        skipped/rounds/stop_reason/milestones) recorded and ``current_focus`` set
        to the first incomplete stage for the chain to finish.
    """
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
    executed_signatures: set[tuple[str, str]] = set()
    max_rounds = get_settings().planner_max_rounds
    for round_index in range(1, max_rounds + 1):
        emit_progress(f"  planner round {round_index} — model selecting tools…")
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
        round_executed = 0
        for decision in plan.decisions[: min(8, max(1, remaining_budget - 2))]:
            if decision.tool_name not in valid_names:
                message = f"LLM selected unknown tool: {decision.tool_name}"
                state.setdefault("errors", []).append(message)
                skipped.append({"tool_name": decision.tool_name, "reason": "unknown_tool"})
                continue
            tool = registry.get(decision.tool_name)
            allowed, block_reason = _planner_tool_allowed(tool)
            if not allowed:
                state.setdefault("errors", []).append(f"Planner blocked side-effect tool {decision.tool_name} ({block_reason})")
                skipped.append({"tool_name": decision.tool_name, "reason": f"blocked_{block_reason}"})
                round_record["decisions"].append({"tool_name": decision.tool_name, "status": f"blocked_{block_reason}"})
                continue
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
            signature = (decision.tool_name, _json_hash(tool_input))
            if signature in executed_signatures:
                skipped.append({"tool_name": decision.tool_name, "reason": "duplicate_call"})
                round_record["decisions"].append({"tool_name": decision.tool_name, "status": "skipped_duplicate"})
                continue
            executed_signatures.add(signature)
            try:
                output = executor.execute(decision.tool_name, tool_input, state)
            except Exception as exc:
                state.setdefault("errors", []).append(f"Tool {decision.tool_name} failed during planning: {type(exc).__name__}: {exc}")
                skipped.append({"tool_name": decision.tool_name, "reason": "execution_error", "error_type": type(exc).__name__})
                round_record["decisions"].append({"tool_name": decision.tool_name, "status": "execution_error"})
                continue
            status = getattr(output, "status", "ok")
            _record_step(state, decision.tool_name, f"{decision.tool_name} selected by LLM: {decision.rationale}")
            record = {"tool_name": decision.tool_name, "status": str(status)}
            executed.append(record)
            round_executed += 1
            round_record["decisions"].append(record)
        planner_rounds.append(round_record)
        if all(_planner_milestones(state).values()):
            stop_reason = "milestones_complete"
            break
        if round_executed == 0:
            stop_reason = "planner_no_new_actions"
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
    """Entry node: create the run directory, log start, and seed the plan.

    Args:
        state: The fresh audit state.
    Returns:
        The same ``state`` with the run dir ensured, a ``run_started`` event
        logged, ``plan`` populated, and ``current_focus`` set to inspect_repo.
    """
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
    """Sync the Solodit historical-findings RAG cache (stale-ok).

    Args:
        state: The audit state.
    Returns:
        The same ``state`` with the sync status in ``last_outputs`` and any
        message appended to ``warnings``; tolerates a stale/unavailable corpus.
    """
    result = sync_solodit(stale_ok=True)
    state["last_outputs"]["research.solodit_sync"] = {"status": result.status.value, "state": result.model_dump(mode="json")}
    if result.message:
        state.setdefault("warnings", []).append(result.message)
    state["current_focus"] = "inspect_repo"
    return state




# "`@_stage(milestone, next_focus)` wraps a graph node so it (a) skips itself if its milestone is already 
# in `completed_stages`, and (b) records that milestone when it finishes — that's what makes every stage 
# run *exactly once* whether the model or the deterministic chain reaches it first. `build_protocol_ir` 
# is the stage that turns flat static facts into the connected Protocol IR + reachability graph; `contest_reasoning` 
# is the next stage that builds the adversarial layer (race actors, reasoning packets, gap hunters, working memory) 
# on top of that IR. Both follow the same node contract: read state → call pure helpers → store typed + JSON results → trace → point to the next stage → return."
@_stage("repo_inspected", "detect_framework")
def inspect_repo(state: AuditState) -> AuditState:
    """Stage 1: enumerate repo files, contracts, and pragma/contract hits.

    Args:
        state: The audit state.
    Returns:
        The same ``state`` with ``repo_facts`` (files, contracts) populated;
        marks the ``repo_inspected`` milestone.
    """
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


@_stage("framework_detected", "run_static_analysis")
def detect_framework(state: AuditState) -> AuditState:
    """Stage 2: detect the build framework, solc, and tool availability.

    Detects Foundry/Hardhat, the compiler, and whether forge/slither are present;
    runs a Foundry build when available.

    Args:
        state: The audit state.
    Returns:
        The same ``state`` with ``build_facts`` (framework, solc, foundry_build)
        populated; marks the ``framework_detected`` milestone.
    """
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


@_stage("static_facts_extracted", "build_protocol_ir")
def run_static_analysis(state: AuditState) -> AuditState:
    """Stage 3: the authoritative static-analysis pass.

    Runs all extractors (contracts, functions, ranges, access control, external
    calls, token transfers/types, storage writes), the 10 custom detectors, and
    Slither, and assembles them into the canonical ``static_facts`` dict that the
    rest of the pipeline consumes.

    Args:
        state: The audit state.
    Returns:
        The same ``state`` with ``static_facts`` fully populated; marks the
        ``static_facts_extracted`` milestone.
    """
    repo_path = state["repo_path"]
    _run_tool(state, "static.extract_contracts", {"repo_path": repo_path})
    _run_tool(state, "static.extract_functions", {"repo_path": repo_path})
    _run_tool(state, "static.map_function_ranges", {"repo_path": repo_path})
    _run_tool(state, "static.find_access_control_terms", {"repo_path": repo_path})
    _run_tool(state, "static.extract_external_calls", {"repo_path": repo_path})
    _run_tool(state, "static.extract_token_transfers", {"repo_path": repo_path})
    _run_tool(state, "static.extract_token_types", {"repo_path": repo_path})
    _run_tool(state, "static.extract_storage_writes", {"repo_path": repo_path})
    # Authoritative static-facts pass: every registered extractor contributes here.
    _run_tool(state, "static.extract_modifiers", {"repo_path": repo_path})
    _run_tool(state, "static.extract_inheritance", {"repo_path": repo_path})
    _run_tool(state, "static.extract_delegatecalls", {"repo_path": repo_path})
    _run_tool(state, "static.find_oracle_patterns", {"repo_path": repo_path})
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
        "static.detect_chainlink_unbounded_price",
        "static.detect_unsafe_approve",
        "static.detect_pause_not_enforced",
        "static.detect_oracle_cached_price_risks",
        "static.detect_erc4626_convertto_includes_fees",
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
        "modifiers": state["last_outputs"].get("static.extract_modifiers", {}).get("facts", []),
        "inheritance": state["last_outputs"].get("static.extract_inheritance", {}).get("facts", []),
        "delegatecalls": state["last_outputs"].get("static.extract_delegatecalls", {}).get("facts", []),
        "oracle_patterns": state["last_outputs"].get("static.find_oracle_patterns", {}).get("facts", []),
        "slither_findings": state["last_outputs"].get("static.parse_slither", {}).get("findings", []),
        "detections": [
            detection
            for detector_name in detector_names
            for detection in state["last_outputs"].get(detector_name, {}).get("detections", [])
        ],
    }
    state["current_focus"] = "build_protocol_ir"
    return state


@_stage("protocol_ir_built", "contest_reasoning")
def build_protocol_ir(state: AuditState) -> AuditState:
    """Stage 4: build the Protocol IR and cross-contract graph.

    Derives the typed IR (contracts, call edges, asset flows, auth constraints)
    and the protocol graph (slices + attack-path candidates) from static facts.

    Args:
        state: The audit state (reads static_facts).
    Returns:
        The same ``state`` with ``protocol_ir`` and ``protocol_graph`` set and
        summarized into ``last_outputs``; marks the ``protocol_ir_built`` milestone.
    """
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


@_stage("contest_reasoning_done", "build_protocol_model")
def contest_reasoning(state: AuditState) -> AuditState:
    """Stage 5: actor/race modeling, reasoning packets, and gap hunters.

    Builds the adversarial reasoning layer over the IR (transaction-race actors,
    reasoning packets, gap-hunter candidates) and the short-term working memory.

    Args:
        state: The audit state (requires ``protocol_ir``; skips gracefully if absent).
    Returns:
        The same ``state`` with reasoning_packets, gap_candidates, and
        working_memory populated; marks the ``contest_reasoning_done`` milestone.
    """
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


@_stage("protocol_model_built", "build_targeted_rag_context")
def build_protocol_model(state: AuditState) -> AuditState:
    """Stage 6: summarize protocol roles, assets, accounting, and upgrades.

    Args:
        state: The audit state (reads static_facts/protocol_ir).
    Returns:
        The same ``state`` with ``protocol_model`` populated; marks the
        ``protocol_model_built`` milestone.
    """
    if state.get("protocol_ir"):
        state.setdefault("static_facts", {})["protocol_ir"] = state["protocol_ir"].model_dump(mode="json")
    model = build_protocol_model_from_facts(state.get("static_facts", {}))
    state["protocol_model"] = model
    state["last_outputs"]["analysis.build_protocol_model"] = {"status": "ok", "protocol_model": model.model_dump(mode="json")}
    _record_step(state, "analysis.build_protocol_model", f"Protocol model terms: roles={len(model.roles)}, accounting={len(model.accounting_terms)}")
    state["current_focus"] = "build_targeted_rag_context"
    return state


@_stage("invariants_mined", "rank_hypotheses")
def mine_invariants(state: AuditState) -> AuditState:
    """Stage 8: mine protocol invariant candidates and build proof packets.

    Args:
        state: The audit state (reads static_facts).
    Returns:
        The same ``state`` with ``invariant_candidates`` and ``proof_packets``
        populated; marks the ``invariants_mined`` milestone.
    """
    candidates = mine_invariant_candidates(state["repo_path"], state.get("static_facts", {}))
    # Enrich the template-mined families with protocol-specific invariants the LLM
    # infers from the actual code (real-LLM only) — these anchor the novel-bug
    # violation reasoner with guarantees no fixed template encodes.
    if state.get("use_llm_refiner", False):
        from sentinel.tools.research import infer_protocol_invariants

        inferred = infer_protocol_invariants(state)
        if inferred:
            candidates = [*candidates, *inferred]
            emit_progress(f"  inferred {len(inferred)} protocol-specific invariants (LLM)…")
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


@_stage("targeted_rag_built", "mine_invariant_candidates")
def build_targeted_rag_context(state: AuditState) -> AuditState:
    """Stage 7: build the repo profile and Solodit checklist RAG context.

    Produces a graph-derived repo profile and retrieves historical-finding
    checklist items (used as prompts only, not proof) to steer ranking.

    Args:
        state: The audit state (reads static_facts/protocol_ir/graph).
    Returns:
        The same ``state`` with ``repo_rag_profile`` and ``targeted_rag`` set;
        marks the ``targeted_rag_built`` milestone.
    """
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


@_stage("hypotheses_ranked", "rag_retrieve_context")
def rank_hypotheses(state: AuditState) -> AuditState:
    """Stage 9: produce and rank vulnerability hypotheses, then enrich them.

    Ranks deterministic-detector hypotheses, merges in LLM-proposed code-grounded
    hypotheses (real-LLM mode only; hallucinations dropped), and attaches
    cross-contract evidence so findings span >=2 contracts.

    Args:
        state: The audit state (reads static_facts, invariants, gap candidates, RAG).
    Returns:
        The same ``state`` with ``hypotheses`` populated; marks the
        ``hypotheses_ranked`` milestone.
    """
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
    _merge_model_proposed_hypotheses(state)
    _merge_invariant_violation_hypotheses(state)
    _attach_cross_contract_evidence(state)
    state["current_focus"] = "research_subgraph"
    return state


def _merge_model_proposed_hypotheses(state: AuditState) -> None:
    """Ask the LLM for novel, code-grounded hypotheses and merge the survivors.

    Only runs in real-LLM mode. Proposals that do not ground to existing source
    are dropped inside the tool, so this never injects hallucinated findings;
    survivors are de-duplicated against existing hypotheses before merging.

    Args:
        state: The audit state; appends to ``state['hypotheses']`` in place.
    Returns:
        None. No-op when the LLM refiner is disabled (deterministic/mock mode).
    """
    if not state.get("use_llm_refiner", False):
        return
    emit_progress("  proposing novel hypotheses (LLM, code-grounded)…")
    proposed = _run_tool(
        state,
        "research.propose_hypotheses",
        {"repo_path": state["repo_path"], "objective": state["objective"], "max_hypotheses": 6},
    )
    model_hypotheses = list(getattr(proposed, "hypotheses", []) or [])
    if not model_hypotheses:
        return
    existing = {
        (h.vulnerability_class, tuple(sorted(h.affected_files)), tuple(sorted(h.affected_functions)))
        for h in state["hypotheses"]
    }
    added = 0
    for hypothesis in model_hypotheses:
        signature = (
            hypothesis.vulnerability_class,
            tuple(sorted(hypothesis.affected_files)),
            tuple(sorted(hypothesis.affected_functions)),
        )
        if signature in existing:
            continue
        existing.add(signature)
        state["hypotheses"].append(hypothesis)
        added += 1
    _record_step(
        state,
        "research.propose_hypotheses",
        f"Merged {added} model-proposed hypotheses (grounded={getattr(proposed, 'grounded_count', 0)}, dropped={getattr(proposed, 'dropped_count', 0)})",
    )


def _merge_invariant_violation_hypotheses(state: AuditState) -> None:
    """Run the invariant-violation reasoner (novel-bug engine) and merge survivors.

    Reasons adversarially over the protocol's own mined invariants to construct
    concrete violating sequences — the path to bugs no pattern detector encodes.
    Real-LLM only; ungrounded proposals are dropped in the tool, survivors are
    de-duplicated against existing hypotheses.

    Args:
        state: The audit state; appends to ``state['hypotheses']`` in place.
    Returns:
        None. No-op when the LLM refiner is disabled or no invariants were mined.
    """
    if not state.get("use_llm_refiner", False) or not state.get("invariant_candidates"):
        return
    emit_progress("  reasoning about invariant violations (LLM, novel-bug engine)…")
    reasoned = _run_tool(
        state,
        "research.reason_invariant_violations",
        {"repo_path": state["repo_path"], "objective": state["objective"], "max_hypotheses": 6},
    )
    violation_hypotheses = list(getattr(reasoned, "hypotheses", []) or [])
    if not violation_hypotheses:
        return
    existing = {
        (h.vulnerability_class, tuple(sorted(h.affected_files)), tuple(sorted(h.affected_functions)))
        for h in state["hypotheses"]
    }
    added = 0
    for hypothesis in violation_hypotheses:
        signature = (
            hypothesis.vulnerability_class,
            tuple(sorted(hypothesis.affected_files)),
            tuple(sorted(hypothesis.affected_functions)),
        )
        if signature in existing:
            continue
        existing.add(signature)
        state["hypotheses"].append(hypothesis)
        added += 1
    _record_step(
        state,
        "research.reason_invariant_violations",
        f"Merged {added} invariant-violation hypotheses (grounded={getattr(reasoned, 'grounded_count', 0)}, dropped={getattr(reasoned, 'dropped_count', 0)})",
    )


def _select_hypotheses_for_deepening(hypotheses: list[VulnerabilityHypothesis], max_items: int = 10) -> list[VulnerabilityHypothesis]:
    """Choose a diversified evidence-backed set for expensive RAG/research/validation work.

    Scores hypotheses by confidence + proof status + evidence/graph signals (with
    a penalty for profile-only leads), then selects strong proofs first, one per
    vulnerability class for diversity, then the remaining best — capped at
    ``max_items`` to bound the cost of per-hypothesis subagent work.

    Args:
        hypotheses: All ranked hypotheses.
        max_items: Maximum number to deepen (default 10).
    Returns:
        The selected, de-duplicated list of hypotheses to deepen.
    """
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


@_stage("rag_context_bundled", "research_subgraph")
def rag_retrieve_context(state: AuditState) -> AuditState:
    """Stage 10: run the RAG subagent per deepened hypothesis.

    For each selected hypothesis, spawns the isolated RAG subgraph to retrieve and
    self-RAG-grade historical findings, attaching only the safe matches.

    Args:
        state: The audit state (reads hypotheses, targeted_rag).
    Returns:
        The same ``state`` with ``rag_context_bundles`` populated and each
        hypothesis's ``historical_matches`` set; marks ``rag_context_bundled``.
    """
    hypotheses = state.get("hypotheses", [])
    if not hypotheses:
        return state
    state.setdefault("rag_context_bundles", {})
    # RAG is enrichment only (research deepens every selected hypothesis); cap the
    # expensive per-hypothesis self-RAG subgraph to the top-ranked few.
    rag_cap = get_settings().rag_max_hypotheses
    for hypothesis in _select_hypotheses_for_deepening(hypotheses)[:rag_cap]:
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


@_stage("research_completed", "summarize_context")
def research_subgraph(state: AuditState) -> AuditState:
    """Stage 11: deepen each hypothesis in the isolated research subagent.

    For each selected hypothesis, gathers evidence + cross-contract caller context
    and runs the research subgraph (analyze → historical context → refine →
    adversarial review → result), which confirms or rejects with a structured
    verdict.

    Args:
        state: The audit state (reads hypotheses, evidence, rag bundles).
    Returns:
        The same ``state`` with ``subgraph_results`` appended and per-hypothesis
        results in ``last_outputs``; marks the ``research_completed`` milestone.
    """
    hypotheses = state.get("hypotheses", [])
    if not hypotheses:
        state.setdefault("errors", []).append("No hypothesis available for research subgraph.")
        state["current_focus"] = "summarize_context"
        return state

    deepened = _select_hypotheses_for_deepening(hypotheses)
    for index, hypothesis in enumerate(deepened, start=1):
        emit_progress(f"  researching {hypothesis.id} ({index}/{len(deepened)}): {hypothesis.vulnerability_class}…")
        selected_snippets = _evidence_snippets_for_hypothesis(state, hypothesis) + _caller_context_snippets(state, hypothesis)
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
    """Compress the run into a short context summary before finishing.

    Args:
        state: The audit state.
    Returns:
        The same ``state`` with ``compressed_context`` set and ``current_focus``
        pointed at the finish node.
    """
    summary = (
        f"Repo files: {len(state.get('repo_facts', {}).get('files', []))}. "
        f"Contracts: {len(state.get('repo_facts', {}).get('contracts', []))}. "
        f"Static function facts: {len(state.get('static_facts', {}).get('functions', []))}. "
        f"Tool calls: {state.get('tool_call_count', 0)}."
    )
    state["compressed_context"] = summary
    state["current_focus"] = "finish"
    return state


_STATE_OMIT_KEYS = {"protocol_graph", "protocol_ir", "working_memory"}


def _state_for_persist(state: AuditState) -> dict:
    """Slim the persisted state.json to keep run dirs small and inspectable.

    The full tool ledger lives in tool_ledger.jsonl; large analysis objects are
    written as their own artifacts. We replace those bulky values with pointers
    and digests rather than inlining megabytes of duplicated data. Set
    SENTINEL_PERSIST_FULL_STATE=true to keep the verbatim state.
    """

    if get_settings().persist_full_state:
        return dict(state)
    slim: dict = {}
    for key, value in state.items():
        if key == "tool_ledger" and isinstance(value, list):
            slim[key] = f"<{len(value)} records; see tool_ledger.jsonl>"
        elif key == "last_outputs" and isinstance(value, dict):
            slim[key] = {
                name: ({"status": out.get("status"), "keys": sorted(out.keys())[:25]} if isinstance(out, dict) else {"type": type(out).__name__})
                for name, out in value.items()
            }
        elif key == "static_facts" and isinstance(value, dict):
            slim[key] = {fk: _digest_persist_value(fv) for fk, fv in value.items()}
        elif key in _STATE_OMIT_KEYS:
            slim[key] = f"<omitted from state.json; persisted as run artifact when available>"
        else:
            slim[key] = value
    return slim


def _digest_persist_value(value) -> object:
    """Summarize bulky list/dict values; keep small scalars and dicts intact."""

    if isinstance(value, list):
        return f"<list:{len(value)} items>"
    if isinstance(value, dict):
        if len(json.dumps(value, default=str)) > 2000:
            return f"<dict:{len(value)} keys; omitted>"
        return value
    return value


def finish(state: AuditState) -> AuditState:
    """Terminal node: validate, generate findings, and persist all artifacts.

    Runs semantic validation and validation-artifact generation/compilation for
    deepened hypotheses, writes durable artifacts (proof_packets, protocol_graph,
    working_memory, candidate_rank_trace), builds the findings + report.json/md,
    and writes a slimmed state.json.

    Args:
        state: The audit state at the end of the pipeline.
    Returns:
        The same ``state`` with ``findings`` and ``artifacts`` populated and
        ``current_focus`` set to ``"done"``; all run files written to disk.
    """
    repo_path = state["repo_path"]
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
    compile_output = _run_tool(state, "dynamic.compile_validation_artifacts", {"repo_path": repo_path})
    # If the generated PoC didn't compile, try to self-repair it (LLM-only) before
    # running, so a hallucinated signature doesn't waste the whole dynamic tier.
    if getattr(compile_output, "status", None) == ToolStatus.ERROR and state.get("use_llm_refiner", False):
        _run_tool(state, "dynamic.repair_validation_artifacts", {"repo_path": repo_path})
    _run_tool(state, "dynamic.run_validation_artifacts", {"repo_path": repo_path})
    # Execution-grounded reasoning loop (real-LLM only): for the top hypotheses,
    # author a runnable test that asserts the invariant, run it, observe whether it
    # breaks, and refine — proving multi-step economic bugs by running numbers.
    if hypotheses and state.get("use_llm_refiner", False):
        exploit_cap = get_settings().exploit_loop_max_hypotheses
        for hypothesis in _select_hypotheses_for_deepening(hypotheses)[:exploit_cap]:
            emit_progress(f"  exploit loop: authoring + running PoC for {hypothesis.id}…")
            _run_tool(
                state,
                "dynamic.author_and_run_exploit",
                {"repo_path": repo_path, "hypothesis": hypothesis.model_dump(mode="json")},
            )
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
    # Loudly flag if any reasoning fell back to the weaker model: a primary-model
    # outage silently downgrades calls, which would invalidate the run's results.
    if state.get("use_llm_refiner", False):
        fallback_hits = _count_fallback_usage(state)
        if fallback_hits:
            emit_progress(
                f"  ⚠ WARNING: {fallback_hits} LLM call(s) fell back to the fallback model "
                f"({get_settings().ollama_fallback_model}) — primary-model results are partially contaminated."
            )
    write_json(Path(state["run_dir"]) / "state.json", _state_for_persist(state))
    log_event(
        state["run_dir"],
        run_id=state["run_id"],
        event="run_finished",
        status="completed",
        tool_call_count=state.get("tool_call_count", 0),
    )
    return state


def build_parent_graph(use_llm_planner: bool = False):
    """Assemble and compile the parent LangGraph audit graph.

    Wires the 16 nodes and edges: in real-LLM mode the entry routes through the
    ``plan_with_llm`` spine (which can drive the whole pipeline via composite
    tools) with a conditional edge into the first missing stage; the idempotent
    stage chain then fills any gaps through to ``finish``.

    Args:
        use_llm_planner: If True, route through the model-driven planner; if
            False, run the deterministic stage chain directly.
    Returns:
        A compiled LangGraph ready to ``.invoke(state)``.
    """
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


def run_audit(repo: str, objective: str, run_id: str | None = None, mock_llm: bool = True, stream: bool = False) -> AuditState:
    """Top-level entry point: run one full audit over a repository.

    Creates the run state, reconciles tracing (so an unreachable LangSmith
    endpoint never stalls LLM calls), builds the graph in the requested mode, and
    invokes it inside a trace span. When ``stream`` is set, live progress lines
    (stage banners, per-tool, planner rounds, per-hypothesis research) are written
    to stderr so a multi-minute run is never silent.

    Args:
        repo: Path to the target Solidity repository.
        objective: Free-text audit objective shown to the planner.
        run_id: Optional explicit run id; a timestamped one is generated if omitted.
        mock_llm: If True (default) run the deterministic graph; if False use the
            real LLM planner + refiner + proposer + adversarial reviewer.
        stream: If True, stream live progress to stderr (off for tests/eval).
    Returns:
        The final ``AuditState`` (also persisted under ``runs/<run_id>/``).
    """
    actual_run_id = run_id or make_run_id()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", actual_run_id):
        raise ValueError(f"Invalid run_id (must match [A-Za-z0-9_-]{{1,128}}, no path separators): {actual_run_id!r}")
    run_dir = str(Path("runs") / actual_run_id)
    state = initial_audit_state(run_id=actual_run_id, repo=repo, objective=objective, run_dir=run_dir)
    state["use_llm_refiner"] = not mock_llm
    if stream:
        set_progress_sink(console_sink)
    tracing_requested = get_settings().langsmith_tracing
    remote_tracing = configure_tracing()
    if tracing_requested and not remote_tracing:
        state.setdefault("warnings", []).append(
            "LangSmith tracing requested but endpoint is unreachable; disabled remote tracing and using local spans."
        )
    ensure_run_dir(run_dir)
    try:
        with trace_span("audit.run", run_dir, run_id=actual_run_id, repo=repo, mock_llm=mock_llm):
            result = build_parent_graph(use_llm_planner=not mock_llm).invoke(state)
    finally:
        if stream:
            set_progress_sink(None)
    return result
