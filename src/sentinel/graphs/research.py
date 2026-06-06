from __future__ import annotations

import json

from langgraph.graph import END, START, StateGraph

from sentinel.llm import provider as llm_provider
from sentinel.schemas.common import ToolStatus
from sentinel.schemas.research import AdversarialVerdict, ResearchRefinement, ResearchSubgraphResult, VulnerabilityHypothesis
from sentinel.state import ResearchState
from sentinel.tools import build_default_registry
from sentinel.tools.executor import ToolExecutor


DEFAULT_RESEARCH_TOOLS = [
    "research.summarize_known_pattern",
    "research.retrieve_historical_findings",
    "research.compare_to_known_bug",
    "research.challenge_finding",
]


def _impact_for_class(vulnerability_class: str, functions: list[str]) -> str:
    function_text = f" `{functions[0]}`" if functions else ""
    if vulnerability_class == "reentrancy":
        return f"External control flow before finalized state in{function_text} can allow repeated withdrawal or inconsistent accounting."
    if vulnerability_class == "unchecked_transfer":
        return f"Ignoring an ERC20 transfer return value in{function_text} can make accounting continue after a token transfer failed."
    if vulnerability_class == "missing_access_control":
        return f"An unauthorized caller may be able to execute sensitive behavior in{function_text}."
    if vulnerability_class == "tx_origin_authorization":
        return f"Origin-based authorization in{function_text} can allow an intermediary contract to satisfy access checks through a victim origin."
    if vulnerability_class == "unguarded_initializer":
        return f"An unguarded initializer in{function_text} can allow unauthorized setup or repeated privileged state changes."
    if vulnerability_class == "oracle_staleness_logic":
        return f"Oracle validation in{function_text} may accept stale or incomplete price data."
    if vulnerability_class == "dangerous_delegatecall":
        return f"Delegatecall in{function_text} can execute external code in this contract's storage context."
    if vulnerability_class == "unsafe_or_guard":
        return f"An OR-combined guard in{function_text} can allow one weak branch to bypass intended constraints."
    if vulnerability_class == "external_call_before_accounting":
        return f"External control flow before finalized accounting in{function_text} can expose stale balances or inconsistent state."
    if vulnerability_class == "strategy_accounting_trust":
        return f"Strategy-controlled calls or reports in{function_text} can influence debt/accounting without sufficient reconciliation."
    return "The evidence supports a manual security review before reporting exploitability."


def _tests_for_class(vulnerability_class: str, functions: list[str]) -> list[str]:
    target = functions[0] if functions else "the affected function"
    if vulnerability_class == "reentrancy":
        return [f"Add an attacker-contract regression test that re-enters {target} before accounting is finalized."]
    if vulnerability_class == "unchecked_transfer":
        return [f"Add a mock ERC20 that returns false and assert {target} reverts or handles the failure."]
    if vulnerability_class == "missing_access_control":
        return [f"Add a non-authorized caller regression test for {target}."]
    if vulnerability_class == "tx_origin_authorization":
        return [f"Call {target} through an intermediary contract where tx.origin is privileged but msg.sender is not."]
    if vulnerability_class == "unguarded_initializer":
        return [f"Call {target} twice and from an unauthorized caller after initial setup."]
    if vulnerability_class == "oracle_staleness_logic":
        return [f"Mock zero and stale oracle responses and assert {target} rejects each independently."]
    if vulnerability_class == "dangerous_delegatecall":
        return [f"Pass a malicious delegatecall payload to {target} and assert storage cannot be corrupted."]
    if vulnerability_class == "unsafe_or_guard":
        return [f"Exercise each OR branch in {target} independently and assert weak branches do not bypass intended constraints."]
    if vulnerability_class == "external_call_before_accounting":
        return [f"Add a callback/reentrancy-style regression test around {target} before accounting is finalized."]
    if vulnerability_class == "strategy_accounting_trust":
        return [f"Use a malicious strategy mock around {target} that misreports or under-returns assets."]
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
                "proof_packet_id": snippet.get("proof_packet_id"),
                "proof_obligations": snippet.get("proof_obligations", []),
                "counterevidence": snippet.get("counterevidence", []),
                "local_facts": snippet.get("local_facts", []),
            }
        )
    return records[:8]


def _refinement_prompt(state: ResearchState) -> str:
    hypothesis = state["hypothesis"]
    evidence = state.get("evidence_records", [])
    payload = {
        "objective": state["objective"],
        "hypothesis": hypothesis.model_dump(mode="json"),
        "evidence": evidence,
        "proof_packets": [record for record in evidence if record.get("kind") == "proof_packet"],
        "instruction": (
            "Act as a protocol auditor over the supplied proof packet and source evidence. "
            "Refine the impact, exploit preconditions, and regression tests. "
            "Use only supplied local evidence for claims; use proof obligations to say what remains uncertain."
        ),
    }
    return json.dumps(payload, indent=2)


def validate_scope(state: ResearchState) -> ResearchState:
    allowed = set(state.get("allowed_tool_names", []))
    forbidden = [name for name in allowed if not name.startswith("research.")]
    if forbidden:
        state.setdefault("notes", []).append(f"Rejected non-research tools from scope: {', '.join(forbidden)}")
        state["allowed_tool_names"] = [name for name in state["allowed_tool_names"] if name.startswith("research.")]
    state.setdefault("notes", []).append("Research subgraph received scoped state only.")
    return state


def _scoped_executor(state: ResearchState) -> ToolExecutor:
    registry = build_default_registry().scoped(state.get("allowed_tool_names", DEFAULT_RESEARCH_TOOLS))
    return ToolExecutor(registry)


def analyze_hypothesis(state: ResearchState) -> ResearchState:
    hypothesis = state["hypothesis"]
    snippets = state.get("selected_snippets", [])
    if snippets:
        state.setdefault("notes", []).append(f"Reviewed {len(snippets)} selected snippet(s) for {hypothesis.id}.")
        # Caller context informs adversarial review but is not itself bug evidence.
        evidence_snippets = [s for s in snippets if s.get("kind") != "caller_context"]
        state["evidence_records"] = _evidence_records(evidence_snippets)
    else:
        state.setdefault("notes", []).append(f"No snippets were provided for {hypothesis.id}; confidence remains conservative.")
        state["evidence_records"] = []
    state.setdefault("notes", []).append(f"Mapped hypothesis class: {hypothesis.vulnerability_class}.")
    return state


def retrieve_historical_context(state: ResearchState) -> ResearchState:
    if state.get("rag_context_bundle"):
        bundle = state["rag_context_bundle"]
        state["historical_findings"] = [critique.model_dump(mode="json") for critique in bundle.safe_matches]
        state.setdefault("notes", []).append(f"Received RAG context bundle graded {bundle.quality_grade.grade}.")
        return state
    hypothesis = state["hypothesis"]
    query = " ".join(
        [
            state["objective"],
            hypothesis.title,
            hypothesis.evidence_summary,
            " ".join(hypothesis.affected_functions),
            " ".join(hypothesis.affected_files),
        ]
    )
    executor = _scoped_executor(state)
    tool_state = {
        "run_id": state["subgraph_run_id"],
        "run_dir": "",
        "tool_call_count": 0,
        "tool_ledger": [],
        "last_outputs": {},
        "static_facts": {},
    }
    try:
        output = executor.execute(
            "research.retrieve_historical_findings",
            {"query": query, "vulnerability_class": hypothesis.vulnerability_class, "top_k": 3},
            tool_state,
        )
        state["historical_findings"] = output.model_dump(mode="json").get("matches", [])
        state["subagent_tool_ledger"] = tool_state.get("tool_ledger", [])
        state.setdefault("notes", []).append(f"Retrieved {len(state['historical_findings'])} historical finding match(es).")
    except Exception as exc:
        state.setdefault("notes", []).append(f"Historical retrieval unavailable: {type(exc).__name__}: {exc}")
    return state


def refine_with_llm(state: ResearchState) -> ResearchState:
    if not state.get("use_llm_refiner", False):
        state.setdefault("notes", []).append("LLM research refinement disabled; using deterministic refinement.")
        return state
    try:
        refinement = llm_provider.get_research_refiner(mock=False).refine(_refinement_prompt(state))
    except Exception as exc:
        primary_error = f"{type(exc).__name__}: {exc}"
        state.setdefault("notes", []).append(f"Primary LLM research refinement unavailable; trying Ollama fallback: {primary_error}")
        try:
            refinement = llm_provider.get_ollama_fallback_refiner().refine(_refinement_prompt(state))
            state.setdefault("notes", []).append("Ollama fallback research refinement applied.")
        except Exception as fallback_exc:
            state.setdefault("notes", []).append(f"LLM research refinement unavailable: {type(fallback_exc).__name__}: {fallback_exc}")
            return state
    state["llm_refinement"] = refinement
    state.setdefault("notes", []).append("LLM research refinement applied.")
    return state


def _adversarial_prompt(state: ResearchState, function_bodies: list[dict], callers: list[dict]) -> str:
    hypothesis = state["hypothesis"]
    payload = {
        "objective": state["objective"],
        "hypothesis": {
            "title": hypothesis.title,
            "vulnerability_class": hypothesis.vulnerability_class,
            "affected_file": hypothesis.affected_files[0] if hypothesis.affected_files else None,
            "affected_function": hypothesis.affected_function or (hypothesis.affected_functions[0] if hypothesis.affected_functions else None),
            "claimed_preconditions": hypothesis.exploit_precondition_terms,
            "reasoning": hypothesis.evidence_summary,
        },
        "affected_function_source": [
            {"file": s.get("file_path"), "function": s.get("function"), "code": s.get("text")}
            for s in function_bodies[:4]
        ],
        "cross_contract_callers": [
            {"file": s.get("file_path"), "function": s.get("function"), "code": s.get("text")}
            for s in callers[:4]
        ],
        "instruction": (
            "Decide whether the hypothesis is exploitable using ONLY the supplied code. If a caller satisfies "
            "the dangerous precondition atomically at deployment, reject with that caller as counterevidence. "
            "If an attacker can reach the function independently or first, confirm with a concrete attack_trace."
        ),
    }
    return json.dumps(payload, indent=2)


def adversarial_review(state: ResearchState) -> ResearchState:
    if not state.get("use_llm_refiner", False):
        state.setdefault("notes", []).append("Adversarial review disabled; relying on static proof status.")
        return state
    snippets = state.get("selected_snippets", [])
    function_bodies = [s for s in snippets if s.get("kind") in {"function_body", "source_evidence"}]
    callers = [s for s in snippets if s.get("kind") == "caller_context"]
    if not function_bodies and not callers:
        state.setdefault("notes", []).append("Adversarial review skipped; no source context available.")
        return state
    prompt = _adversarial_prompt(state, function_bodies, callers)
    try:
        verdict = llm_provider.get_adversarial_reviewer(mock=False).review(prompt)
    except Exception as exc:
        state.setdefault("notes", []).append(f"Primary adversarial reviewer unavailable; trying Ollama fallback: {type(exc).__name__}: {exc}")
        try:
            verdict = llm_provider.get_ollama_fallback_reviewer().review(prompt)
            state.setdefault("notes", []).append("Ollama fallback adversarial reviewer applied.")
        except Exception as fallback_exc:
            state.setdefault("notes", []).append(f"Adversarial review unavailable: {type(fallback_exc).__name__}: {fallback_exc}")
            return state
    state["adversarial_verdict"] = verdict
    state.setdefault("notes", []).append(
        f"Adversarial verdict: {verdict.verdict} (callers reviewed: {len(callers)})."
    )
    return state


_ADVERSARIAL_STATUS = {
    "confirmed": "confirmed",
    "likely": "likely",
    "rejected": "rejected",
    "needs_manual_review": "needs_manual_review",
}


def create_result(state: ResearchState) -> ResearchState:
    hypothesis = state["hypothesis"]
    functions = hypothesis.affected_functions
    files = hypothesis.affected_files
    deterministic_impact = _impact_for_class(hypothesis.vulnerability_class, functions)
    deterministic_tests = _tests_for_class(hypothesis.vulnerability_class, functions)
    deterministic_limitations = ["Research subgraph is deterministic; exploitability still requires targeted validation on the full project."]
    refinement = state.get("llm_refinement") or ResearchRefinement()
    likely_impact = refinement.likely_impact or deterministic_impact
    recommended_tests = refinement.recommended_tests or deterministic_tests
    exploit_preconditions = refinement.exploit_preconditions or (["Attacker can reach the affected function"] if functions else [])
    limitations = refinement.limitations or deterministic_limitations
    confidence = min(0.95, max(0.0, hypothesis.confidence + 0.1 + refinement.confidence_delta))
    limitation_text = " ".join(limitations).lower()
    has_local_evidence = bool(state.get("evidence_records"))
    has_function = bool(functions or hypothesis.affected_function)
    has_cross_function_or_static_proof = _has_cross_function_or_static_proof(hypothesis, functions)
    blocking_limitation = any(
        phrase in limitation_text
        for phrase in [
            "only proves",
            "specific function",
            "not provided",
            "unknown if",
            "compile failed",
            "validation artifact compile failed",
            "setup inference",
            "missing trigger",
            "missing affected function",
            "low to none",
        ]
    )
    if hypothesis.status == "rejected" or hypothesis.proof_status == "rejected_by_counterevidence":
        finding_status = "rejected"
    elif not has_local_evidence or not has_function:
        finding_status = "needs_manual_review"
    elif blocking_limitation:
        finding_status = "needs_manual_review"
    elif _has_complete_static_proof(hypothesis) and has_local_evidence:
        finding_status = "confirmed"
    elif hypothesis.proof_status == "strong_local_path" and has_cross_function_or_static_proof:
        finding_status = "likely"
    elif hypothesis.status == "needs_manual_review" and not state.get("llm_refinement"):
        finding_status = "needs_manual_review"
    elif has_local_evidence and has_cross_function_or_static_proof:
        finding_status = "likely"
    else:
        finding_status = "needs_manual_review"

    
    reasoning_summary = likely_impact
    verdict = state.get("adversarial_verdict")
    if verdict is not None and verdict.verdict in {"confirmed", "likely", "rejected"}:
        finding_status = _ADVERSARIAL_STATUS[verdict.verdict]
        confidence = min(0.95, max(0.0, confidence + verdict.confidence_delta))
        if verdict.reasoning:
            reasoning_summary = verdict.reasoning
        if verdict.attack_trace:
            exploit_preconditions = verdict.attack_trace
        if verdict.counterevidence:
            limitations = [*limitations, *(f"Counterevidence: {item}" for item in verdict.counterevidence)]
            hypothesis.counterevidence = [*hypothesis.counterevidence, *verdict.counterevidence]
        if finding_status == "rejected":
            hypothesis.status = "rejected"
            hypothesis.proof_status = "rejected_by_counterevidence"

    result = ResearchSubgraphResult(
        status=ToolStatus.OK,
        subgraph_run_id=state["subgraph_run_id"],
        hypothesis_id=hypothesis.id,
        refined_title=hypothesis.title,
        vulnerability_class=hypothesis.vulnerability_class,
        evidence=state.get("evidence_records", []),
        exploit_preconditions=exploit_preconditions,
        likely_impact=likely_impact,
        evidence_to_collect=[*files, *functions],
        recommended_tests=recommended_tests,
        confidence=confidence,
        limitations=limitations,
        notes=state.get("notes", []),
        historical_findings=state.get("historical_findings", []),
        subagent_tool_ledger=[record.model_dump(mode="json") if hasattr(record, "model_dump") else record for record in state.get("subagent_tool_ledger", [])],
        finding_status=finding_status,
        reasoning_summary=reasoning_summary,
        historical_context_used=bool(state.get("historical_findings")),
        rag_context_bundle=state.get("rag_context_bundle"),
    )
    state["result"] = result
    return state


def _has_complete_static_proof(hypothesis: VulnerabilityHypothesis) -> bool:
    return hypothesis.proof_status == "static_proof_complete"


def _has_cross_function_or_static_proof(hypothesis: VulnerabilityHypothesis, functions: list[str]) -> bool:
    if _has_complete_static_proof(hypothesis):
        return True
    if hypothesis.proof_status not in {"strong_local_path", "missing_counterevidence"}:
        return False
    return (
        len(set(functions)) >= 2
        or len(hypothesis.evidence_lines) >= 2
        or bool(hypothesis.graph_slice_ids)
        or (
            hypothesis.status == "likely"
            and any("_gap_agent" in source for source in hypothesis.source_detection_ids)
            and bool(hypothesis.exploit_precondition_terms)
        )
    )

# Builds the isolated research subgraph for a single vulnerability hypothesis:
# the flow first validates that the subagent only has access to its approved
# research-scoped tools, then analyzes the local hypothesis and source evidence,
# retrieves historical context when available, asks the LLM to refine the claim,
# performs an adversarial review to challenge assumptions and look for
# counterevidence, and finally returns a structured research result to the parent
# audit graph. The graph is linear because each stage strengthens or filters the
# previous one: scope validation enforces isolation, local analysis grounds the
# hypothesis, historical retrieval adds context, LLM refinement improves the
# explanation, adversarial review reduces false positives, and create_result
# packages the final status, rationale, validation ideas, and subagent ledger.
def build_research_graph():
    graph = StateGraph(ResearchState)
    graph.add_node("validate_scope", validate_scope)
    graph.add_node("analyze_hypothesis", analyze_hypothesis)
    graph.add_node("retrieve_historical_context", retrieve_historical_context)
    graph.add_node("refine_with_llm", refine_with_llm)
    graph.add_node("adversarial_review", adversarial_review)
    graph.add_node("create_result", create_result)

    graph.add_edge(START, "validate_scope")
    graph.add_edge("validate_scope", "analyze_hypothesis")
    graph.add_edge("analyze_hypothesis", "retrieve_historical_context")
    graph.add_edge("retrieve_historical_context", "refine_with_llm")
    graph.add_edge("refine_with_llm", "adversarial_review")
    graph.add_edge("adversarial_review", "create_result")
    graph.add_edge("create_result", END)
    return graph.compile()


def run_research_subgraph(state: ResearchState) -> ResearchSubgraphResult:
    result_state = build_research_graph().invoke(state)
    return result_state["result"]
