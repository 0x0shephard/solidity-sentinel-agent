from __future__ import annotations

from collections import defaultdict
import re
from pathlib import Path

from sentinel.evidence import classify_source_path
from sentinel.schemas.invariants import AuditWorkingMemory, GapFindingCandidate, ReasoningDisciplinePacket
from sentinel.schemas.protocol_ir import (
    ActorModel,
    MutableStateAssumption,
    ProtocolIR,
    TransactionAction,
    TransactionRaceEdge,
    TransactionRaceGraph,
    UserIntent,
)
from sentinel.schemas.static import FunctionRange, SourceEvidence


ORDER_STATE_TERMS = {"order", "price", "amount", "deadline", "active", "cancel", "amend", "buy", "fill"}
SLIPPAGE_TERMS = {"min", "max", "slippage", "limit", "expected"}


def build_transaction_race_graph(repo_path: str, ir: ProtocolIR) -> TransactionRaceGraph:
    actors = _actors_from_ir(ir)
    actions = _actions_from_ir(repo_path, ir)
    intents = _intents_from_actions(actions)
    edges: list[TransactionRaceEdge] = []
    assumptions: list[MutableStateAssumption] = []

    by_function = {action.function_name.lower(): action for action in actions}
    buy_actions = [action for action in actions if any(term in action.function_name.lower() for term in ("buy", "fill", "match"))]
    mutate_actions = [
        action
        for action in actions
        if any(term in action.function_name.lower() for term in ("amend", "update", "edit", "cancel"))
        and any(_is_order_state(var) for var in action.mutates + action.reads)
    ]
    for buy in buy_actions:
        mutable_state = [var for var in buy.reads if _is_order_state(var)]
        missing_bounds = _missing_bounds_for_action(buy)
        for mutate in mutate_actions:
            shared = sorted(set(mutable_state).intersection(mutate.mutates + mutate.reads) or set(mutable_state))
            if not shared:
                continue
            edge_type = "can_cancel_before" if "cancel" in mutate.function_name.lower() else "can_mutate_before"
            edges.append(
                TransactionRaceEdge(
                    edge_id=f"race-{len(edges) + 1}",
                    edge_type=edge_type,
                    from_action_id=mutate.action_id,
                    to_action_id=buy.action_id,
                    affected_state=shared,
                    adversarial_trace=[
                        f"Victim prepares `{buy.function_name}` using currently visible order terms.",
                        f"Adversary submits `{mutate.function_name}` first and changes {', '.join(shared[:4])}.",
                        f"`{buy.function_name}` executes against changed state without explicit user-supplied bounds.",
                    ],
                    evidence=[*mutate.evidence[:2], *buy.evidence[:2]],
                    confidence=0.86 if missing_bounds else 0.68,
                )
            )
        if missing_bounds and mutable_state:
            assumptions.append(
                MutableStateAssumption(
                    assumption_id=f"assumption-{len(assumptions) + 1}",
                    victim_action_id=buy.action_id,
                    mutable_by_action_ids=[action.action_id for action in mutate_actions],
                    state_variables=mutable_state,
                    missing_bounds=missing_bounds,
                    evidence=buy.evidence,
                )
            )

    cancel = by_function.get("cancelsellorder") or next((action for action in actions if "cancel" in action.function_name.lower()), None)
    if cancel and any("deadline" in value.lower() for value in cancel.reads):
        seller_only = any("seller" in ev.source_text.lower() and "msg.sender" in ev.source_text.lower() for ev in cancel.evidence)
        if seller_only:
            assumptions.append(
                MutableStateAssumption(
                    assumption_id=f"assumption-{len(assumptions) + 1}",
                    victim_action_id=cancel.action_id,
                    state_variables=["deadlineTimestamp", "isActive", "seller"],
                    missing_bounds=["expired order recovery by non-seller"],
                    evidence=cancel.evidence,
                )
            )
    return TransactionRaceGraph(actors=actors, intents=intents, actions=actions, race_edges=edges, mutable_assumptions=assumptions)


def build_reasoning_packets(ir: ProtocolIR) -> list[ReasoningDisciplinePacket]:
    packets: list[ReasoningDisciplinePacket] = []
    for action in ir.transaction_race_graph.actions:
        packets.append(
            ReasoningDisciplinePacket(
                packet_id=f"reason-feynman-{len(packets) + 1}",
                pass_type="feynman",
                function_name=action.function_name,
                affected_functions=[action.function_name],
                plain_english=_plain_english_action(action),
                assumptions=[f"Reads {', '.join(action.reads[:5]) or 'no tracked state'} before mutating {', '.join(action.mutates[:5]) or 'no tracked state'}."],
                evidence=action.evidence[:3],
            )
        )
    for assumption in ir.transaction_race_graph.mutable_assumptions:
        action = _action_by_id(ir.transaction_race_graph.actions, assumption.victim_action_id)
        packets.append(
            ReasoningDisciplinePacket(
                packet_id=f"reason-socratic-{len(packets) + 1}",
                pass_type="socratic",
                function_name=action.function_name if action else None,
                affected_functions=[action.function_name] if action else [],
                plain_english="Question whether the user's observed state can change before their transaction executes.",
                assumptions=assumption.state_variables,
                adversarial_questions=[
                    "Who can change this state before the victim transaction lands?",
                    "Does the victim provide min/max bounds that bind the expected terms?",
                    "What happens after deadline if the original actor disappears?",
                ],
                evidence=assumption.evidence,
            )
        )
    for edge in ir.transaction_race_graph.race_edges:
        packets.append(
            ReasoningDisciplinePacket(
                packet_id=f"reason-inversion-{len(packets) + 1}",
                pass_type="inversion",
                affected_functions=[edge.from_action_id, edge.to_action_id],
                plain_english="Invert the happy path by letting the adversary reorder mutable-state transactions.",
                inversion_traces=edge.adversarial_trace,
                evidence=edge.evidence,
            )
        )
    return packets


def run_gap_hunters(repo_path: str, ir: ProtocolIR, reasoning_packets: list[ReasoningDisciplinePacket]) -> list[GapFindingCandidate]:
    candidates: list[GapFindingCandidate] = []
    candidates.extend(_market_gap_candidates(ir))
    candidates.extend(_numerical_gap_candidates(repo_path, ir))
    candidates.extend(_lifecycle_gap_candidates(ir))
    candidates.extend(_flow_gap_candidates(ir))
    candidates.extend(_trust_gap_candidates(ir, reasoning_packets))
    return _dedupe_gap_candidates(candidates)[:20]


def build_working_memory(reasoning_packets: list[ReasoningDisciplinePacket], gap_candidates: list[GapFindingCandidate]) -> AuditWorkingMemory:
    rejected = [
        f"{candidate.id}: {', '.join(candidate.counterevidence)}"
        for candidate in gap_candidates
        if candidate.status == "rejected" and candidate.counterevidence
    ]
    return AuditWorkingMemory(
        function_summaries=[packet for packet in reasoning_packets if packet.pass_type == "feynman"],
        actor_assumptions=[question for packet in reasoning_packets for question in packet.adversarial_questions],
        open_proof_obligations=[item for candidate in gap_candidates for item in candidate.proof_obligations],
        rejected_hypotheses=rejected,
        benchmark_lessons=[
            "Mutable order terms require slippage or min/max bound reasoning.",
            "CEI-safe SafeERC20 reentrancy candidates need a concrete secondary target before promotion.",
            "Expired-but-active lifecycle state requires liveness and cleanup checks.",
        ],
    )


def _actors_from_ir(ir: ProtocolIR) -> list[ActorModel]:
    roles = {
        "seller": ["create/amend/cancel owned orders"],
        "buyer": ["fill active orders"],
        "owner": ["configure tokens and withdraw protocol fees"],
        "mev_searcher": ["observe public mempool and reorder public calls"],
        "inactive_user": ["fails to clean up expired positions"],
        "external_token": ["executes token transfer logic"],
    }
    evidence_by_role: dict[str, list[SourceEvidence]] = defaultdict(list)
    for contract in ir.contracts:
        for function in contract.functions:
            ev = _evidence(function.file_path, function.start_line, function.contract_name, function.name, function.signature, "actor capability inferred from public function")
            lower = function.name.lower() + " " + function.signature.lower()
            if "seller" in lower or any(term in lower for term in ("sell", "amend", "cancel")):
                evidence_by_role["seller"].append(ev)
            if any(term in lower for term in ("buy", "fill", "match")):
                evidence_by_role["buyer"].append(ev)
            if "onlyowner" in lower or "owner" in lower:
                evidence_by_role["owner"].append(ev)
    return [
        ActorModel(actor_id=f"actor-{role}", role=role, capabilities=caps, evidence=evidence_by_role.get(role, [])[:4])
        for role, caps in roles.items()
    ]


def _actions_from_ir(repo_path: str, ir: ProtocolIR) -> list[TransactionAction]:
    actions = []
    for contract in ir.contracts:
        for function in contract.functions:
            if function.visibility not in {"public", "external"}:
                continue
            evidence = [_function_body_evidence(repo_path, function.file_path, function.start_line or 1, function.end_line or function.start_line or 1, contract.name, function.name)]
            flows = [flow.expression for flow in ir.asset_flows if flow.contract_name == contract.name and flow.function_name == function.name]
            actions.append(
                TransactionAction(
                    action_id=f"action-{len(actions) + 1}",
                    actor_role=_actor_role_for_function(function.name, function.signature),
                    function_name=function.name,
                    file_path=function.file_path,
                    line=function.start_line,
                    mutates=function.writes,
                    reads=function.reads,
                    asset_effects=flows,
                    evidence=evidence,
                )
            )
    return actions


def _intents_from_actions(actions: list[TransactionAction]) -> list[UserIntent]:
    intents = []
    for action in actions:
        if action.actor_role == "unknown":
            continue
        intents.append(
            UserIntent(
                intent_id=f"intent-{len(intents) + 1}",
                actor_role=action.actor_role,
                function_name=action.function_name,
                plain_english=_plain_english_action(action),
                assumed_state=action.reads,
                evidence=action.evidence,
            )
        )
    return intents


def _market_gap_candidates(ir: ProtocolIR) -> list[GapFindingCandidate]:
    candidates = []
    for edge in ir.transaction_race_graph.race_edges:
        evidence = edge.evidence
        if not evidence:
            continue
        title = "Mutable order terms can be changed before a buyer fill executes"
        if edge.edge_type == "can_cancel_before":
            title = "Order cancellation can race a public fill or state-dependent action"
        candidates.append(
            GapFindingCandidate(
                id=f"gap-market-{len(candidates) + 1}",
                agent_id="market_gap_agent",
                gap_type=edge.edge_type,
                vulnerability_class="transaction_ordering",
                title=title,
                confidence=edge.confidence,
                affected_functions=_functions_from_evidence(evidence),
                affected_state_variables=edge.affected_state,
                evidence=evidence[:6],
                adversarial_trace=edge.adversarial_trace,
                proof_obligations=[
                    "Show the victim cannot bind expected price, amount, or state with transaction parameters.",
                    "Show the adversary-controlled action can execute before the victim action in the public mempool.",
                ],
                validation_template="mempool_order_race",
                status="likely" if edge.confidence >= 0.8 else "needs_manual_review",
            )
        )
    return candidates


def _numerical_gap_candidates(repo_path: str, ir: ProtocolIR) -> list[GapFindingCandidate]:
    candidates = []
    for action in ir.transaction_race_graph.actions:
        text = " ".join(ev.source_text for ev in action.evidence)
        if not re.search(r"\bfee\b|\bprice\b|precision|bps|percent", text, flags=re.IGNORECASE):
            continue
        if "*" not in text or "/" not in text:
            continue
        evidence = action.evidence[:3]
        candidates.append(
            GapFindingCandidate(
                id=f"gap-numerical-{len(candidates) + 1}",
                agent_id="numerical_gap_agent",
                gap_type="integer_rounding",
                vulnerability_class="accounting_invariant",
                title="Integer division can round protocol fees or payouts to zero",
                confidence=0.78,
                affected_functions=[action.function_name],
                affected_state_variables=[item for item in [*action.reads, *action.mutates] if re.search(r"fee|price|amount|precision", item, flags=re.IGNORECASE)][:6],
                evidence=evidence,
                adversarial_trace=[
                    "Choose the smallest input value where `(value * fee) / precision` truncates to zero.",
                    "Repeat the action or split orders to avoid fees while preserving intended transfer behavior.",
                ],
                proof_obligations=["Compute the concrete zero-fee threshold and show the action still succeeds."],
                validation_template="low_price_zero_fee_rounding",
                status="likely",
            )
        )
    return candidates


def _lifecycle_gap_candidates(ir: ProtocolIR) -> list[GapFindingCandidate]:
    candidates = []
    has_deadline_state = any(
        "deadline" in value.lower()
        for action in ir.transaction_race_graph.actions
        for value in [*action.reads, *action.mutates]
    )
    cleanup_actions = [
        action
        for action in ir.transaction_race_graph.actions
        if any(term in action.function_name.lower() for term in ("expire", "cleanup", "sweep"))
    ]
    for action in ir.transaction_race_graph.actions:
        lower = " ".join([action.function_name, *action.reads, *action.mutates, *(ev.source_text for ev in action.evidence)]).lower()
        if ("deadline" in lower or has_deadline_state) and "seller" in lower and "cancel" in action.function_name.lower() and not cleanup_actions:
            candidates.append(
                GapFindingCandidate(
                    id=f"gap-lifecycle-{len(candidates) + 1}",
                    agent_id="lifecycle_gap_agent",
                    gap_type="expired_assets_seller_only_recovery",
                    vulnerability_class="business_logic",
                    title="Expired positions may remain recoverable only by the original actor",
                    confidence=0.78,
                    affected_functions=[action.function_name],
                    affected_state_variables=["deadlineTimestamp", "isActive", "seller"],
                    evidence=action.evidence,
                    adversarial_trace=[
                        "Seller creates an order and becomes inactive after the deadline.",
                        "A third party attempts cleanup but authorization remains seller-only.",
                        "Assets and active storage can remain stuck.",
                    ],
                    proof_obligations=["Show no public cleanup path exists for expired positions when the seller is inactive."],
                    validation_template="expired_order_non_seller_cancel",
                    status="likely",
                )
            )
        if "deadline" in lower and "active" in lower and any(term in action.function_name.lower() for term in ("buy", "fill")):
            candidates.append(
                GapFindingCandidate(
                    id=f"gap-lifecycle-{len(candidates) + 1}",
                    agent_id="lifecycle_gap_agent",
                    gap_type="expired_state_remains_active",
                    vulnerability_class="business_logic",
                    title="Expired state can remain marked active after the deadline check reverts",
                    confidence=0.74,
                    affected_functions=[action.function_name],
                    affected_state_variables=["deadlineTimestamp", "isActive"],
                    evidence=action.evidence,
                    adversarial_trace=[
                        "Order passes time beyond deadline while `isActive` remains true.",
                        "A buyer call reverts on expiry before any cleanup writes execute.",
                        "The order remains active in storage but unusable.",
                    ],
                    proof_obligations=["Show the expired branch reverts before writing inactive state and no cleanup path fixes it."],
                    validation_template="expired_order_remains_active",
                    status="likely",
                )
            )
    return candidates


def _flow_gap_candidates(ir: ProtocolIR) -> list[GapFindingCandidate]:
    candidates = []
    for action in ir.transaction_race_graph.actions:
        has_safe_transfer = any("safetransfer" in ev.source_text.lower() for ev in action.evidence)
        active_before_transfer = any("isactive=false" in ev.source_text.lower().replace(" ", "") for ev in action.evidence)
        if has_safe_transfer and active_before_transfer:
            candidates.append(
                GapFindingCandidate(
                    id=f"gap-flow-rejected-{len(candidates) + 1}",
                    agent_id="flow_gap_agent",
                    gap_type="cei_safe_external_transfer",
                    vulnerability_class="business_logic",
                    title="CEI-safe external transfer has no concrete secondary target",
                    confidence=0.2,
                    affected_functions=[action.function_name],
                    evidence=action.evidence,
                    counterevidence=["State is marked inactive before token transfer.", "SafeERC20 transfer helper is used."],
                    proof_obligations=["Find a concrete secondary target before promoting reentrancy/flow risk."],
                    validation_template="reject_cei_safe_reentrancy",
                    status="rejected",
                )
            )
    return candidates


def _trust_gap_candidates(ir: ProtocolIR, reasoning_packets: list[ReasoningDisciplinePacket]) -> list[GapFindingCandidate]:
    candidates = []
    for assumption in ir.transaction_race_graph.mutable_assumptions:
        evidence = assumption.evidence
        if not evidence:
            continue
        if any("min" in item.lower() or "max" in item.lower() for item in assumption.missing_bounds):
            continue
        candidates.append(
            GapFindingCandidate(
                id=f"gap-trust-{len(candidates) + 1}",
                agent_id="trust_gap_agent",
                gap_type="mutable_state_assumption",
                vulnerability_class="business_logic",
                title="Victim action trusts mutable state without explicit binding",
                confidence=0.7,
                affected_functions=_functions_from_evidence(evidence),
                affected_state_variables=assumption.state_variables,
                evidence=evidence,
                adversarial_trace=["A user observes state off-chain, then another actor mutates it before execution."],
                proof_obligations=["Bind the expected state with explicit transaction parameters or prove state cannot change first."],
                validation_template="mutable_state_assumption",
                status="needs_manual_review",
            )
        )
    return candidates


def _actor_role_for_function(name: str, signature: str) -> str:
    lower = f"{name} {signature}".lower()
    if any(term in lower for term in ("buy", "fill", "match")):
        return "buyer"
    if any(term in lower for term in ("sell", "amend", "cancel", "order")):
        return "seller"
    if "owner" in lower or "admin" in lower:
        return "owner"
    return "unknown"


def _is_order_state(value: str) -> bool:
    lower = value.lower()
    return any(term in lower for term in ORDER_STATE_TERMS)


def _missing_bounds_for_action(action: TransactionAction) -> list[str]:
    lower = f"{action.function_name} {' '.join(action.reads)} {' '.join(action.mutates)}".lower()
    if not any(term in lower for term in ("buy", "fill", "match")):
        return []
    params_text = " ".join(ev.source_text for ev in action.evidence).lower()
    missing = []
    if "price" in lower and not any(term in params_text for term in ("maxprice", "max_price", "limitprice", "limit_price")):
        missing.append("max price bound")
    if "amount" in lower and not any(term in params_text for term in ("minreceive", "min_receive", "minamount", "min_amount")):
        missing.append("minimum received amount")
    return missing


def _plain_english_action(action: TransactionAction) -> str:
    effects = []
    if action.reads:
        effects.append(f"reads {', '.join(action.reads[:4])}")
    if action.mutates:
        effects.append(f"updates {', '.join(action.mutates[:4])}")
    if action.asset_effects:
        effects.append("moves assets")
    tail = "; ".join(effects) or "has no tracked state or asset effect"
    return f"`{action.function_name}` is callable by a likely {action.actor_role} and {tail}."


def _action_by_id(actions: list[TransactionAction], action_id: str) -> TransactionAction | None:
    return next((action for action in actions if action.action_id == action_id), None)


def _functions_from_evidence(evidence: list[SourceEvidence]) -> list[str]:
    return list(dict.fromkeys(item.function_name for item in evidence if item.function_name))


def _dedupe_gap_candidates(candidates: list[GapFindingCandidate]) -> list[GapFindingCandidate]:
    deduped = []
    seen = set()
    for candidate in sorted(candidates, key=lambda item: item.confidence, reverse=True):
        key = (candidate.gap_type, tuple(candidate.affected_functions), tuple((ev.file_path, ev.line_start) for ev in candidate.evidence[:2]))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)
    return deduped


def _evidence(file_path: str, line: int | None, contract: str | None, function: str | None, expression: str, reason: str) -> SourceEvidence:
    return SourceEvidence(
        file_path=file_path,
        line_start=max(1, line or 1),
        line_end=max(1, line or 1),
        contract_name=contract,
        function_name=function,
        source_text=expression,
        reason=reason,
    )


def _function_body_evidence(repo_path: str, file_path: str, start_line: int, end_line: int, contract: str | None, function: str | None) -> SourceEvidence:
    path = Path(repo_path) / file_path
    if path.exists() and classify_source_path(file_path) == "production":
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        excerpt = " ".join(line.strip() for line in lines[max(0, start_line - 1) : min(len(lines), end_line)])
    else:
        excerpt = function or "unknown"
    return SourceEvidence(
        file_path=file_path,
        line_start=max(1, start_line),
        line_end=max(1, end_line),
        contract_name=contract,
        function_name=function,
        source_text=excerpt[:1600],
        reason="full function context for contest-auditor reasoning",
    )
