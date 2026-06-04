from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

from sentinel.evidence import classify_source_path
from sentinel.schemas.invariants import InvariantCandidate, ProtocolModel
from sentinel.schemas.protocol_ir import GraphSlice, ProtocolGraph, ProtocolIR
from sentinel.schemas.static import FunctionRange, SourceEvidence
from sentinel.solidity.ranges import containing_function


ACCOUNTING_TERMS = {
    "balance",
    "balances",
    "supply",
    "debt",
    "reward",
    "rewards",
    "bursary",
    "wage",
    "fee",
    "fees",
    "score",
    "count",
    "share",
    "shares",
}
LIFECYCLE_TERMS = {"start", "end", "deadline", "session", "epoch", "round", "graduate", "enroll", "review"}
UPGRADE_TERMS = {"upgrade", "authorizeupgrade", "uups", "implementation", "initializer"}
ROLE_TERMS = {"owner", "admin", "role", "teacher", "student", "manager", "governor"}
ASSET_TERMS = {"token", "erc20", "ether", "eth", "weth", "usdc", "asset"}


def build_protocol_model(static_facts: dict) -> ProtocolModel:
    protocol_ir = _protocol_ir_from_static_facts(static_facts)
    if protocol_ir:
        texts = [
            *[flow.expression for flow in protocol_ir.asset_flows],
            *[auth.expression for auth in protocol_ir.auth_constraints],
            *[transition.expression for transition in protocol_ir.lifecycle_transitions],
            *[access.expression for access in protocol_ir.storage_accesses],
        ]
        haystack = " ".join(texts).lower()
        return ProtocolModel(
            contracts=protocol_ir.contract_names(),
            roles=sorted(term for term in ROLE_TERMS if term in haystack),
            assets=sorted(term for term in ASSET_TERMS if term in haystack),
            accounting_terms=sorted(term for term in ACCOUNTING_TERMS if term in haystack),
            lifecycle_terms=sorted(term for term in LIFECYCLE_TERMS if term in haystack),
            upgrade_terms=sorted(term for term in UPGRADE_TERMS if term in haystack),
            notes=[f"Profiled {len(protocol_ir.contracts)} contracts from Protocol IR."],
        )
    texts = _all_fact_texts(static_facts)
    contracts = sorted({str(item.get("contract")) for item in static_facts.get("contracts", []) if item.get("contract")})
    haystack = " ".join(texts).lower()
    return ProtocolModel(
        contracts=contracts,
        roles=sorted(term for term in ROLE_TERMS if term in haystack),
        assets=sorted(term for term in ASSET_TERMS if term in haystack),
        accounting_terms=sorted(term for term in ACCOUNTING_TERMS if term in haystack),
        lifecycle_terms=sorted(term for term in LIFECYCLE_TERMS if term in haystack),
        upgrade_terms=sorted(term for term in UPGRADE_TERMS if term in haystack),
        notes=[f"Profiled {len(contracts)} contracts from static facts."],
    )


def mine_invariant_candidates(repo_path: str, static_facts: dict) -> list[InvariantCandidate]:
    protocol_ir = _protocol_ir_from_static_facts(static_facts)
    protocol_graph = _protocol_graph_from_static_facts(static_facts)
    ranges = [FunctionRange.model_validate(item) for item in static_facts.get("function_ranges", [])]
    candidates: list[InvariantCandidate] = []
    if protocol_graph:
        candidates.extend(_graph_slice_invariant_candidates(repo_path, protocol_graph, ranges))
    if protocol_ir:
        candidates.extend(_graph_invariant_candidates(repo_path, protocol_ir, ranges, static_facts.get("rag_checklist_items", [])))
    files = _production_solidity_files(repo_path)
    variable_writes: dict[str, list[SourceEvidence]] = defaultdict(list)
    variable_reads: dict[str, list[SourceEvidence]] = defaultdict(list)
    contract_state_vars: dict[str, list[str]] = defaultdict(list)

    for path in files:
        rel = _relative(repo_path, path)
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        contract_name = None
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            code = _strip_inline_comment(stripped)
            contract_match = re.match(r"(?:abstract\s+)?contract\s+(\w+)|library\s+(\w+)", stripped)
            if contract_match:
                contract_name = contract_match.group(1) or contract_match.group(2)
            if _is_comment_or_empty(stripped):
                continue
            state_var = _state_variable_name(code)
            if contract_name and state_var:
                contract_state_vars[contract_name].append(state_var)
            for name in _assigned_variables(code):
                ev = _evidence(repo_path, ranges, rel, line_no, "state/accounting variable is written")
                variable_writes[name].append(ev)
            for name in _guard_variables(code):
                ev = _evidence(repo_path, ranges, rel, line_no, "variable participates in a guard or branch")
                variable_reads[name].append(ev)

            evidence = _evidence(repo_path, ranges, rel, line_no, "suspicious protocol invariant pattern")
            if _looks_like_distribution_math(code):
                candidates.append(
                    _candidate(
                        "percentage_distribution_math",
                        "Distribution math mixes percentages, looped recipients, or precision constants; verify total payout cannot exceed funds or leave unsafe residue.",
                        [evidence],
                        ["percentage", "loop", "total payout", "precision"],
                        "percentage_distribution_math",
                        0.70,
                    )
                )
            if _looks_like_upgrade_authorizer(code) and not _file_contains(lines, ("upgradeTo(", "upgradeToAndCall(")):
                candidates.append(
                    _candidate(
                        "upgrade_authorization_without_upgrade",
                        "Upgrade authorization logic exists but no explicit upgrade execution path was found in the same source file; verify upgrade lifecycle and access boundaries.",
                        [evidence],
                        ["upgrade authorization", "implementation lifecycle"],
                        "upgrade_authorization_without_upgrade",
                        0.66,
                    )
                )
            if _looks_like_unbounded_loop(code):
                candidates.append(
                    _candidate(
                        "unbounded_loop_dos",
                        "Public or external logic appears to iterate over a dynamic collection; verify gas bounds and denial-of-service resistance.",
                        [evidence],
                        ["unbounded loop", "dynamic array", "gas griefing"],
                        "unbounded_loop_dos",
                        0.62,
                    )
                )
            if _looks_like_external_balance_trust(code):
                candidates.append(
                    _candidate(
                        "external_state_accounting_trust",
                        "Accounting logic appears to trust external balance/state reads; verify reconciliation and manipulation resistance.",
                        [evidence],
                        ["external state", "accounting trust", "reconciliation"],
                        "external_state_accounting_trust",
                        0.64,
                    )
                )

    candidates.extend(_configured_but_not_enforced(variable_writes, variable_reads))
    candidates.extend(_checked_but_not_updated(variable_reads, variable_writes))
    candidates.extend(_storage_layout_candidates(contract_state_vars, files, repo_path, ranges))
    return _dedupe_candidates(candidates)[:12]


def _protocol_ir_from_static_facts(static_facts: dict) -> ProtocolIR | None:
    raw = static_facts.get("protocol_ir")
    if not raw:
        return None
    try:
        return ProtocolIR.model_validate(raw)
    except Exception:
        return None


def _protocol_graph_from_static_facts(static_facts: dict) -> ProtocolGraph | None:
    raw = static_facts.get("protocol_graph")
    if not raw:
        return None
    try:
        return ProtocolGraph.model_validate(raw)
    except Exception:
        return None


def _graph_slice_invariant_candidates(repo_path: str, graph: ProtocolGraph, ranges: list[FunctionRange]) -> list[InvariantCandidate]:
    by_id = {item.slice_id: item for item in graph.slices}
    candidates = []
    for attack_path in graph.attack_paths:
        slice_item = by_id.get(attack_path.graph_slice_id)
        if not slice_item:
            continue
        if "custody/accounting" in attack_path.invariant_family:
            invariant_type = "custody_accounting_consistency"
            terms = ["custody", "accounting", "asset flow", *[access.variable_name for access in slice_item.storage_accesses if access.access == "write"]]
            required = "Prove asset owner/custodian and accounting beneficiary cannot diverge along the graph path."
        elif "lifecycle" in attack_path.invariant_family:
            invariant_type = "lifecycle_transition_gating"
            terms = ["lifecycle", "transition", "authorization"]
            required = "Prove lifecycle transitions are authorized, monotonic, and cannot be repeated out of order."
        else:
            invariant_type = "external_call_before_accounting"
            terms = ["external call", "accounting order", "trust boundary"]
            required = "Prove external control flow cannot observe or exploit stale accounting."
        evidence = _slice_source_evidence(repo_path, ranges, slice_item)
        if not evidence:
            continue
        candidates.append(
            _candidate(
                invariant_type,
                attack_path.summary,
                evidence,
                terms,
                invariant_type,
                attack_path.confidence,
                invariant_family=attack_path.invariant_family,
                affected_state_variables=[access.variable_name for access in slice_item.storage_accesses if access.access == "write"],
                required_proof=required,
                validation_questions=[*slice_item.missing_proof, *slice_item.counterevidence],
                local_facts=[attack_path.summary, *[edge.expression for edge in slice_item.call_edges[:2]]],
                proof_status=attack_path.proof_status,
                graph_slice_ids=[slice_item.slice_id],
            )
        )
    return candidates


def _slice_source_evidence(repo_path: str, ranges: list[FunctionRange], slice_item: GraphSlice) -> list[SourceEvidence]:
    if slice_item.evidence:
        return slice_item.evidence[:6]
    evidence = []
    for item in [*slice_item.asset_flows[:2], *slice_item.storage_accesses[:2], *slice_item.call_edges[:2]]:
        evidence.append(_evidence(repo_path, ranges, item.file_path, item.line or 1, "graph slice evidence"))
    return evidence[:6]


def _graph_invariant_candidates(repo_path: str, ir: ProtocolIR, ranges: list[FunctionRange], checklist_items: list[dict]) -> list[InvariantCandidate]:
    candidates: list[InvariantCandidate] = []
    candidates.extend(_custody_accounting_candidates(repo_path, ir, ranges))
    candidates.extend(_auth_to_state_write_candidates(repo_path, ir, ranges))
    candidates.extend(_lifecycle_candidates(repo_path, ir, ranges))
    candidates.extend(_randomness_candidates(repo_path, ir, ranges))
    candidates.extend(_checklist_candidates(repo_path, ir, ranges, checklist_items))
    return candidates


def _custody_accounting_candidates(repo_path: str, ir: ProtocolIR, ranges: list[FunctionRange]) -> list[InvariantCandidate]:
    candidates = []
    for flow in ir.asset_flows:
        related_writes = [
            access
            for access in ir.storage_accesses
            if access.file_path == flow.file_path
            and access.function_name == flow.function_name
            and access.access == "write"
            and any(term in access.variable_name.lower() for term in ["deposit", "stored", "balance", "owner", "supply", "count"])
        ]
        if not related_writes:
            continue
        evidence = [_evidence(repo_path, ranges, flow.file_path, flow.line or 1, "asset custody changes in this function")]
        evidence.extend(_evidence(repo_path, ranges, item.file_path, item.line or 1, "accounting state changes in the same asset flow") for item in related_writes[:2])
        candidates.append(
            _candidate(
                "custody_accounting_consistency",
                "Asset custody and accounting state change in the same flow; verify ownership, depositor attribution, and accounting cannot diverge.",
                evidence,
                ["custody", "accounting", "asset flow"],
                "custody_accounting_consistency",
                0.74,
                invariant_family="custody/accounting consistency",
                affected_state_variables=[item.variable_name for item in related_writes],
                required_proof="Show asset owner/custodian and accounting beneficiary remain consistent across deposit/withdraw paths.",
                validation_questions=["Can a user transfer an asset into custody and assign accounting ownership to another account?"],
                local_facts=[flow.expression, *[item.expression for item in related_writes[:2]]],
            )
        )
    return candidates


def _auth_to_state_write_candidates(repo_path: str, ir: ProtocolIR, ranges: list[FunctionRange]) -> list[InvariantCandidate]:
    candidates = []
    guarded = {(auth.file_path, auth.function_name) for auth in ir.auth_constraints}
    for access in ir.storage_accesses:
        if access.access != "write" or not any(term in access.variable_name.lower() for term in ["owner", "admin", "threshold", "fee", "oracle", "game", "vault", "config"]):
            continue
        if (access.file_path, access.function_name) in guarded:
            continue
        candidates.append(
            _candidate(
                "authorization_to_state_write_consistency",
                f"`{access.variable_name}` is a sensitive/configuration state write without a detected authorization constraint in the same function.",
                [_evidence(repo_path, ranges, access.file_path, access.line or 1, "sensitive state write without local auth constraint")],
                [access.variable_name, "authorization", "state write"],
                "authorization_to_state_write_consistency",
                0.66,
                invariant_family="authorization-to-state-write consistency",
                affected_state_variables=[access.variable_name],
                required_proof="Show unauthorized callers can reach or cannot reach the sensitive state transition.",
                validation_questions=["Which auth constraint gates this write, including inherited modifiers?"],
                local_facts=[access.expression],
            )
        )
    return candidates


def _lifecycle_candidates(repo_path: str, ir: ProtocolIR, ranges: list[FunctionRange]) -> list[InvariantCandidate]:
    candidates = []
    for transition in ir.lifecycle_transitions:
        if not transition.state_variables:
            continue
        has_guard = any(auth.file_path == transition.file_path and auth.function_name == transition.function_name for auth in ir.auth_constraints)
        if has_guard:
            continue
        candidates.append(
            _candidate(
                "lifecycle_transition_gating",
                "Lifecycle transition writes state without a detected role or transition guard; verify monotonicity and access boundaries.",
                [_evidence(repo_path, ranges, transition.file_path, transition.line or 1, "lifecycle transition state write")],
                ["lifecycle", "transition", *transition.state_variables],
                "lifecycle_transition_gating",
                0.62,
                invariant_family="lifecycle monotonicity and transition gating",
                affected_state_variables=transition.state_variables,
                required_proof="Show state transitions cannot be skipped, repeated unsafely, or executed by unauthorized users.",
                validation_questions=["Can the transition be repeated or called out of order?"],
                local_facts=[transition.expression],
            )
        )
    return candidates


def _randomness_candidates(repo_path: str, ir: ProtocolIR, ranges: list[FunctionRange]) -> list[InvariantCandidate]:
    candidates = []
    entropy_terms = ("block.timestamp", "block.prevrandao", "blockhash", "block.number")
    for boundary in ir.trust_boundaries:
        expression = boundary.expression.lower()
        if not any(term in expression for term in entropy_terms):
            continue
        if not any(flow.file_path == boundary.file_path and flow.function_name == boundary.function_name for flow in ir.asset_flows):
            continue
        candidates.append(
            _candidate(
                "randomness_unpredictability",
                "Reward/game outcome appears to combine predictable chain or caller inputs with an asset/reward effect.",
                [_evidence(repo_path, ranges, boundary.file_path, boundary.line or 1, "predictable entropy used near reward/asset effect")],
                ["weak randomness", "predictable entropy", "reward"],
                "randomness_unpredictability",
                0.76,
                invariant_family="randomness unpredictability for rewards/games",
                required_proof="Show attacker/miner/caller influence over entropy can bias reward outcome.",
                validation_questions=["Can caller timing or repeated calls improve winning probability beyond intended odds?"],
                local_facts=[boundary.expression],
            )
        )
    return candidates


def _checklist_candidates(repo_path: str, ir: ProtocolIR, ranges: list[FunctionRange], checklist_items: list[dict]) -> list[InvariantCandidate]:
    candidates = []
    for item in checklist_items[:10]:
        required = [str(value).lower() for value in item.get("required_local_evidence", [])]
        if not required:
            continue
        evidence = _evidence_for_checklist(repo_path, ir, ranges, required)
        if not evidence:
            continue
        candidates.append(
            _candidate(
                f"rag_checklist_{item.get('vulnerability_class') or 'review'}",
                f"Historical checklist pattern: {item.get('historical_pattern')}",
                evidence[:3],
                required,
                "rag_checklist_validation",
                0.58,
                invariant_family="RAG-guided historical checklist",
                required_proof="Tie historical pattern back to local Protocol IR evidence before promotion.",
                validation_questions=[str(value) for value in item.get("validation_questions", [])],
                rag_checklist_refs=[str(item.get("checklist_id"))],
                local_facts=[item.get("historical_pattern", "")],
            )
        )
    return candidates


def _evidence_for_checklist(repo_path: str, ir: ProtocolIR, ranges: list[FunctionRange], required: list[str]) -> list[SourceEvidence]:
    evidence = []
    haystacks = [
        *[(flow.file_path, flow.line or 1, f"asset flow token transfer custody {flow.expression}") for flow in ir.asset_flows],
        *[
            (
                access.file_path,
                access.line or 1,
                f"storage accounting {'write' if access.access == 'write' else 'read'} {access.variable_name} {access.expression}",
            )
            for access in ir.storage_accesses
        ],
        *[(auth.file_path, auth.line or 1, f"authorization local evidence {auth.expression}") for auth in ir.auth_constraints],
        *[(transition.file_path, transition.line or 1, f"lifecycle transition {transition.expression}") for transition in ir.lifecycle_transitions],
    ]
    for file_path, line, expression in haystacks:
        lower = expression.lower()
        if any(any(term in lower for term in group.split()) for group in required):
            evidence.append(_evidence(repo_path, ranges, file_path, line, "local evidence satisfies RAG checklist requirement"))
    return evidence[:4]


def _production_solidity_files(repo_path: str) -> list[Path]:
    root = Path(repo_path)
    return [
        path
        for path in root.rglob("*.sol")
        if path.is_file()
        and "out" not in path.parts
        and "cache" not in path.parts
        and classify_source_path(_relative(repo_path, path)) == "production"
    ]


def _relative(repo_path: str, path: Path) -> str:
    try:
        return str(path.relative_to(Path(repo_path))).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def _all_fact_texts(static_facts: dict) -> list[str]:
    texts: list[str] = []
    for facts in static_facts.values():
        if not isinstance(facts, list):
            continue
        for fact in facts:
            if isinstance(fact, dict):
                texts.append(" ".join(str(value) for value in fact.values() if isinstance(value, (str, int, float))))
    return texts


def _source_line(repo_path: str, relative_path: str, line_no: int) -> str:
    path = Path(repo_path) / relative_path
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return lines[line_no - 1].strip() if 1 <= line_no <= len(lines) else ""


def _strip_inline_comment(line: str) -> str:
    return line.split("//", 1)[0].strip()


def _is_comment_or_empty(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith(("//", "/*", "*", "*/"))


def _evidence(repo_path: str, ranges: list[FunctionRange], relative_path: str, line_no: int, reason: str) -> SourceEvidence:
    fn = containing_function(ranges, relative_path, line_no)
    return SourceEvidence(
        file_path=relative_path,
        line_start=line_no,
        line_end=line_no,
        contract_name=fn.contract_name if fn else None,
        function_name=fn.function_name if fn else None,
        source_text=_source_line(repo_path, relative_path, line_no),
        reason=reason,
    )


def _candidate(
    invariant_type: str,
    description: str,
    evidence: list[SourceEvidence],
    suspicious_terms: list[str],
    template: str,
    confidence: float,
    invariant_family: str | None = None,
    affected_state_variables: list[str] | None = None,
    required_proof: str | None = None,
    proof_status: str = "setup_required",
    graph_slice_ids: list[str] | None = None,
    validation_questions: list[str] | None = None,
    detector_ids: list[str] | None = None,
    rag_checklist_refs: list[str] | None = None,
    local_facts: list[str] | None = None,
) -> InvariantCandidate:
    return InvariantCandidate(
        id=f"inv-{invariant_type}-{evidence[0].file_path.replace('/', '-')}-{evidence[0].line_start}",
        invariant_type=invariant_type,
        invariant_family=invariant_family or invariant_type,
        description=description,
        affected_contracts=sorted({item.contract_name for item in evidence if item.contract_name}),
        affected_functions=sorted({item.function_name for item in evidence if item.function_name}),
        affected_state_variables=affected_state_variables or [],
        production_evidence=evidence,
        missing_guard_terms=[],
        suspicious_terms=suspicious_terms,
        local_facts=[fact for fact in (local_facts or []) if fact],
        required_proof=required_proof,
        proof_status=proof_status,
        graph_slice_ids=graph_slice_ids or [],
        validation_questions=validation_questions or [],
        detector_ids=detector_ids or [],
        rag_checklist_refs=rag_checklist_refs or [],
        recommended_validation_template=template,
        confidence=confidence,
    )


def _state_variable_name(line: str) -> str | None:
    if "(" in line or line.startswith(("function ", "constructor", "if ", "for ", "while ", "return ")):
        return None
    match = re.match(r"(?:mapping\s*\([^;]+\)|[\w\[\]]+)\s+(?:public|private|internal|external)?\s*(\w+)\s*(?:=|;)", line)
    return match.group(1) if match else None


def _assigned_variables(line: str) -> list[str]:
    if "==" in line or "!=" in line or "<=" in line or ">=" in line:
        line = re.sub(r"==|!=|<=|>=", " ", line)
    names = []
    for match in re.finditer(r"\b([A-Za-z_]\w*)\s*(?:=|\+=|-=|\*=|/=|\+\+|--)", line):
        name = match.group(1)
        if name not in {"return", "if", "for", "while", "require", "assert"}:
            names.append(name)
    return names


def _guard_variables(line: str) -> list[str]:
    if not re.search(r"\b(require|assert|if)\s*\(", line):
        return []
    return [
        name
        for name in re.findall(r"\b[A-Za-z_]\w*\b", line)
        if name not in {"require", "assert", "if", "msg", "sender", "block", "timestamp", "true", "false"}
    ]


def _looks_like_distribution_math(line: str) -> bool:
    lower = line.lower()
    return (
        any(term in lower for term in ["percentage", "percent", "precision", "basis", "bps", "wage", "share", "bursary", "reward", "payout", "transfer"])
        and any(op in line for op in ["*", "/", "%"])
    ) or bool(re.search(r"\bfor\s*\(.+\)\s*{?", line) and any(term in lower for term in ["transfer", "pay", "reward", "bursary"]))


def _looks_like_upgrade_authorizer(line: str) -> bool:
    return "_authorizeupgrade" in line.lower()


def _file_contains(lines: list[str], needles: tuple[str, ...]) -> bool:
    haystack = "\n".join(lines)
    return any(needle in haystack for needle in needles)


def _looks_like_unbounded_loop(line: str) -> bool:
    lower = line.lower()
    return bool(re.search(r"\bfor\s*\(", lower) and any(term in lower for term in [".length", "list", "array", "students", "teachers", "users"]))


def _looks_like_external_balance_trust(line: str) -> bool:
    lower = line.lower()
    return any(term in lower for term in [".balanceof(", ".balance", "totalassets(", "latestanswer("]) and any(
        term in lower for term in ACCOUNTING_TERMS
    )


def _configured_but_not_enforced(
    variable_writes: dict[str, list[SourceEvidence]],
    variable_reads: dict[str, list[SourceEvidence]],
) -> list[InvariantCandidate]:
    candidates = []
    config_terms = ("limit", "cap", "threshold", "cutoff", "cut_off", "fee", "max", "min", "score")
    for name, writes in variable_writes.items():
        lower = name.lower()
        if not any(term in lower for term in config_terms):
            continue
        if variable_reads.get(name):
            continue
        candidates.append(
            _candidate(
                "configured_but_not_enforced",
                f"`{name}` is written as a configuration/accounting variable, but no guard using it was found in production sources.",
                writes[:2],
                [name, "configured but not enforced", "missing guard"],
                "configured_but_not_enforced",
                0.72,
            )
        )
    return candidates


def _checked_but_not_updated(
    variable_reads: dict[str, list[SourceEvidence]],
    variable_writes: dict[str, list[SourceEvidence]],
) -> list[InvariantCandidate]:
    candidates = []
    for name, reads in variable_reads.items():
        lower = name.lower()
        if not any(term in lower for term in ["count", "nonce", "review", "epoch", "round", "attempt"]):
            continue
        if variable_writes.get(name):
            continue
        candidates.append(
            _candidate(
                "checked_but_never_updated",
                f"`{name}` is checked in guard logic, but no production write/update was found.",
                reads[:2],
                [name, "checked but not updated", "stale guard"],
                "checked_but_never_updated",
                0.68,
            )
        )
    return candidates


def _storage_layout_candidates(
    contract_state_vars: dict[str, list[str]],
    files: list[Path],
    repo_path: str,
    ranges: list[FunctionRange],
) -> list[InvariantCandidate]:
    names = sorted(contract_state_vars)
    candidates = []
    for left in names:
        for right in names:
            if left >= right:
                continue
            common_prefix = _common_alpha_prefix(left.lower(), right.lower())
            if len(common_prefix) < 4 and not any(term in (left + right).lower() for term in ["level", "v1", "v2", "upgrade"]):
                continue
            if contract_state_vars[left] == contract_state_vars[right]:
                continue
            evidence = _contract_evidence(files, repo_path, ranges, left) + _contract_evidence(files, repo_path, ranges, right)
            if not evidence:
                continue
            candidates.append(
                _candidate(
                    "storage_layout_mismatch",
                    f"`{left}` and `{right}` look related but have different state-variable ordering; verify upgrade/storage-layout compatibility.",
                    evidence[:2],
                    ["storage layout", "upgrade compatibility", left, right],
                    "storage_layout_mismatch",
                    0.60,
                )
            )
    return candidates


def _common_alpha_prefix(left: str, right: str) -> str:
    chars = []
    for l_char, r_char in zip(left, right):
        if l_char != r_char or not l_char.isalpha():
            break
        chars.append(l_char)
    return "".join(chars)


def _contract_evidence(files: list[Path], repo_path: str, ranges: list[FunctionRange], contract_name: str) -> list[SourceEvidence]:
    evidence = []
    pattern = re.compile(rf"\bcontract\s+{re.escape(contract_name)}\b")
    for path in files:
        rel = _relative(repo_path, path)
        for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            if pattern.search(line):
                evidence.append(_evidence(repo_path, ranges, rel, line_no, "related contract declaration for storage-layout review"))
                return evidence
    return evidence


def _dedupe_candidates(candidates: list[InvariantCandidate]) -> list[InvariantCandidate]:
    deduped = []
    seen = set()
    for candidate in sorted(candidates, key=lambda item: item.confidence, reverse=True):
        key = (
            candidate.invariant_type,
            tuple((item.file_path, item.line_start, item.source_text) for item in candidate.production_evidence),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)
    return deduped
