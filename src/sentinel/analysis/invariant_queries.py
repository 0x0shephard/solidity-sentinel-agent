from __future__ import annotations

from collections import defaultdict

from sentinel.schemas.invariants import InvariantCandidate
from sentinel.schemas.protocol_ir import (
    AssetCompatibilityPath,
    CheckpointLookupIR,
    DocumentationClaim,
    FeeFormulaIR,
    LoopIR,
    ProtocolIR,
    StatementIR,
)
from sentinel.schemas.static import SourceEvidence


def semantic_invariant_candidates(repo_path: str, ir: ProtocolIR) -> list[InvariantCandidate]:
    candidates: list[InvariantCandidate] = []
    candidates.extend(query_signature_uniqueness_threshold(ir))
    candidates.extend(query_checkpoint_boundary_mismatch(ir))
    candidates.extend(query_multi_report_fee_accrual(ir))
    candidates.extend(query_fee_formula_dimension_mismatch(ir))
    candidates.extend(query_pending_redeem_fee_base_exclusion(ir))
    candidates.extend(query_boolean_policy_inversion(ir))
    candidates.extend(query_native_asset_receive_mismatch(ir))
    candidates.extend(query_indexed_structure_key_mismatch(ir))
    candidates.extend(query_lockup_transfer_bypass(ir))
    return _dedupe(candidates)


def query_signature_uniqueness_threshold(ir: ProtocolIR) -> list[InvariantCandidate]:
    candidates: list[InvariantCandidate] = []
    statements_by_function = _statements_by_function(ir)
    loops_by_function = _loops_by_function(ir)
    for key, statements in statements_by_function.items():
        haystack = " ".join(statement.source_text for statement in statements).lower()
        if "signature" not in haystack or "threshold" not in haystack:
            continue
        threshold = [statement for statement in statements if "threshold" in statement.source_text.lower() and ".length" in statement.source_text.lower()]
        signer_reads = [statement for statement in statements if "signer" in statement.source_text.lower()]
        uniqueness_terms = ("seen", "used", "unique", "duplicate", "visited", "already", "mapping")
        has_uniqueness = any(term in haystack for term in uniqueness_terms)
        loop = next((item for item in loops_by_function.get(key, []) if "signature" in " ".join(item.body_terms).lower()), None)
        if not threshold or not signer_reads or has_uniqueness:
            continue
        evidence = [_ev_from_statement(threshold[0], "threshold is checked against signature array length")]
        evidence.extend(_ev_from_statement(item, "signer is accepted without detected uniqueness tracking") for item in signer_reads[:3])
        if loop:
            evidence.append(loop.evidence[0])
        candidates.append(
            _candidate(
                "signature_threshold_uniqueness",
                "Signature threshold is based on the signature array length, but the semantic scan did not find per-signer uniqueness tracking.",
                evidence,
                ["signature threshold", "duplicate signer", "uniqueness", "array length"],
                "signature_uniqueness_threshold",
                0.86,
                affected_state_variables=["threshold", "signers"],
                required_proof="Show the same valid signer/signature can appear more than once and satisfy the threshold.",
                proof_status="strong_local_path",
                validation_questions=["Does the loop insert recovered/declared signers into a seen set before accepting the next signature?"],
            )
        )
    return candidates


def query_checkpoint_boundary_mismatch(ir: ProtocolIR) -> list[InvariantCandidate]:
    candidates: list[InvariantCandidate] = []
    by_contract: dict[tuple[str, str | None], list[CheckpointLookupIR]] = defaultdict(list)
    for lookup in ir.checkpoint_lookups:
        by_contract[(lookup.file_path, lookup.contract_name)].append(lookup)
    for (_file_path, _contract), lookups in by_contract.items():
        lower = [item for item in lookups if item.boundary_direction == "lower"]
        upper_or_latest = [item for item in lookups if item.boundary_direction in {"upper", "latest"}]
        decrements = [item for item in lookups if item.index_adjustment == "decrement"]
        functions = {item.function_name for item in [*lower, *upper_or_latest, *decrements] if item.function_name}
        if not lower or not upper_or_latest or len(functions) < 2:
            continue
        evidence = [*(item.evidence[0] for item in lower[:2]), *(item.evidence[0] for item in upper_or_latest[:3])]
        evidence.extend(item.evidence[0] for item in decrements[:2])
        candidates.append(
            _candidate(
                "checkpoint_boundary_mismatch",
                "Checkpoint eligibility uses different lower/upper/latest boundary semantics across related functions; verify batch creation and claim eligibility agree.",
                evidence,
                ["checkpoint", "lowerLookup", "upperLookupRecent", "boundary", "batch", "claim eligibility"],
                "checkpoint_boundary_mismatch",
                0.84,
                required_proof="Show the same timestamp/index can be included by one path and excluded by the paired accounting path.",
                proof_status="strong_local_path",
                validation_questions=["Do claim and batch/report paths use the same inclusive/exclusive timestamp boundary?"],
            )
        )
    return candidates


def query_multi_report_fee_accrual(ir: ProtocolIR) -> list[InvariantCandidate]:
    candidates: list[InvariantCandidate] = []
    report_loops = [
        loop for loop in ir.loops if any(term.lower().startswith("report") for term in loop.body_terms) and any(term in loop.body_terms for term in ["handleReport", "submitReports"])
    ]
    fee_functions = [
        formula for formula in ir.fee_formulas if formula.function_name and any(term.lower().startswith(("performancefee", "protocolfee", "managementfee")) for term in formula.unit_terms)
    ]
    if not report_loops or not fee_functions:
        return candidates
    evidence = [loop.evidence[0] for loop in report_loops[:2]]
    evidence.extend(formula.evidence[0] for formula in fee_functions[:3])
    candidates.append(
        _candidate(
            "multi_report_fee_accrual",
            "A loop processes multiple reports while fee formulas update share/accounting state; verify fees are not accrued once per report when they should accrue once per aggregate period.",
            evidence,
            ["report loop", "fee accrual", "handleReport", "performance fee", "protocol fee"],
            "multi_report_fee_accrual",
            0.78,
            required_proof="Show repeated report processing can compound or duplicate fee accrual against the same accounting base.",
            validation_questions=["Is fee state updated inside every report iteration instead of once for the aggregate report period?"],
        )
    )
    return candidates


def query_fee_formula_dimension_mismatch(ir: ProtocolIR) -> list[InvariantCandidate]:
    candidates: list[InvariantCandidate] = []
    for formula in ir.fee_formulas:
        units = " ".join([*formula.unit_terms, formula.expression]).lower()
        has_price = "price" in units or "d18" in units
        has_fee_d6 = "feed6" in units or "d6" in units
        has_shares = "share" in units or "totalshares" in units
        suspicious_denominator = formula.denominator and formula.denominator.strip() in {"1e24", "1e18", "1e6"}
        if not (has_price and has_fee_d6 and has_shares and suspicious_denominator):
            continue
        candidates.append(
            _candidate(
                "fee_formula_dimension_mismatch",
                "Fee formula combines price delta, D6 fee precision, and share supply terms; verify dimensional scaling and sign match intended assets/shares accounting.",
                formula.evidence,
                ["fee formula", "D6", "D18", "shares", "dimension mismatch"],
                "fee_formula_dimension_mismatch",
                0.82,
                affected_state_variables=formula.state_dependencies,
                required_proof="Show the formula output is denominated in the intended unit and cannot over/under-mint fees.",
                proof_status="strong_local_path",
                validation_questions=["Should the formula multiply by total shares, total assets, or a price-normalized ratio?"],
            )
        )
    return candidates


def query_pending_redeem_fee_base_exclusion(ir: ProtocolIR) -> list[InvariantCandidate]:
    candidates: list[InvariantCandidate] = []
    statements = ir.statements
    burn_or_redeem = [item for item in statements if any(term in item.source_text.lower() for term in ["burn", "redeem", "pending"])]
    fee_state = [item for item in statements if "fee" in item.source_text.lower() and any(term in item.source_text.lower() for term in ["totalshares", "shares", "assets"])]
    if not burn_or_redeem or not fee_state:
        return candidates
    files = {item.file_path for item in burn_or_redeem}.intersection(item.file_path for item in fee_state)
    if not files:
        return candidates
    evidence = [_ev_from_statement(item, "redeem/burn/pending-share path affects the fee base") for item in burn_or_redeem[:3]]
    evidence.extend(_ev_from_statement(item, "fee formula depends on shares/assets accounting base") for item in fee_state[:3])
    candidates.append(
        _candidate(
            "pending_redeem_fee_base_exclusion",
            "Redeem/burn paths and fee formulas share a local accounting base; verify pending redemptions cannot avoid management/performance fees.",
            evidence,
            ["pending redeem", "burn", "fee base", "total shares"],
            "pending_redeem_fee_base_exclusion",
            0.66,
            required_proof="Show shares removed from supply still keep assets in a fee-accruing pending state, or prove the opposite.",
            validation_questions=["Are pending redeemed assets still charged fees after shares are burned?"],
        )
    )
    return candidates


def query_boolean_policy_inversion(ir: ProtocolIR) -> list[InvariantCandidate]:
    candidates: list[InvariantCandidate] = []
    docs = [claim for claim in ir.documentation_claims if any(term in claim.claim_text.lower() for term in ["transfer", "allowed", "can", "whitelist", "permission"])]
    for statement in ir.statements:
        text = statement.source_text.replace(" ", "")
        lower = text.lower()
        if "cantransfer" not in lower and "whitelist" not in lower and "allowed" not in lower:
            continue
        if "||!" not in lower and "&&!" not in lower and "revert" not in lower:
            continue
        matching_doc = next((doc for doc in docs if doc.file_path == statement.file_path), None)
        evidence = [_ev_from_statement(statement, "boolean policy guard may be inverted or bypassable")]
        if matching_doc:
            evidence.append(matching_doc.evidence[0])
        candidates.append(
            _candidate(
                "boolean_policy_inversion",
                "Boolean allow/whitelist policy uses a guard shape that may invert the documented or intended permission semantics.",
                evidence,
                ["boolean guard", "whitelist", "canTransfer", "policy inversion"],
                "boolean_policy_inversion",
                0.80 if matching_doc else 0.70,
                required_proof="Compare the documented policy to the concrete revert/allow condition on both sender and receiver.",
                proof_status="strong_local_path" if matching_doc else "setup_required",
                validation_questions=["Does the guard revert when the account is allowed or allow when one side is disallowed?"],
            )
        )
    return candidates


def query_native_asset_receive_mismatch(ir: ProtocolIR) -> list[InvariantCandidate]:
    candidates: list[InvariantCandidate] = []
    for path in ir.asset_compatibility_paths:
        if path.asset_kind != "native":
            continue
        if not path.receiver_contract:
            continue
        if path.receiver_has_receive is True or path.receiver_has_fallback is True:
            continue
        candidates.append(
            _candidate(
                "native_asset_receive_mismatch",
                "Native asset transfer path targets a receiver where semantic extraction did not find a receive/fallback handler.",
                path.evidence,
                ["native asset", "receive", "fallback", "transfer path"],
                "native_asset_receive_mismatch",
                0.72,
                required_proof="Show the receiver can be sent native ETH on this path and lacks receive/fallback compatibility.",
                validation_questions=["Does this contract ever configure the native asset while the receiver rejects ETH?"],
            )
        )
    return candidates


def query_indexed_structure_key_mismatch(ir: ProtocolIR) -> list[InvariantCandidate]:
    candidates: list[InvariantCandidate] = []
    for statement in ir.statements:
        text = statement.source_text
        lower = text.lower()
        if not any(term in lower for term in ["fenwick", "tree", "index", "lookup"]):
            continue
        if not any(op in text for op in ["-", "+", "--", "++"]):
            continue
        candidates.append(
            _candidate(
                "indexed_structure_key_mismatch",
                "Indexed lookup/tree logic adjusts indexes around a mutating operation; verify key/index bases are consistent.",
                [_ev_from_statement(statement, "indexed structure or lookup adjustment")],
                ["indexed structure", "lookup", "off-by-one", "tree"],
                "indexed_structure_key_mismatch",
                0.64,
                required_proof="Show the same key/index basis is used for insert, lookup, cancel, and claim paths.",
                validation_questions=["Does cancellation use request timestamp/index or the request insertion position consistently?"],
            )
        )
    return candidates


def query_lockup_transfer_bypass(ir: ProtocolIR) -> list[InvariantCandidate]:
    candidates: list[InvariantCandidate] = []
    lockup_statements = [item for item in ir.statements if any(term in item.source_text.lower() for term in ["lockup", "locked", "lock_until", "lockuntil"])]
    transfer_statements = [item for item in ir.statements if any(term in item.source_text.lower() for term in ["transfer", "mint", "burn"])]
    if not lockup_statements or not transfer_statements:
        return candidates
    same_files = {item.file_path for item in lockup_statements}.intersection(item.file_path for item in transfer_statements)
    if not same_files:
        return candidates
    evidence = [_ev_from_statement(item, "lockup state or guard") for item in lockup_statements[:3]]
    evidence.extend(_ev_from_statement(item, "share transfer/mint/burn path interacts with lockup policy") for item in transfer_statements[:3])
    candidates.append(
        _candidate(
            "lockup_transfer_bypass",
            "Lockup state and share transfer/mint/burn paths coexist; verify transfer/mint flows cannot bypass intended lockup enforcement.",
            evidence,
            ["lockup", "transfer", "mint", "share", "bypass"],
            "lockup_transfer_bypass",
            0.62,
            required_proof="Trace minted/transferred shares from creation to receiver and prove lockup constraints follow the shares.",
            validation_questions=["Can a user mint and transfer shares to bypass their own lockup?"],
        )
    )
    return candidates


def _statements_by_function(ir: ProtocolIR) -> dict[tuple[str, str | None, str | None], list[StatementIR]]:
    grouped: dict[tuple[str, str | None, str | None], list[StatementIR]] = defaultdict(list)
    for statement in ir.statements:
        grouped[(statement.file_path, statement.contract_name, statement.function_name)].append(statement)
    return grouped


def _loops_by_function(ir: ProtocolIR) -> dict[tuple[str, str | None, str | None], list[LoopIR]]:
    grouped: dict[tuple[str, str | None, str | None], list[LoopIR]] = defaultdict(list)
    for loop in ir.loops:
        grouped[(loop.file_path, loop.contract_name, loop.function_name)].append(loop)
    return grouped


def _ev_from_statement(statement: StatementIR, reason: str) -> SourceEvidence:
    return SourceEvidence(
        file_path=statement.file_path,
        line_start=statement.line_start,
        line_end=statement.line_end,
        contract_name=statement.contract_name,
        function_name=statement.function_name,
        source_text=statement.source_text,
        reason=reason,
    )


def _candidate(
    invariant_type: str,
    description: str,
    evidence: list[SourceEvidence],
    suspicious_terms: list[str],
    template: str,
    confidence: float,
    affected_state_variables: list[str] | None = None,
    required_proof: str | None = None,
    proof_status: str = "setup_required",
    validation_questions: list[str] | None = None,
) -> InvariantCandidate:
    evidence = _dedupe_evidence(evidence)
    candidate_id = f"semantic-{invariant_type}-{evidence[0].file_path.replace('/', '-')}-{evidence[0].line_start}"
    return InvariantCandidate(
        id=candidate_id,
        invariant_type=invariant_type,
        invariant_family="semantic protocol invariant",
        description=description,
        affected_contracts=sorted({item.contract_name for item in evidence if item.contract_name}),
        affected_functions=sorted({item.function_name for item in evidence if item.function_name}),
        affected_state_variables=affected_state_variables or [],
        production_evidence=evidence,
        suspicious_terms=list(dict.fromkeys(suspicious_terms)),
        local_facts=[item.source_text for item in evidence[:6]],
        required_proof=required_proof,
        proof_status=proof_status,
        proof_packet_id=f"proof-{candidate_id}",
        validation_questions=validation_questions or [],
        detector_ids=[f"semantic.{invariant_type}"],
        recommended_validation_template=template,
        confidence=confidence,
    )


def _dedupe_evidence(evidence: list[SourceEvidence]) -> list[SourceEvidence]:
    deduped: list[SourceEvidence] = []
    seen = set()
    for item in evidence:
        key = (item.file_path, item.line_start, item.source_text)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped[:8]


def _dedupe(candidates: list[InvariantCandidate]) -> list[InvariantCandidate]:
    deduped: list[InvariantCandidate] = []
    seen = set()
    for candidate in sorted(candidates, key=lambda item: item.confidence, reverse=True):
        key = (
            candidate.invariant_type,
            tuple((item.file_path, item.line_start, item.source_text) for item in candidate.production_evidence[:4]),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)
    return deduped
