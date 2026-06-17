from __future__ import annotations

from pathlib import Path
import re

from pydantic import BaseModel, Field

from sentinel.artifacts import append_jsonl
from sentinel.config import get_settings
from sentinel.evidence import classify_source_path
from sentinel.rag.canonical import build_canonical_query_text
from sentinel.rag.checklist import build_solodit_checklists_from_cache, write_generated_checklists
from sentinel.rag.ranking import rank_matches
from sentinel.rag.store import HistoricalFindingStore
from sentinel.rag.sync import sync_solodit
from sentinel.rag.targeted import build_repo_rag_profile, build_targeted_rag, repo_profile_root
from sentinel.schemas.common import SideEffect, ToolStatus
from sentinel.schemas.invariants import GapFindingCandidate, InvariantCandidate
from sentinel.schemas.rag import (
    HistoricalFindingMatch,
    HistoricalFindingQuery,
    HistoricalFindingSearchOutput,
    HistoricalMatchCritique,
    RAGContextBundle,
    RAGQuery,
    RagSyncOutput,
    RepoRAGProfile,
    RetrievalQualityGrade,
    TargetedRAGState,
)
from sentinel.schemas.research import VulnerabilityHypothesis
from sentinel.schemas.static import SourceEvidence, StaticDetection
from sentinel.tools.base import RegisteredTool


class RankHypothesesInput(BaseModel):
    objective: str
    static_facts: list[dict] = Field(default_factory=list)


class RankHypothesesOutput(BaseModel):
    status: ToolStatus
    hypotheses: list[VulnerabilityHypothesis]


class ProposeHypothesesInput(BaseModel):
    repo_path: str
    objective: str = ""
    max_hypotheses: int = Field(default=8, ge=1, le=20)


class ProposeHypothesesOutput(BaseModel):
    status: ToolStatus
    hypotheses: list[VulnerabilityHypothesis] = Field(default_factory=list)
    proposed_count: int = 0
    grounded_count: int = 0
    dropped_count: int = 0
    notes: list[str] = Field(default_factory=list)
    raw_preview: str | None = None
    dropped_proposals: list[dict] = Field(default_factory=list)


class ResearchNoteInput(BaseModel):
    topic: str


class ResearchNoteOutput(BaseModel):
    status: ToolStatus
    notes: list[str]


class ResearchGenericInput(BaseModel):
    data: dict = Field(default_factory=dict)


class ResearchGenericOutput(BaseModel):
    status: ToolStatus
    message: str | None = None
    data: dict = Field(default_factory=dict)


class RepoRAGProfileInput(BaseModel):
    repo_path: str
    static_facts: dict = Field(default_factory=dict)


class RepoRAGProfileOutput(BaseModel):
    status: ToolStatus
    profile: RepoRAGProfile


class TargetedRAGInput(BaseModel):
    repo_path: str
    static_facts: dict = Field(default_factory=dict)


class TargetedRAGOutput(BaseModel):
    status: ToolStatus
    state: TargetedRAGState


class RAGQueriesInput(BaseModel):
    hypothesis: VulnerabilityHypothesis
    objective: str = ""


class RAGQueriesOutput(BaseModel):
    status: ToolStatus
    queries: list[RAGQuery] = Field(default_factory=list)


class MultiQueryRetrievalInput(BaseModel):
    queries: list[RAGQuery]


class MultiQueryRetrievalOutput(BaseModel):
    status: ToolStatus
    matches_by_query: dict[str, list[HistoricalFindingMatch]] = Field(default_factory=dict)


class MergeRAGResultsInput(BaseModel):
    matches_by_query: dict[str, list[HistoricalFindingMatch]] = Field(default_factory=dict)


class MergeRAGResultsOutput(BaseModel):
    status: ToolStatus
    matches: list[HistoricalFindingMatch] = Field(default_factory=list)


class RetrievalGradeInput(BaseModel):
    hypothesis: VulnerabilityHypothesis
    matches: list[HistoricalFindingMatch] = Field(default_factory=list)


class RetrievalGradeOutput(BaseModel):
    status: ToolStatus
    grade: RetrievalQualityGrade


class RepairRAGQueryInput(BaseModel):
    hypothesis: VulnerabilityHypothesis
    grade: RetrievalQualityGrade


class CritiqueHistoricalMatchesInput(BaseModel):
    hypothesis: VulnerabilityHypothesis
    matches: list[HistoricalFindingMatch] = Field(default_factory=list)


class CritiqueHistoricalMatchesOutput(BaseModel):
    status: ToolStatus
    critiques: list[HistoricalMatchCritique] = Field(default_factory=list)


class BuildRAGContextBundleInput(BaseModel):
    hypothesis: VulnerabilityHypothesis
    queries: list[RAGQuery] = Field(default_factory=list)
    matches: list[HistoricalFindingMatch] = Field(default_factory=list)
    grade: RetrievalQualityGrade | None = None
    critiques: list[HistoricalMatchCritique] = Field(default_factory=list)
    used_repair: bool = False


SENSITIVE_FUNCTION_TERMS = ("emergency", "withdraw", "sweep", "drain", "claim", "redeem", "pay", "send")
SLITHER_CLASS_MAP = {
    "reentrancy": "reentrancy",
    "reentrancy-benign": "reentrancy",
    "reentrancy-eth": "reentrancy",
    "reentrancy-no-eth": "reentrancy",
    "reentrancy-unlimited-gas": "reentrancy",
    "unchecked-lowlevel": "unchecked_transfer",
    "unchecked-send": "unchecked_transfer",
    "unchecked-transfer": "unchecked_transfer",
    "arbitrary-send": "missing_access_control",
    "arbitrary-send-erc20": "missing_access_control",
    "arbitrary-send-erc20-permit": "missing_access_control",
    "suicidal": "missing_access_control",
}


def _facts_with_key(facts: list[dict], key: str) -> list[dict]:
    return [fact for fact in facts if fact.get(key)]


def _facts_containing(facts: list[dict], terms: tuple[str, ...]) -> list[dict]:
    return [fact for fact in facts if any(term in fact.get("text", "") for term in terms)]


def _is_target_source_path(path: str | None) -> bool:
    return classify_source_path(path) in {"production", "unknown"}


def _has_target_source(paths: list[str]) -> bool:
    return any(_is_target_source_path(path) for path in paths)


def _sensitive_function_for_file(functions: list[dict], file_path: str) -> dict | None:
    candidates = [fact for fact in functions if fact.get("file_path") == file_path]
    for fact in candidates:
        function_name = str(fact.get("function", "")).lower()
        if any(term in function_name for term in SENSITIVE_FUNCTION_TERMS):
            return fact
    return candidates[0] if candidates else None


def _has_authorization_guard(access_facts: list[dict]) -> bool:
    access_text = " ".join(fact.get("text", "") for fact in access_facts).replace(" ", "").lower()
    return any(term in access_text for term in ["onlyowner", "hasrole", "onlyrole", "msg.sender==owner", "_checkowner"])


def _is_unchecked_token_transfer(fact: dict) -> bool:
    text = fact.get("text", "")
    compact = text.replace(" ", "")
    lower = text.lower()
    if "safetransfer" in lower or "require(" in compact or "assert(" in compact:
        return False
    if ".transfer(" not in text and ".transferFrom(" not in text:
        return False
    if compact.startswith("to.transfer(") or "address(this).balance" in compact:
        return False
    return True


def _token_type_map_from_facts(facts: list[dict]) -> dict[str, str]:
    token_types: dict[str, str] = {}
    for fact in facts:
        if fact.get("source") not in {"contract", "state_variable"}:
            continue
        symbol = str(fact.get("symbol") or "")
        kind = str(fact.get("kind") or "")
        if symbol and kind:
            token_types[symbol] = kind
    return token_types


def _transfer_receiver(text: str) -> str | None:
    match = re.search(r"\b([A-Za-z_]\w*)\s*\.\s*(?:transfer|transferFrom)\s*\(", text)
    return match.group(1) if match else None


def _slither_confidence_score(finding: dict) -> float:
    impact = str(finding.get("impact") or "").lower()
    confidence = str(finding.get("confidence") or "").lower()
    score = 0.6
    if impact == "high":
        score += 0.15
    elif impact == "medium":
        score += 0.08
    if confidence == "high":
        score += 0.1
    elif confidence == "medium":
        score += 0.05
    return min(score, 0.9)


def _class_from_slither_check(check: str) -> str | None:
    normalized = check.lower()
    if normalized in SLITHER_CLASS_MAP:
        return SLITHER_CLASS_MAP[normalized]
    for prefix, vulnerability_class in SLITHER_CLASS_MAP.items():
        if normalized.startswith(prefix):
            return vulnerability_class
    return None


def _validation_for_class(vulnerability_class: str, function_name: str | None = None) -> list[str]:
    target = function_name or "the affected function"
    if vulnerability_class in {"reentrancy", "external_call_before_accounting"}:
        return [f"Add a callback/reentrancy regression test around {target} and assert accounting remains invariant."]
    if vulnerability_class in {"unchecked_erc20_return", "unchecked_transfer"}:
        return [f"Use a mock ERC20 that returns false and assert {target} handles the failure."]
    if vulnerability_class in {"missing_access_control", "tx_origin_authorization"}:
        return [f"Call {target} through unauthorized direct and intermediary callers."]
    if vulnerability_class == "unguarded_initializer":
        return [f"Call {target} twice and from a non-admin account after deployment."]
    if vulnerability_class == "oracle_staleness_logic":
        return [f"Mock stale and zero oracle responses and assert {target} rejects each case independently."]
    if vulnerability_class == "dangerous_delegatecall":
        return [f"Attempt to execute a malicious delegatecall payload through {target}."]
    if vulnerability_class == "weak_randomness":
        return [f"Model attacker-controlled timing/caller inputs around {target} and verify rewards cannot be predicted or biased."]
    if vulnerability_class == "vault_accounting_spoof":
        return [f"Transfer an asset into custody, call {target} with a spoofed depositor, and assert withdrawals cannot be redirected."]
    return [f"Add a targeted regression test for {target}."]


def _hypothesis_from_detection(index: int, detection: StaticDetection) -> VulnerabilityHypothesis:
    affected_files = []
    for item in detection.evidence:
        if item.file_path not in affected_files:
            affected_files.append(item.file_path)
    affected_functions = detection.affected_functions or [
        item.function_name for item in detection.evidence if item.function_name
    ]
    affected_functions = list(dict.fromkeys(affected_functions))
    first_evidence = detection.evidence[0] if detection.evidence else None
    evidence_summary = "; ".join(
        f"{item.file_path}:{item.line_start} {item.reason}" for item in detection.evidence[:4]
    )
    return VulnerabilityHypothesis(
        id=f"hyp-{index}",
        title=detection.title,
        vulnerability_class=detection.vulnerability_class,
        affected_files=affected_files,
        affected_functions=affected_functions,
        evidence_summary=evidence_summary or detection.title,
        confidence=detection.confidence,
        affected_contract=first_evidence.contract_name if first_evidence else None,
        affected_function=affected_functions[0] if affected_functions else None,
        evidence_lines=detection.evidence,
        root_cause_terms=detection.root_cause_terms,
        recommended_validation=_validation_for_class(detection.vulnerability_class, affected_functions[0] if affected_functions else None),
        source_detection_ids=[detection.detector_id],
        proof_status="static_proof_complete" if detection.confidence >= 0.75 else "strong_local_path",
    )


def _dedupe_hypotheses(hypotheses: list[VulnerabilityHypothesis]) -> list[VulnerabilityHypothesis]:
    deduped: list[VulnerabilityHypothesis] = []
    seen: set[tuple[str, str, str, str]] = set()
    for item in sorted(hypotheses, key=_hypothesis_rank_key, reverse=True):
        file_key = item.affected_files[0] if item.affected_files else ""
        function_key = item.affected_functions[0] if item.affected_functions else item.affected_function or ""
        source_key = item.source_detection_ids[0] if item.source_detection_ids else item.proof_packet_id or ""
        invariant_key = source_key.split(":", 1)[-1].split("-", 3)[0] if source_key else item.vulnerability_class
        key = (item.vulnerability_class, invariant_key, file_key, function_key)
        if key in seen:
            continue
        seen.add(key)
        item.id = f"hyp-{len(deduped) + 1}"
        deduped.append(item)
    return deduped[:15]


def _hypothesis_rank_key(hypothesis: VulnerabilityHypothesis) -> tuple[float, float, float, float, float]:
    source_text = " ".join(hypothesis.source_detection_ids).lower()
    semantic_bonus = 1.0 if "semantic." in source_text or any(source.startswith("semantic-") for source in hypothesis.source_detection_ids) else 0.0
    detector_only_penalty = -1.0 if "configured_but_not_enforced" in source_text and not hypothesis.affected_functions else 0.0
    proof_score = {
        "static_proof_complete": 1.0,
        "strong_local_path": 0.85,
        "missing_counterevidence": 0.55,
        "setup_required": 0.35,
        "rejected_by_counterevidence": 0.0,
    }.get(hypothesis.proof_status, 0.35)
    evidence_score = min(len(hypothesis.evidence_lines), 6) / 6
    cross_function_score = min(len(set(hypothesis.affected_functions)), 3) / 3
    return (semantic_bonus + detector_only_penalty, proof_score, evidence_score, cross_function_score, hypothesis.confidence)


def _evidence_from_fact(fact: dict, reason: str) -> SourceEvidence | None:
    line = fact.get("line") or fact.get("line_start") or fact.get("start_line")
    file_path = fact.get("file_path")
    text = fact.get("text") or fact.get("signature") or fact.get("source_text")
    if not file_path or not line or not text:
        return None
    try:
        line_number = int(line)
    except (TypeError, ValueError):
        return None
    return SourceEvidence(
        file_path=str(file_path),
        line_start=line_number,
        line_end=int(fact.get("line_end") or line_number),
        contract_name=fact.get("contract") or fact.get("contract_name"),
        function_name=fact.get("function") or fact.get("function_name"),
        source_text=str(text),
        reason=reason,
    )


def _profile_invariant_hypotheses(static_facts: list[dict]) -> list[VulnerabilityHypothesis]:
    profile = next((fact for fact in static_facts if isinstance(fact, dict) and fact.get("search_intents") and fact.get("invariant_candidates")), None)
    if not profile:
        return []
    fact_texts = [fact for fact in static_facts if isinstance(fact, dict) and fact.get("text")]
    candidates: list[VulnerabilityHypothesis] = []
    invariant_terms = {
        term.lower()
        for candidate in profile.get("invariant_candidates", [])
        for term in str(candidate).split()
        if len(term) > 4
    }
    for intent in profile.get("search_intents", []):
        query = str(intent.get("query", ""))
        purpose = str(intent.get("purpose", ""))
        terms = {term.lower() for term in query.split() if len(term) > 4}.union(invariant_terms)
        evidence = []
        for fact in fact_texts:
            text = str(fact.get("text", "")).lower()
            if any(term in text for term in terms):
                item = _evidence_from_fact(fact, f"Source term overlaps repo-profile intent: {intent.get('intent_id')}")
                if item:
                    evidence.append(item)
            if len(evidence) >= 4:
                break
        if not evidence:
            continue
        vulnerability_class = str(intent.get("vulnerability_class") or "business_logic")
        affected_files = list(dict.fromkeys(item.file_path for item in evidence))
        affected_functions = list(dict.fromkeys(item.function_name for item in evidence if item.function_name))
        candidates.append(
            VulnerabilityHypothesis(
                id="hyp-profile",
                title=f"Profile-guided {vulnerability_class.replace('_', ' ')} review: {purpose}",
                vulnerability_class=vulnerability_class,
                affected_files=affected_files,
                affected_functions=affected_functions,
                evidence_summary="; ".join(f"{item.file_path}:{item.line_start} {item.reason}" for item in evidence[:3]),
                confidence=0.48,
                affected_contract=evidence[0].contract_name,
                affected_function=affected_functions[0] if affected_functions else evidence[0].function_name,
                evidence_lines=evidence,
                root_cause_terms=list(dict.fromkeys([*intent.get("tags", []), *query.lower().split()[:8]])),
                recommended_validation=[f"Write an invariant or regression test for: {purpose}"],
                source_detection_ids=[f"repo-profile:{intent.get('intent_id')}"],
                suggested_rag_queries=[query],
                status="needs_manual_review",
            )
        )
    return candidates[:5]


def _class_from_invariant_type(invariant_type: str) -> str:
    mapping = {
        "custody_accounting_consistency": "accounting_invariant",
        "authorization_to_state_write_consistency": "missing_access_control",
        "lifecycle_transition_gating": "business_logic",
        "randomness_unpredictability": "weak_randomness",
        "signature_threshold_uniqueness": "access_control",
        "checkpoint_boundary_mismatch": "accounting_invariant",
        "multi_report_fee_accrual": "accounting_invariant",
        "fee_formula_dimension_mismatch": "accounting_invariant",
        "pending_redeem_fee_base_exclusion": "accounting_invariant",
        "boolean_policy_inversion": "business_logic",
        "native_asset_receive_mismatch": "asset_flow",
        "indexed_structure_key_mismatch": "accounting_invariant",
        "lockup_transfer_bypass": "business_logic",
        "configured_but_not_enforced": "business_logic",
        "checked_but_never_updated": "business_logic",
        "percentage_distribution_math": "accounting_invariant",
        "upgrade_authorization_without_upgrade": "upgradeability",
        "storage_layout_mismatch": "storage_layout",
        "unbounded_loop_dos": "denial_of_service",
        "external_state_accounting_trust": "accounting_invariant",
    }
    if invariant_type.startswith("rag_checklist_"):
        suffix = invariant_type.removeprefix("rag_checklist_")
        return {
            "access_control": "missing_access_control",
            "accounting": "accounting_invariant",
            "weak_randomness": "weak_randomness",
            "oracle_staleness_logic": "oracle_staleness_logic",
        }.get(suffix, "business_logic")
    return mapping.get(invariant_type, "business_logic")


def _hypotheses_from_invariant_candidates(static_facts: list[dict]) -> list[VulnerabilityHypothesis]:
    hypotheses: list[VulnerabilityHypothesis] = []
    raw_candidates = [
        fact.get("invariant_candidate")
        for fact in static_facts
        if isinstance(fact, dict) and fact.get("invariant_candidate")
    ]
    for index, raw in enumerate(raw_candidates, start=1):
        candidate = InvariantCandidate.model_validate(raw)
        evidence = candidate.production_evidence
        if not evidence:
            continue
        affected_files = list(dict.fromkeys(item.file_path for item in evidence))
        affected_functions = list(dict.fromkeys([*candidate.affected_functions, *(item.function_name for item in evidence if item.function_name)]))
        vulnerability_class = _class_from_invariant_type(candidate.invariant_type)
        validation_steps = [
            step
            for step in [
                candidate.required_proof,
                *candidate.validation_questions,
                f"Use validation template `{candidate.recommended_validation_template}` to prove or refute this invariant candidate.",
                candidate.description,
            ]
            if step
        ]
        proof_obligations = [
            step
            for step in [
                candidate.required_proof,
                *candidate.validation_questions,
            ]
            if step
        ]
        roots = [
            candidate.invariant_type,
            candidate.invariant_family or "",
            *candidate.missing_guard_terms,
            *candidate.suspicious_terms,
            *candidate.affected_state_variables,
        ]
        hypotheses.append(
            VulnerabilityHypothesis(
                id=f"hyp-invariant-{index}",
                title=f"Protocol invariant candidate: {candidate.invariant_type.replace('_', ' ')}",
                vulnerability_class=vulnerability_class,
                affected_files=affected_files,
                affected_functions=affected_functions,
                evidence_summary=candidate.description,
                confidence=candidate.confidence,
                affected_contract=candidate.affected_contracts[0] if candidate.affected_contracts else evidence[0].contract_name,
                affected_function=affected_functions[0] if affected_functions else evidence[0].function_name,
                evidence_lines=evidence,
                root_cause_terms=list(dict.fromkeys([term for term in roots if term])),
                recommended_validation=validation_steps,
                source_detection_ids=list(dict.fromkeys([candidate.id, *candidate.detector_ids, *candidate.rag_checklist_refs])),
                graph_slice_ids=candidate.graph_slice_ids,
                proof_packet_id=candidate.proof_packet_id,
                proof_obligations=proof_obligations,
                counterevidence=[fact for fact in candidate.local_facts if "counter" in fact.lower()],
                proof_status=candidate.proof_status,
                exploit_precondition_terms=list(dict.fromkeys([*candidate.suspicious_terms, *(candidate.local_facts[:3])])),
                suggested_rag_queries=[
                    f"{vulnerability_class} {candidate.invariant_type} {candidate.invariant_family or ''} {' '.join(candidate.suspicious_terms)}"
                ],
                status="needs_manual_review" if candidate.is_detector_only else "likely" if candidate.proof_status == "strong_local_path" else "needs_manual_review",
            )
        )
    return hypotheses


def _hypotheses_from_gap_candidates(static_facts: list[dict]) -> list[VulnerabilityHypothesis]:
    hypotheses: list[VulnerabilityHypothesis] = []
    raw_candidates = [
        fact.get("gap_candidate")
        for fact in static_facts
        if isinstance(fact, dict) and fact.get("gap_candidate")
    ]
    for index, raw in enumerate(raw_candidates, start=1):
        candidate = GapFindingCandidate.model_validate(raw)
        evidence = candidate.evidence
        if not evidence:
            continue
        affected_files = list(dict.fromkeys(item.file_path for item in evidence))
        affected_functions = list(dict.fromkeys([*candidate.affected_functions, *(item.function_name for item in evidence if item.function_name)]))
        status = "rejected" if candidate.status == "rejected" else "likely" if candidate.status == "likely" and candidate.adversarial_trace else "needs_manual_review"
        proof_status = "rejected_by_counterevidence" if status == "rejected" else "strong_local_path" if status == "likely" else "setup_required"
        hypotheses.append(
            VulnerabilityHypothesis(
                id=f"hyp-gap-{index}",
                title=f"{candidate.agent_id.replace('_', ' ')}: {candidate.title}",
                vulnerability_class=candidate.vulnerability_class,
                affected_files=affected_files,
                affected_functions=affected_functions,
                evidence_summary="; ".join(candidate.adversarial_trace or [candidate.title]),
                confidence=candidate.confidence,
                affected_contract=evidence[0].contract_name,
                affected_function=affected_functions[0] if affected_functions else evidence[0].function_name,
                evidence_lines=evidence,
                root_cause_terms=list(dict.fromkeys([candidate.gap_type, candidate.agent_id, candidate.validation_template, *candidate.affected_state_variables])),
                recommended_validation=[
                    *candidate.proof_obligations,
                    f"Use validation template `{candidate.validation_template}`.",
                    *candidate.adversarial_trace,
                ],
                source_detection_ids=[candidate.id, candidate.agent_id],
                proof_obligations=candidate.proof_obligations,
                counterevidence=candidate.counterevidence,
                proof_status=proof_status,
                exploit_precondition_terms=candidate.adversarial_trace,
                suggested_rag_queries=[
                    f"{candidate.vulnerability_class} {candidate.gap_type} {' '.join(candidate.affected_state_variables)} mempool slippage lifecycle"
                ],
                status=status,
            )
        )
    return hypotheses


def _detect_slither_finding(functions: list[dict], slither_findings: list[dict]) -> VulnerabilityHypothesis | None:
    for finding in slither_findings:
        check = str(finding.get("check", "unknown"))
        vulnerability_class = _class_from_slither_check(check)
        if not vulnerability_class:
            continue

        source_files = [str(file_path) for file_path in finding.get("source_files", [])]
        affected_functions = [str(function) for function in finding.get("functions", [])]
        if not affected_functions and source_files:
            function_fact = _sensitive_function_for_file(functions, source_files[0])
            if function_fact:
                affected_functions = [str(function_fact.get("function"))]
        if not affected_functions:
            affected_functions = ["unknown"]

        title_class = vulnerability_class.replace("_", " ")
        return VulnerabilityHypothesis(
            id="hyp-1",
            title=f"Slither {title_class} candidate: {check}",
            vulnerability_class=vulnerability_class,
            affected_files=source_files,
            affected_functions=affected_functions,
            evidence_summary=f"Slither detector {check} reported: {finding.get('description', '').strip()}",
            confidence=_slither_confidence_score(finding),
        )
    return None


def _detect_reentrancy(functions: list[dict], external_calls: list[dict], storage_writes: list[dict]) -> VulnerabilityHypothesis | None:
    low_level_calls = _facts_containing(external_calls, (".call(", ".call{", ".send("))
    for call in low_level_calls:
        call_file = call.get("file_path")
        call_line = int(call.get("line", 0) or 0)
        call_fn = call.get("function")
        if not call_fn:
            continue  # cannot establish same-function (reachable-path) scope
        # Require the later state write in the SAME function as the external call,
        # not merely the same file — a call in f() + an unrelated write in g()
        # is not reentrancy.
        later_storage_write = next(
            (
                write
                for write in storage_writes
                if write.get("file_path") == call_file
                and write.get("function") == call_fn
                and int(write.get("line", 0) or 0) > call_line
            ),
            None,
        )
        if later_storage_write:
            function_name = str(call_fn)
            evidence = [
                item
                for item in [
                    _evidence_from_fact(call, "external call transfers control before accounting is finalized"),
                    _evidence_from_fact(later_storage_write, "state/accounting write occurs after external control transfer"),
                ]
                if item
            ]
            return VulnerabilityHypothesis(
                id="hyp-1",
                title=f"Reentrancy candidate in {function_name}",
                vulnerability_class="reentrancy",
                affected_files=[str(call_file)],
                affected_functions=[str(function_name)],
                evidence_summary=(
                    f"{function_name} performs an external call on line {call_line} before a later state write "
                    f"on line {later_storage_write.get('line')}."
                ),
                confidence=0.78,
                evidence_lines=evidence,
                source_detection_ids=["deterministic.reentrancy"],
                proof_status="strong_local_path",
            )
    return None


def _detect_unchecked_transfer(functions: list[dict], token_transfers: list[dict], token_types: dict[str, str]) -> VulnerabilityHypothesis | None:
    for transfer in token_transfers:
        if not _is_unchecked_token_transfer(transfer):
            continue
        receiver = _transfer_receiver(str(transfer.get("text", "")))
        if receiver and token_types.get(receiver) in {"erc721", "erc1155"}:
            continue
        file_path = str(transfer.get("file_path", "unknown"))
        function_fact = _sensitive_function_for_file(functions, file_path)
        function_name = str(transfer.get("function") or (function_fact.get("function") if function_fact else None) or "unknown")
        evidence = [_evidence_from_fact(transfer, "token transfer return value is not checked")]
        return VulnerabilityHypothesis(
            id="hyp-1",
            title=f"Unchecked token transfer candidate in {function_name}",
            vulnerability_class="unchecked_transfer",
            affected_files=[file_path],
            affected_functions=[function_name],
            evidence_summary=f"{transfer.get('text')} is not wrapped in require/assert or SafeERC20 handling.",
            confidence=0.73,
            evidence_lines=[item for item in evidence if item],
            source_detection_ids=["deterministic.unchecked_transfer"],
            proof_status="strong_local_path",
        )
    return None


_GUARD_MODIFIERS = ("onlyowner", "onlyrole", "onlygovernance", "onlyadmin", "onlykeeper", "onlyguardian", "onlyauthorized", "requiresauth", "authorized", "restricted")
_GUARD_BODY_TERMS = ("require(msg.sender", "_checkowner", "_checkrole", "hasrole(", "msg.sender == owner", "msg.sender==owner", "onlyowner", "accesscontrol")


def _function_is_guarded(function_fact: dict, functions: list[dict], access_facts: list[dict]) -> bool:
    """Whether THIS function has an authorization guard — evaluated per function.

    A function is guarded if its declaration carries a known access modifier, or
    a guard expression appears within its own line window (declaration line up to
    the next function in the same file). This replaces the previous global check
    where a single guarded function anywhere suppressed every missing-AC finding.
    """
    decl = str(function_fact.get("text") or "").lower()
    if any(modifier in decl for modifier in _GUARD_MODIFIERS):
        return True
    file_path = function_fact.get("file_path")
    start = int(function_fact.get("line", 0) or 0)
    later_starts = sorted(
        int(f.get("line", 0) or 0)
        for f in functions
        if f.get("file_path") == file_path and int(f.get("line", 0) or 0) > start
    )
    end = later_starts[0] if later_starts else 10**9
    for fact in access_facts:
        if fact.get("file_path") != file_path:
            continue
        line_no = int(fact.get("line", 0) or 0)
        if start <= line_no < end and any(term in str(fact.get("text") or "").lower() for term in _GUARD_BODY_TERMS):
            return True
    return False


def _detect_missing_access_control(
    functions: list[dict],
    external_calls: list[dict],
    access_facts: list[dict],
) -> VulnerabilityHypothesis | None:
    eth_value_transfers = _facts_containing(external_calls, (".transfer(", ".call(", ".call{", ".send("))
    if not eth_value_transfers:
        return None
    for function_fact in functions:
        function_name = str(function_fact.get("function", ""))
        suspicious_name = any(term in function_name.lower() for term in ["emergency", "sweep", "drain"])
        if suspicious_name and not _function_is_guarded(function_fact, functions, access_facts):
            evidence = [
                item
                for item in [
                    _evidence_from_fact(function_fact, "sensitive public/external function name suggests privileged asset movement"),
                    *[
                        _evidence_from_fact(call, "native asset transfer reachable from sensitive function")
                        for call in external_calls
                        if str(call.get("file_path")) == str(function_fact.get("file_path"))
                    ][:2],
                ]
                if item
            ]
            return VulnerabilityHypothesis(
                id="hyp-1",
                title=f"Missing access control candidate in {function_name}",
                vulnerability_class="missing_access_control",
                affected_files=[function_fact.get("file_path", "unknown")],
                affected_functions=[function_name],
                evidence_summary=f"{function_name} appears sensitive and the collected facts did not show an authorization guard.",
                confidence=0.72,
                evidence_lines=evidence,
                source_detection_ids=["deterministic.missing_access_control"],
                proof_status="strong_local_path",
            )
    return None


def rank_hypotheses(inp: RankHypothesesInput, state) -> RankHypothesesOutput:
    static_detections = [
        StaticDetection.model_validate(fact)
        for fact in inp.static_facts
        if isinstance(fact, dict)
        and fact.get("detector_id")
        and fact.get("evidence")
        and any(_is_target_source_path(item.get("file_path")) for item in fact.get("evidence", []))
    ]
    hypotheses: list[VulnerabilityHypothesis] = [
        _hypothesis_from_detection(index, detection)
        for index, detection in enumerate(static_detections, start=1)
    ]

    target_facts = [fact for fact in inp.static_facts if not fact.get("file_path") or _is_target_source_path(fact.get("file_path"))]
    functions = _facts_with_key(target_facts, "function")
    external_calls = _facts_containing(target_facts, (".transfer(", ".call(", ".call{", ".send(", ".delegatecall(", ".delegatecall{"))
    token_transfers = _facts_containing(target_facts, (".transfer(", ".transferFrom("))
    token_types = _token_type_map_from_facts(inp.static_facts)
    storage_writes = [fact for fact in target_facts if "line" in fact and ("=" in fact.get("text", "") or "+=" in fact.get("text", "") or "-=" in fact.get("text", ""))]
    slither_findings = [
        fact
        for fact in _facts_with_key(inp.static_facts, "check")
        if _has_target_source([str(path) for path in fact.get("source_files", [])])
    ]
    access_facts = [
        fact
        for fact in target_facts
        if any(term in fact.get("text", "") for term in ["owner", "onlyOwner", "hasRole", "AccessControl", "msg.sender"])
    ]

    for detector in [
        lambda: _detect_slither_finding(functions, slither_findings),
        lambda: _detect_reentrancy(functions, external_calls, storage_writes),
        lambda: _detect_unchecked_transfer(functions, token_transfers, token_types),
        lambda: _detect_missing_access_control(functions, external_calls, access_facts),
    ]:
        hypothesis = detector()
        if hypothesis:
            hypotheses.append(hypothesis)

    hypotheses.extend(_hypotheses_from_invariant_candidates(inp.static_facts))
    hypotheses.extend(_hypotheses_from_gap_candidates(inp.static_facts))
    hypotheses.extend(_profile_invariant_hypotheses(inp.static_facts))

    hypotheses = _dedupe_hypotheses(hypotheses)
    if hypotheses:
        return RankHypothesesOutput(status=ToolStatus.OK, hypotheses=hypotheses)

    hypothesis = VulnerabilityHypothesis(
        id="hyp-1",
        title="Manual review candidate",
        vulnerability_class="manual_review",
        evidence_summary=f"Initial hypothesis from objective: {inp.objective}",
        confidence=0.2,
    )
    return RankHypothesesOutput(status=ToolStatus.OK, hypotheses=[hypothesis])


def summarize_known_pattern(inp: ResearchNoteInput, state) -> ResearchNoteOutput:
    return ResearchNoteOutput(status=ToolStatus.OK, notes=[f"Pattern '{inp.topic}' requires file/function evidence before reporting."])


def search_local_vuln_db(inp: ResearchGenericInput, state) -> ResearchGenericOutput:
    return ResearchGenericOutput(status=ToolStatus.OK, data={"classes": ["missing_access_control", "unchecked_transfer", "reentrancy"]})


def retrieve_similar_cases(inp: ResearchGenericInput, state) -> ResearchGenericOutput:
    return ResearchGenericOutput(status=ToolStatus.OK, data={"similar_cases": ["SWC-105", "SWC-107", "unchecked ERC20 return values"]})


def solodit_sync(inp: ResearchGenericInput, state) -> RagSyncOutput:
    stale_ok = bool(inp.data.get("stale_ok", True))
    result = sync_solodit(stale_ok=stale_ok)
    state.setdefault("last_outputs", {})["research.solodit_sync"] = result.model_dump(mode="json")
    if result.message:
        state.setdefault("warnings", []).append(result.message)
    return RagSyncOutput(status=result.status, state=result)


def build_solodit_checklist(inp: ResearchGenericInput, state) -> ResearchGenericOutput:
    path = write_generated_checklists()
    items = build_solodit_checklists_from_cache()
    return ResearchGenericOutput(
        status=ToolStatus.OK,
        data={
            "path": str(path),
            "checklist_count": len(items),
            "classes": sorted({item.vulnerability_class for item in items}),
        },
    )


def build_repo_profile(inp: RepoRAGProfileInput, state) -> RepoRAGProfileOutput:
    profile = build_repo_rag_profile(inp.repo_path, inp.static_facts)
    state["repo_rag_profile"] = profile
    state.setdefault("last_outputs", {})["research.build_repo_profile"] = {"profile": profile.model_dump(mode="json")}
    return RepoRAGProfileOutput(status=ToolStatus.OK, profile=profile)


def targeted_solodit_context(inp: TargetedRAGInput, state) -> TargetedRAGOutput:
    result = build_targeted_rag(inp.repo_path, inp.static_facts)
    state["targeted_rag"] = result
    state.setdefault("last_outputs", {})["research.targeted_solodit_context"] = {"state": result.model_dump(mode="json")}
    if result.message:
        state.setdefault("warnings", []).append(result.message)
    return TargetedRAGOutput(status=result.status, state=result)


def retrieve_historical_findings(inp: HistoricalFindingQuery, state) -> HistoricalFindingSearchOutput:
    settings = get_settings()
    candidates = []
    used_targeted_cache = False
    used_global_cache = False
    targeted = state.get("targeted_rag") or {}
    repo_id = targeted.get("repo_id") if isinstance(targeted, dict) else getattr(targeted, "repo_id", None)
    targeted_status = targeted.get("status") if isinstance(targeted, dict) else getattr(targeted, "status", None)
    if repo_id and str(targeted_status).lower().endswith("ok"):
        targeted_root = repo_profile_root(settings, str(repo_id))
        targeted_candidates = HistoricalFindingStore(settings, root=targeted_root).search(inp, candidate_k=30)
        candidates.extend(targeted_candidates)
        used_targeted_cache = bool(targeted_candidates)
    seen_ids = {finding.id for finding, _ in candidates}
    global_candidates = HistoricalFindingStore(settings).search(inp)
    used_global_cache = bool(global_candidates)
    for finding, score in global_candidates:
        if finding.id not in seen_ids:
            candidates.append((finding, score))
            seen_ids.add(finding.id)
    matches = rank_matches(inp, candidates)
    if matches:
        state.setdefault("historical_findings", []).extend(matches)
    _record_retrieval_telemetry(
        state,
        query=inp,
        raw_candidate_count=len(candidates),
        final_candidate_count=len(matches),
        top_score=matches[0].final_score if matches else 0.0,
        used_targeted_cache=used_targeted_cache,
        used_global_cache=used_global_cache,
    )
    return HistoricalFindingSearchOutput(status=ToolStatus.OK, matches=matches)


def _record_retrieval_telemetry(
    state,
    query: HistoricalFindingQuery,
    raw_candidate_count: int,
    final_candidate_count: int,
    top_score: float,
    used_targeted_cache: bool,
    used_global_cache: bool,
) -> None:
    import hashlib

    run_dir = state.get("run_dir")
    if not run_dir:
        return
    record = {
        "run_id": state.get("run_id"),
        "hypothesis_id": state.get("hypothesis_id"),
        "embedding_model": get_settings().rag_embed_model,
        "query_text_hash": hashlib.sha256(query.query.encode("utf-8")).hexdigest(),
        "query_intent": state.get("query_intent"),
        "top_k": query.top_k,
        "raw_candidate_count": raw_candidate_count,
        "final_candidate_count": final_candidate_count,
        "top_score": round(float(top_score), 4),
        "retrieval_grade": state.get("retrieval_grade"),
        "used_targeted_cache": used_targeted_cache,
        "used_global_cache": used_global_cache,
        "repair_attempted": bool(state.get("repair_attempted", False)),
    }
    append_jsonl(f"{run_dir}/retrieval_telemetry.jsonl", record)


def expand_rag_queries(inp: RAGQueriesInput, state) -> RAGQueriesOutput:
    hyp = inp.hypothesis
    snippets = " ".join(item.source_text for item in hyp.evidence_lines[:3])
    affected = " ".join([hyp.affected_contract or "", hyp.affected_function or "", " ".join(hyp.affected_functions)])
    roots = " ".join(hyp.root_cause_terms)
    preconditions = " ".join(hyp.exploit_precondition_terms)
    seeds = [
        ("root_cause", f"{hyp.vulnerability_class} {roots} {hyp.title}"),
        ("exploit_preconditions", f"{hyp.vulnerability_class} {preconditions or roots} exploit preconditions"),
        ("code_indicators", f"{hyp.vulnerability_class} {snippets[:500]}"),
        ("affected_surface", f"{hyp.vulnerability_class} {affected} Solidity audit finding"),
    ]
    if hyp.suggested_rag_queries:
        seeds.extend((f"suggested_{idx}", query) for idx, query in enumerate(hyp.suggested_rag_queries[:2], start=1))
    queries = []
    seen = set()
    for intent, query in seeds:
        cleaned = build_canonical_query_text(
            hyp,
            intent,
            source_evidence=[item.source_text for item in hyp.evidence_lines[:3]],
            root_cause_terms=hyp.root_cause_terms,
            exploit_precondition_terms=hyp.exploit_precondition_terms,
        )
        if not cleaned:
            cleaned = " ".join(query.split())
        if not cleaned or cleaned.lower() in seen:
            continue
        seen.add(cleaned.lower())
        queries.append(
            RAGQuery(
                hypothesis_id=hyp.id,
                query=cleaned,
                intent=intent,
                vulnerability_class=hyp.vulnerability_class,
                root_cause_terms=hyp.root_cause_terms,
                top_k=5,
            )
        )
    return RAGQueriesOutput(status=ToolStatus.OK, queries=queries[:5])


def retrieve_multi_query(inp: MultiQueryRetrievalInput, state) -> MultiQueryRetrievalOutput:
    matches_by_query: dict[str, list[HistoricalFindingMatch]] = {}
    for query in inp.queries:
        state["hypothesis_id"] = query.hypothesis_id
        state["query_intent"] = query.intent
        output = retrieve_historical_findings(
            HistoricalFindingQuery(
                query=query.query,
                vulnerability_class=query.vulnerability_class,
                tags=query.root_cause_terms,
                top_k=query.top_k,
            ),
            state,
        )
        matches_by_query[query.intent] = output.matches
    return MultiQueryRetrievalOutput(status=ToolStatus.OK, matches_by_query=matches_by_query)


def merge_rag_results(inp: MergeRAGResultsInput, state) -> MergeRAGResultsOutput:
    best: dict[str, HistoricalFindingMatch] = {}
    for matches in inp.matches_by_query.values():
        for match in matches:
            key = match.finding.id or match.finding.title
            existing = best.get(key)
            if existing is None or match.final_score > existing.final_score:
                best[key] = match
    merged = sorted(best.values(), key=lambda item: item.final_score, reverse=True)[:10]
    return MergeRAGResultsOutput(status=ToolStatus.OK, matches=merged)


def _root_overlap(hypothesis: VulnerabilityHypothesis, match: HistoricalFindingMatch) -> set[str]:
    hyp_terms = {term.lower() for term in hypothesis.root_cause_terms if term}
    finding_terms = {term.lower() for term in match.finding.root_cause_terms if term}
    matched_terms = {term.lower() for term in match.matched_terms if term}
    return hyp_terms.intersection(finding_terms.union(matched_terms))


def _same_vulnerability_class(hypothesis: VulnerabilityHypothesis, match: HistoricalFindingMatch) -> bool:
    return bool(match.finding.vulnerability_class and match.finding.vulnerability_class == hypothesis.vulnerability_class)


def grade_retrieval_quality(inp: RetrievalGradeInput, state) -> RetrievalGradeOutput:
    if not inp.matches:
        grade = RetrievalQualityGrade(grade="bad", score=0.0, reason="No historical matches returned.", repair_hint="Use root-cause and source-code terms.")
        return RetrievalGradeOutput(status=ToolStatus.OK, grade=grade)
    strong = [match for match in inp.matches if match.final_score >= 0.30 and _same_vulnerability_class(inp.hypothesis, match) and _root_overlap(inp.hypothesis, match)]
    weak = [match for match in inp.matches if match.final_score >= 0.18]
    if len(strong) >= 2:
        score = min(1.0, sum(match.final_score for match in strong[:3]) / 3)
        grade = RetrievalQualityGrade(grade="good", score=score, reason=f"{len(strong)} matches share root-cause terms.")
    elif weak:
        score = max(match.final_score for match in weak)
        grade = RetrievalQualityGrade(grade="weak", score=score, reason="Matches exist but root-cause overlap is thin.", repair_hint="Add exact vulnerability class and evidence source terms.")
    else:
        grade = RetrievalQualityGrade(grade="bad", score=0.05, reason="Only low-scoring lexical matches returned.", repair_hint="Use concrete source evidence and exploit precondition terms.")
    return RetrievalGradeOutput(status=ToolStatus.OK, grade=grade)


def repair_rag_query(inp: RepairRAGQueryInput, state) -> RAGQueriesOutput:
    hyp = inp.hypothesis
    snippets = " ".join(item.source_text for item in hyp.evidence_lines[:2])
    query = " ".join(
        [
            hyp.vulnerability_class,
            " ".join(hyp.root_cause_terms),
            " ".join(hyp.exploit_precondition_terms),
            snippets[:400],
            inp.grade.repair_hint or "",
        ]
    )
    return RAGQueriesOutput(
        status=ToolStatus.OK,
        queries=[
            RAGQuery(
                hypothesis_id=hyp.id,
                query=" ".join(query.split()),
                intent="repair",
                vulnerability_class=hyp.vulnerability_class,
                root_cause_terms=hyp.root_cause_terms,
                top_k=8,
            )
        ],
    )


def critique_historical_matches(inp: CritiqueHistoricalMatchesInput, state) -> CritiqueHistoricalMatchesOutput:
    critiques = []
    preconditions = {term.lower() for term in inp.hypothesis.exploit_precondition_terms if term}
    for match in inp.matches:
        overlap = _root_overlap(inp.hypothesis, match)
        haystack = f"{match.finding.title} {match.finding.summary or ''} {match.finding.search_text[:2000]}".lower()
        shared_preconditions = bool(preconditions and any(term in haystack for term in preconditions))
        same_class = _same_vulnerability_class(inp.hypothesis, match)
        safe = bool(same_class and match.final_score >= 0.25 and (overlap or shared_preconditions))
        differences = []
        if not same_class:
            differences.append(f"class differs: {match.finding.vulnerability_class}")
        if not overlap:
            differences.append("no explicit root-cause term overlap")
        if not shared_preconditions:
            differences.append("no shared exploit precondition")
        if match.final_score < 0.25:
            differences.append("retrieval score below citation threshold")
        critiques.append(
            HistoricalMatchCritique(
                match=match,
                shared_root_cause=bool(overlap),
                shared_exploit_preconditions=shared_preconditions,
                important_differences=differences,
                safe_to_cite=safe,
                reason="Safe to cite as historical context." if safe else "Rejected: similar wording without shared root cause or exploit preconditions.",
            )
        )
    return CritiqueHistoricalMatchesOutput(status=ToolStatus.OK, critiques=critiques)


def build_rag_context_bundle(inp: BuildRAGContextBundleInput, state) -> ResearchGenericOutput:
    grade = inp.grade or RetrievalQualityGrade(grade="bad", score=0.0, reason="No retrieval grade provided.")
    safe = [critique for critique in inp.critiques if critique.safe_to_cite][:3]
    rejected = [critique for critique in inp.critiques if not critique.safe_to_cite]
    bundle = RAGContextBundle(
        hypothesis_id=inp.hypothesis.id,
        queries=inp.queries,
        raw_match_count=len(inp.matches),
        quality_grade=grade,
        safe_matches=safe,
        rejected_matches=rejected,
        used_repair=inp.used_repair,
        notes=[grade.reason],
    )
    return ResearchGenericOutput(status=ToolStatus.OK, data={"bundle": bundle.model_dump(mode="json")})


def compare_to_known_bug(inp: HistoricalFindingQuery, state) -> HistoricalFindingSearchOutput:
    output = retrieve_historical_findings(inp, state)
    for match in output.matches:
        match.relevance_reason = f"Known-bug comparison: {match.relevance_reason}"
    return output


def challenge_finding(inp: HistoricalFindingQuery, state) -> ResearchGenericOutput:
    local_evidence = state.get("static_facts", {})
    has_local_evidence = any(local_evidence.get(group) for group in ["functions", "external_calls", "token_transfers", "storage_writes", "slither_findings", "access_control"])
    warning = None if has_local_evidence else "Historical findings are not local evidence; collect target-repo evidence before reporting."
    return ResearchGenericOutput(
        status=ToolStatus.OK,
        data={
            "query": inp.query,
            "has_local_evidence": has_local_evidence,
            "challenge": warning or "Historical matches may support prioritization, but the report must cite local source facts.",
        },
    )


def map_to_vulnerability_class(inp: ResearchGenericInput, state) -> ResearchGenericOutput:
    text = " ".join(str(value) for value in inp.data.values()).lower()
    vuln_class = "missing_access_control" if "owner" in text or "access" in text else "manual_review"
    return ResearchGenericOutput(status=ToolStatus.OK, data={"vulnerability_class": vuln_class})


def summarize_prior_case(inp: ResearchGenericInput, state) -> ResearchGenericOutput:
    return ResearchGenericOutput(status=ToolStatus.OK, message="Prior cases require concrete file/function evidence before reporting.")


def spawn_research_subgraph_tool(inp: ResearchGenericInput, state) -> ResearchGenericOutput:
    return ResearchGenericOutput(status=ToolStatus.OK, message="Parent graph owns real research subgraph spawning; this tool exposes the capability in registry metadata.")


# --- Model-driven, evidence-grounded hypothesis proposal (Phase 2.1) ---


def _file_basename(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def _file_match(range_file: str, proposed_file: str) -> bool:
    rf = range_file.replace("\\", "/")
    pf = proposed_file.replace("\\", "/").strip()
    if not pf:
        return False
    return rf == pf or rf.endswith("/" + pf) or pf.endswith("/" + rf) or _file_basename(rf) == _file_basename(pf)


def _read_source_block(repo_path: str, file_path: str, start_line: int, end_line: int, max_chars: int = 2400) -> str:
    source = Path(repo_path) / file_path
    if not source.exists():
        return ""
    lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(lines[max(0, start_line - 1) : end_line])[:max_chars]


def _function_range_index(static_facts: dict) -> list[dict]:
    """Function ranges restricted to the target protocol source.

    Dependency (lib/), test, script, and mock files are excluded so the proposer
    reasons about — and can only ground hypotheses to — the code actually under
    audit, not forge-std mocks or third-party libraries.
    """

    ranges = static_facts.get("function_ranges", [])
    return [
        r
        for r in ranges
        if isinstance(r, dict)
        and r.get("function_name")
        and r.get("file_path")
        and _is_target_source_path(str(r.get("file_path")))
    ]


def _priority_function_names(state) -> set[str]:
    names: set[str] = set()
    graph = state.get("protocol_graph")
    if graph is not None:
        for sl in getattr(graph, "slices", [])[:20]:
            if getattr(sl, "entry_function", None):
                names.add(sl.entry_function)
            names.update(getattr(sl, "reachable_functions", [])[:8])
    for det in state.get("static_facts", {}).get("detections", []):
        if isinstance(det, dict):
            names.update(det.get("affected_functions", []))
    return {n for n in names if n}


_FUND_MARKERS = (".transfer(", ".safetransfer(", ".transferfrom(", ".safetransferfrom(", ".call{", ".send(", ".mint(", ".burn(")
_UPGRADE_MARKERS = ("_authorizeupgrade", "upgradeto", "delegatecall", "_disableinitializers", "reinitializer")
_LOOP_MARKERS = ("for (", "for(", "while (", "while(")


def _high_value_function_names(state, repo_path: str) -> set[str]:
    """Functions that move funds, perform upgrades, or loop over collections.

    These are where critical-severity logic bugs concentrate (e.g. a payout loop
    that also authorizes an upgrade), yet static detectors often miss them. We
    surface them so the proposer always reasons about the riskiest code, not just
    detector-flagged or graph-entry functions.
    """

    out: set[str] = set()
    for r in _function_range_index(state.get("static_facts", {})):
        s, e = r.get("start_line"), r.get("end_line")
        if not isinstance(s, int) or not isinstance(e, int):
            continue
        body = _read_source_block(repo_path, str(r.get("file_path")), s, e, max_chars=4000).lower()
        has_funds = any(m in body for m in _FUND_MARKERS)
        has_upgrade = any(m in body for m in _UPGRADE_MARKERS)
        has_loop = any(m in body for m in _LOOP_MARKERS)
        if has_funds or has_upgrade or (has_loop and ("[" in body or ".length" in body)):
            name = r.get("function_name")
            if name:
                out.add(str(name))
    return out


def _proposer_code_context(state, repo_path: str, boost: set[str] | None = None) -> str:
    ranges = _function_range_index(state.get("static_facts", {}))
    priority = _priority_function_names(state) | (boost or set())
    prioritized = sorted(ranges, key=lambda r: (r.get("function_name") not in priority, str(r.get("file_path"))))
    blocks: list[str] = []
    used = 0
    seen: set[tuple] = set()
    for r in prioritized:
        fn, fp = r.get("function_name"), r.get("file_path")
        s, e = r.get("start_line"), r.get("end_line")
        if not isinstance(s, int) or not isinstance(e, int) or (fp, fn) in seen:
            continue
        body = _read_source_block(repo_path, fp, s, e)
        if not body.strip():
            continue
        seen.add((fp, fn))
        block = f"// file: {fp} | contract: {r.get('contract_name')} | function: {fn} | lines {s}-{e}\n{body}"
        if used + len(block) > 16000:
            break
        used += len(block)
        blocks.append(block)
        if len(blocks) >= 16:
            break
    return "\n\n".join(blocks)


def _build_proposer_prompt(state, objective: str) -> str:
    import json as _json

    graph = state.get("protocol_graph")
    attack_paths = [
        {"id": p.attack_path_id, "invariant_family": p.invariant_family, "summary": p.summary}
        for p in (getattr(graph, "attack_paths", [])[:8] if graph is not None else [])
    ]
    targeted = state.get("targeted_rag")
    raw_targeted = targeted.model_dump(mode="json") if hasattr(targeted, "model_dump") else (targeted or {})
    checklist = [
        {
            "vulnerability_class": it.get("vulnerability_class"),
            "root_cause_terms": it.get("root_cause_terms", [])[:6],
            "code_indicators": it.get("code_indicators", [])[:6],
        }
        for it in (raw_targeted or {}).get("checklist_items", [])[:8]
    ]
    contracts = [
        {"name": c.get("contract") or c.get("name"), "file": c.get("file_path")}
        for c in state.get("static_facts", {}).get("contracts", [])[:30]
        if isinstance(c, dict)
    ]
    repo_path = state.get("repo_path", "")
    high_value = sorted(_high_value_function_names(state, repo_path))
    header = _json.dumps(
        {
            "objective": objective,
            "contracts": contracts,
            "attack_path_candidates": attack_paths,
            "historical_checklist": checklist,
            "focus_functions": high_value[:20],
            "analysis_checklist": [
                "access/eligibility: is a required role, threshold, score, deadline, or state precondition NOT enforced before a privileged action or state transition? (e.g. a function that promotes/graduates/pays without checking the eligibility threshold)",
                "upgrade safety: for UUPS/proxy contracts, is _authorizeUpgrade missing an access guard, or does the function authorize an upgrade WITHOUT actually performing it (no upgradeToAndCall/upgradeTo), or omit _disableInitializers / onlyProxy?",
                "accounting: is state (balances, counters, accrued debt) updated correctly AFTER transfers, and is every amount divided/normalized correctly (per-recipient division, precision, rounding)?",
                "reentrancy / ordering: are external calls or token transfers made before state is finalized?",
                "initialization: can initialize be front-run or called twice; are _disableInitializers / initializer guards present?",
                "loops: does a loop over an unbounded array enable griefing/DoS or skipped iterations?",
            ],
            "instruction": (
                "Reason like a protocol auditor over the SOURCE CODE below. For EACH focus function, evaluate it "
                "against EVERY item in analysis_checklist and emit a SEPARATE hypothesis for each distinct issue you "
                "find — do not stop after one or two angles per function. A single risky function (e.g. one that pays "
                "out, transfers, AND upgrades) often has multiple independent bugs; report each separately. Be "
                "thorough: aim for 6-10 hypotheses overall. Set affected_file and affected_function to names that "
                "appear verbatim in the source headers below. Explain the exploit precondition. Do not invent files "
                "or functions."
            ),
        },
        indent=2,
    )
    return f"{header}\n\n=== SOURCE CODE ===\n{_proposer_code_context(state, repo_path, boost=set(high_value))}"


def _ground_proposal(index: int, proposal, ranges: list[dict], repo_path: str) -> VulnerabilityHypothesis | None:
    """Attach real source to a proposal; return None if it cites code that does not exist."""

    def _candidates(case_insensitive: bool) -> list[dict]:
        return [
            r
            for r in ranges
            if _file_match(str(r.get("file_path")), proposal.affected_file)
            and (
                str(r.get("function_name")) == proposal.affected_function
                if not case_insensitive
                else str(r.get("function_name")).lower() == proposal.affected_function.lower()
            )
        ]

    matches = _candidates(False) or _candidates(True)
    if not matches:
        return None
    r = matches[0]
    fp = str(r.get("file_path"))
    s, e = int(r.get("start_line")), int(r.get("end_line"))
    body = _read_source_block(repo_path, fp, s, e)
    if not body.strip():
        return None
    function_name = str(r.get("function_name"))
    evidence = SourceEvidence(
        file_path=fp,
        line_start=s,
        line_end=e,
        contract_name=r.get("contract_name") or proposal.affected_contract,
        function_name=function_name,
        source_text=body[:1800],
        reason=(proposal.reasoning or proposal.title)[:300],
    )
    return VulnerabilityHypothesis(
        id=f"llm-hyp-{index}",
        title=proposal.title,
        vulnerability_class=proposal.vulnerability_class or "manual_review",
        affected_files=[fp],
        affected_functions=[function_name],
        affected_contract=r.get("contract_name") or proposal.affected_contract,
        affected_function=function_name,
        evidence_summary=(proposal.reasoning or proposal.title)[:500],
        confidence=min(0.6, max(0.1, proposal.confidence)),
        evidence_lines=[evidence],
        exploit_precondition_terms=proposal.exploit_preconditions,
        recommended_validation=[f"Validate exploitability of {function_name} against the stated precondition."],
        source_detection_ids=["llm_proposer"],
        proof_status="strong_local_path",
        status="needs_manual_review",
    )


def propose_hypotheses(inp: ProposeHypothesesInput, state) -> ProposeHypothesesOutput:
    from sentinel.llm import provider as llm_provider

    ranges = _function_range_index(state.get("static_facts", {}))
    if not ranges:
        return ProposeHypothesesOutput(status=ToolStatus.OK, notes=["No function ranges available; proposer skipped."])
    if not state.get("use_llm_refiner", False):
        return ProposeHypothesesOutput(status=ToolStatus.OK, notes=["LLM disabled; proposer skipped."])

    prompt = _build_proposer_prompt(state, inp.objective or state.get("objective", ""))
    notes: list[str] = []
    raw_preview: str | None = None
    proposer = llm_provider.get_hypothesis_proposer(mock=False)
    try:
        batch = proposer.propose(prompt)
    except Exception as exc:
        notes.append(f"Primary proposer unavailable; trying Ollama fallback: {type(exc).__name__}: {exc}")
        try:
            proposer = llm_provider.get_ollama_fallback_proposer()
            batch = proposer.propose(prompt)
            notes.append("Ollama fallback proposer applied.")
        except Exception as fallback_exc:
            return ProposeHypothesesOutput(
                status=ToolStatus.OK,
                notes=[*notes, f"Proposer unavailable: {type(fallback_exc).__name__}: {fallback_exc}"],
                raw_preview=str(getattr(proposer, "last_raw", "") or "")[:1200] or None,
            )

    raw_preview = str(getattr(proposer, "last_raw", "") or "")[:1200] or None
    proposed = batch.hypotheses[: inp.max_hypotheses]
    grounded: list[VulnerabilityHypothesis] = []
    dropped_proposals: list[dict] = []
    for i, proposal in enumerate(proposed, start=1):
        hypothesis = _ground_proposal(i, proposal, ranges, inp.repo_path)
        if hypothesis is not None:
            grounded.append(hypothesis)
        else:
            dropped_proposals.append(
                {"affected_file": proposal.affected_file, "affected_function": proposal.affected_function, "title": proposal.title}
            )
    dropped = len(proposed) - len(grounded)
    if dropped:
        notes.append(f"Dropped {dropped} ungrounded proposal(s) citing non-existent file/function.")
    if not proposed:
        notes.append("Model returned no parseable hypotheses (see raw_preview).")
    return ProposeHypothesesOutput(
        status=ToolStatus.OK,
        hypotheses=grounded,
        proposed_count=len(proposed),
        grounded_count=len(grounded),
        dropped_count=dropped,
        notes=notes,
        raw_preview=raw_preview,
        dropped_proposals=dropped_proposals[:10],
    )


def register(registry) -> None:
    for tool in [
        RegisteredTool(namespace="research", name="search_local_vuln_db", description="Search local vulnerability class memory.", input_model=ResearchGenericInput, output_model=ResearchGenericOutput, fn=search_local_vuln_db, side_effects=[SideEffect.NONE]),
        RegisteredTool(namespace="research", name="retrieve_similar_cases", description="Retrieve similar vulnerability cases.", input_model=ResearchGenericInput, output_model=ResearchGenericOutput, fn=retrieve_similar_cases, side_effects=[SideEffect.NONE]),
        RegisteredTool(namespace="research", name="solodit_sync", description="Synchronize Solodit historical findings into the local RAG cache.", input_model=ResearchGenericInput, output_model=RagSyncOutput, fn=solodit_sync, side_effects=[SideEffect.EXTERNAL_NETWORK]),
        RegisteredTool(namespace="research", name="build_solodit_checklist", description="Build Solodit-informed detection checklists from the local RAG cache.", input_model=ResearchGenericInput, output_model=ResearchGenericOutput, fn=build_solodit_checklist, side_effects=[SideEffect.WRITE_FILES]),
        RegisteredTool(namespace="research", name="build_repo_profile", description="Extract a repo RAG profile with protocol domain, invariants, and Solodit search intents.", input_model=RepoRAGProfileInput, output_model=RepoRAGProfileOutput, fn=build_repo_profile, side_effects=[SideEffect.NONE]),
        RegisteredTool(namespace="research", name="targeted_solodit_context", description="Build a repo-specific Solodit RAG cache from targeted search intents plus global cache fallback.", input_model=TargetedRAGInput, output_model=TargetedRAGOutput, fn=targeted_solodit_context, side_effects=[SideEffect.EXTERNAL_NETWORK, SideEffect.WRITE_FILES]),
        RegisteredTool(namespace="research", name="retrieve_historical_findings", description="Retrieve and hybrid-rank Solodit historical findings.", input_model=HistoricalFindingQuery, output_model=HistoricalFindingSearchOutput, fn=retrieve_historical_findings, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="research", name="expand_rag_queries", description="Expand one hypothesis into multiple RAG query intents.", input_model=RAGQueriesInput, output_model=RAGQueriesOutput, fn=expand_rag_queries, side_effects=[SideEffect.NONE]),
        RegisteredTool(namespace="research", name="retrieve_multi_query", description="Retrieve historical matches for multiple RAG queries.", input_model=MultiQueryRetrievalInput, output_model=MultiQueryRetrievalOutput, fn=retrieve_multi_query, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="research", name="merge_rag_results", description="Deduplicate and rerank multi-query RAG results.", input_model=MergeRAGResultsInput, output_model=MergeRAGResultsOutput, fn=merge_rag_results, side_effects=[SideEffect.NONE]),
        RegisteredTool(namespace="research", name="grade_retrieval_quality", description="Grade historical retrieval quality as good, weak, or bad.", input_model=RetrievalGradeInput, output_model=RetrievalGradeOutput, fn=grade_retrieval_quality, side_effects=[SideEffect.NONE]),
        RegisteredTool(namespace="research", name="repair_rag_query", description="Repair weak historical retrieval with a more specific query.", input_model=RepairRAGQueryInput, output_model=RAGQueriesOutput, fn=repair_rag_query, side_effects=[SideEffect.NONE]),
        RegisteredTool(namespace="research", name="critique_historical_matches", description="Critique historical matches and mark which are safe to cite.", input_model=CritiqueHistoricalMatchesInput, output_model=CritiqueHistoricalMatchesOutput, fn=critique_historical_matches, side_effects=[SideEffect.NONE]),
        RegisteredTool(namespace="research", name="build_rag_context_bundle", description="Build a final Self-RAG context bundle for a hypothesis.", input_model=BuildRAGContextBundleInput, output_model=ResearchGenericOutput, fn=build_rag_context_bundle, side_effects=[SideEffect.NONE]),
        RegisteredTool(namespace="research", name="compare_to_known_bug", description="Compare local hypothesis text to known historical findings.", input_model=HistoricalFindingQuery, output_model=HistoricalFindingSearchOutput, fn=compare_to_known_bug, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="research", name="challenge_finding", description="Challenge whether historical matches are supported by local target evidence.", input_model=HistoricalFindingQuery, output_model=ResearchGenericOutput, fn=challenge_finding, side_effects=[SideEffect.NONE]),
        RegisteredTool(namespace="research", name="map_to_vulnerability_class", description="Map evidence to vulnerability class.", input_model=ResearchGenericInput, output_model=ResearchGenericOutput, fn=map_to_vulnerability_class, side_effects=[SideEffect.NONE]),
        RegisteredTool(namespace="research", name="rank_hypotheses", description="Rank candidate vulnerability hypotheses.", input_model=RankHypothesesInput, output_model=RankHypothesesOutput, fn=rank_hypotheses, side_effects=[SideEffect.NONE]),
        RegisteredTool(namespace="research", name="propose_hypotheses", description="Use the LLM to propose novel, code-specific vulnerability hypotheses grounded in real source; ungrounded proposals are dropped.", input_model=ProposeHypothesesInput, output_model=ProposeHypothesesOutput, fn=propose_hypotheses, side_effects=[SideEffect.EXTERNAL_NETWORK], requires_network=True, execution_kind="llm"),
        RegisteredTool(namespace="research", name="summarize_known_pattern", description="Summarize a known vulnerability pattern.", input_model=ResearchNoteInput, output_model=ResearchNoteOutput, fn=summarize_known_pattern, side_effects=[SideEffect.NONE]),
        RegisteredTool(namespace="research", name="summarize_prior_case", description="Summarize a prior vulnerability case.", input_model=ResearchGenericInput, output_model=ResearchGenericOutput, fn=summarize_prior_case, side_effects=[SideEffect.NONE]),
        RegisteredTool(namespace="research", name="spawn_research_subgraph", description="Expose research subgraph spawning capability.", input_model=ResearchGenericInput, output_model=ResearchGenericOutput, fn=spawn_research_subgraph_tool, side_effects=[SideEffect.NONE]),
    ]:
        registry.register(tool)
