from __future__ import annotations

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
from sentinel.schemas.invariants import InvariantCandidate
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
    # ETH transfers such as `to.transfer(...)` do not return a bool, so they
    # belong to access/reentrancy triage rather than unchecked ERC20 return triage.
    if compact.startswith("to.transfer(") or "address(this).balance" in compact:
        return False
    return True


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
    if vulnerability_class == "unchecked_erc20_return":
        return [f"Use a mock ERC20 that returns false and assert {target} handles the failure."]
    if vulnerability_class in {"missing_access_control", "tx_origin_authorization"}:
        return [f"Call {target} through unauthorized direct and intermediary callers."]
    if vulnerability_class == "unguarded_initializer":
        return [f"Call {target} twice and from a non-admin account after deployment."]
    if vulnerability_class == "oracle_staleness_logic":
        return [f"Mock stale and zero oracle responses and assert {target} rejects each case independently."]
    if vulnerability_class == "dangerous_delegatecall":
        return [f"Attempt to execute a malicious delegatecall payload through {target}."]
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
    )


def _dedupe_hypotheses(hypotheses: list[VulnerabilityHypothesis]) -> list[VulnerabilityHypothesis]:
    deduped: list[VulnerabilityHypothesis] = []
    seen: set[tuple[str, str, str]] = set()
    for item in sorted(hypotheses, key=lambda hyp: hyp.confidence, reverse=True):
        file_key = item.affected_files[0] if item.affected_files else ""
        function_key = item.affected_functions[0] if item.affected_functions else item.affected_function or ""
        key = (item.vulnerability_class, file_key, function_key)
        if key in seen:
            continue
        seen.add(key)
        item.id = f"hyp-{len(deduped) + 1}"
        deduped.append(item)
    return deduped[:10]


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
        "configured_but_not_enforced": "business_logic",
        "checked_but_never_updated": "business_logic",
        "percentage_distribution_math": "accounting_invariant",
        "upgrade_authorization_without_upgrade": "upgradeability",
        "storage_layout_mismatch": "storage_layout",
        "unbounded_loop_dos": "denial_of_service",
        "external_state_accounting_trust": "accounting_invariant",
    }
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
                root_cause_terms=list(dict.fromkeys([candidate.invariant_type, *candidate.missing_guard_terms, *candidate.suspicious_terms])),
                recommended_validation=[
                    f"Use validation template `{candidate.recommended_validation_template}` to prove or refute this invariant candidate.",
                    candidate.description,
                ],
                source_detection_ids=[candidate.id],
                exploit_precondition_terms=candidate.suspicious_terms,
                suggested_rag_queries=[
                    f"{vulnerability_class} {candidate.invariant_type} {' '.join(candidate.suspicious_terms)}"
                ],
                status="needs_manual_review",
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
        later_storage_write = next(
            (
                write
                for write in storage_writes
                if write.get("file_path") == call_file and int(write.get("line", 0) or 0) > call_line
            ),
            None,
        )
        function_fact = _sensitive_function_for_file(functions, str(call_file))
        if later_storage_write and function_fact:
            function_name = function_fact.get("function", "unknown")
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
            )
    return None


def _detect_unchecked_transfer(functions: list[dict], token_transfers: list[dict]) -> VulnerabilityHypothesis | None:
    for transfer in token_transfers:
        if not _is_unchecked_token_transfer(transfer):
            continue
        file_path = str(transfer.get("file_path", "unknown"))
        function_fact = _sensitive_function_for_file(functions, file_path)
        function_name = str(function_fact.get("function", "unknown")) if function_fact else "unknown"
        return VulnerabilityHypothesis(
            id="hyp-1",
            title=f"Unchecked token transfer candidate in {function_name}",
            vulnerability_class="unchecked_transfer",
            affected_files=[file_path],
            affected_functions=[function_name],
            evidence_summary=f"{transfer.get('text')} is not wrapped in require/assert or SafeERC20 handling.",
            confidence=0.73,
        )
    return None


def _detect_missing_access_control(
    functions: list[dict],
    external_calls: list[dict],
    access_facts: list[dict],
) -> VulnerabilityHypothesis | None:
    if _has_authorization_guard(access_facts):
        return None
    eth_value_transfers = _facts_containing(external_calls, (".transfer(", ".call(", ".call{", ".send("))
    if not eth_value_transfers:
        return None
    for function_fact in functions:
        function_name = str(function_fact.get("function", ""))
        suspicious_name = any(term in function_name.lower() for term in ["emergency", "withdraw", "sweep", "drain"])
        if suspicious_name:
            return VulnerabilityHypothesis(
                id="hyp-1",
                title=f"Missing access control candidate in {function_name}",
                vulnerability_class="missing_access_control",
                affected_files=[function_fact.get("file_path", "unknown")],
                affected_functions=[function_name],
                evidence_summary=f"{function_name} appears sensitive and the collected facts did not show an authorization guard.",
                confidence=0.72,
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
        lambda: _detect_unchecked_transfer(functions, token_transfers),
        lambda: _detect_missing_access_control(functions, external_calls, access_facts),
    ]:
        hypothesis = detector()
        if hypothesis:
            hypotheses.append(hypothesis)

    hypotheses.extend(_hypotheses_from_invariant_candidates(inp.static_facts))
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
    hyp_terms = {term.lower() for term in hypothesis.root_cause_terms + [hypothesis.vulnerability_class] if term}
    finding_terms = {term.lower() for term in match.finding.root_cause_terms + [match.finding.vulnerability_class] if term}
    matched_terms = {term.lower() for term in match.matched_terms if term}
    return hyp_terms.intersection(finding_terms.union(matched_terms))


def grade_retrieval_quality(inp: RetrievalGradeInput, state) -> RetrievalGradeOutput:
    if not inp.matches:
        grade = RetrievalQualityGrade(grade="bad", score=0.0, reason="No historical matches returned.", repair_hint="Use root-cause and source-code terms.")
        return RetrievalGradeOutput(status=ToolStatus.OK, grade=grade)
    strong = [match for match in inp.matches if match.final_score >= 0.30 and _root_overlap(inp.hypothesis, match)]
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
        same_class = match.finding.vulnerability_class == inp.hypothesis.vulnerability_class
        safe = bool(overlap or shared_preconditions or (same_class and match.final_score >= 0.30))
        differences = []
        if not same_class:
            differences.append(f"class differs: {match.finding.vulnerability_class}")
        if not overlap:
            differences.append("no explicit root-cause term overlap")
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
        RegisteredTool(namespace="research", name="summarize_known_pattern", description="Summarize a known vulnerability pattern.", input_model=ResearchNoteInput, output_model=ResearchNoteOutput, fn=summarize_known_pattern, side_effects=[SideEffect.NONE]),
        RegisteredTool(namespace="research", name="summarize_prior_case", description="Summarize a prior vulnerability case.", input_model=ResearchGenericInput, output_model=ResearchGenericOutput, fn=summarize_prior_case, side_effects=[SideEffect.NONE]),
        RegisteredTool(namespace="research", name="spawn_research_subgraph", description="Expose research subgraph spawning capability.", input_model=ResearchGenericInput, output_model=ResearchGenericOutput, fn=spawn_research_subgraph_tool, side_effects=[SideEffect.NONE]),
    ]:
        registry.register(tool)
