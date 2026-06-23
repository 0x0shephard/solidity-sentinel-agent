from __future__ import annotations

from sentinel.evidence import classify_source_path, default_evidence_role
from sentinel.schemas.report import AnalysisCompleteness, AnalysisToolStatus, Evidence, Finding, ReportDocument
from sentinel.state import AuditState


SEVERITY_BY_CLASS = {
    "transaction_ordering": "high",
    "missing_access_control": "high",
    "tx_origin_authorization": "high",
    "dangerous_delegatecall": "high",
    "reentrancy": "high",
    "external_call_before_accounting": "high",
    "strategy_accounting_trust": "medium",
    "unchecked_transfer": "medium",
    "unchecked_erc20_return": "medium",
    "weak_randomness": "medium",
    "vault_accounting_spoof": "medium",
    "oracle_staleness_logic": "medium",
    "unsafe_or_guard": "medium",
    "unguarded_initializer": "medium",
    "accounting_invariant": "medium",
    "business_logic": "medium",
}


def _historical_matches_for(hypothesis, research) -> list[dict]:
    matches = []
    if getattr(hypothesis, "historical_matches", None):
        matches.extend(
            match.model_dump(mode="json") if hasattr(match, "model_dump") else match
            for match in hypothesis.historical_matches
        )
    if research and research.historical_findings:
        matches.extend(research.historical_findings)
    deduped = []
    seen = set()
    for match in matches:
        if isinstance(match, dict) and "match" in match:
            match = match["match"]
        finding = match.get("finding", {}) if isinstance(match, dict) else {}
        key = finding.get("id") or finding.get("title") or str(match)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(match)
    return deduped[:3]


def _evidence_from_hypothesis(hypothesis) -> list[Evidence]:
    evidence = []
    for item in hypothesis.evidence_lines:
        source_type = classify_source_path(item.file_path)
        evidence.append(
            Evidence(
                kind="source_evidence",
                file_path=item.file_path,
                line_start=item.line_start,
                line_end=item.line_end,
                function=item.function_name,
                message=f"{item.reason}: {item.source_text}",
                source_type=source_type,
                evidence_role=default_evidence_role(source_type),
            )
        )
    return evidence


def _evidence_from_research(hypothesis, research) -> list[Evidence]:
    if not research or not research.evidence:
        return []
    evidence = []
    for item in research.evidence:
        file_path = item.get("file_path") or (hypothesis.affected_files[0] if hypothesis.affected_files else None)
        source_type = classify_source_path(file_path)
        evidence.append(
            Evidence(
                kind=item.get("kind", "research_subgraph"),
                file_path=file_path,
                line_start=item.get("line_start"),
                line_end=item.get("line_end"),
                function=item.get("function"),
                message=item.get("message", research.likely_impact),
                source_type=source_type,
                evidence_role=default_evidence_role(source_type),
            )
        )
    return evidence


def _has_primary_production_evidence(evidence: list[Evidence]) -> bool:
    return any(item.source_type == "production" and item.evidence_role == "primary" and item.file_path and item.line_start for item in evidence)


def _has_executable_primary_evidence(evidence: list[Evidence]) -> bool:
    weak_markers = (
        "Source term overlaps repo-profile intent",
        "suspicious protocol invariant pattern: ///",
        "suspicious protocol invariant pattern: //",
    )
    for item in evidence:
        if item.source_type != "production" or item.evidence_role != "primary" or not item.file_path or not item.line_start:
            continue
        message = item.message.strip()
        if any(marker in message for marker in weak_markers):
            continue
        if message.endswith(":") or message.endswith(": ///") or message.endswith(": //"):
            continue
        return True
    return False


def _status_with_evidence_gate(status: str, evidence: list[Evidence]) -> tuple[str, list[str]]:
    if status not in {"confirmed", "likely"}:
        return status, []
    if _has_executable_primary_evidence(evidence):
        return status, []
    return "needs_manual_review", [
        "Demoted because the hypothesis lacks executable primary production-source evidence. Test, script, documentation, comments, RAG, or dependency evidence is supporting context only."
    ]


def _has_validation_proof(hypothesis, state: AuditState) -> bool:
    """Whether a finding has proof strong enough to be 'confirmed'.

    Confirmation requires a complete static-dataflow proof (per-hypothesis
    semantic validation set ``proof_status='static_proof_complete'``) or an
    executable validation artifact that demonstrated the issue — not LLM or
    heuristic reasoning alone.
    """
    if getattr(hypothesis, "proof_status", "") in {"static_proof_complete", "executed_poc_confirmed"}:
        return True
    run_output = (state.get("last_outputs", {}) or {}).get("dynamic.run_validation_artifacts", {}) or {}
    classification = str((run_output.get("data") or {}).get("classification", ""))
    return classification == "security_invariant_violation_or_test_needs_review"


def _has_executed_validation_proof(hypothesis, state: AuditState) -> bool:
    """True only when an executable validation run demonstrated the issue.

    Stricter than :func:`_has_validation_proof`: a static-dataflow proof is enough
    to *confirm* status, but only an executed PoC justifies near-certain
    confidence on what is otherwise a mined/heuristic candidate.
    """
    # The execution-grounded loop sets this when a runnable PoC broke the invariant.
    if getattr(hypothesis, "proof_status", "") == "executed_poc_confirmed":
        return True
    run_output = (state.get("last_outputs", {}) or {}).get("dynamic.run_validation_artifacts", {}) or {}
    classification = str((run_output.get("data") or {}).get("classification", ""))
    return classification == "security_invariant_violation_or_test_needs_review"


def _calibrated_confidence(raw: float, hypothesis, state: AuditState) -> float:
    """Cap reported confidence for findings without an executed validation.

    Mined invariant candidates and static-only proofs were surfacing at ~0.95,
    which over-states certainty for a finding no PoC has actually executed. Cap
    such findings at 0.85; an executed validation lifts the cap.
    """
    if _has_executed_validation_proof(hypothesis, state):
        return raw
    return min(raw, 0.85)


def _status_with_proof_gate(status: str, hypothesis, state: AuditState) -> tuple[str, list[str]]:
    if status != "confirmed":
        return status, []
    if _has_validation_proof(hypothesis, state):
        return status, []
    return "likely", [
        "Demoted from confirmed: reserved for semantic validation, an executable PoC, or complete static-dataflow proof — model/heuristic reasoning alone does not confirm."
    ]


def _status_with_counterevidence_gate(status: str, hypothesis, research) -> tuple[str, list[str]]:
    if status not in {"confirmed", "likely"}:
        return status, []
    negative_text = " ".join(
        [
            *(getattr(hypothesis, "counterevidence", []) or []),
            *(getattr(research, "limitations", []) if research else []),
            getattr(research, "likely_impact", "") if research else "",
        ]
    ).lower()
    blocking_markers = (
        "low to none",
        "no concrete secondary target",
        "cei-safe",
        "safeerc20-only",
        "missing concrete",
        "blocking counterevidence",
        "no unprivileged impact",
    )
    if any(marker in negative_text for marker in blocking_markers):
        return "rejected", ["Demoted because research/counterevidence identified a blocking negative indicator."]
    return status, []


def _tool_status_from_last_output(output: dict | None) -> AnalysisToolStatus:
    if not output:
        return AnalysisToolStatus()
    status = str(output.get("status", "ok")).lower()
    message = output.get("message") or output.get("stderr") or output.get("stdout")
    if isinstance(message, str) and len(message) > 240:
        message = message[:237] + "..."
    return AnalysisToolStatus(attempted=True, status=status, message=message)


def build_analysis_completeness(state: AuditState) -> AnalysisCompleteness:
    last_outputs = state.get("last_outputs", {})
    validation_output = last_outputs.get("dynamic.run_validation_artifacts") or last_outputs.get("dynamic.compile_validation_artifacts")
    build_output = last_outputs.get("build.foundry_build") or last_outputs.get("build.detect_framework")
    completeness = AnalysisCompleteness(
        build=_tool_status_from_last_output(build_output),
        slither=_tool_status_from_last_output(last_outputs.get("static.run_slither")),
        validation=_tool_status_from_last_output(validation_output),
    )
    limitations: list[str] = []
    penalty = 0.0
    for label, tool_status in [
        ("Build", completeness.build),
        ("Slither", completeness.slither),
        ("Validation", completeness.validation),
    ]:
        if not tool_status.attempted:
            limitations.append(f"{label} was not attempted.")
            penalty += 0.08
        elif tool_status.status not in {"ok", "toolstatus.ok", "completed", "success"}:
            limitations.append(f"{label} did not complete successfully: {tool_status.status}.")
            penalty += 0.08
    completeness.limitations = limitations
    completeness.confidence_penalty = min(0.4, penalty)
    return completeness


def create_findings_from_state(state: AuditState) -> list[Finding]:
    findings: list[Finding] = []
    hypotheses = state.get("hypotheses", [])
    subgraph_results = state.get("subgraph_results", [])
    if not hypotheses:
        return findings

    research_by_hypothesis = {result.hypothesis_id: result for result in subgraph_results}
    for hypothesis in hypotheses:
        if _is_profile_lead(hypothesis):
            evidence = _evidence_from_hypothesis(hypothesis)
            findings.append(
                Finding(
                    id=hypothesis.id.replace("hyp", "lead"),
                    title=hypothesis.title,
                    severity="info",
                    confidence=min(hypothesis.confidence, 0.45),
                    vulnerability_class=hypothesis.vulnerability_class,
                    summary=hypothesis.evidence_summary,
                    affected_files=hypothesis.affected_files,
                    affected_functions=hypothesis.affected_functions,
                    evidence=evidence,
                    reproduction_steps=hypothesis.recommended_validation,
                    recommendation="Treat this as a profile-derived lead until a non-profile detector, invariant proof, or validation artifact supplies local primary evidence.",
                    limitations=["Repo-profile lead: not promoted to manual review or findings without non-profile local evidence."],
                    historical_matches=[],
                    graph_slice_ids=hypothesis.graph_slice_ids,
                    proof_packet_id=hypothesis.proof_packet_id,
                    proof_obligations=hypothesis.proof_obligations,
                    counterevidence=hypothesis.counterevidence,
                    proof_status=hypothesis.proof_status,
                    status="lead",
                )
            )
            continue
        research = research_by_hypothesis.get(hypothesis.id)
        evidence = _evidence_from_research(hypothesis, research) or _evidence_from_hypothesis(hypothesis)
        local_evidence = [item for item in evidence if item.file_path and item.line_start]
        if not local_evidence:
            continue
        severity = SEVERITY_BY_CLASS.get(hypothesis.vulnerability_class, "info")
        status = research.finding_status if research else hypothesis.status
        gated_status, gating_limitations = _status_with_evidence_gate(status, local_evidence)
        # An executed PoC whose ASSERTION broke is strong proof, so promote to
        # confirmed BEFORE the counterevidence gate — but deliberately not after it:
        # if there is concrete counterevidence the bug is mitigated, that must still
        # be able to demote the finding (an executed PoC never auto-overrides it).
        if getattr(hypothesis, "proof_status", "") == "executed_poc_confirmed":
            gated_status = "confirmed"
        gated_status, proof_limitations = _status_with_proof_gate(gated_status, hypothesis, state)
        gated_status, counterevidence_limitations = _status_with_counterevidence_gate(gated_status, hypothesis, research)
        limitations = [
            *(research.limitations if research else ["Generated before research subgraph refinement."]),
            *_proof_gate_limitations(hypothesis, research),
            *_rag_quality_limitations(state, hypothesis.id),
            *gating_limitations,
            *proof_limitations,
            *counterevidence_limitations,
        ]
        findings.append(
            Finding(
                id=hypothesis.id.replace("hyp", "finding"),
                title=research.refined_title if research else hypothesis.title,
                severity=severity,
                confidence=_calibrated_confidence(research.confidence if research else hypothesis.confidence, hypothesis, state),
                vulnerability_class=hypothesis.vulnerability_class,
                summary=research.likely_impact if research else hypothesis.evidence_summary,
                affected_files=hypothesis.affected_files,
                affected_functions=hypothesis.affected_functions,
                evidence=local_evidence,
                reproduction_steps=research.recommended_tests if research else hypothesis.recommended_validation,
                recommendation="Use the cited local source evidence to add a targeted regression test and patch the root cause.",
                limitations=limitations,
                historical_matches=_historical_matches_for(hypothesis, research),
                graph_slice_ids=hypothesis.graph_slice_ids,
                proof_packet_id=hypothesis.proof_packet_id,
                proof_obligations=hypothesis.proof_obligations,
                counterevidence=hypothesis.counterevidence,
                proof_status=hypothesis.proof_status,
                status=gated_status,
            )
        )
    return findings


def _is_profile_lead(hypothesis) -> bool:
    sources = [str(source).lower() for source in getattr(hypothesis, "source_detection_ids", [])]
    has_profile = any(source.startswith("repo-profile:") for source in sources)
    has_non_profile = any(not source.startswith("repo-profile:") for source in sources)
    return has_profile and not has_non_profile


def _proof_gate_limitations(hypothesis, research) -> list[str]:
    if hypothesis.proof_status == "static_proof_complete":
        return ["Proof gate: complete static proof is available from local source evidence."]
    if research and research.finding_status == "confirmed":
        return ["Proof gate: confirmed by research/validation evidence."]
    if hypothesis.proof_status in {"setup_required", "missing_counterevidence"}:
        return [f"Proof gate: {hypothesis.proof_status}; this cannot be confirmed without executable validation or complete static proof."]
    return [f"Proof gate: {hypothesis.proof_status}."]


def _rag_quality_limitations(state: AuditState, hypothesis_id: str) -> list[str]:
    bundle = state.get("rag_context_bundles", {}).get(hypothesis_id)
    if not bundle:
        return []
    quality = getattr(bundle, "quality_grade", None)
    grade = getattr(quality, "grade", None)
    safe_count = len(getattr(bundle, "safe_matches", []) or [])
    return [f"RAG quality: grade={grade or 'unknown'}, safe_matches={safe_count}; historical context is not proof."]


def build_report_document(state: AuditState) -> ReportDocument:
    contest = state.get("last_outputs", {}).get("analysis.contest_reasoning", {})
    return ReportDocument(
        run_id=state["run_id"],
        objective=state["objective"],
        repo_path=state["repo_path"],
        findings=[finding for finding in state.get("findings", []) if finding.status in {"confirmed", "likely"}],
        leads=[finding for finding in state.get("findings", []) if finding.status == "lead"],
        needs_manual_review=[finding for finding in state.get("findings", []) if finding.status == "needs_manual_review"],
        suspicious_hypotheses=[finding for finding in state.get("findings", []) if finding.status == "suspicious"],
        rejected_hypotheses=[finding for finding in state.get("findings", []) if finding.status == "rejected"],
        analysis_completeness=build_analysis_completeness(state),
        actor_model=contest.get("actor_model", []),
        transaction_race_edges=contest.get("race_edges", []),
        reasoning_packets=contest.get("reasoning_packets", [])[:20],
        working_memory=_filtered_report_memory(contest.get("working_memory", {}), contest),
        artifacts=state.get("artifacts", []),
        tool_call_count=state.get("tool_call_count", 0),
        subgraphs_spawned=len(state.get("subgraph_results", [])),
    )


def _filtered_report_memory(memory: dict, contest: dict | None = None) -> dict:
    if not isinstance(memory, dict):
        return {}
    filtered = dict(memory)
    contest = contest or {}
    has_market_context = bool(contest.get("race_edges")) or any(
        actor.get("role") in {"seller", "buyer", "mev_searcher"} for actor in contest.get("actor_model", []) if isinstance(actor, dict)
    )
    lessons = []
    for lesson in filtered.get("benchmark_lessons", [])[:5]:
        lower = str(lesson).lower()
        if not has_market_context and ("mutable order terms" in lower or "expired-but-active" in lower):
            continue
        lessons.append(lesson)
    filtered["benchmark_lessons"] = lessons
    return filtered


def render_markdown_report(report: ReportDocument) -> str:
    lines = [
        "# Solidity Sentinel Report",
        "",
        f"Run ID: {report.run_id}",
        f"Objective: {report.objective}",
        f"Repository: {report.repo_path}",
        f"Tool calls: {report.tool_call_count}",
        f"Research subgraphs: {report.subgraphs_spawned}",
        "",
    ]
    if report.artifacts:
        lines.extend(["## Artifacts", ""])
        for artifact in report.artifacts:
            description = f": {artifact.description}" if artifact.description else ""
            lines.append(f"- `{artifact.path}` ({artifact.kind}){description}")
        lines.append("")
    if report.analysis_completeness:
        lines.extend(["## Analysis Completeness", ""])
        for label, tool_status in [
            ("Build", report.analysis_completeness.build),
            ("Slither", report.analysis_completeness.slither),
            ("Validation", report.analysis_completeness.validation),
        ]:
            attempted = "attempted" if tool_status.attempted else "not attempted"
            message = f": {tool_status.message}" if tool_status.message else ""
            lines.append(f"- {label}: {attempted}, status={tool_status.status}{message}")
        lines.append(f"- Confidence penalty: {report.analysis_completeness.confidence_penalty:.2f}")
        if report.analysis_completeness.limitations:
            lines.append("- Limitations: " + "; ".join(report.analysis_completeness.limitations))
        lines.append("")
    if report.actor_model:
        lines.extend(["## Actor / Intent Model", ""])
        for actor in report.actor_model:
            evidence_count = len(actor.get("evidence", [])) if isinstance(actor, dict) else 0
            capabilities = ", ".join(actor.get("capabilities", [])[:3]) if isinstance(actor, dict) else ""
            lines.append(f"- {actor.get('role', 'unknown')}: {capabilities} (evidence={evidence_count})")
        lines.append("")
    if report.transaction_race_edges:
        lines.extend(["## Transaction Race Model", ""])
        for edge in report.transaction_race_edges[:8]:
            affected_state = ", ".join(edge.get("affected_state", [])[:5])
            lines.append(f"- {edge.get('edge_id')}: {edge.get('edge_type')} over {affected_state}; confidence={edge.get('confidence', 0):.2f}")
            for step in edge.get("adversarial_trace", [])[:3]:
                lines.append(f"  - {step}")
        lines.append("")
    if report.working_memory:
        lessons = report.working_memory.get("benchmark_lessons", [])[:5]
        if lessons:
            lines.extend(["## Audit Memory Notes", ""])
            for lesson in lessons:
                lines.append(f"- {lesson}")
            lines.append("")
    if not report.findings and not report.leads and not report.needs_manual_review and not report.suspicious_hypotheses and not report.rejected_hypotheses:
        lines.append("No findings were generated.")
        return "\n".join(lines) + "\n"

    def render_finding_group(title: str, findings: list[Finding]) -> None:
        if not findings:
            return
        lines.extend([f"## {title}", ""])
        for finding in findings:
            lines.extend(
                [
                    f"### {finding.title}",
                    "",
                    f"- Status: {finding.status}",
                    f"- Severity: {finding.severity}",
                    f"- Confidence: {finding.confidence:.2f}",
                    f"- Class: {finding.vulnerability_class}",
                    f"- Proof status: {finding.proof_status}",
                    f"- Proof packet: {finding.proof_packet_id or 'n/a'}",
                    f"- Graph slices: {', '.join(finding.graph_slice_ids) or 'n/a'}",
                    f"- Files: {', '.join(finding.affected_files) or 'n/a'}",
                    f"- Functions: {', '.join(finding.affected_functions) or 'n/a'}",
                    "",
                    finding.summary,
                    "",
                    "#### Evidence",
                ]
            )
            for item in finding.evidence:
                location = item.file_path or "unknown file"
                if item.line_start:
                    location += f":{item.line_start}"
                if item.function:
                    location += f"::{item.function}"
                lines.append(f"- `{location}` [{item.source_type}/{item.evidence_role}]: {item.message}")
            if finding.proof_obligations:
                lines.extend(["", "#### Proof Obligations"])
                for obligation in finding.proof_obligations:
                    lines.append(f"- {obligation}")
            if finding.counterevidence:
                lines.extend(["", "#### Counterevidence / Negative Indicators"])
                for item in finding.counterevidence:
                    lines.append(f"- {item}")
            if finding.reproduction_steps:
                lines.extend(["", "#### Suggested Tests"])
                for step in finding.reproduction_steps:
                    lines.append(f"- {step}")
            if finding.historical_matches:
                lines.extend(["", "#### Historical Similar Findings", ""])
                lines.append("These are supporting historical context from Solodit/RAG, not proof of a bug in this repository.")
                for match in finding.historical_matches[:3]:
                    if isinstance(match, dict) and "match" in match:
                        match = match["match"]
                    historical = match.get("finding", {}) if isinstance(match, dict) else {}
                    title = historical.get("title", "Untitled historical finding")
                    source = historical.get("source_link") or historical.get("github_link") or historical.get("pdf_link") or "n/a"
                    score = match.get("final_score") if isinstance(match, dict) else None
                    score_text = f", score={score:.2f}" if isinstance(score, (int, float)) else ""
                    lines.append(f"- {title} ({source}{score_text})")
            if finding.limitations:
                lines.extend(["", "#### Limitations"])
                for limitation in finding.limitations:
                    lines.append(f"- {limitation}")
            lines.append("")

    render_finding_group("Findings", report.findings)
    render_finding_group("Leads", report.leads)
    render_finding_group("Needs Manual Review", report.needs_manual_review)
    render_finding_group("Suspicious Hypotheses", report.suspicious_hypotheses)
    render_finding_group("Rejected Hypotheses", report.rejected_hypotheses)
    return "\n".join(lines)
