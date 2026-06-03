from __future__ import annotations

from sentinel.schemas.report import Evidence, Finding, ReportDocument
from sentinel.state import AuditState


SEVERITY_BY_CLASS = {
    "missing_access_control": "high",
    "tx_origin_authorization": "high",
    "dangerous_delegatecall": "high",
    "reentrancy": "high",
    "external_call_before_accounting": "high",
    "strategy_accounting_trust": "medium",
    "unchecked_transfer": "medium",
    "unchecked_erc20_return": "medium",
    "oracle_staleness_logic": "medium",
    "unsafe_or_guard": "medium",
    "unguarded_initializer": "medium",
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
    return [
        Evidence(
            kind="source_evidence",
            file_path=item.file_path,
            line_start=item.line_start,
            line_end=item.line_end,
            function=item.function_name,
            message=f"{item.reason}: {item.source_text}",
        )
        for item in hypothesis.evidence_lines
    ]


def _evidence_from_research(hypothesis, research) -> list[Evidence]:
    if not research or not research.evidence:
        return []
    return [
        Evidence(
            kind=item.get("kind", "research_subgraph"),
            file_path=item.get("file_path") or (hypothesis.affected_files[0] if hypothesis.affected_files else None),
            line_start=item.get("line_start"),
            line_end=item.get("line_end"),
            function=item.get("function"),
            message=item.get("message", research.likely_impact),
        )
        for item in research.evidence
    ]


def create_findings_from_state(state: AuditState) -> list[Finding]:
    findings: list[Finding] = []
    hypotheses = state.get("hypotheses", [])
    subgraph_results = state.get("subgraph_results", [])
    if not hypotheses:
        return findings

    research_by_hypothesis = {result.hypothesis_id: result for result in subgraph_results}
    for hypothesis in hypotheses:
        research = research_by_hypothesis.get(hypothesis.id)
        evidence = _evidence_from_research(hypothesis, research) or _evidence_from_hypothesis(hypothesis)
        local_evidence = [item for item in evidence if item.file_path and item.line_start]
        if not local_evidence:
            continue
        severity = SEVERITY_BY_CLASS.get(hypothesis.vulnerability_class, "info")
        status = research.finding_status if research else hypothesis.status
        findings.append(
            Finding(
                id=hypothesis.id.replace("hyp", "finding"),
                title=research.refined_title if research else hypothesis.title,
                severity=severity,
                confidence=research.confidence if research else hypothesis.confidence,
                vulnerability_class=hypothesis.vulnerability_class,
                summary=research.likely_impact if research else hypothesis.evidence_summary,
                affected_files=hypothesis.affected_files,
                affected_functions=hypothesis.affected_functions,
                evidence=local_evidence,
                reproduction_steps=research.recommended_tests if research else hypothesis.recommended_validation,
                recommendation="Use the cited local source evidence to add a targeted regression test and patch the root cause.",
                limitations=research.limitations if research else ["Generated before research subgraph refinement."],
                historical_matches=_historical_matches_for(hypothesis, research),
                status=status,
            )
        )
    return findings


def build_report_document(state: AuditState) -> ReportDocument:
    return ReportDocument(
        run_id=state["run_id"],
        objective=state["objective"],
        repo_path=state["repo_path"],
        findings=[finding for finding in state.get("findings", []) if finding.status in {"confirmed", "likely"}],
        needs_manual_review=[finding for finding in state.get("findings", []) if finding.status == "needs_manual_review"],
        rejected_hypotheses=[finding for finding in state.get("findings", []) if finding.status == "rejected"],
        artifacts=state.get("artifacts", []),
        tool_call_count=state.get("tool_call_count", 0),
        subgraphs_spawned=len(state.get("subgraph_results", [])),
    )


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
    if not report.findings and not report.needs_manual_review and not report.rejected_hypotheses:
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
                lines.append(f"- `{location}`: {item.message}")
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
    render_finding_group("Needs Manual Review", report.needs_manual_review)
    render_finding_group("Rejected Hypotheses", report.rejected_hypotheses)
    return "\n".join(lines)
