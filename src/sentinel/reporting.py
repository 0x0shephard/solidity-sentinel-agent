from __future__ import annotations

from sentinel.schemas.report import Evidence, Finding, ReportDocument
from sentinel.state import AuditState


def create_findings_from_state(state: AuditState) -> list[Finding]:
    findings: list[Finding] = []
    hypotheses = state.get("hypotheses", [])
    subgraph_results = state.get("subgraph_results", [])
    if not hypotheses:
        return findings

    hypothesis = hypotheses[0]
    research = subgraph_results[0] if subgraph_results else None
    severity_by_class = {
        "missing_access_control": "high",
        "reentrancy": "high",
        "unchecked_transfer": "medium",
    }
    severity = severity_by_class.get(hypothesis.vulnerability_class, "info")
    evidence = [
        Evidence(
            kind="research_subgraph" if research else "static_analysis",
            file_path=hypothesis.affected_files[0] if hypothesis.affected_files else None,
            function=hypothesis.affected_functions[0] if hypothesis.affected_functions else None,
            message=research.likely_impact if research else hypothesis.evidence_summary,
        )
    ]
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
            evidence=evidence,
            reproduction_steps=research.recommended_tests if research else [],
            recommendation="Collect file/function evidence and add targeted regression tests.",
            limitations=research.limitations if research else ["Generated before research subgraph refinement."],
        )
    )
    return findings


def build_report_document(state: AuditState) -> ReportDocument:
    return ReportDocument(
        run_id=state["run_id"],
        objective=state["objective"],
        repo_path=state["repo_path"],
        findings=state.get("findings", []),
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
    if not report.findings:
        lines.append("No findings were generated.")
        return "\n".join(lines) + "\n"

    for finding in report.findings:
        lines.extend(
            [
                f"## {finding.title}",
                "",
                f"- Severity: {finding.severity}",
                f"- Confidence: {finding.confidence:.2f}",
                f"- Class: {finding.vulnerability_class}",
                f"- Files: {', '.join(finding.affected_files) or 'n/a'}",
                f"- Functions: {', '.join(finding.affected_functions) or 'n/a'}",
                "",
                finding.summary,
                "",
                "### Evidence",
            ]
        )
        for item in finding.evidence:
            location = item.file_path or "unknown file"
            if item.function:
                location += f"::{item.function}"
            lines.append(f"- `{location}`: {item.message}")
        if finding.reproduction_steps:
            lines.extend(["", "### Suggested Tests"])
            for step in finding.reproduction_steps:
                lines.append(f"- {step}")
        if finding.limitations:
            lines.extend(["", "### Limitations"])
            for limitation in finding.limitations:
                lines.append(f"- {limitation}")
        lines.append("")
    return "\n".join(lines)
