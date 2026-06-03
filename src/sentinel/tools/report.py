from __future__ import annotations

from pydantic import BaseModel, Field

from sentinel.reporting import build_report_document, create_findings_from_state, render_markdown_report
from sentinel.schemas.common import SideEffect, ToolStatus
from sentinel.schemas.report import Evidence, Finding
from sentinel.tools.base import RegisteredTool


class ReportGenericInput(BaseModel):
    data: dict = Field(default_factory=dict)


class ReportGenericOutput(BaseModel):
    status: ToolStatus
    message: str | None = None
    data: dict = Field(default_factory=dict)


class CreateFindingOutput(BaseModel):
    status: ToolStatus
    findings: list[Finding]


def create_finding(inp: ReportGenericInput, state) -> CreateFindingOutput:
    findings = create_findings_from_state(state)
    state["findings"] = findings
    return CreateFindingOutput(status=ToolStatus.OK, findings=findings)


def generate_json(inp: ReportGenericInput, state) -> ReportGenericOutput:
    report = build_report_document(state)
    return ReportGenericOutput(status=ToolStatus.OK, data=report.model_dump(mode="json"))


def add_evidence(inp: ReportGenericInput, state) -> ReportGenericOutput:
    if not state.get("findings"):
        state["findings"] = create_findings_from_state(state)
    if not state.get("findings"):
        return ReportGenericOutput(status=ToolStatus.ERROR, message="No finding available to attach evidence.")
    evidence = Evidence(
        kind=inp.data.get("kind", "manual"),
        file_path=inp.data.get("file_path"),
        function=inp.data.get("function"),
        message=inp.data.get("message", "Additional evidence"),
    )
    state["findings"][0].evidence.append(evidence)
    return ReportGenericOutput(status=ToolStatus.OK, data={"evidence": evidence.model_dump(mode="json")})


def rank_severity(inp: ReportGenericInput, state) -> ReportGenericOutput:
    severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    severity = "info"
    if state.get("findings"):
        severity = max((finding.severity for finding in state["findings"]), key=lambda item: severity_rank[item])
    return ReportGenericOutput(status=ToolStatus.OK, data={"severity": severity})


def generate_markdown(inp: ReportGenericInput, state) -> ReportGenericOutput:
    report = build_report_document(state)
    return ReportGenericOutput(status=ToolStatus.OK, data={"markdown": render_markdown_report(report)})


def generate_repro_steps(inp: ReportGenericInput, state) -> ReportGenericOutput:
    steps = [step for finding in state.get("findings", []) for step in finding.reproduction_steps]
    if not steps and state.get("hypotheses"):
        steps = [f"Write a regression test for {fn}" for fn in state["hypotheses"][0].affected_functions]
    return ReportGenericOutput(status=ToolStatus.OK, data={"reproduction_steps": steps})


def export_artifacts(inp: ReportGenericInput, state) -> ReportGenericOutput:
    run_dir = state.get("run_dir")
    return ReportGenericOutput(
        status=ToolStatus.OK,
        data={
            "run_dir": run_dir,
            "artifacts": [
                "state.json",
                "report.json",
                "report.md",
                "tool_ledger.jsonl",
                "trace.jsonl",
                "logs.jsonl",
                "artifacts/validation-tests/*.t.sol",
                "artifacts/validation-compile-result.json",
            ],
        },
    )


def register(registry) -> None:
    specs = [
        ("create_finding", "Create structured findings from state.", ReportGenericInput, CreateFindingOutput, create_finding),
        ("add_evidence", "Add evidence to a finding.", ReportGenericInput, ReportGenericOutput, add_evidence),
        ("rank_severity", "Rank finding severity.", ReportGenericInput, ReportGenericOutput, rank_severity),
        ("generate_markdown", "Generate Markdown report data.", ReportGenericInput, ReportGenericOutput, generate_markdown),
        ("generate_json", "Generate JSON report data.", ReportGenericInput, ReportGenericOutput, generate_json),
        ("generate_repro_steps", "Generate reproduction steps.", ReportGenericInput, ReportGenericOutput, generate_repro_steps),
        ("export_artifacts", "Export report artifacts.", ReportGenericInput, ReportGenericOutput, export_artifacts),
    ]
    for name, description, input_model, output_model, fn in specs:
        registry.register(RegisteredTool(namespace="report", name=name, description=description, input_model=input_model, output_model=output_model, fn=fn, side_effects=[SideEffect.NONE]))
