from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from sentinel.schemas.common import ArtifactRef


class Evidence(BaseModel):
    kind: str
    file_path: str | None = None
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    function: str | None = None
    message: str
    source_type: str = "unknown"
    evidence_role: str = "supporting"
    artifact: ArtifactRef | None = None


class AnalysisToolStatus(BaseModel):
    attempted: bool = False
    status: str = "not_attempted"
    message: str | None = None


class AnalysisCompleteness(BaseModel):
    build: AnalysisToolStatus = Field(default_factory=AnalysisToolStatus)
    slither: AnalysisToolStatus = Field(default_factory=AnalysisToolStatus)
    aderyn: AnalysisToolStatus = Field(default_factory=AnalysisToolStatus)
    validation: AnalysisToolStatus = Field(default_factory=AnalysisToolStatus)
    confidence_penalty: float = Field(default=0.0, ge=0.0, le=1.0)
    limitations: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    id: str
    title: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    confidence: float = Field(ge=0.0, le=1.0)
    vulnerability_class: str
    summary: str
    affected_files: list[str] = Field(default_factory=list)
    affected_functions: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    reproduction_steps: list[str] = Field(default_factory=list)
    recommendation: str | None = None
    limitations: list[str] = Field(default_factory=list)
    historical_matches: list[dict] = Field(default_factory=list)
    graph_slice_ids: list[str] = Field(default_factory=list)
    proof_status: str = "setup_required"
    status: str = "likely"


class ReportDocument(BaseModel):
    run_id: str
    objective: str
    repo_path: str
    findings: list[Finding] = Field(default_factory=list)
    needs_manual_review: list[Finding] = Field(default_factory=list)
    suspicious_hypotheses: list[Finding] = Field(default_factory=list)
    rejected_hypotheses: list[Finding] = Field(default_factory=list)
    analysis_completeness: AnalysisCompleteness | None = None
    artifacts: list[ArtifactRef] = Field(default_factory=list)
    tool_call_count: int = Field(ge=0)
    subgraphs_spawned: int = Field(ge=0)
