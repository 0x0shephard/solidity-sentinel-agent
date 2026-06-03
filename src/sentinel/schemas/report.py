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
    artifact: ArtifactRef | None = None


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
    status: str = "likely"


class ReportDocument(BaseModel):
    run_id: str
    objective: str
    repo_path: str
    findings: list[Finding] = Field(default_factory=list)
    needs_manual_review: list[Finding] = Field(default_factory=list)
    rejected_hypotheses: list[Finding] = Field(default_factory=list)
    artifacts: list[ArtifactRef] = Field(default_factory=list)
    tool_call_count: int = Field(ge=0)
    subgraphs_spawned: int = Field(ge=0)
