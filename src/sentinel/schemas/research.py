from __future__ import annotations

from pydantic import BaseModel, Field

from sentinel.schemas.common import ToolStatus


class SlitherFinding(BaseModel):
    check: str
    impact: str | None = None
    confidence: str | None = None
    description: str
    elements: list[dict] = Field(default_factory=list)
    source_files: list[str] = Field(default_factory=list)
    functions: list[str] = Field(default_factory=list)


class VulnerabilityHypothesis(BaseModel):
    id: str
    title: str
    vulnerability_class: str
    affected_files: list[str] = Field(default_factory=list)
    affected_functions: list[str] = Field(default_factory=list)
    evidence_summary: str
    confidence: float = Field(ge=0.0, le=1.0)


class ResearchSubgraphResult(BaseModel):
    status: ToolStatus
    subgraph_run_id: str
    hypothesis_id: str
    refined_title: str
    vulnerability_class: str
    evidence: list[dict] = Field(default_factory=list)
    exploit_preconditions: list[str] = Field(default_factory=list)
    likely_impact: str
    evidence_to_collect: list[str] = Field(default_factory=list)
    recommended_tests: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    limitations: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    historical_findings: list[dict] = Field(default_factory=list)
    subagent_tool_ledger: list[dict] = Field(default_factory=list)


class ResearchRefinement(BaseModel):
    likely_impact: str | None = None
    exploit_preconditions: list[str] = Field(default_factory=list)
    recommended_tests: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    confidence_delta: float = Field(default=0.0, ge=-0.2, le=0.2)
