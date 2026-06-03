from __future__ import annotations

from pydantic import BaseModel, Field

from sentinel.schemas.common import ToolStatus


class SourceEvidence(BaseModel):
    file_path: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    contract_name: str | None = None
    function_name: str | None = None
    source_text: str
    reason: str


class FunctionRange(BaseModel):
    file_path: str
    contract_name: str | None = None
    function_name: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    signature: str


class StaticDetection(BaseModel):
    detector_id: str
    vulnerability_class: str
    title: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[SourceEvidence] = Field(default_factory=list)
    affected_functions: list[str] = Field(default_factory=list)
    root_cause_terms: list[str] = Field(default_factory=list)
    recommendation_hint: str
    checklist_refs: list[str] = Field(default_factory=list)


class StaticDetectionsOutput(BaseModel):
    status: ToolStatus
    detections: list[StaticDetection] = Field(default_factory=list)
    message: str | None = None


class SoloditChecklistItem(BaseModel):
    checklist_id: str
    vulnerability_class: str
    historical_titles: list[str] = Field(default_factory=list)
    root_cause_terms: list[str] = Field(default_factory=list)
    code_indicators: list[str] = Field(default_factory=list)
    required_local_evidence: list[str] = Field(default_factory=list)
    negative_indicators: list[str] = Field(default_factory=list)
    validation_questions: list[str] = Field(default_factory=list)
    reporting_guidance: str

