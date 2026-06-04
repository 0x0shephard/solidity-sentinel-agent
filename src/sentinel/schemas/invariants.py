from __future__ import annotations

from pydantic import BaseModel, Field

from sentinel.schemas.static import SourceEvidence


class ProtocolModel(BaseModel):
    contracts: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    assets: list[str] = Field(default_factory=list)
    accounting_terms: list[str] = Field(default_factory=list)
    lifecycle_terms: list[str] = Field(default_factory=list)
    upgrade_terms: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class InvariantCandidate(BaseModel):
    id: str
    invariant_type: str
    invariant_family: str | None = None
    description: str
    affected_contracts: list[str] = Field(default_factory=list)
    affected_functions: list[str] = Field(default_factory=list)
    affected_state_variables: list[str] = Field(default_factory=list)
    production_evidence: list[SourceEvidence] = Field(default_factory=list)
    missing_guard_terms: list[str] = Field(default_factory=list)
    suspicious_terms: list[str] = Field(default_factory=list)
    local_facts: list[str] = Field(default_factory=list)
    required_proof: str | None = None
    proof_status: str = "setup_required"
    graph_slice_ids: list[str] = Field(default_factory=list)
    validation_questions: list[str] = Field(default_factory=list)
    detector_ids: list[str] = Field(default_factory=list)
    rag_checklist_refs: list[str] = Field(default_factory=list)
    is_detector_only: bool = False
    recommended_validation_template: str
    confidence: float = Field(ge=0.0, le=1.0)
