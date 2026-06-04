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
    description: str
    affected_contracts: list[str] = Field(default_factory=list)
    affected_functions: list[str] = Field(default_factory=list)
    production_evidence: list[SourceEvidence] = Field(default_factory=list)
    missing_guard_terms: list[str] = Field(default_factory=list)
    suspicious_terms: list[str] = Field(default_factory=list)
    recommended_validation_template: str
    confidence: float = Field(ge=0.0, le=1.0)
