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
    proof_packet_id: str | None = None
    graph_slice_ids: list[str] = Field(default_factory=list)
    validation_questions: list[str] = Field(default_factory=list)
    detector_ids: list[str] = Field(default_factory=list)
    rag_checklist_refs: list[str] = Field(default_factory=list)
    is_detector_only: bool = False
    recommended_validation_template: str
    confidence: float = Field(ge=0.0, le=1.0)


class ProofObligation(BaseModel):
    obligation_id: str
    description: str
    local_evidence: list[SourceEvidence] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    negative_indicators: list[str] = Field(default_factory=list)
    validation_question: str | None = None


class InvariantProofPacket(BaseModel):
    packet_id: str
    candidate_id: str
    invariant_type: str
    invariant_family: str
    title: str
    proof_status: str = "setup_required"
    confidence: float = Field(ge=0.0, le=1.0)
    affected_contracts: list[str] = Field(default_factory=list)
    affected_functions: list[str] = Field(default_factory=list)
    affected_state_variables: list[str] = Field(default_factory=list)
    graph_slice_ids: list[str] = Field(default_factory=list)
    source_evidence: list[SourceEvidence] = Field(default_factory=list)
    local_facts: list[str] = Field(default_factory=list)
    proof_obligations: list[ProofObligation] = Field(default_factory=list)
    counterevidence: list[str] = Field(default_factory=list)
    rag_checklist_refs: list[str] = Field(default_factory=list)
    validation_template: str


class ReasoningDisciplinePacket(BaseModel):
    packet_id: str
    pass_type: str
    function_name: str | None = None
    affected_functions: list[str] = Field(default_factory=list)
    plain_english: str
    assumptions: list[str] = Field(default_factory=list)
    adversarial_questions: list[str] = Field(default_factory=list)
    inversion_traces: list[str] = Field(default_factory=list)
    evidence: list[SourceEvidence] = Field(default_factory=list)


class GapFindingCandidate(BaseModel):
    id: str
    agent_id: str
    gap_type: str
    vulnerability_class: str
    title: str
    confidence: float = Field(ge=0.0, le=1.0)
    affected_functions: list[str] = Field(default_factory=list)
    affected_state_variables: list[str] = Field(default_factory=list)
    evidence: list[SourceEvidence] = Field(default_factory=list)
    adversarial_trace: list[str] = Field(default_factory=list)
    proof_obligations: list[str] = Field(default_factory=list)
    counterevidence: list[str] = Field(default_factory=list)
    validation_template: str
    status: str = "needs_manual_review"


class AuditWorkingMemory(BaseModel):
    function_summaries: list[ReasoningDisciplinePacket] = Field(default_factory=list)
    actor_assumptions: list[str] = Field(default_factory=list)
    open_proof_obligations: list[str] = Field(default_factory=list)
    rejected_hypotheses: list[str] = Field(default_factory=list)
    subagent_disagreements: list[str] = Field(default_factory=list)
    validation_attempts: list[str] = Field(default_factory=list)
    benchmark_lessons: list[str] = Field(default_factory=list)
