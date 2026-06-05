from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from sentinel.schemas.common import ToolStatus
from sentinel.schemas.rag import RAGContextBundle
from sentinel.schemas.static import SourceEvidence


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
    affected_contract: str | None = None
    affected_function: str | None = None
    evidence_lines: list[SourceEvidence] = Field(default_factory=list)
    root_cause_terms: list[str] = Field(default_factory=list)
    recommended_validation: list[str] = Field(default_factory=list)
    historical_matches: list[dict] = Field(default_factory=list)
    source_detection_ids: list[str] = Field(default_factory=list)
    graph_slice_ids: list[str] = Field(default_factory=list)
    proof_packet_id: str | None = None
    proof_obligations: list[str] = Field(default_factory=list)
    counterevidence: list[str] = Field(default_factory=list)
    proof_status: str = "setup_required"
    exploit_precondition_terms: list[str] = Field(default_factory=list)
    suggested_rag_queries: list[str] = Field(default_factory=list)
    status: Literal["confirmed", "likely", "needs_manual_review", "rejected"] = "likely"


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
    finding_status: Literal["confirmed", "likely", "needs_manual_review", "rejected"] = "likely"
    reasoning_summary: str | None = None
    historical_context_used: bool = False
    rag_context_bundle: RAGContextBundle | None = None


class ResearchRefinement(BaseModel):
    likely_impact: str | None = None
    exploit_preconditions: list[str] = Field(default_factory=list)
    recommended_tests: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    confidence_delta: float = Field(default=0.0, ge=-0.2, le=0.2)


class ProposedHypothesis(BaseModel):
    """A model-proposed, code-specific vulnerability lead.

    The model only *names* the file and function it is reasoning about; the
    proposer tool attaches the real source from the repository's function ranges
    and drops any proposal that does not ground to existing code. This keeps
    proposals evidence-grounded rather than hallucinated.
    """

    title: str
    vulnerability_class: str
    affected_file: str
    affected_function: str
    affected_contract: str | None = None
    reasoning: str = ""
    exploit_preconditions: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class ProposedHypothesisBatch(BaseModel):
    hypotheses: list[ProposedHypothesis] = Field(default_factory=list)


class AdversarialVerdict(BaseModel):
    """Result of adversarially deepening a hypothesis against its callers.

    The reviewer is shown the affected function plus its cross-contract callers
    and must either construct a concrete attack trace (confirm) or cite the
    mitigation it found (reject), e.g. an atomic initialize+wire in a factory.
    """

    verdict: Literal["confirmed", "likely", "rejected", "needs_manual_review"] = "needs_manual_review"
    attack_trace: list[str] = Field(default_factory=list)
    counterevidence: list[str] = Field(default_factory=list)
    reasoning: str = ""
    confidence_delta: float = Field(default=0.0, ge=-0.5, le=0.5)
