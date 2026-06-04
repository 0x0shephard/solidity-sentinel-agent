from __future__ import annotations

from pydantic import BaseModel, Field


class EvalScore(BaseModel):
    fixture: str
    completed: bool
    tool_call_count: int = Field(ge=0)
    used_20_plus_tools: bool
    spawned_research_subgraph: bool
    generated_json_report: bool
    generated_markdown_report: bool
    expected_class_found: bool
    expected_function_found: bool
    evidence_present: bool
    composition_chain_present: bool
    hypothesis_recall: float = Field(default=0.0, ge=0.0, le=1.0)
    finding_recall: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_coverage: float = Field(default=0.0, ge=0.0, le=1.0)
    production_evidence_coverage: float = Field(default=0.0, ge=0.0, le=1.0)
    rag_context_coverage: float = Field(default=0.0, ge=0.0, le=1.0)
    unsupported_claim_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    false_positive_count: int = Field(default=0, ge=0)
    invariant_candidate_count: int = Field(default=0, ge=0)
    proof_success_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    cross_contract_evidence_coverage: float = Field(default=0.0, ge=0.0, le=1.0)
    rag_useful_context_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    novel_pattern_discovery_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    high_severity_recall: float = Field(default=0.0, ge=0.0, le=1.0)
    contest_recall: float = Field(default=0.0, ge=0.0, le=1.0)
    false_likely_count: int = Field(default=0, ge=0)
    rejected_counterevidence_quality: float = Field(default=0.0, ge=0.0, le=1.0)
    executable_poc_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    actor_model_coverage: float = Field(default=0.0, ge=0.0, le=1.0)
    transaction_race_coverage: float = Field(default=0.0, ge=0.0, le=1.0)
    gap_agent_contribution_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    validation_artifacts_compile: bool = False
    score: float = Field(ge=0.0, le=100.0)
    notes: list[str] = Field(default_factory=list)
