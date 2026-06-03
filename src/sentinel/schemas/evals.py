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
    rag_context_coverage: float = Field(default=0.0, ge=0.0, le=1.0)
    unsupported_claim_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    false_positive_count: int = Field(default=0, ge=0)
    score: float = Field(ge=0.0, le=100.0)
    notes: list[str] = Field(default_factory=list)
