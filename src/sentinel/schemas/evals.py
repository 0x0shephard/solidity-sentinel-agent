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
    score: float = Field(ge=0.0, le=100.0)
    notes: list[str] = Field(default_factory=list)

