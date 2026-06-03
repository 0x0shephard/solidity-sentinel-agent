from __future__ import annotations

from pydantic import BaseModel, Field

from sentinel.schemas.research import ResearchRefinement


class ToolDecision(BaseModel):
    tool_name: str
    tool_input: dict = Field(default_factory=dict)
    rationale: str = ""
    output_references: list[dict] = Field(default_factory=list)


class ToolPlan(BaseModel):
    decisions: list[ToolDecision] = Field(default_factory=list)
    stop: bool = False


class BasePlanner:
    def plan(self, prompt: str, tools: list[dict]) -> ToolPlan:
        raise NotImplementedError


class BaseResearchRefiner:
    def refine(self, prompt: str) -> ResearchRefinement:
        raise NotImplementedError
