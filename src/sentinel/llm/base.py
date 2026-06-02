from __future__ import annotations

from pydantic import BaseModel, Field


class ToolDecision(BaseModel):
    tool_name: str
    tool_input: dict = Field(default_factory=dict)
    rationale: str = ""


class ToolPlan(BaseModel):
    decisions: list[ToolDecision] = Field(default_factory=list)


class BasePlanner:
    def plan(self, prompt: str, tools: list[dict]) -> ToolPlan:
        raise NotImplementedError

