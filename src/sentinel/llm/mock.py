from __future__ import annotations

from sentinel.llm.base import BasePlanner, ToolPlan


class MockPlanner(BasePlanner):
    def plan(self, prompt: str, tools: list[dict]) -> ToolPlan:
        return ToolPlan(decisions=[])

