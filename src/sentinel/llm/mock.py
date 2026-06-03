from __future__ import annotations

from sentinel.llm.base import BasePlanner, BaseResearchRefiner, ToolPlan
from sentinel.schemas.research import ResearchRefinement


class MockPlanner(BasePlanner):
    def plan(self, prompt: str, tools: list[dict]) -> ToolPlan:
        return ToolPlan(decisions=[])


class MockResearchRefiner(BaseResearchRefiner):
    def refine(self, prompt: str) -> ResearchRefinement:
        return ResearchRefinement()
