from __future__ import annotations

from sentinel.llm.base import (
    BaseAdversarialReviewer,
    BaseHypothesisProposer,
    BasePlanner,
    BaseResearchRefiner,
    ToolPlan,
)
from sentinel.schemas.research import AdversarialVerdict, ProposedHypothesisBatch, ResearchRefinement


class MockPlanner(BasePlanner):
    def plan(self, prompt: str, tools: list[dict]) -> ToolPlan:
        return ToolPlan(decisions=[])


class MockResearchRefiner(BaseResearchRefiner):
    def refine(self, prompt: str) -> ResearchRefinement:
        return ResearchRefinement()


class MockHypothesisProposer(BaseHypothesisProposer):
    def propose(self, prompt: str) -> ProposedHypothesisBatch:
        return ProposedHypothesisBatch()


class MockAdversarialReviewer(BaseAdversarialReviewer):
    def review(self, prompt: str) -> AdversarialVerdict:
        return AdversarialVerdict()
