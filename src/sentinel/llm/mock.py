from __future__ import annotations

from sentinel.llm.base import (
    BaseAdversarialReviewer,
    BaseHypothesisProposer,
    BaseInvariantInferencer,
    BaseInvariantReasoner,
    BasePlanner,
    BasePocAuthor,
    BasePocRepairer,
    BaseResearchRefiner,
    ToolPlan,
)
from sentinel.schemas.research import AdversarialVerdict, InferredInvariantBatch, ProposedHypothesisBatch, ResearchRefinement


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


class MockInvariantInferencer(BaseInvariantInferencer):
    def infer(self, prompt: str) -> InferredInvariantBatch:
        # Deterministic: no inferred invariants without a model.
        return InferredInvariantBatch()


class MockInvariantReasoner(BaseInvariantReasoner):
    def reason(self, prompt: str) -> ProposedHypothesisBatch:
        # Deterministic: no invariant-violation hypotheses without a model.
        return ProposedHypothesisBatch()


class MockPocRepairer(BasePocRepairer):
    def repair(self, prompt: str) -> str:
        # Deterministic: produce no repair so the loop stops without a model.
        return ""


class MockPocAuthor(BasePocAuthor):
    def author(self, prompt: str) -> str:
        # Deterministic: author nothing so plan-only behavior is unchanged.
        return ""
