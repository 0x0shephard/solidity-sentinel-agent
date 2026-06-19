from __future__ import annotations

from pydantic import BaseModel, Field

from sentinel.schemas.research import AdversarialVerdict, ProposedHypothesisBatch, ResearchRefinement


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


class BaseHypothesisProposer:
    def propose(self, prompt: str) -> ProposedHypothesisBatch:
        raise NotImplementedError


class BaseAdversarialReviewer:
    def review(self, prompt: str) -> AdversarialVerdict:
        raise NotImplementedError


class BasePocRepairer:
    """Repairs a generated Foundry PoC test that failed to compile.

    Given the failing test source, the real target-contract source, and the
    compiler stderr, returns corrected Solidity test source (or "" to signal no
    repair was produced, so the caller stops retrying).
    """

    def repair(self, prompt: str) -> str:
        raise NotImplementedError


class BasePocAuthor:
    """Authors an executable Foundry PoC for a hypothesis by inheriting the
    protocol's own test fixture (so proxies/initializers are set up correctly).

    Returns Solidity test source, or "" when no PoC could be authored.
    """

    def author(self, prompt: str) -> str:
        raise NotImplementedError
