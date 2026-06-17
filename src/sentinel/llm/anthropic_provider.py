"""Anthropic Claude provider — the frontier-model path for landing crit/high.

Implements the four LLM capabilities (planner, research refiner, hypothesis
proposer, adversarial reviewer) on the official ``anthropic`` SDK. Uses adaptive
thinking + the ``effort`` control (no ``temperature``/``budget_tokens``, which
are removed on Opus 4.7/4.8), streams the response so long reasoning never trips
the SDK timeout guard, and reuses the existing JSON parsers/coercers so output
handling is identical across providers.

The ``anthropic`` package is imported lazily so the rest of Sentinel runs without
it installed; selecting this provider without the package raises a clear error.
"""

from __future__ import annotations

import json

from sentinel.config import get_settings
from sentinel.errors import ConfigurationError
from sentinel.llm.base import (
    BaseAdversarialReviewer,
    BaseHypothesisProposer,
    BasePlanner,
    BaseResearchRefiner,
    ToolPlan,
)
from sentinel.llm.ollama import (
    _PROPOSER_SYSTEM,
    _REVIEWER_SYSTEM,
    extract_json_object,
    parse_adversarial_verdict,
    parse_proposed_hypotheses,
    parse_research_refinement,
)
from sentinel.llm.resilience import get_rate_limiter
from sentinel.schemas.research import AdversarialVerdict, ProposedHypothesisBatch, ResearchRefinement


_PLANNER_SYSTEM = (
    "You are Solidity Sentinel's planner. Return only JSON with this schema: "
    '{"decisions":[{"tool_name":"audit.inspect_repo","tool_input":{"repo_path":"..."},"rationale":"why"}],"stop":false}. '
    "Choose only from the provided tool catalog and respect schemas, risks, side effects, and chaining hints. "
    "Prefer the composite audit.* tools to advance milestones. Set stop=true only when no useful tool remains."
)

_REFINER_SYSTEM = (
    "You refine Solidity audit hypotheses. Return only JSON with keys: "
    "likely_impact, exploit_preconditions, recommended_tests, limitations, confidence_delta. "
    "Do not invent files, line numbers, or functions outside the supplied evidence."
)


class _AnthropicChat:
    """Shared Claude chat helper: streamed completion with thinking + effort."""

    def __init__(
        self,
        model: str,
        api_key: str | None = None,
        effort: str = "high",
        thinking: bool = True,
        max_tokens: int = 16000,
        client=None,
    ) -> None:
        self.model = model
        self.effort = effort
        self.thinking = thinking
        self.max_tokens = max_tokens
        if client is not None:
            self.client = client
            return
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - exercised only without the dep
            raise ConfigurationError(
                "The 'anthropic' package is required for SENTINEL_LLM_PROVIDER=anthropic. Install it with: pip install anthropic"
            ) from exc
        self.client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()

    def _stream_text(self, kwargs: dict) -> str:
        with self.client.messages.stream(**kwargs) as stream:
            message = stream.get_final_message()
        return "".join(getattr(block, "text", "") for block in message.content if getattr(block, "type", None) == "text")

    def _chat(self, system: str, user: str) -> str:
        """Run one rate-limited Claude completion and return its text.

        Args:
            system: System prompt (role/persona + output schema).
            user: The full user message (prompt + any catalog/evidence).
        Returns:
            The concatenated text of the response's text blocks (thinking blocks
            are skipped). Falls back to a plain request if the installed SDK does
            not accept the thinking/effort kwargs.
        """
        get_rate_limiter().acquire()
        base = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        extras: dict = {}
        if self.thinking:
            extras["thinking"] = {"type": "adaptive"}
        if self.effort:
            extras["output_config"] = {"effort": self.effort}
        try:
            return self._stream_text({**base, **extras})
        except TypeError:
            # Older anthropic SDK without thinking/output_config kwargs.
            return self._stream_text(base)


class AnthropicPlanner(_AnthropicChat, BasePlanner):
    def plan(self, prompt: str, tools: list[dict]) -> ToolPlan:
        catalog = json.dumps(tools, indent=2, default=str)[:120_000]
        content = self._chat(_PLANNER_SYSTEM, f"{prompt}\n\nTool catalog:\n{catalog}")
        return ToolPlan.model_validate_json(extract_json_object(content))


class AnthropicResearchRefiner(_AnthropicChat, BaseResearchRefiner):
    def refine(self, prompt: str) -> ResearchRefinement:
        content = self._chat(_REFINER_SYSTEM, prompt)
        return parse_research_refinement(content)


class AnthropicHypothesisProposer(_AnthropicChat, BaseHypothesisProposer):
    def propose(self, prompt: str) -> ProposedHypothesisBatch:
        self.last_raw = ""
        content = self._chat(_PROPOSER_SYSTEM, prompt)
        self.last_raw = content
        return parse_proposed_hypotheses(content)


class AnthropicAdversarialReviewer(_AnthropicChat, BaseAdversarialReviewer):
    def review(self, prompt: str) -> AdversarialVerdict:
        content = self._chat(_REVIEWER_SYSTEM, prompt)
        return parse_adversarial_verdict(content)


def _anthropic_kwargs(settings) -> dict:
    """Resolve the constructor kwargs for the Anthropic capability classes.

    Args:
        settings: The active ``Settings``.
    Returns:
        kwargs dict (model/api_key/effort/thinking/max_tokens) shared by all four
        Anthropic capability classes.
    Raises:
        ConfigurationError: if no Anthropic API key is configured.
    """
    if not settings.anthropic_api_key:
        raise ConfigurationError("ANTHROPIC_API_KEY is required when SENTINEL_LLM_PROVIDER=anthropic")
    return {
        "model": settings.anthropic_model,
        "api_key": settings.anthropic_api_key,
        "effort": settings.anthropic_effort,
        "thinking": settings.anthropic_thinking,
        "max_tokens": settings.anthropic_max_tokens,
    }
