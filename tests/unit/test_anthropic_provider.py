from __future__ import annotations

import types

import pytest

from sentinel.config import Settings
from sentinel.errors import ConfigurationError
from sentinel.llm.anthropic_provider import (
    AnthropicAdversarialReviewer,
    AnthropicHypothesisProposer,
    AnthropicPlanner,
    AnthropicResearchRefiner,
)
from sentinel.llm.provider import get_planner


class _FakeStream:
    def __init__(self, text: str, kwargs: dict, sink: list) -> None:
        self._text = text
        self._kwargs = kwargs
        self._sink = sink

    def __enter__(self):
        self._sink.append(self._kwargs)
        return self

    def __exit__(self, *exc):
        return False

    def get_final_message(self):
        # thinking block (empty text by default) + the JSON text block
        return types.SimpleNamespace(
            content=[
                types.SimpleNamespace(type="thinking", text=""),
                types.SimpleNamespace(type="text", text=self._text),
            ]
        )


class _FakeMessages:
    def __init__(self, text: str, sink: list, reject_extras: bool) -> None:
        self._text = text
        self._sink = sink
        self._reject_extras = reject_extras

    def stream(self, **kwargs):
        if self._reject_extras and ("thinking" in kwargs or "output_config" in kwargs):
            raise TypeError("unexpected keyword argument")
        return _FakeStream(self._text, kwargs, self._sink)


class FakeClient:
    """Stand-in for anthropic.Anthropic with a streamed JSON response."""

    def __init__(self, text: str, reject_extras: bool = False) -> None:
        self.sink: list[dict] = []
        self.messages = _FakeMessages(text, self.sink, reject_extras)


def test_anthropic_planner_parses_tool_plan():
    raw = '{"decisions":[{"tool_name":"audit.inspect_repo","tool_input":{"repo_path":"."},"rationale":"go"}],"stop":false}'
    client = FakeClient(raw)
    plan = AnthropicPlanner(model="claude-opus-4-8", client=client).plan("prompt", [{"name": "audit.inspect_repo"}])
    assert plan.decisions[0].tool_name == "audit.inspect_repo"
    # adaptive thinking + effort are sent by default
    assert client.sink[0]["thinking"] == {"type": "adaptive"}
    assert client.sink[0]["output_config"] == {"effort": "high"}


def test_anthropic_proposer_parses_and_records_raw():
    raw = '{"hypotheses":[{"title":"Unprotected init","vulnerability_class":"access_control","affected_file":"src/A.sol","affected_function":"initialize"}]}'
    proposer = AnthropicHypothesisProposer(model="claude-opus-4-8", client=FakeClient(raw))
    batch = proposer.propose("prompt")
    assert len(batch.hypotheses) == 1
    assert batch.hypotheses[0].affected_function == "initialize"
    assert proposer.last_raw == raw


def test_anthropic_reviewer_parses_verdict():
    raw = '{"verdict":"rejected","counterevidence":["wired atomically in Factory.create"],"reasoning":"no window"}'
    verdict = AnthropicAdversarialReviewer(model="claude-opus-4-8", client=FakeClient(raw)).review("prompt")
    assert verdict.verdict == "rejected"
    assert verdict.counterevidence == ["wired atomically in Factory.create"]


def test_anthropic_refiner_parses_refinement():
    raw = '{"likely_impact":"funds at risk","exploit_preconditions":["attacker reaches f"],"confidence_delta":0.1}'
    refinement = AnthropicResearchRefiner(model="claude-opus-4-8", client=FakeClient(raw)).refine("prompt")
    assert refinement.likely_impact == "funds at risk"
    assert refinement.exploit_preconditions == ["attacker reaches f"]


def test_anthropic_falls_back_when_sdk_rejects_thinking_kwargs():
    client = FakeClient('{"hypotheses":[]}', reject_extras=True)
    batch = AnthropicHypothesisProposer(model="claude-opus-4-8", client=client).propose("prompt")
    assert batch.hypotheses == []
    # retried without thinking/output_config
    assert "thinking" not in client.sink[-1]
    assert "output_config" not in client.sink[-1]


def test_thinking_disabled_omits_kwarg():
    client = FakeClient('{"decisions":[],"stop":true}')
    AnthropicPlanner(model="claude-opus-4-8", thinking=False, effort="", client=client).plan("p", [])
    assert "thinking" not in client.sink[0]
    assert "output_config" not in client.sink[0]


def test_factory_anthropic_requires_api_key():
    settings = Settings(llm_provider="anthropic", anthropic_api_key=None)
    with pytest.raises(ConfigurationError):
        get_planner(settings=settings)
