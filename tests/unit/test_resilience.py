from __future__ import annotations

import httpx
import pytest

from sentinel.llm.resilience import RateLimiter, invoke_chat, is_retryable_error


def test_is_retryable_error_classifies_network_vs_logic():
    assert is_retryable_error(OSError("Broken pipe"))
    assert is_retryable_error(httpx.ReadError("read error"))
    assert is_retryable_error(TimeoutError("timed out"))
    assert is_retryable_error(RuntimeError("429 rate limit"))
    assert not is_retryable_error(ValueError("model returned bad json"))


def test_rate_limiter_throttles_after_capacity():
    waited: list[float] = []
    clock = {"t": 0.0}
    rl = RateLimiter(60, sleep_fn=lambda s: waited.append(s), clock=lambda: clock["t"])
    for _ in range(60):
        assert rl.acquire() == 0.0
    # 61st within the same minute must block.
    assert rl.acquire() > 0.0
    assert waited and waited[0] > 0.0


class _FlakyLLM:
    def __init__(self, fail_times: int, exc: Exception):
        self.calls = 0
        self.fail_times = fail_times
        self.exc = exc

    def invoke(self, messages):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise self.exc
        return "ok"


def test_invoke_chat_retries_transient_then_succeeds(monkeypatch):
    monkeypatch.setenv("SENTINEL_LLM_BACKOFF_BASE_SECONDS", "0")
    monkeypatch.setenv("SENTINEL_LLM_BACKOFF_MAX_SECONDS", "0")
    monkeypatch.setenv("SENTINEL_LLM_MAX_CALLS_PER_MINUTE", "100000")
    monkeypatch.setenv("SENTINEL_LLM_MAX_RETRIES", "3")
    llm = _FlakyLLM(fail_times=2, exc=httpx.ReadError("Broken pipe"))
    assert invoke_chat(llm, ["m"]) == "ok"
    assert llm.calls == 3


def test_invoke_chat_does_not_retry_logic_errors(monkeypatch):
    monkeypatch.setenv("SENTINEL_LLM_BACKOFF_BASE_SECONDS", "0")
    monkeypatch.setenv("SENTINEL_LLM_MAX_CALLS_PER_MINUTE", "100000")
    monkeypatch.setenv("SENTINEL_LLM_MAX_RETRIES", "3")
    llm = _FlakyLLM(fail_times=5, exc=ValueError("bad json"))
    with pytest.raises(ValueError):
        invoke_chat(llm, ["m"])
    assert llm.calls == 1
