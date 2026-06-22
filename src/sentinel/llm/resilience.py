"""Resilience for external LLM calls: rate limiting + retries with backoff.

Every provider routes its `llm.invoke(...)` through :func:`invoke_chat`, which
applies a process-wide token-bucket rate limiter and a tenacity retry policy
with exponential backoff on transient/network failures (the kind we saw as
`Broken pipe` against a remote inference endpoint). This is the single choke
point for external-call reliability, so policy lives in one place.
"""

from __future__ import annotations

import threading
import time
from typing import Any

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from sentinel.config import get_settings


class RateLimiter:
    """Thread-safe token bucket: at most ``max_per_minute`` acquisitions/minute."""

    def __init__(self, max_per_minute: int, sleep_fn=time.sleep, clock=time.monotonic) -> None:
        self.capacity = float(max(1, max_per_minute))
        self.tokens = self.capacity
        self.updated = clock()
        self._lock = threading.Lock()
        self._sleep = sleep_fn
        self._clock = clock

    def acquire(self) -> float:
        """Block until a token is available; return seconds waited."""

        with self._lock:
            now = self._clock()
            self.tokens = min(self.capacity, self.tokens + (now - self.updated) * (self.capacity / 60.0))
            self.updated = now
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return 0.0
            wait = (1.0 - self.tokens) * (60.0 / self.capacity)
        self._sleep(wait)
        with self._lock:
            self.tokens = 0.0
            self.updated = self._clock()
        return wait


_limiter: RateLimiter | None = None
_limiter_lock = threading.Lock()
_limiter_capacity: int | None = None


def get_rate_limiter() -> RateLimiter:
    global _limiter, _limiter_capacity
    configured = get_settings().llm_max_calls_per_minute
    with _limiter_lock:
        if _limiter is None or _limiter_capacity != configured:
            _limiter = RateLimiter(configured)
            _limiter_capacity = configured
        return _limiter


_RETRYABLE_TYPES = (
    httpx.TransportError,
    httpx.TimeoutException,
    ConnectionError,
    TimeoutError,
    OSError,  # BrokenPipeError, ConnectionResetError
)
_RETRYABLE_MARKERS = (
    "broken pipe",
    "timed out",
    "timeout",
    "connection",
    "reset by peer",
    "read error",
    "temporarily unavailable",
    "rate limit",
    "429",
    "503",
    "502",
    "overloaded",
    "service unavailable",
    # Ollama Cloud intermittently routes a tagged model (e.g. "qwen3-coder:480b")
    # to a backend that rejects the tag with a transient 400; retry the SAME model
    # rather than silently downgrading to the weaker fallback.
    "model_not_supported",
    "provider or policy you attempted to specify",
)


def is_retryable_error(exc: BaseException) -> bool:
    if isinstance(exc, _RETRYABLE_TYPES):
        return True
    message = str(exc).lower()
    return any(marker in message for marker in _RETRYABLE_MARKERS)


def invoke_chat(llm: Any, messages: Any) -> Any:
    """Invoke a chat model with rate limiting and retry/backoff."""

    settings = get_settings()
    get_rate_limiter().acquire()

    @retry(
        reraise=True,
        stop=stop_after_attempt(settings.llm_max_retries),
        wait=wait_exponential(multiplier=settings.llm_backoff_base_seconds, max=settings.llm_backoff_max_seconds),
        retry=retry_if_exception(is_retryable_error),
    )
    def _call() -> Any:
        return llm.invoke(messages)

    return _call()
