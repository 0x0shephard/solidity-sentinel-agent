from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
import time
from typing import Any

import httpx

from sentinel.config import Settings
from sentinel.errors import NonRetryableExternalError, RetryableExternalError


SleepFn = Callable[[float], None]


class SoloditClient:
    """Small typed adapter for the Solodit findings API."""

    def __init__(self, settings: Settings, sleep_fn: SleepFn = time.sleep, timeout: float = 30.0) -> None:
        self.settings = settings
        self.sleep_fn = sleep_fn
        self.timeout = timeout

    def default_filters(self) -> dict[str, Any]:
        return {
            "languages": [{"value": value} for value in self.settings.rag_filter_languages],
            "impact": self.settings.rag_filter_impacts,
            "qualityScore": self.settings.rag_quality_score,
            "sortField": "Quality",
            "sortDirection": "Desc",
        }

    def fetch_page(self, page: int, page_size: int | None = None, filters: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.settings.solodit_api_key:
            raise NonRetryableExternalError("SOLODIT_API_KEY is not configured")
        url = f"{self.settings.solodit_api_url.rstrip('/')}/findings"
        payload = {"page": page, "pageSize": page_size or self.settings.rag_default_page_size, "filters": filters or self.default_filters()}
        headers = {"Content-Type": "application/json", "X-Cyfrin-API-Key": self.settings.solodit_api_key}
        try:
            response = httpx.post(url, headers=headers, json=payload, timeout=self.timeout)
        except httpx.HTTPError as exc:
            raise RetryableExternalError(f"Solodit request failed: {exc}") from exc
        if response.status_code == 429:
            reset = response.headers.get("X-RateLimit-Reset")
            if reset and reset.isdigit():
                delay = max(1.0, float(int(reset) - int(datetime.now(UTC).timestamp())))
            else:
                delay = 60.0
            self.sleep_fn(min(delay, 60.0))
            raise RetryableExternalError("Solodit rate limit exceeded")
        if response.status_code in {400, 401}:
            raise NonRetryableExternalError(response.text)
        if response.status_code >= 500:
            raise RetryableExternalError(response.text)
        response.raise_for_status()
        data = response.json()
        rate_limit = data.get("rateLimit") or {}
        remaining = int(rate_limit.get("remaining") or response.headers.get("X-RateLimit-Remaining") or 1)
        reset = int(rate_limit.get("reset") or response.headers.get("X-RateLimit-Reset") or 0)
        if remaining <= 1 and reset:
            delay = max(0.0, float(reset - int(datetime.now(UTC).timestamp())))
            if delay:
                self.sleep_fn(min(delay, 60.0))
        return data

    def fetch_all(self, filters: dict[str, Any] | None = None) -> tuple[list[dict[str, Any]], int]:
        page = 1
        findings: list[dict[str, Any]] = []
        total_pages = 1
        while page <= total_pages:
            attempts = 0
            while True:
                try:
                    data = self.fetch_page(page=page, filters=filters)
                    break
                except RetryableExternalError:
                    attempts += 1
                    if attempts >= 3:
                        raise
                    self.sleep_fn(min(2 ** attempts, 30))
            findings.extend(data.get("findings", []))
            metadata = data.get("metadata") or {}
            total_pages = int(metadata.get("totalPages") or page)
            page += 1
        return findings, total_pages
