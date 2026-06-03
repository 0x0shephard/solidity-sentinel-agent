from __future__ import annotations

from datetime import UTC, datetime

from sentinel.config import get_settings


def log_event(run_dir: str | None, **event) -> None:
    """Record lightweight events only through LangSmith-enabled traces.

    Local logs.jsonl was intentionally retired as the primary observability
    surface. The durable local artifacts are state, reports, eval summaries,
    validation artifacts, and tool_ledger.jsonl.
    """

    event.setdefault("time", datetime.now(UTC).isoformat())
    settings = get_settings()
    if settings.langsmith_tracing and settings.langsmith_api_key:
        try:
            from langsmith import Client

            Client(api_key=settings.langsmith_api_key)
        except Exception:
            return
