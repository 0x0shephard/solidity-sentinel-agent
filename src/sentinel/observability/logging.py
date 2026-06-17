from __future__ import annotations

from datetime import UTC, datetime

from sentinel.config import get_settings
from sentinel.observability.progress import emit


def _emit_progress(event: dict) -> None:
    """Translate a structured event into a live progress line (when streaming).

    Args:
        event: The event kwargs passed to ``log_event`` (kind, tool_name, etc.).
    Returns:
        None. Emits one concise line per tool start / failure / lifecycle event;
        a no-op when no progress sink is installed.
    """
    kind = event.get("event")
    if kind == "tool_started":
        emit(f"  → {event.get('tool_name')}")
    elif kind == "tool_failed":
        emit(f"  ✗ {event.get('tool_name')}: {event.get('error_type', 'error')}")
    elif kind == "run_started":
        emit("▶ audit started")
    elif kind == "report_generated":
        emit(f"✓ report generated — {event.get('finding_count', 0)} findings")
    elif kind == "run_finished":
        emit(f"✓ audit complete — {event.get('tool_call_count', 0)} tool calls")


def log_event(run_dir: str | None, **event) -> None:
    """Record lightweight events only through LangSmith-enabled traces.

    Local logs.jsonl was intentionally retired as the primary observability
    surface. The durable local artifacts are state, reports, eval summaries,
    validation artifacts, and tool_ledger.jsonl. Also streams a human-readable
    progress line when a progress sink is installed.

    Args:
        run_dir: The run directory (unused locally; kept for the trace surface).
        **event: Event fields (``event`` kind, ``tool_name``, ``status``, ...).
    Returns:
        None.
    """

    event.setdefault("time", datetime.now(UTC).isoformat())
    _emit_progress(event)
    settings = get_settings()
    if settings.langsmith_tracing and settings.langsmith_api_key:
        try:
            from langsmith import Client

            Client(api_key=settings.langsmith_api_key)
        except Exception:
            return
