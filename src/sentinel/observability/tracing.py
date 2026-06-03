from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime
import uuid

from sentinel.config import get_settings


@contextmanager
def trace_span(name: str, run_dir: str | None = None, **attrs):
    settings = get_settings()
    if settings.langsmith_tracing and settings.langsmith_api_key:
        try:
            from langsmith.run_helpers import trace

            with trace(name, run_type="chain", inputs=attrs, project_name=settings.langsmith_project) as run:
                try:
                    yield run
                except Exception:
                    raise
            return
        except Exception:
            pass
    span = {
        "trace_id": attrs.get("trace_id") or str(uuid.uuid4()),
        "span_id": str(uuid.uuid4()),
        "name": name,
        "start_time": datetime.now(UTC).isoformat(),
        "attrs": attrs,
        "status": "running",
    }
    try:
        yield span
        span["status"] = "ok"
    except Exception as exc:
        span["status"] = "error"
        span["error_type"] = type(exc).__name__
        span["error_message"] = str(exc)
        raise
    finally:
        span["end_time"] = datetime.now(UTC).isoformat()
