from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
import uuid

from sentinel.artifacts import append_jsonl


@contextmanager
def trace_span(name: str, run_dir: str | None = None, **attrs):
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
        if run_dir:
            append_jsonl(Path(run_dir) / "trace.jsonl", span)

