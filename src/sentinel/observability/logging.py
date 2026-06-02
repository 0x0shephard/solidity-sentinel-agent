from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from sentinel.artifacts import append_jsonl


def log_event(run_dir: str | None, **event) -> None:
    event.setdefault("time", datetime.now(UTC).isoformat())
    if run_dir:
        append_jsonl(Path(run_dir) / "logs.jsonl", event)

