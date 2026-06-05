from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime
from functools import lru_cache
import contextlib
import io
import os
import uuid

from sentinel.config import get_settings


_REMOTE_TRACING_ENV = ("LANGCHAIN_TRACING_V2", "LANGCHAIN_TRACING", "LANGSMITH_TRACING")


def configure_tracing() -> bool:
    """Reconcile LangChain/LangSmith auto-tracing with Sentinel settings.

    LangChain auto-traces every LLM call when any of the LANGSMITH/LANGCHAIN
    tracing env vars are truthy. If the configured LangSmith endpoint is
    unreachable, each span blocks on a 10s connect timeout and stalls the whole
    audit. This reconciles the env with our settings: remote tracing stays on
    only when it is enabled *and* the endpoint is actually writable; otherwise
    every auto-tracing env var is forced off so runs degrade to local spans.

    Returns True when remote tracing is active.
    """

    settings = get_settings()
    active = False
    if settings.langsmith_tracing and settings.langsmith_api_key:
        active = _langsmith_trace_writable(settings.langsmith_api_key, settings.langsmith_project)
    if not active:
        for var in _REMOTE_TRACING_ENV:
            os.environ[var] = "false"
    return active


@lru_cache(maxsize=8)
def _langsmith_trace_writable(api_key: str, project_name: str) -> bool:
    """Return whether this key can write traces to the configured project.

    Constructing a LangSmith client is not enough: invalid workspace/project
    permissions often fail only when posting runs. This preflight keeps a bad
    key from producing noisy async multipart-ingest failures during every tool
    span.
    """

    try:
        from langsmith import Client

        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            client = Client(api_key=api_key)
            try:
                client.read_project(project_name=project_name)
            except Exception:
                client.create_project(project_name=project_name, upsert=True)
            run_id = uuid.uuid4()
            client.create_run(
                id=run_id,
                name="sentinel.langsmith_preflight",
                run_type="chain",
                inputs={"purpose": "trace_write_preflight"},
                project_name=project_name,
            )
            client.update_run(run_id, outputs={"ok": True}, end_time=datetime.now(UTC))
        return True
    except Exception:
        return False


@contextmanager
def trace_span(name: str, run_dir: str | None = None, **attrs):
    settings = get_settings()
    if (
        settings.langsmith_tracing
        and settings.langsmith_api_key
        and _langsmith_trace_writable(settings.langsmith_api_key, settings.langsmith_project)
    ):
        try:
            from langsmith import Client

            client = Client(api_key=settings.langsmith_api_key)
            run_id = uuid.uuid4()
            client.create_run(
                id=run_id,
                name=name,
                run_type="chain",
                inputs=attrs,
                project_name=settings.langsmith_project,
            )
            try:
                yield {"id": str(run_id), "name": name, "langsmith": True}
                client.update_run(run_id, outputs={"status": "ok"}, end_time=datetime.now(UTC))
            except Exception as exc:
                client.update_run(
                    run_id,
                    error=f"{type(exc).__name__}: {exc}",
                    outputs={"status": "error"},
                    end_time=datetime.now(UTC),
                )
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
