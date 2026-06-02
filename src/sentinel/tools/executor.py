from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
import time
import uuid

from pydantic import BaseModel, ValidationError

from sentinel.errors import ToolExecutionError, ToolValidationError
from sentinel.schemas.common import ToolCallRecord, ToolStatus
from sentinel.state import AuditState
from sentinel.tools.registry import ToolRegistry


def _json_hash(payload: object) -> str:
    raw = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class ToolExecutor:
    """The only layer that invokes tools.

    This is our enforcement boundary. LangGraph nodes will choose tool names
    and inputs, but this executor validates schemas, runs the tool, validates
    output, and records a ledger entry.
    """

    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry

    def execute(self, tool_name: str, raw_input: dict, state: AuditState) -> BaseModel:
        tool = self.registry.get(tool_name)
        started_at = datetime.now(UTC)
        start_timer = time.perf_counter()
        call_id = str(uuid.uuid4())
        record = ToolCallRecord(
            call_id=call_id,
            run_id=state["run_id"],
            tool_name=tool.full_name,
            namespace=tool.namespace,
            input_hash=_json_hash(raw_input),
            status=ToolStatus.OK,
            started_at=started_at.isoformat(),
        )

        try:
            parsed_input = tool.input_model.model_validate(raw_input)
        except ValidationError as exc:
            record.status = ToolStatus.ERROR
            record.error_type = "ToolValidationError"
            record.error_message = str(exc)
            self._record_call(state, record, start_timer)
            raise ToolValidationError(str(exc)) from exc

        try:
            output = tool.fn(parsed_input, state)
            parsed_output = tool.output_model.model_validate(output)
        except ValidationError as exc:
            record.status = ToolStatus.ERROR
            record.error_type = "ToolValidationError"
            record.error_message = str(exc)
            self._record_call(state, record, start_timer)
            raise ToolValidationError(str(exc)) from exc
        except Exception as exc:
            record.status = ToolStatus.ERROR
            record.error_type = type(exc).__name__
            record.error_message = str(exc)
            self._record_call(state, record, start_timer)
            raise ToolExecutionError(f"{tool.full_name} failed: {exc}") from exc

        if hasattr(parsed_output, "status"):
            record.status = parsed_output.status
        record.output_hash = _json_hash(parsed_output.model_dump(mode="json"))
        self._record_call(state, record, start_timer)
        return parsed_output

    def _record_call(self, state: AuditState, record: ToolCallRecord, start_timer: float) -> None:
        record.ended_at = datetime.now(UTC).isoformat()
        record.latency_ms = int((time.perf_counter() - start_timer) * 1000)
        state["tool_call_count"] = state.get("tool_call_count", 0) + 1
        state.setdefault("tool_ledger", []).append(record)

