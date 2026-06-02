from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SideEffect(str, Enum):
    NONE = "none"
    READ_FILES = "read_files"
    WRITE_FILES = "write_files"
    EXECUTE_LOCAL = "execute_local"
    EXTERNAL_NETWORK = "external_network"


class ToolStatus(str, Enum):
    OK = "ok"
    ERROR = "error"
    UNAVAILABLE = "unavailable"
    SKIPPED = "skipped"


class ArtifactRef(BaseModel):
    kind: str
    path: str
    description: str | None = None


class ToolCallRecord(BaseModel):
    call_id: str
    run_id: str
    tool_name: str
    namespace: str
    input_hash: str
    status: ToolStatus
    started_at: str
    parent_call_id: str | None = None
    output_hash: str | None = None
    ended_at: str | None = None
    latency_ms: int | None = Field(default=None, ge=0)
    error_type: str | None = None
    error_message: str | None = None
    retry_count: int = Field(default=0, ge=0)


class PlanStep(BaseModel):
    id: str
    description: str
    status: Literal["pending", "running", "done", "failed", "skipped"] = "pending"
    depends_on: list[str] = Field(default_factory=list)


class CompletedStep(BaseModel):
    step_id: str
    summary: str
    evidence_refs: list[ArtifactRef] = Field(default_factory=list)

