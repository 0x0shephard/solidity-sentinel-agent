from __future__ import annotations

from pydantic import BaseModel, Field

from sentinel.schemas.common import ArtifactRef, SideEffect, ToolStatus
from sentinel.tools.base import RegisteredTool


class MemoryInput(BaseModel):
    note: str | None = None
    data: dict = Field(default_factory=dict)


class MemoryOutput(BaseModel):
    status: ToolStatus
    message: str | None = None
    data: dict = Field(default_factory=dict)


def write_note(inp: MemoryInput, state) -> MemoryOutput:
    state.setdefault("last_outputs", {}).setdefault("memory.notes", {"notes": []})["notes"].append(inp.note or "")
    return MemoryOutput(status=ToolStatus.OK, message="Note stored.")


def read_notes(inp: MemoryInput, state) -> MemoryOutput:
    return MemoryOutput(status=ToolStatus.OK, data=state.get("last_outputs", {}).get("memory.notes", {"notes": []}))


def summarize_context(inp: MemoryInput, state) -> MemoryOutput:
    summary = f"Tool calls: {state.get('tool_call_count', 0)}. Findings: {len(state.get('findings', []))}."
    state["compressed_context"] = summary
    return MemoryOutput(status=ToolStatus.OK, data={"compressed_context": summary})


def generic(inp: MemoryInput, state) -> MemoryOutput:
    return MemoryOutput(status=ToolStatus.OK, data=inp.data)


def store_artifact_ref(inp: MemoryInput, state) -> MemoryOutput:
    artifact = ArtifactRef(
        kind=inp.data.get("kind", "artifact"),
        path=inp.data.get("path", ""),
        description=inp.data.get("description"),
    )
    state.setdefault("artifacts", []).append(artifact)
    return MemoryOutput(status=ToolStatus.OK, data={"artifact": artifact.model_dump(mode="json"), "artifact_count": len(state["artifacts"])})


def get_plan_state(inp: MemoryInput, state) -> MemoryOutput:
    return MemoryOutput(status=ToolStatus.OK, data={"plan": [step.model_dump(mode="json") for step in state.get("plan", [])], "current_focus": state.get("current_focus")})


def update_plan_state(inp: MemoryInput, state) -> MemoryOutput:
    target_id = inp.data.get("id")
    status = inp.data.get("status")
    updated = 0
    for step in state.get("plan", []):
        if step.id == target_id:
            step.status = status
            updated += 1
    return MemoryOutput(status=ToolStatus.OK, data={"updated": updated})


def register(registry) -> None:
    specs = [
        ("write_note", "Write a memory note.", write_note),
        ("read_notes", "Read memory notes.", read_notes),
        ("summarize_context", "Summarize graph context.", summarize_context),
        ("store_artifact_ref", "Store artifact reference.", store_artifact_ref),
        ("get_plan_state", "Get current plan state.", get_plan_state),
        ("update_plan_state", "Update plan state.", update_plan_state),
    ]
    for name, description, fn in specs:
        registry.register(RegisteredTool(namespace="memory", name=name, description=description, input_model=MemoryInput, output_model=MemoryOutput, fn=fn, side_effects=[SideEffect.NONE]))
