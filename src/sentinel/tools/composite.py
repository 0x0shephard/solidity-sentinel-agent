"""Composite ``audit.*`` tools that let the model drive the whole pipeline.

Each tool resumes the deterministic audit pipeline through one stage. They are
self-healing: a tool ensures every prerequisite stage has run (in dependency
order) before completing its own, using the idempotent stage nodes in
``sentinel.graphs.parent``. This is what makes the LLM planner the spine of the
audit instead of a preamble in front of a fixed linear graph.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from sentinel.schemas.common import SideEffect, ToolStatus
from sentinel.tools.base import RegisteredTool


class CompositeStageInput(BaseModel):
    repo_path: str
    note: str | None = Field(default=None, description="Optional planner rationale; unused by execution.")


class CompositeStageOutput(BaseModel):
    status: ToolStatus
    milestone: str
    milestone_satisfied: bool
    completed_stages: list[str] = Field(default_factory=list)
    tool_calls_after: int = 0
    message: str | None = None


# Composite tool name -> milestone it drives. Order mirrors the audit pipeline.
_STAGE_TOOLS: list[tuple[str, str, str]] = [
    ("inspect_repo", "repo_inspected", "Inspect repository files and Solidity contracts."),
    ("detect_framework", "framework_detected", "Detect the Solidity framework, compiler, and build availability."),
    ("run_static_analysis", "static_facts_extracted", "Run the full static-analysis pass (extractors, detectors, Slither)."),
    ("build_protocol_ir", "protocol_ir_built", "Build the Protocol IR, cross-contract graph, asset flows, and attack paths."),
    ("contest_reasoning", "contest_reasoning_done", "Run actor/race modeling, reasoning packets, and gap hunters."),
    ("build_protocol_model", "protocol_model_built", "Summarize protocol roles, assets, accounting, and upgrade surfaces."),
    ("build_targeted_rag_context", "targeted_rag_built", "Build the graph-derived repo profile and Solodit checklist context."),
    ("mine_invariants", "invariants_mined", "Mine protocol invariant candidates and build proof packets."),
    ("rank_hypotheses", "hypotheses_ranked", "Generate and rank vulnerability hypotheses from local evidence."),
    ("retrieve_rag_context", "rag_context_bundled", "Retrieve and grade historical-finding RAG context per hypothesis."),
    ("research_hypotheses", "research_completed", "Run the isolated research subagent over ranked hypotheses."),
]


def _make_stage_fn(milestone: str):
    def fn(inp: CompositeStageInput, state) -> CompositeStageOutput:
        # Imported lazily to avoid a tools <-> graph import cycle.
        from sentinel.graphs.parent import _ensure_pipeline_through, _planner_milestones

        _ensure_pipeline_through(state, milestone)
        milestones = _planner_milestones(state)
        return CompositeStageOutput(
            status=ToolStatus.OK,
            milestone=milestone,
            milestone_satisfied=milestones.get(milestone, False),
            completed_stages=list(state.get("completed_stages", [])),
            tool_calls_after=state.get("tool_call_count", 0),
            message=f"Audit pipeline ensured through '{milestone}'.",
        )

    return fn


def register(registry) -> None:
    for name, milestone, description in _STAGE_TOOLS:
        registry.register(
            RegisteredTool(
                namespace="audit",
                name=name,
                description=description,
                input_model=CompositeStageInput,
                output_model=CompositeStageOutput,
                fn=_make_stage_fn(milestone),
                side_effects=[SideEffect.READ_FILES, SideEffect.EXECUTE_LOCAL],
                execution_kind="composite",
                chaining_hints=[
                    "Self-healing: runs any missing prerequisite stages in dependency order before this one.",
                    "Completing 'audit.research_hypotheses' drives the entire pipeline end to end.",
                ],
            )
        )
