from __future__ import annotations

from pydantic import BaseModel, Field

from sentinel.schemas.common import SideEffect, ToolStatus
from sentinel.schemas.research import VulnerabilityHypothesis
from sentinel.tools.base import RegisteredTool


class RankHypothesesInput(BaseModel):
    objective: str
    static_facts: list[dict] = Field(default_factory=list)


class RankHypothesesOutput(BaseModel):
    status: ToolStatus
    hypotheses: list[VulnerabilityHypothesis]


class ResearchNoteInput(BaseModel):
    topic: str


class ResearchNoteOutput(BaseModel):
    status: ToolStatus
    notes: list[str]


def rank_hypotheses(inp: RankHypothesesInput, state) -> RankHypothesesOutput:
    functions = {fact.get("function"): fact for fact in inp.static_facts if fact.get("function")}
    external_calls = [fact for fact in inp.static_facts if ".transfer(" in fact.get("text", "") or ".call(" in fact.get("text", "")]
    access_text = " ".join(fact.get("text", "") for fact in inp.static_facts).lower()
    for function_name, function_fact in functions.items():
        suspicious_name = function_name and any(term in function_name.lower() for term in ["emergency", "withdraw", "sweep", "drain"])
        if suspicious_name and external_calls and "onlyowner" not in access_text and "hasrole" not in access_text:
            hypothesis = VulnerabilityHypothesis(
                id="hyp-1",
                title=f"Missing access control candidate in {function_name}",
                vulnerability_class="missing_access_control",
                affected_files=[function_fact.get("file_path", "unknown")],
                affected_functions=[function_name],
                evidence_summary=f"{function_name} appears sensitive and the collected facts did not show an authorization guard.",
                confidence=0.72,
            )
            return RankHypothesesOutput(status=ToolStatus.OK, hypotheses=[hypothesis])

    hypothesis = VulnerabilityHypothesis(
        id="hyp-1",
        title="Manual review candidate",
        vulnerability_class="manual_review",
        evidence_summary=f"Initial hypothesis from objective: {inp.objective}",
        confidence=0.2,
    )
    return RankHypothesesOutput(status=ToolStatus.OK, hypotheses=[hypothesis])


def summarize_known_pattern(inp: ResearchNoteInput, state) -> ResearchNoteOutput:
    return ResearchNoteOutput(status=ToolStatus.OK, notes=[f"Pattern '{inp.topic}' requires file/function evidence before reporting."])


def register(registry) -> None:
    for tool in [
        RegisteredTool(namespace="research", name="rank_hypotheses", description="Rank candidate vulnerability hypotheses.", input_model=RankHypothesesInput, output_model=RankHypothesesOutput, fn=rank_hypotheses, side_effects=[SideEffect.NONE]),
        RegisteredTool(namespace="research", name="summarize_known_pattern", description="Summarize a known vulnerability pattern.", input_model=ResearchNoteInput, output_model=ResearchNoteOutput, fn=summarize_known_pattern, side_effects=[SideEffect.NONE]),
    ]:
        registry.register(tool)
