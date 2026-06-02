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


class ResearchGenericInput(BaseModel):
    data: dict = Field(default_factory=dict)


class ResearchGenericOutput(BaseModel):
    status: ToolStatus
    message: str | None = None
    data: dict = Field(default_factory=dict)


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


def search_local_vuln_db(inp: ResearchGenericInput, state) -> ResearchGenericOutput:
    return ResearchGenericOutput(status=ToolStatus.OK, data={"classes": ["missing_access_control", "unchecked_transfer", "reentrancy"]})


def retrieve_similar_cases(inp: ResearchGenericInput, state) -> ResearchGenericOutput:
    return ResearchGenericOutput(status=ToolStatus.OK, data={"similar_cases": ["SWC-105", "SWC-107", "unchecked ERC20 return values"]})


def map_to_vulnerability_class(inp: ResearchGenericInput, state) -> ResearchGenericOutput:
    text = " ".join(str(value) for value in inp.data.values()).lower()
    vuln_class = "missing_access_control" if "owner" in text or "access" in text else "manual_review"
    return ResearchGenericOutput(status=ToolStatus.OK, data={"vulnerability_class": vuln_class})


def summarize_prior_case(inp: ResearchGenericInput, state) -> ResearchGenericOutput:
    return ResearchGenericOutput(status=ToolStatus.OK, message="Prior cases require concrete file/function evidence before reporting.")


def spawn_research_subgraph_tool(inp: ResearchGenericInput, state) -> ResearchGenericOutput:
    return ResearchGenericOutput(status=ToolStatus.OK, message="Parent graph owns real research subgraph spawning; this tool exposes the capability in registry metadata.")


def register(registry) -> None:
    for tool in [
        RegisteredTool(namespace="research", name="search_local_vuln_db", description="Search local vulnerability class memory.", input_model=ResearchGenericInput, output_model=ResearchGenericOutput, fn=search_local_vuln_db, side_effects=[SideEffect.NONE]),
        RegisteredTool(namespace="research", name="retrieve_similar_cases", description="Retrieve similar vulnerability cases.", input_model=ResearchGenericInput, output_model=ResearchGenericOutput, fn=retrieve_similar_cases, side_effects=[SideEffect.NONE]),
        RegisteredTool(namespace="research", name="map_to_vulnerability_class", description="Map evidence to vulnerability class.", input_model=ResearchGenericInput, output_model=ResearchGenericOutput, fn=map_to_vulnerability_class, side_effects=[SideEffect.NONE]),
        RegisteredTool(namespace="research", name="rank_hypotheses", description="Rank candidate vulnerability hypotheses.", input_model=RankHypothesesInput, output_model=RankHypothesesOutput, fn=rank_hypotheses, side_effects=[SideEffect.NONE]),
        RegisteredTool(namespace="research", name="summarize_known_pattern", description="Summarize a known vulnerability pattern.", input_model=ResearchNoteInput, output_model=ResearchNoteOutput, fn=summarize_known_pattern, side_effects=[SideEffect.NONE]),
        RegisteredTool(namespace="research", name="summarize_prior_case", description="Summarize a prior vulnerability case.", input_model=ResearchGenericInput, output_model=ResearchGenericOutput, fn=summarize_prior_case, side_effects=[SideEffect.NONE]),
        RegisteredTool(namespace="research", name="spawn_research_subgraph", description="Expose research subgraph spawning capability.", input_model=ResearchGenericInput, output_model=ResearchGenericOutput, fn=spawn_research_subgraph_tool, side_effects=[SideEffect.NONE]),
    ]:
        registry.register(tool)
