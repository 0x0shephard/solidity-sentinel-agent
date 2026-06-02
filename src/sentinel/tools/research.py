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


SENSITIVE_FUNCTION_TERMS = ("emergency", "withdraw", "sweep", "drain", "claim", "redeem", "pay", "send")


def _facts_with_key(facts: list[dict], key: str) -> list[dict]:
    return [fact for fact in facts if fact.get(key)]


def _facts_containing(facts: list[dict], terms: tuple[str, ...]) -> list[dict]:
    return [fact for fact in facts if any(term in fact.get("text", "") for term in terms)]


def _sensitive_function_for_file(functions: list[dict], file_path: str) -> dict | None:
    candidates = [fact for fact in functions if fact.get("file_path") == file_path]
    for fact in candidates:
        function_name = str(fact.get("function", "")).lower()
        if any(term in function_name for term in SENSITIVE_FUNCTION_TERMS):
            return fact
    return candidates[0] if candidates else None


def _has_authorization_guard(access_facts: list[dict]) -> bool:
    access_text = " ".join(fact.get("text", "") for fact in access_facts).replace(" ", "").lower()
    return any(term in access_text for term in ["onlyowner", "hasrole", "onlyrole", "msg.sender==owner", "_checkowner"])


def _is_unchecked_token_transfer(fact: dict) -> bool:
    text = fact.get("text", "")
    compact = text.replace(" ", "")
    lower = text.lower()
    if "safetransfer" in lower or "require(" in compact or "assert(" in compact:
        return False
    if ".transfer(" not in text and ".transferFrom(" not in text:
        return False
    # ETH transfers such as `to.transfer(...)` do not return a bool, so they
    # belong to access/reentrancy triage rather than unchecked ERC20 return triage.
    if compact.startswith("to.transfer(") or "address(this).balance" in compact:
        return False
    return True


def _detect_reentrancy(functions: list[dict], external_calls: list[dict], storage_writes: list[dict]) -> VulnerabilityHypothesis | None:
    low_level_calls = _facts_containing(external_calls, (".call(", ".call{", ".send("))
    for call in low_level_calls:
        call_file = call.get("file_path")
        call_line = int(call.get("line", 0) or 0)
        later_storage_write = next(
            (
                write
                for write in storage_writes
                if write.get("file_path") == call_file and int(write.get("line", 0) or 0) > call_line
            ),
            None,
        )
        function_fact = _sensitive_function_for_file(functions, str(call_file))
        if later_storage_write and function_fact:
            function_name = function_fact.get("function", "unknown")
            return VulnerabilityHypothesis(
                id="hyp-1",
                title=f"Reentrancy candidate in {function_name}",
                vulnerability_class="reentrancy",
                affected_files=[str(call_file)],
                affected_functions=[str(function_name)],
                evidence_summary=(
                    f"{function_name} performs an external call on line {call_line} before a later state write "
                    f"on line {later_storage_write.get('line')}."
                ),
                confidence=0.78,
            )
    return None


def _detect_unchecked_transfer(functions: list[dict], token_transfers: list[dict]) -> VulnerabilityHypothesis | None:
    for transfer in token_transfers:
        if not _is_unchecked_token_transfer(transfer):
            continue
        file_path = str(transfer.get("file_path", "unknown"))
        function_fact = _sensitive_function_for_file(functions, file_path)
        function_name = str(function_fact.get("function", "unknown")) if function_fact else "unknown"
        return VulnerabilityHypothesis(
            id="hyp-1",
            title=f"Unchecked token transfer candidate in {function_name}",
            vulnerability_class="unchecked_transfer",
            affected_files=[file_path],
            affected_functions=[function_name],
            evidence_summary=f"{transfer.get('text')} is not wrapped in require/assert or SafeERC20 handling.",
            confidence=0.73,
        )
    return None


def _detect_missing_access_control(
    functions: list[dict],
    external_calls: list[dict],
    access_facts: list[dict],
) -> VulnerabilityHypothesis | None:
    if _has_authorization_guard(access_facts):
        return None
    eth_value_transfers = _facts_containing(external_calls, (".transfer(", ".call(", ".call{", ".send("))
    if not eth_value_transfers:
        return None
    for function_fact in functions:
        function_name = str(function_fact.get("function", ""))
        suspicious_name = any(term in function_name.lower() for term in ["emergency", "withdraw", "sweep", "drain"])
        if suspicious_name:
            return VulnerabilityHypothesis(
                id="hyp-1",
                title=f"Missing access control candidate in {function_name}",
                vulnerability_class="missing_access_control",
                affected_files=[function_fact.get("file_path", "unknown")],
                affected_functions=[function_name],
                evidence_summary=f"{function_name} appears sensitive and the collected facts did not show an authorization guard.",
                confidence=0.72,
            )
    return None


def rank_hypotheses(inp: RankHypothesesInput, state) -> RankHypothesesOutput:
    functions = _facts_with_key(inp.static_facts, "function")
    external_calls = _facts_containing(inp.static_facts, (".transfer(", ".call(", ".call{", ".send(", ".delegatecall(", ".delegatecall{"))
    token_transfers = _facts_containing(inp.static_facts, (".transfer(", ".transferFrom("))
    storage_writes = [fact for fact in inp.static_facts if "line" in fact and ("=" in fact.get("text", "") or "+=" in fact.get("text", "") or "-=" in fact.get("text", ""))]
    access_facts = [
        fact
        for fact in inp.static_facts
        if any(term in fact.get("text", "") for term in ["owner", "onlyOwner", "hasRole", "AccessControl", "msg.sender"])
    ]

    for detector in [
        lambda: _detect_reentrancy(functions, external_calls, storage_writes),
        lambda: _detect_unchecked_transfer(functions, token_transfers),
        lambda: _detect_missing_access_control(functions, external_calls, access_facts),
    ]:
        hypothesis = detector()
        if hypothesis:
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
