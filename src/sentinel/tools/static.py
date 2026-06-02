from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel, Field

from sentinel.schemas.common import SideEffect, ToolStatus
from sentinel.tools.base import RegisteredTool
from sentinel.tools.repo import RepoPathInput


class StaticFactsOutput(BaseModel):
    status: ToolStatus
    facts: list[dict] = Field(default_factory=list)


def _solidity_files(repo_path: str) -> list[Path]:
    return [path for path in Path(repo_path).rglob("*.sol") if path.is_file() and "out" not in path.parts and "cache" not in path.parts]


def extract_contracts(inp: RepoPathInput, state) -> StaticFactsOutput:
    facts = []
    for path in _solidity_files(inp.repo_path):
        text = path.read_text(encoding="utf-8", errors="replace")
        facts.append({"file_path": str(path.relative_to(inp.repo_path)), "contracts": re.findall(r"\bcontract\s+(\w+)", text)})
    return StaticFactsOutput(status=ToolStatus.OK, facts=facts)


def extract_functions(inp: RepoPathInput, state) -> StaticFactsOutput:
    facts = []
    for path in _solidity_files(inp.repo_path):
        for match in re.finditer(r"\bfunction\s+(\w+)", path.read_text(encoding="utf-8", errors="replace")):
            facts.append({"file_path": str(path.relative_to(inp.repo_path)), "function": match.group(1)})
    return StaticFactsOutput(status=ToolStatus.OK, facts=facts)


def find_access_control_terms(inp: RepoPathInput, state) -> StaticFactsOutput:
    facts = []
    for path in _solidity_files(inp.repo_path):
        for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            if any(term in line for term in ["owner", "onlyOwner", "hasRole", "AccessControl"]):
                facts.append({"file_path": str(path.relative_to(inp.repo_path)), "line": line_no, "text": line.strip()})
    return StaticFactsOutput(status=ToolStatus.OK, facts=facts)


def register(registry) -> None:
    for tool in [
        RegisteredTool(namespace="static", name="extract_contracts", description="Extract Solidity contract declarations.", input_model=RepoPathInput, output_model=StaticFactsOutput, fn=extract_contracts, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="extract_functions", description="Extract Solidity function declarations.", input_model=RepoPathInput, output_model=StaticFactsOutput, fn=extract_functions, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="find_access_control_terms", description="Find access-control related source terms.", input_model=RepoPathInput, output_model=StaticFactsOutput, fn=find_access_control_terms, side_effects=[SideEffect.READ_FILES]),
    ]:
        registry.register(tool)

