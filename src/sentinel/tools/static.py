from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path

from pydantic import BaseModel, Field

from sentinel.reliability.subprocess import run_command
from sentinel.schemas.common import SideEffect, ToolStatus
from sentinel.schemas.research import SlitherFinding
from sentinel.tools.base import RegisteredTool
from sentinel.tools.repo import RepoPathInput


class StaticFactsOutput(BaseModel):
    status: ToolStatus
    facts: list[dict] = Field(default_factory=list)


class RunSlitherOutput(BaseModel):
    status: ToolStatus
    command: list[str]
    raw_json_path: str | None = None
    return_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    message: str | None = None


class ParseSlitherInput(BaseModel):
    raw_json_path: str


class ParseSlitherOutput(BaseModel):
    status: ToolStatus
    findings: list[SlitherFinding] = Field(default_factory=list)
    finding_count: int = Field(ge=0)
    message: str | None = None


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


def extract_external_calls(inp: RepoPathInput, state) -> StaticFactsOutput:
    facts = []
    for path in _solidity_files(inp.repo_path):
        for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            if any(term in line for term in [".call(", ".delegatecall(", ".transfer(", ".send("]):
                facts.append({"file_path": str(path.relative_to(inp.repo_path)), "line": line_no, "text": line.strip()})
    return StaticFactsOutput(status=ToolStatus.OK, facts=facts)


def run_slither(inp: RepoPathInput, state) -> RunSlitherOutput:
    command = ["slither", inp.repo_path, "--json", ""]
    if shutil.which("slither") is None:
        return RunSlitherOutput(status=ToolStatus.UNAVAILABLE, command=command, message="slither is not installed")

    run_dir = Path(state.get("run_dir", "runs/tmp"))
    artifact_dir = run_dir / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    raw_json_path = artifact_dir / "slither.json"
    slither_home = artifact_dir / "slither-home"
    slither_home.mkdir(parents=True, exist_ok=True)

    command = ["slither", inp.repo_path, "--json", str(raw_json_path)]
    env = {**os.environ, "HOME": str(slither_home)}
    result = run_command(command, cwd=".", timeout=180, env=env)

    if not raw_json_path.exists():
        raw_json_path.write_text(json.dumps({"success": False, "results": {"detectors": []}}), encoding="utf-8")

    return RunSlitherOutput(
        status=ToolStatus.OK if result.return_code == 0 else ToolStatus.ERROR,
        command=result.command,
        raw_json_path=str(raw_json_path),
        return_code=result.return_code,
        stdout=result.stdout[-8000:],
        stderr=result.stderr[-8000:],
        timed_out=result.timed_out,
    )


def parse_slither(inp: ParseSlitherInput, state) -> ParseSlitherOutput:
    path = Path(inp.raw_json_path)
    if not path.exists():
        return ParseSlitherOutput(status=ToolStatus.ERROR, finding_count=0, message=f"Slither JSON not found: {inp.raw_json_path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return ParseSlitherOutput(status=ToolStatus.ERROR, finding_count=0, message=f"Invalid Slither JSON: {exc}")

    findings = []
    for detector in data.get("results", {}).get("detectors", []):
        findings.append(
            SlitherFinding(
                check=detector.get("check", "unknown"),
                impact=detector.get("impact"),
                confidence=detector.get("confidence"),
                description=detector.get("description", ""),
                elements=detector.get("elements", []),
            )
        )
    return ParseSlitherOutput(status=ToolStatus.OK, findings=findings, finding_count=len(findings))


def register(registry) -> None:
    for tool in [
        RegisteredTool(namespace="static", name="extract_contracts", description="Extract Solidity contract declarations.", input_model=RepoPathInput, output_model=StaticFactsOutput, fn=extract_contracts, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="extract_functions", description="Extract Solidity function declarations.", input_model=RepoPathInput, output_model=StaticFactsOutput, fn=extract_functions, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="find_access_control_terms", description="Find access-control related source terms.", input_model=RepoPathInput, output_model=StaticFactsOutput, fn=find_access_control_terms, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="extract_external_calls", description="Extract low-level/external call sites.", input_model=RepoPathInput, output_model=StaticFactsOutput, fn=extract_external_calls, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="run_slither", description="Run Slither and write JSON artifact.", input_model=RepoPathInput, output_model=RunSlitherOutput, fn=run_slither, side_effects=[SideEffect.EXECUTE_LOCAL]),
        RegisteredTool(namespace="static", name="parse_slither", description="Parse Slither JSON artifact into typed findings.", input_model=ParseSlitherInput, output_model=ParseSlitherOutput, fn=parse_slither, side_effects=[SideEffect.READ_FILES]),
    ]:
        registry.register(tool)
