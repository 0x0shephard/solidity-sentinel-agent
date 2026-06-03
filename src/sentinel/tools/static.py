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


def _normalize_slither_path(filename: str | None) -> str | None:
    if not filename:
        return None
    path = Path(filename)
    parts = path.parts
    if "src" in parts:
        return str(Path(*parts[parts.index("src") :]))
    if "contracts" in parts:
        return str(Path(*parts[parts.index("contracts") :]))
    return path.name


def _extract_slither_locations(elements: list[dict]) -> tuple[list[str], list[str]]:
    files: list[str] = []
    functions: list[str] = []
    for element in elements:
        source_mapping = element.get("source_mapping") or {}
        filename = _normalize_slither_path(source_mapping.get("filename_relative") or source_mapping.get("filename_absolute"))
        if filename and filename not in files:
            files.append(filename)

        element_type = str(element.get("type", "")).lower()
        name = element.get("name")
        if name and "function" in element_type and str(name) not in functions:
            functions.append(str(name).split("(")[0])

        parent = element.get("parent") or {}
        parent_type = str(parent.get("type", "")).lower()
        parent_name = parent.get("name")
        if parent_name and "function" in parent_type and str(parent_name) not in functions:
            functions.append(str(parent_name).split("(")[0])
    return files, functions


def _solidity_files(repo_path: str) -> list[Path]:
    return [path for path in Path(repo_path).rglob("*.sol") if path.is_file() and "out" not in path.parts and "cache" not in path.parts]


def _function_context_by_line(lines: list[str]) -> dict[int, str]:
    context: dict[int, str] = {}
    current_function: str | None = None
    brace_depth = 0
    declaration = re.compile(r"\bfunction\s+(\w+)|\bconstructor\s*\(")
    for line_no, line in enumerate(lines, start=1):
        if current_function is None:
            match = declaration.search(line)
            if match:
                current_function = match.group(1) or "constructor"
                brace_depth = line.count("{") - line.count("}")
                context[line_no] = current_function
                if brace_depth <= 0:
                    current_function = None
                continue
        if current_function is not None:
            context[line_no] = current_function
            brace_depth += line.count("{") - line.count("}")
            if brace_depth <= 0:
                current_function = None
    return context


def extract_contracts(inp: RepoPathInput, state) -> StaticFactsOutput:
    facts = []
    for path in _solidity_files(inp.repo_path):
        text = path.read_text(encoding="utf-8", errors="replace")
        facts.append({"file_path": str(path.relative_to(inp.repo_path)), "contracts": re.findall(r"\bcontract\s+(\w+)", text)})
    return StaticFactsOutput(status=ToolStatus.OK, facts=facts)


def extract_functions(inp: RepoPathInput, state) -> StaticFactsOutput:
    facts = []
    for path in _solidity_files(inp.repo_path):
        for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            match = re.search(r"\bfunction\s+(\w+)", line)
            if match:
                facts.append({"file_path": str(path.relative_to(inp.repo_path)), "line": line_no, "function": match.group(1)})
    return StaticFactsOutput(status=ToolStatus.OK, facts=facts)


def find_access_control_terms(inp: RepoPathInput, state) -> StaticFactsOutput:
    facts = []
    for path in _solidity_files(inp.repo_path):
        for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            if any(term in line for term in ["owner", "onlyOwner", "hasRole", "AccessControl"]):
                facts.append({"file_path": str(path.relative_to(inp.repo_path)), "line": line_no, "text": line.strip()})
    return StaticFactsOutput(status=ToolStatus.OK, facts=facts)


def extract_inheritance(inp: RepoPathInput, state) -> StaticFactsOutput:
    facts = []
    for path in _solidity_files(inp.repo_path):
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in re.finditer(r"\bcontract\s+(\w+)\s+is\s+([^{]+)", text):
            facts.append({"file_path": str(path.relative_to(inp.repo_path)), "contract": match.group(1), "inherits": [item.strip() for item in match.group(2).split(",")]})
    return StaticFactsOutput(status=ToolStatus.OK, facts=facts)


def extract_modifiers(inp: RepoPathInput, state) -> StaticFactsOutput:
    facts = []
    for path in _solidity_files(inp.repo_path):
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in re.finditer(r"\bmodifier\s+(\w+)", text):
            facts.append({"file_path": str(path.relative_to(inp.repo_path)), "modifier": match.group(1)})
    return StaticFactsOutput(status=ToolStatus.OK, facts=facts)


def extract_external_calls(inp: RepoPathInput, state) -> StaticFactsOutput:
    facts = []
    for path in _solidity_files(inp.repo_path):
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        function_context = _function_context_by_line(lines)
        for line_no, line in enumerate(lines, start=1):
            if any(term in line for term in [".call(", ".call{", ".delegatecall(", ".delegatecall{", ".transfer(", ".send("]):
                facts.append({"file_path": str(path.relative_to(inp.repo_path)), "line": line_no, "function": function_context.get(line_no), "text": line.strip()})
    return StaticFactsOutput(status=ToolStatus.OK, facts=facts)


def extract_delegatecalls(inp: RepoPathInput, state) -> StaticFactsOutput:
    facts = []
    for path in _solidity_files(inp.repo_path):
        for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            if ".delegatecall(" in line:
                facts.append({"file_path": str(path.relative_to(inp.repo_path)), "line": line_no, "text": line.strip()})
    return StaticFactsOutput(status=ToolStatus.OK, facts=facts)


def extract_token_transfers(inp: RepoPathInput, state) -> StaticFactsOutput:
    facts = []
    for path in _solidity_files(inp.repo_path):
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        function_context = _function_context_by_line(lines)
        for line_no, line in enumerate(lines, start=1):
            if ".transfer(" in line or ".transferFrom(" in line:
                facts.append({"file_path": str(path.relative_to(inp.repo_path)), "line": line_no, "function": function_context.get(line_no), "text": line.strip()})
    return StaticFactsOutput(status=ToolStatus.OK, facts=facts)


def extract_storage_writes(inp: RepoPathInput, state) -> StaticFactsOutput:
    facts = []
    assignment = re.compile(r"(?<![=!<>])=(?![=>])|\+=|-=")
    local_declaration = re.compile(r"^(u?int\d*|address|bool|string|bytes\d*|\w+\s+memory|\w+\s+calldata)\s+\w+\s*=")
    for path in _solidity_files(inp.repo_path):
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        function_context = _function_context_by_line(lines)
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if assignment.search(stripped) and function_context.get(line_no) and not stripped.startswith(("require", "assert", "if ", "for ")) and not local_declaration.search(stripped):
                facts.append({"file_path": str(path.relative_to(inp.repo_path)), "line": line_no, "function": function_context.get(line_no), "text": stripped})
    return StaticFactsOutput(status=ToolStatus.OK, facts=facts)


def find_oracle_patterns(inp: RepoPathInput, state) -> StaticFactsOutput:
    facts = []
    for path in _solidity_files(inp.repo_path):
        for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            if any(term in line.lower() for term in ["oracle", "latestanswer", "latestrounddata", "getprice", "price"]):
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
        source_files, functions = _extract_slither_locations(detector.get("elements", []))
        findings.append(
            SlitherFinding(
                check=detector.get("check", "unknown"),
                impact=detector.get("impact"),
                confidence=detector.get("confidence"),
                description=detector.get("description", ""),
                elements=detector.get("elements", []),
                source_files=source_files,
                functions=functions,
            )
        )
    return ParseSlitherOutput(status=ToolStatus.OK, findings=findings, finding_count=len(findings))


def register(registry) -> None:
    for tool in [
        RegisteredTool(namespace="static", name="extract_contracts", description="Extract Solidity contract declarations.", input_model=RepoPathInput, output_model=StaticFactsOutput, fn=extract_contracts, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="extract_inheritance", description="Extract Solidity inheritance declarations.", input_model=RepoPathInput, output_model=StaticFactsOutput, fn=extract_inheritance, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="extract_functions", description="Extract Solidity function declarations.", input_model=RepoPathInput, output_model=StaticFactsOutput, fn=extract_functions, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="extract_modifiers", description="Extract Solidity modifier declarations.", input_model=RepoPathInput, output_model=StaticFactsOutput, fn=extract_modifiers, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="find_access_control_terms", description="Find access-control related source terms.", input_model=RepoPathInput, output_model=StaticFactsOutput, fn=find_access_control_terms, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="extract_external_calls", description="Extract low-level/external call sites.", input_model=RepoPathInput, output_model=StaticFactsOutput, fn=extract_external_calls, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="extract_delegatecalls", description="Extract delegatecall sites.", input_model=RepoPathInput, output_model=StaticFactsOutput, fn=extract_delegatecalls, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="extract_token_transfers", description="Extract token transfer patterns.", input_model=RepoPathInput, output_model=StaticFactsOutput, fn=extract_token_transfers, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="extract_storage_writes", description="Extract likely storage write lines.", input_model=RepoPathInput, output_model=StaticFactsOutput, fn=extract_storage_writes, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="find_oracle_patterns", description="Find oracle and price-read patterns.", input_model=RepoPathInput, output_model=StaticFactsOutput, fn=find_oracle_patterns, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="run_slither", description="Run Slither and write JSON artifact.", input_model=RepoPathInput, output_model=RunSlitherOutput, fn=run_slither, side_effects=[SideEffect.EXECUTE_LOCAL], chaining_hints=["Use raw_json_path as static.parse_slither.raw_json_path."]),
        RegisteredTool(namespace="static", name="parse_slither", description="Parse Slither JSON artifact into typed findings.", input_model=ParseSlitherInput, output_model=ParseSlitherOutput, fn=parse_slither, side_effects=[SideEffect.READ_FILES]),
    ]:
        registry.register(tool)
