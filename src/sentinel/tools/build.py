from __future__ import annotations

import shutil
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from sentinel.reliability.subprocess import CommandResult, run_command
from sentinel.schemas.common import SideEffect, ToolStatus
from sentinel.tools.base import RegisteredTool
from sentinel.tools.repo import RepoPathInput


class DetectFrameworkOutput(BaseModel):
    status: ToolStatus
    framework: Literal["foundry", "hardhat", "mixed", "unknown"]
    evidence_files: list[str]


class BuildToolOutput(BaseModel):
    status: ToolStatus
    message: str | None = None
    data: dict = Field(default_factory=dict)


class CommandToolOutput(BaseModel):
    status: ToolStatus
    command: list[str]
    return_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    message: str | None = None


def _command_output(result: CommandResult, ok_message: str | None = None) -> CommandToolOutput:
    return CommandToolOutput(
        status=ToolStatus.OK if result.return_code == 0 else ToolStatus.ERROR,
        command=result.command,
        return_code=result.return_code,
        stdout=result.stdout[-8000:],
        stderr=result.stderr[-8000:],
        timed_out=result.timed_out,
        message=ok_message,
    )


def detect_framework(inp: RepoPathInput, state) -> DetectFrameworkOutput:
    root = Path(inp.repo_path)
    foundry = (root / "foundry.toml").exists()
    hardhat = (root / "hardhat.config.js").exists() or (root / "hardhat.config.ts").exists()
    framework = "mixed" if foundry and hardhat else "foundry" if foundry else "hardhat" if hardhat else "unknown"
    evidence = [name for name in ["foundry.toml", "hardhat.config.js", "hardhat.config.ts"] if (root / name).exists()]
    return DetectFrameworkOutput(status=ToolStatus.OK, framework=framework, evidence_files=evidence)


def detect_solc(inp: RepoPathInput, state) -> BuildToolOutput:
    pragmas = []
    for path in Path(inp.repo_path).rglob("*.sol"):
        if path.is_file() and not any(part in {"out", "cache", "node_modules"} for part in path.parts):
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.strip().startswith("pragma solidity"):
                    pragmas.append(line.strip())
    return BuildToolOutput(status=ToolStatus.OK, data={"pragmas": sorted(set(pragmas))})


def check_foundry_available(inp: RepoPathInput, state) -> CommandToolOutput:
    forge = shutil.which("forge")
    if forge is None:
        return CommandToolOutput(status=ToolStatus.UNAVAILABLE, command=["forge", "--version"], message="forge is not installed")
    return _command_output(run_command(["forge", "--version"], cwd=inp.repo_path, timeout=15), ok_message=f"forge found at {forge}")


def check_slither_available(inp: RepoPathInput, state) -> CommandToolOutput:
    slither = shutil.which("slither")
    if slither is None:
        return CommandToolOutput(status=ToolStatus.UNAVAILABLE, command=["slither", "--version"], message="slither is not installed")
    return _command_output(run_command(["slither", "--version"], cwd=inp.repo_path, timeout=15), ok_message=f"slither found at {slither}")


def foundry_build(inp: RepoPathInput, state) -> CommandToolOutput:
    if shutil.which("forge") is None:
        return CommandToolOutput(status=ToolStatus.UNAVAILABLE, command=["forge", "build"], message="forge is not installed")
    return _command_output(run_command(["forge", "build"], cwd=inp.repo_path, timeout=120))


def foundry_test(inp: RepoPathInput, state) -> CommandToolOutput:
    if shutil.which("forge") is None:
        return CommandToolOutput(status=ToolStatus.UNAVAILABLE, command=["forge", "test"], message="forge is not installed")
    return _command_output(run_command(["forge", "test"], cwd=inp.repo_path, timeout=120))


def register(registry) -> None:
    for tool in [
        RegisteredTool(namespace="build", name="detect_framework", description="Detect Solidity project framework.", input_model=RepoPathInput, output_model=DetectFrameworkOutput, fn=detect_framework, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="build", name="detect_solc", description="Detect Solidity pragma versions.", input_model=RepoPathInput, output_model=BuildToolOutput, fn=detect_solc, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="build", name="check_foundry_available", description="Check Foundry availability.", input_model=RepoPathInput, output_model=CommandToolOutput, fn=check_foundry_available, side_effects=[SideEffect.EXECUTE_LOCAL]),
        RegisteredTool(namespace="build", name="check_slither_available", description="Check Slither availability.", input_model=RepoPathInput, output_model=CommandToolOutput, fn=check_slither_available, side_effects=[SideEffect.EXECUTE_LOCAL]),
        RegisteredTool(namespace="build", name="foundry_build", description="Run forge build in a Foundry repository.", input_model=RepoPathInput, output_model=CommandToolOutput, fn=foundry_build, side_effects=[SideEffect.EXECUTE_LOCAL]),
        RegisteredTool(namespace="build", name="foundry_test", description="Run forge test in a Foundry repository.", input_model=RepoPathInput, output_model=CommandToolOutput, fn=foundry_test, side_effects=[SideEffect.EXECUTE_LOCAL]),
    ]:
        registry.register(tool)
