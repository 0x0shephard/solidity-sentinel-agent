from __future__ import annotations

import os
import shutil
import shutil as shutil_module
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from sentinel.config import get_settings
from sentinel.reliability.subprocess import CommandResult, run_command, sanitized_env
from sentinel.schemas.common import RiskLevel, SideEffect, ToolStatus
from sentinel.tools.base import RegisteredTool, StateEffect
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


class FoundryTestMatchInput(RepoPathInput):
    match: str


def _failure_message(result: CommandResult) -> str:
    """Build a concise, operator-visible diagnostic for a failed command.

    The full stdout/stderr live in the artifact, but the ledger/state only keep
    ``message`` — so on failure we surface the timeout flag and the stderr tail
    here, otherwise a failed build/slither shows up as a blank error.
    """
    if result.timed_out:
        tail = (result.stderr or result.stdout or "").strip()[-300:]
        return f"Command timed out (return_code {result.return_code}). {tail}".strip()
    tail = (result.stderr or result.stdout or "").strip()[-600:]
    return f"Command failed (return_code {result.return_code}). {tail}".strip() if tail else f"Command failed (return_code {result.return_code})."


def _command_output(result: CommandResult, ok_message: str | None = None) -> CommandToolOutput:
    ok = result.return_code == 0
    return CommandToolOutput(
        status=ToolStatus.OK if ok else ToolStatus.ERROR,
        command=result.command,
        return_code=result.return_code,
        stdout=result.stdout[-8000:],
        stderr=result.stderr[-8000:],
        timed_out=result.timed_out,
        message=ok_message if ok else _failure_message(result),
    )


def _forge_timeout() -> int:
    """Timeout (seconds) for heavy forge/hardhat commands; cold builds are slow."""
    return get_settings().forge_command_timeout


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
    artifact_home = Path(state.get("run_dir", "runs/tmp")) / "artifacts" / "slither-home"
    artifact_home.mkdir(parents=True, exist_ok=True)
    env = sanitized_env(home=artifact_home)
    return _command_output(run_command(["slither", "--version"], cwd=inp.repo_path, timeout=15, env=env), ok_message=f"slither found at {slither}")


def foundry_build(inp: RepoPathInput, state) -> CommandToolOutput:
    if shutil.which("forge") is None:
        return CommandToolOutput(status=ToolStatus.UNAVAILABLE, command=["forge", "build"], message="forge is not installed")
    return _command_output(run_command(["forge", "build"], cwd=inp.repo_path, timeout=_forge_timeout()))


def foundry_test(inp: RepoPathInput, state) -> CommandToolOutput:
    if shutil.which("forge") is None:
        return CommandToolOutput(status=ToolStatus.UNAVAILABLE, command=["forge", "test"], message="forge is not installed")
    return _command_output(run_command(["forge", "test"], cwd=inp.repo_path, timeout=_forge_timeout()))


def install_dependencies(inp: RepoPathInput, state) -> BuildToolOutput:
    if not get_settings().allow_installs:
        return BuildToolOutput(
            status=ToolStatus.SKIPPED,
            message="Dependency installs are disabled (they run untrusted network/postinstall code). Set SENTINEL_ALLOW_INSTALLS=true to opt in.",
        )
    root = Path(inp.repo_path)
    if (root / "package-lock.json").exists() and shutil.which("npm"):
        result = run_command(["npm", "ci"], cwd=inp.repo_path, timeout=300)
        return BuildToolOutput(status=ToolStatus.OK if result.return_code == 0 else ToolStatus.ERROR, data=result.model_dump(mode="json"))
    if (root / "package.json").exists() and shutil.which("npm"):
        result = run_command(["npm", "install"], cwd=inp.repo_path, timeout=300)
        return BuildToolOutput(status=ToolStatus.OK if result.return_code == 0 else ToolStatus.ERROR, data=result.model_dump(mode="json"))
    if (root / "foundry.toml").exists() and shutil.which("forge"):
        result = run_command(["forge", "install"], cwd=inp.repo_path, timeout=300)
        return BuildToolOutput(status=ToolStatus.OK if result.return_code == 0 else ToolStatus.ERROR, data=result.model_dump(mode="json"))
    return BuildToolOutput(status=ToolStatus.UNAVAILABLE, message="No supported dependency install command was available.")


def foundry_test_match(inp: FoundryTestMatchInput, state) -> CommandToolOutput:
    if shutil.which("forge") is None:
        return CommandToolOutput(status=ToolStatus.UNAVAILABLE, command=["forge", "test", "--match-test", inp.match], message="forge is not installed")
    return _command_output(run_command(["forge", "test", "--match-test", inp.match], cwd=inp.repo_path, timeout=_forge_timeout()))


def foundry_coverage(inp: RepoPathInput, state) -> CommandToolOutput:
    if shutil.which("forge") is None:
        return CommandToolOutput(status=ToolStatus.UNAVAILABLE, command=["forge", "coverage"], message="forge is not installed")
    return _command_output(run_command(["forge", "coverage"], cwd=inp.repo_path, timeout=_forge_timeout()))


def hardhat_compile(inp: RepoPathInput, state) -> CommandToolOutput:
    if shutil.which("npx") is None:
        return CommandToolOutput(status=ToolStatus.UNAVAILABLE, command=["npx", "hardhat", "compile"], message="npx is not installed")
    return _command_output(run_command(["npx", "hardhat", "compile"], cwd=inp.repo_path, timeout=_forge_timeout()))


def hardhat_test(inp: RepoPathInput, state) -> CommandToolOutput:
    if shutil.which("npx") is None:
        return CommandToolOutput(status=ToolStatus.UNAVAILABLE, command=["npx", "hardhat", "test"], message="npx is not installed")
    return _command_output(run_command(["npx", "hardhat", "test"], cwd=inp.repo_path, timeout=_forge_timeout()))


def clean(inp: RepoPathInput, state) -> BuildToolOutput:
    root = Path(inp.repo_path)
    removed = []
    for name in ["out", "cache", "artifacts", "coverage"]:
        target = root / name
        if target.exists() and target.is_dir():
            shutil_module.rmtree(target)
            removed.append(name)
    return BuildToolOutput(status=ToolStatus.OK, data={"removed": removed})


def register(registry) -> None:
    for tool in [
        RegisteredTool(namespace="build", name="detect_framework", description="Detect Solidity project framework.", input_model=RepoPathInput, output_model=DetectFrameworkOutput, fn=detect_framework, side_effects=[SideEffect.READ_FILES], state_effects=[StateEffect(output_path="", state_path="build_facts.framework", merge="set")]),
        RegisteredTool(namespace="build", name="detect_solc", description="Detect Solidity pragma versions.", input_model=RepoPathInput, output_model=BuildToolOutput, fn=detect_solc, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="build", name="install_dependencies", description="Install project dependencies when explicitly enabled.", input_model=RepoPathInput, output_model=BuildToolOutput, fn=install_dependencies, side_effects=[SideEffect.EXECUTE_LOCAL, SideEffect.EXTERNAL_NETWORK, SideEffect.WRITE_FILES], risk_level=RiskLevel.HIGH),
        RegisteredTool(namespace="build", name="check_foundry_available", description="Check Foundry availability.", input_model=RepoPathInput, output_model=CommandToolOutput, fn=check_foundry_available, side_effects=[SideEffect.EXECUTE_LOCAL]),
        RegisteredTool(namespace="build", name="check_slither_available", description="Check Slither availability.", input_model=RepoPathInput, output_model=CommandToolOutput, fn=check_slither_available, side_effects=[SideEffect.EXECUTE_LOCAL]),
        RegisteredTool(namespace="build", name="foundry_build", description="Run forge build in a Foundry repository.", input_model=RepoPathInput, output_model=CommandToolOutput, fn=foundry_build, side_effects=[SideEffect.EXECUTE_LOCAL]),
        RegisteredTool(namespace="build", name="foundry_test", description="Run forge test in a Foundry repository.", input_model=RepoPathInput, output_model=CommandToolOutput, fn=foundry_test, side_effects=[SideEffect.EXECUTE_LOCAL]),
        RegisteredTool(namespace="build", name="foundry_test_match", description="Run forge test for a named test.", input_model=FoundryTestMatchInput, output_model=CommandToolOutput, fn=foundry_test_match, side_effects=[SideEffect.EXECUTE_LOCAL]),
        RegisteredTool(namespace="build", name="foundry_coverage", description="Run forge coverage.", input_model=RepoPathInput, output_model=CommandToolOutput, fn=foundry_coverage, side_effects=[SideEffect.EXECUTE_LOCAL]),
        RegisteredTool(namespace="build", name="hardhat_compile", description="Run hardhat compile.", input_model=RepoPathInput, output_model=CommandToolOutput, fn=hardhat_compile, side_effects=[SideEffect.EXECUTE_LOCAL]),
        RegisteredTool(namespace="build", name="hardhat_test", description="Run hardhat test.", input_model=RepoPathInput, output_model=CommandToolOutput, fn=hardhat_test, side_effects=[SideEffect.EXECUTE_LOCAL]),
        RegisteredTool(namespace="build", name="clean", description="Clean build artifacts when explicitly enabled.", input_model=RepoPathInput, output_model=BuildToolOutput, fn=clean, side_effects=[SideEffect.WRITE_FILES]),
    ]:
        registry.register(tool)
