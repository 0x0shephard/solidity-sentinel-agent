from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

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
        if path.is_file():
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.strip().startswith("pragma solidity"):
                    pragmas.append(line.strip())
    return BuildToolOutput(status=ToolStatus.OK, data={"pragmas": sorted(set(pragmas))})


def check_foundry_available(inp: RepoPathInput, state) -> BuildToolOutput:
    return BuildToolOutput(status=ToolStatus.OK, message="Foundry command execution is implemented in Phase 4.")


def check_slither_available(inp: RepoPathInput, state) -> BuildToolOutput:
    return BuildToolOutput(status=ToolStatus.OK, message="Slither command execution is implemented in Phase 4.")


def register(registry) -> None:
    for tool in [
        RegisteredTool(namespace="build", name="detect_framework", description="Detect Solidity project framework.", input_model=RepoPathInput, output_model=DetectFrameworkOutput, fn=detect_framework, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="build", name="detect_solc", description="Detect Solidity pragma versions.", input_model=RepoPathInput, output_model=BuildToolOutput, fn=detect_solc, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="build", name="check_foundry_available", description="Check Foundry availability placeholder.", input_model=RepoPathInput, output_model=BuildToolOutput, fn=check_foundry_available, side_effects=[SideEffect.NONE]),
        RegisteredTool(namespace="build", name="check_slither_available", description="Check Slither availability placeholder.", input_model=RepoPathInput, output_model=BuildToolOutput, fn=check_slither_available, side_effects=[SideEffect.NONE]),
    ]:
        registry.register(tool)
