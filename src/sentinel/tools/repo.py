from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from sentinel.schemas.common import SideEffect, ToolStatus
from sentinel.tools.base import RegisteredTool


class RepoPathInput(BaseModel):
    repo_path: str


class RepoListFilesInput(RepoPathInput):
    max_files: int = Field(default=500, ge=1)


class RepoListFilesOutput(BaseModel):
    status: ToolStatus
    files: list[str]
    truncated: bool = False
    message: str | None = None


class RepoReadFileInput(RepoPathInput):
    file_path: str
    max_bytes: int = Field(default=100_000, ge=1)


class RepoReadFileOutput(BaseModel):
    status: ToolStatus
    file_path: str
    content: str
    truncated: bool
    line_count: int = Field(ge=0)


class RepoSearchInput(RepoPathInput):
    query: str
    max_matches: int = Field(default=100, ge=1)


class RepoSearchOutput(BaseModel):
    status: ToolStatus
    matches: list[dict]


def _safe_files(repo_path: str) -> list[Path]:
    root = Path(repo_path)
    return [path for path in root.rglob("*") if path.is_file() and ".git" not in path.parts]


def list_files(inp: RepoListFilesInput, state) -> RepoListFilesOutput:
    root = Path(inp.repo_path)
    files = [str(path.relative_to(root)) for path in _safe_files(inp.repo_path)]
    truncated = len(files) > inp.max_files
    return RepoListFilesOutput(status=ToolStatus.OK, files=files[: inp.max_files], truncated=truncated)


def read_file(inp: RepoReadFileInput, state) -> RepoReadFileOutput:
    target = Path(inp.repo_path) / inp.file_path
    raw = target.read_bytes()
    truncated = len(raw) > inp.max_bytes
    content = raw[: inp.max_bytes].decode("utf-8", errors="replace")
    return RepoReadFileOutput(status=ToolStatus.OK, file_path=inp.file_path, content=content, truncated=truncated, line_count=len(content.splitlines()))


def find_contracts(inp: RepoPathInput, state) -> RepoListFilesOutput:
    root = Path(inp.repo_path)
    files = [str(path.relative_to(root)) for path in _safe_files(inp.repo_path) if path.suffix == ".sol" and "test" not in path.parts]
    return RepoListFilesOutput(status=ToolStatus.OK, files=files)


def search_text(inp: RepoSearchInput, state) -> RepoSearchOutput:
    root = Path(inp.repo_path)
    matches: list[dict] = []
    for path in _safe_files(inp.repo_path):
        text = path.read_text(encoding="utf-8", errors="replace")
        for line_no, line in enumerate(text.splitlines(), start=1):
            if inp.query.lower() in line.lower():
                matches.append({"file_path": str(path.relative_to(root)), "line": line_no, "text": line.strip()})
                if len(matches) >= inp.max_matches:
                    return RepoSearchOutput(status=ToolStatus.OK, matches=matches)
    return RepoSearchOutput(status=ToolStatus.OK, matches=matches)


def register(registry) -> None:
    for tool in [
        RegisteredTool(namespace="repo", name="list_files", description="List repository files.", input_model=RepoListFilesInput, output_model=RepoListFilesOutput, fn=list_files, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="repo", name="read_file", description="Read a single repository file.", input_model=RepoReadFileInput, output_model=RepoReadFileOutput, fn=read_file, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="repo", name="find_contracts", description="Find Solidity contract files.", input_model=RepoPathInput, output_model=RepoListFilesOutput, fn=find_contracts, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="repo", name="search_text", description="Search repository text.", input_model=RepoSearchInput, output_model=RepoSearchOutput, fn=search_text, side_effects=[SideEffect.READ_FILES]),
    ]:
        registry.register(tool)

