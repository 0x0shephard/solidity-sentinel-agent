from __future__ import annotations

from pathlib import Path
import shutil

from pydantic import BaseModel, Field

from sentinel.reliability.subprocess import run_command
from sentinel.errors import SandboxViolationError
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


class RepoWriteFileInput(RepoPathInput):
    file_path: str
    content: str


class RepoGenericOutput(BaseModel):
    status: ToolStatus
    message: str | None = None
    data: dict = Field(default_factory=dict)


class RepoCloneInput(BaseModel):
    repo_url: str
    dest_path: str
    ref: str | None = None


class RepoCheckoutInput(RepoPathInput):
    ref: str


def _safe_files(repo_path: str) -> list[Path]:
    root = Path(repo_path)
    return [path for path in root.rglob("*") if path.is_file() and ".git" not in path.parts]


def _resolve_inside(repo_path: str, file_path: str) -> Path:
    root = Path(repo_path).resolve()
    target = (root / file_path).resolve()
    if target != root and root not in target.parents:
        raise SandboxViolationError(f"Path escapes repo_path: {file_path}")
    return target


def list_files(inp: RepoListFilesInput, state) -> RepoListFilesOutput:
    root = Path(inp.repo_path)
    files = [str(path.relative_to(root)) for path in _safe_files(inp.repo_path)]
    truncated = len(files) > inp.max_files
    return RepoListFilesOutput(status=ToolStatus.OK, files=files[: inp.max_files], truncated=truncated)


def read_file(inp: RepoReadFileInput, state) -> RepoReadFileOutput:
    target = _resolve_inside(inp.repo_path, inp.file_path)
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


def find_tests(inp: RepoPathInput, state) -> RepoListFilesOutput:
    root = Path(inp.repo_path)
    files = [
        str(path.relative_to(root))
        for path in _safe_files(inp.repo_path)
        if path.suffix == ".sol" and ("test" in path.parts or path.name.endswith(".t.sol"))
    ]
    return RepoListFilesOutput(status=ToolStatus.OK, files=files)


def write_file(inp: RepoWriteFileInput, state) -> RepoGenericOutput:
    target = _resolve_inside(inp.repo_path, inp.file_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(inp.content, encoding="utf-8")
    return RepoGenericOutput(status=ToolStatus.OK, message=f"Wrote {inp.file_path}")


def patch_file(inp: RepoWriteFileInput, state) -> RepoGenericOutput:
    return write_file(inp, state)


def git_status(inp: RepoPathInput, state) -> RepoGenericOutput:
    if shutil.which("git") is None:
        return RepoGenericOutput(status=ToolStatus.UNAVAILABLE, message="git is not installed")
    result = run_command(["git", "status", "--short"], cwd=inp.repo_path, timeout=30)
    return RepoGenericOutput(
        status=ToolStatus.OK if result.return_code == 0 else ToolStatus.ERROR,
        data={"command": result.command, "return_code": result.return_code, "stdout": result.stdout, "stderr": result.stderr},
    )


def git_diff(inp: RepoPathInput, state) -> RepoGenericOutput:
    if shutil.which("git") is None:
        return RepoGenericOutput(status=ToolStatus.UNAVAILABLE, message="git is not installed")
    result = run_command(["git", "diff", "--"], cwd=inp.repo_path, timeout=30)
    return RepoGenericOutput(
        status=ToolStatus.OK if result.return_code == 0 else ToolStatus.ERROR,
        data={"command": result.command, "return_code": result.return_code, "stdout": result.stdout[-20_000:], "stderr": result.stderr[-4000:]},
    )


def snapshot(inp: RepoPathInput, state) -> RepoGenericOutput:
    files = list_files(RepoListFilesInput(repo_path=inp.repo_path), state)
    contracts = find_contracts(inp, state)
    tests = find_tests(inp, state)
    return RepoGenericOutput(status=ToolStatus.OK, data={"file_count": len(files.files), "contracts": contracts.files, "tests": tests.files})


def clone(inp: RepoCloneInput, state) -> RepoGenericOutput:
    if shutil.which("git") is None:
        return RepoGenericOutput(status=ToolStatus.UNAVAILABLE, message="git is not installed")
    dest = Path(inp.dest_path)
    if dest.exists() and any(dest.iterdir()):
        return RepoGenericOutput(status=ToolStatus.ERROR, message=f"Destination is not empty: {inp.dest_path}")
    result = run_command(["git", "clone", inp.repo_url, inp.dest_path], cwd=".", timeout=300)
    status = ToolStatus.OK if result.return_code == 0 else ToolStatus.ERROR
    data = {"command": result.command, "return_code": result.return_code, "stdout": result.stdout[-8000:], "stderr": result.stderr[-8000:]}
    if status == ToolStatus.OK and inp.ref:
        checkout_result = run_command(["git", "checkout", inp.ref], cwd=inp.dest_path, timeout=120)
        data["checkout"] = checkout_result.model_dump(mode="json")
        status = ToolStatus.OK if checkout_result.return_code == 0 else ToolStatus.ERROR
    return RepoGenericOutput(status=status, data=data)


def checkout(inp: RepoCheckoutInput, state) -> RepoGenericOutput:
    if shutil.which("git") is None:
        return RepoGenericOutput(status=ToolStatus.UNAVAILABLE, message="git is not installed")
    result = run_command(["git", "checkout", inp.ref], cwd=inp.repo_path, timeout=120)
    return RepoGenericOutput(
        status=ToolStatus.OK if result.return_code == 0 else ToolStatus.ERROR,
        data={"command": result.command, "return_code": result.return_code, "stdout": result.stdout[-8000:], "stderr": result.stderr[-8000:]},
    )


def register(registry) -> None:
    for tool in [
        RegisteredTool(namespace="repo", name="clone", description="Clone a remote repository.", input_model=RepoCloneInput, output_model=RepoGenericOutput, fn=clone, side_effects=[SideEffect.EXTERNAL_NETWORK]),
        RegisteredTool(namespace="repo", name="checkout", description="Checkout a git ref.", input_model=RepoCheckoutInput, output_model=RepoGenericOutput, fn=checkout, side_effects=[SideEffect.EXECUTE_LOCAL]),
        RegisteredTool(namespace="repo", name="list_files", description="List repository files.", input_model=RepoListFilesInput, output_model=RepoListFilesOutput, fn=list_files, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="repo", name="read_file", description="Read a single repository file.", input_model=RepoReadFileInput, output_model=RepoReadFileOutput, fn=read_file, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="repo", name="write_file", description="Write a repository file.", input_model=RepoWriteFileInput, output_model=RepoGenericOutput, fn=write_file, side_effects=[SideEffect.WRITE_FILES]),
        RegisteredTool(namespace="repo", name="patch_file", description="Patch a repository file.", input_model=RepoWriteFileInput, output_model=RepoGenericOutput, fn=patch_file, side_effects=[SideEffect.WRITE_FILES]),
        RegisteredTool(namespace="repo", name="find_contracts", description="Find Solidity contract files.", input_model=RepoPathInput, output_model=RepoListFilesOutput, fn=find_contracts, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="repo", name="find_tests", description="Find Solidity test files.", input_model=RepoPathInput, output_model=RepoListFilesOutput, fn=find_tests, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="repo", name="search_text", description="Search repository text.", input_model=RepoSearchInput, output_model=RepoSearchOutput, fn=search_text, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="repo", name="git_status", description="Return a safe git status summary.", input_model=RepoPathInput, output_model=RepoGenericOutput, fn=git_status, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="repo", name="git_diff", description="Return a safe git diff summary.", input_model=RepoPathInput, output_model=RepoGenericOutput, fn=git_diff, side_effects=[SideEffect.EXECUTE_LOCAL]),
        RegisteredTool(namespace="repo", name="snapshot", description="Create a compact repository snapshot.", input_model=RepoPathInput, output_model=RepoGenericOutput, fn=snapshot, side_effects=[SideEffect.READ_FILES]),
    ]:
        registry.register(tool)
