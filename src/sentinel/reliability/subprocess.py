from __future__ import annotations

import subprocess
from pathlib import Path

from pydantic import BaseModel, Field


class CommandResult(BaseModel):
    command: list[str]
    cwd: str
    return_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


def run_command(command: list[str], cwd: str | Path, timeout: int = 60, env: dict[str, str] | None = None) -> CommandResult:
    """Run a local command safely.

    `command` must be a list of arguments. This prevents accidental shell
    interpretation of model-produced strings.
    """

    if not command or not all(isinstance(part, str) and part for part in command):
        raise ValueError("command must be a non-empty list[str]")
    try:
        proc = subprocess.run(
            command,
            cwd=str(cwd),
            text=True,
            capture_output=True,
            timeout=timeout,
            env=env,
            shell=False,
        )
        return CommandResult(command=command, cwd=str(cwd), return_code=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            command=command,
            cwd=str(cwd),
            return_code=124,
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
            timed_out=True,
        )

