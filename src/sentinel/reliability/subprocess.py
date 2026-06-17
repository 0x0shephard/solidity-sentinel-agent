from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile

from pydantic import BaseModel, Field


class CommandResult(BaseModel):
    command: list[str]
    cwd: str
    return_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


# Only these non-sensitive variables are forwarded to untrusted repo commands.
# Everything else (API keys, tokens, cloud creds, ssh-agent sockets, …) is dropped.
_ENV_ALLOWLIST = (
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LANGUAGE",
    "TERM",
    "TZ",
    "TMPDIR",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
)


def _sandbox_home() -> str:
    """An isolated HOME so commands never read the user's real ~ (ssh keys, creds)."""
    home = Path(tempfile.gettempdir()) / "sentinel-sandbox-home"
    home.mkdir(parents=True, exist_ok=True)
    return str(home)


def sanitized_env(home: str | Path | None = None, extra: dict[str, str] | None = None) -> dict[str, str]:
    """Build a minimal, secret-free environment for untrusted repo commands.

    Forwards only an allowlist of non-sensitive variables and isolates ``HOME`` to
    a sandbox directory (never the user's real ``$HOME``), so a malicious target
    repo's build/test scripts cannot read host secrets or write the user's dotfiles.

    Args:
        home: Optional explicit isolated HOME (e.g. a per-run artifacts dir);
            defaults to a shared sandbox home so solc/svm caches persist.
        extra: Optional extra benign vars to add (e.g. a build profile).
    Returns:
        The sanitized environment dict to pass to ``run_command``.
    """
    env = {key: os.environ[key] for key in _ENV_ALLOWLIST if key in os.environ}
    env["HOME"] = str(home) if home is not None else _sandbox_home()
    if extra:
        env.update(extra)
    return env


def run_command(
    command: list[str],
    cwd: str | Path,
    timeout: int = 60,
    env: dict[str, str] | None = None,
    inherit_env: bool = False,
) -> CommandResult:
    """Run a local command safely.

    `command` must be a list of arguments. This prevents accidental shell
    interpretation of model-produced strings. By default the command runs with a
    sanitized, secret-free environment (see ``sanitized_env``); pass an explicit
    ``env`` or set ``inherit_env=True`` only when you trust the command.

    Args:
        command: Argument list (no shell).
        cwd: Working directory.
        timeout: Seconds before the command is killed (return_code 124).
        env: Explicit environment; if None, a sanitized env is used.
        inherit_env: If True and ``env`` is None, inherit the full host env
            (use only for trusted, secret-independent commands).
    Returns:
        A ``CommandResult`` with return code, stdout/stderr, and timeout flag.
    """

    if not command or not all(isinstance(part, str) and part for part in command):
        raise ValueError("command must be a non-empty list[str]")
    if env is None:
        env = os.environ.copy() if inherit_env else sanitized_env()
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

