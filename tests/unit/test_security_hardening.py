from __future__ import annotations

import os
import sys

from sentinel.config import Settings
from sentinel.graphs.parent import _planner_tool_allowed
from sentinel.reliability.subprocess import run_command, sanitized_env
from sentinel.schemas.common import ToolStatus
from sentinel.tools import build_default_registry
from sentinel.tools.repo import RepoPathInput, _safe_files
from sentinel.tools.build import install_dependencies


# --- Fix #2: subprocess env is sanitized (no host secrets, isolated HOME) ---

def test_sanitized_env_drops_secrets_and_isolates_home(monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "leak-me")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-leak")
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    env = sanitized_env()
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "ANTHROPIC_API_KEY" not in env
    assert env["PATH"] == "/usr/bin:/bin"  # benign var forwarded
    assert env["HOME"] != os.environ.get("HOME")  # never the real home


def test_run_command_default_env_hides_secrets(monkeypatch):
    monkeypatch.setenv("SENTINEL_SECRET_TEST", "topsecret")
    script = "import os,sys;sys.stdout.write(os.environ.get('SENTINEL_SECRET_TEST','MISSING'))"
    # Default (sanitized) env must not leak the secret to the child process.
    sanitized = run_command([sys.executable, "-c", script], cwd=".", timeout=30)
    assert sanitized.stdout == "MISSING"
    # Opt-in inheritance still works for trusted commands.
    inherited = run_command([sys.executable, "-c", script], cwd=".", timeout=30, inherit_env=True)
    assert inherited.stdout == "topsecret"


# --- Fix #1: planner may not directly select side-effect tools ---

def test_planner_blocks_side_effect_and_install_tools(monkeypatch):
    monkeypatch.delenv("SENTINEL_PLANNER_ALLOW_SIDE_EFFECTS", raising=False)
    reg = build_default_registry()

    def allowed(name):
        return _planner_tool_allowed(reg.get(name))[0]

    # read / analysis tools the audit needs are allowed
    assert allowed("repo.list_files")
    assert allowed("static.run_slither")
    assert allowed("static.find_access_control_terms")  # not blocked by "rm" in "terms"
    assert allowed("audit.inspect_repo")
    # write / network / install / cleanup are blocked
    assert not allowed("build.install_dependencies")
    assert not allowed("build.clean")
    assert not allowed("repo.write_file")


def test_planner_allow_flag_overrides(monkeypatch):
    monkeypatch.setenv("SENTINEL_PLANNER_ALLOW_SIDE_EFFECTS", "true")
    reg = build_default_registry()
    assert _planner_tool_allowed(reg.get("build.clean"))[0]


# --- Fix #2b: installs are opt-in ---

def test_installs_disabled_by_default(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINEL_ALLOW_INSTALLS", raising=False)
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    out = install_dependencies(RepoPathInput(repo_path=str(tmp_path)), {})
    assert out.status == ToolStatus.SKIPPED
    assert "SENTINEL_ALLOW_INSTALLS" in (out.message or "")


# --- Fix #3: filesystem boundary rejects symlink escapes ---

def test_safe_files_skips_symlink_escapes(tmp_path):
    (tmp_path / "src").mkdir()
    real = tmp_path / "src" / "Vault.sol"
    real.write_text("contract Vault {}", encoding="utf-8")
    # secret outside the repo
    outside = tmp_path.parent / "outside_secret.txt"
    outside.write_text("SECRET", encoding="utf-8")
    # a symlink inside the repo pointing outside it
    escape = tmp_path / "src" / "escape.sol"
    try:
        escape.symlink_to(outside)
    except (OSError, NotImplementedError):
        return  # platform without symlink support
    files = {str(p.name) for p in _safe_files(str(tmp_path))}
    assert "Vault.sol" in files
    assert "escape.sol" not in files  # symlink escape excluded
