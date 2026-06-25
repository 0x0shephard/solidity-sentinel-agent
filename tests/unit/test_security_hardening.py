from __future__ import annotations

import os
import sys

from sentinel.config import Settings
from sentinel.graphs.parent import _planner_tool_allowed
from sentinel.reliability.subprocess import run_command, sanitized_env
from sentinel.schemas.common import ToolStatus
from sentinel.tools import build_default_registry
from sentinel.tools.repo import RepoPathInput, RepoReadFileInput, _safe_files, read_file
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


def test_blind_eval_hides_audit_reports(tmp_path, monkeypatch):
    from sentinel.tools.repo import _is_audit_leak_path, _safe_files
    from pathlib import Path as _P

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Pool.sol").write_text("contract Pool {}", encoding="utf-8")
    (tmp_path / "audits").mkdir()
    (tmp_path / "audits" / "sentiment_v2_zobront.md").write_text("# H-1 reentrancy ...", encoding="utf-8")
    (tmp_path / "findings.md").write_text("known issues", encoding="utf-8")
    (tmp_path / "README.md").write_text("# project", encoding="utf-8")

    # blind on (default): audit report + findings hidden; source + README kept
    visible = {str(p.relative_to(tmp_path)) for p in _safe_files(str(tmp_path))}
    assert "src/Pool.sol" in visible
    assert "README.md" in visible
    assert "audits/sentiment_v2_zobront.md" not in visible
    assert "findings.md" not in visible

    # predicate spot-checks
    assert _is_audit_leak_path(_P("audits/x.md")) is True
    assert _is_audit_leak_path(_P("reports/c4-final.md")) is True
    assert _is_audit_leak_path(_P("src/Pool.sol")) is False
    assert _is_audit_leak_path(_P("README.md")) is False

    # blind off: everything visible again (get_settings reads env fresh per call)
    monkeypatch.setenv("SENTINEL_BLIND_AUDIT_EVAL", "0")
    visible_off = {str(p.relative_to(tmp_path)) for p in _safe_files(str(tmp_path))}
    assert "audits/sentiment_v2_zobront.md" in visible_off


def test_blind_eval_blocks_direct_audit_report_reads(tmp_path, monkeypatch):
    (tmp_path / "audits").mkdir()
    (tmp_path / "audits" / "known-findings.md").write_text("H-1 answer leak", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Pool.sol").write_text("contract Pool {}", encoding="utf-8")

    blocked = read_file(RepoReadFileInput(repo_path=str(tmp_path), file_path="audits/known-findings.md"), {})
    assert blocked.status == ToolStatus.ERROR
    assert blocked.content == ""

    source = read_file(RepoReadFileInput(repo_path=str(tmp_path), file_path="src/Pool.sol"), {})
    assert source.status == ToolStatus.OK
    assert "contract Pool" in source.content

    monkeypatch.setenv("SENTINEL_BLIND_AUDIT_EVAL", "0")
    allowed = read_file(RepoReadFileInput(repo_path=str(tmp_path), file_path="audits/known-findings.md"), {})
    assert allowed.status == ToolStatus.OK
    assert "answer leak" in allowed.content


def test_rag_excludes_same_project_findings():
    from sentinel.rag.store import _finding_matches_terms
    from sentinel.schemas.rag import HistoricalFinding

    def _f(**kw):
        base = {"id": "1", "title": "t", "content": "c", "search_text": "s"}
        base.update(kw)
        return HistoricalFinding(**base)

    terms = ["sentiment"]
    # target project's own finding (by protocol or source) -> excluded
    assert _finding_matches_terms(_f(protocol_name="Sentiment"), terms) is True
    assert _finding_matches_terms(_f(source_link="https://code4rena.com/reports/2024-08-sentiment-v2"), terms) is True
    # an unrelated finding that doesn't name the project -> kept
    assert _finding_matches_terms(_f(protocol_name="Intuition", title="reentrancy"), terms) is False
    # empty term list never excludes
    assert _finding_matches_terms(_f(protocol_name="Sentiment"), []) is False
