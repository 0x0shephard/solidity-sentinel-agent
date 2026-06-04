from pathlib import Path

from sentinel.schemas.common import ToolStatus
from sentinel.schemas.research import VulnerabilityHypothesis
from sentinel.reliability.subprocess import CommandResult
from sentinel.state import initial_audit_state
from sentinel.tools import build_default_registry
from sentinel.tools.executor import ToolExecutor


def test_repo_git_status_is_real_command(tmp_path):
    state = initial_audit_state("run-1", str(tmp_path), "Find bugs", "runs/run-1")
    executor = ToolExecutor(build_default_registry())

    output = executor.execute("repo.git_status", {"repo_path": str(tmp_path)}, state)

    assert output.status in {ToolStatus.OK, ToolStatus.ERROR, ToolStatus.UNAVAILABLE}
    if output.status != ToolStatus.UNAVAILABLE:
        assert output.data["command"] == ["git", "status", "--short"]


def test_dynamic_create_and_patch_poc_test(tmp_path):
    (tmp_path / "test").mkdir()
    state = initial_audit_state("run-1", str(tmp_path), "Find bugs", "runs/run-1")
    state["hypotheses"] = [
        VulnerabilityHypothesis(
            id="hyp-1",
            title="Missing access control",
            vulnerability_class="missing_access_control",
            affected_files=["src/Vault.sol"],
            affected_functions=["emergencyWithdraw"],
            evidence_summary="Sensitive function lacks guard",
            confidence=0.7,
        )
    ]
    executor = ToolExecutor(build_default_registry())

    created = executor.execute("dynamic.create_poc_test", {"repo_path": str(tmp_path)}, state)
    patched = executor.execute("dynamic.patch_poc_test", {"repo_path": str(tmp_path)}, state)

    assert created.status == ToolStatus.OK
    assert created.data["target_function"] == "emergencyWithdraw"
    assert patched.status == ToolStatus.OK
    assert Path(patched.data["path"]).exists()


def test_dynamic_generate_validation_artifact_plan_only_when_setup_unknown(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    run_dir = tmp_path / "runs" / "run-1"
    state = initial_audit_state("run-1", str(repo), "Find bugs", str(run_dir))
    state["hypotheses"] = [
        VulnerabilityHypothesis(
            id="hyp-1",
            title="Unchecked transfer",
            vulnerability_class="unchecked_transfer",
            affected_files=["src/UnsafeTokenVault.sol"],
            affected_functions=["withdraw"],
            evidence_summary="Ignored ERC20 transfer return value",
            confidence=0.7,
        )
    ]
    executor = ToolExecutor(build_default_registry())

    generated = executor.execute("dynamic.generate_validation_artifacts", {"repo_path": str(repo)}, state)

    plan_path = Path(generated.data["plan_path"])
    assert generated.status == ToolStatus.OK
    assert generated.data["path"] is None
    assert generated.data["generated_test"] is False
    assert plan_path.exists()
    assert "mock ERC20 that returns false" in plan_path.read_text(encoding="utf-8")
    assert state["artifacts"][0].kind == "validation_plan"


def test_dynamic_compile_validation_artifact_uses_temporary_worktree(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")
    (repo / "src" / "Vault.sol").write_text("pragma solidity ^0.8.20; contract Vault {}\n", encoding="utf-8")
    run_dir = tmp_path / "runs" / "run-1"
    state = initial_audit_state("run-1", str(repo), "Find bugs", str(run_dir))
    state["hypotheses"] = [
        VulnerabilityHypothesis(
            id="hyp-1",
            title="Missing access control",
            vulnerability_class="missing_access_control",
            affected_files=["src/Vault.sol"],
            affected_functions=["emergencyWithdraw"],
            evidence_summary="Sensitive function lacks auth",
            confidence=0.7,
        )
    ]
    captured = {}

    def fake_which(name):
        return "/fake/forge" if name == "forge" else None

    def fake_run(command, cwd, timeout=60, env=None):
        captured["command"] = command
        captured["cwd"] = cwd
        return CommandResult(command=command, cwd=str(cwd), return_code=0, stdout="compiled", stderr="")

    monkeypatch.setattr("sentinel.tools.dynamic.shutil.which", fake_which)
    monkeypatch.setattr("sentinel.tools.dynamic.run_command", fake_run)
    executor = ToolExecutor(build_default_registry())

    generated = executor.execute("dynamic.generate_validation_artifacts", {"repo_path": str(repo)}, state)
    compiled = executor.execute("dynamic.compile_validation_artifacts", {"repo_path": str(repo)}, state)

    manifest = run_dir / "artifacts" / "validation-compile-result.json"
    assert generated.status == ToolStatus.OK
    assert compiled.status == ToolStatus.OK
    assert captured["command"] == ["forge", "build"]
    assert captured["cwd"].endswith("artifacts/validation-worktree")
    assert manifest.exists()
    assert not (repo / "test").exists()
    assert any(artifact.kind == "validation_compile_result" for artifact in state["artifacts"])


def test_dynamic_run_validation_artifact_classifies_failure(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")
    (repo / "src" / "Vault.sol").write_text("pragma solidity ^0.8.20; contract Vault {}\n", encoding="utf-8")
    run_dir = tmp_path / "runs" / "run-1"
    state = initial_audit_state("run-1", str(repo), "Find bugs", str(run_dir))
    state["hypotheses"] = [
        VulnerabilityHypothesis(
            id="hyp-1",
            title="Missing access control",
            vulnerability_class="missing_access_control",
            affected_files=["src/Vault.sol"],
            affected_functions=["emergencyWithdraw"],
            evidence_summary="Sensitive function lacks auth",
            confidence=0.7,
        )
    ]

    def fake_which(name):
        return "/fake/forge" if name == "forge" else None

    def fake_run(command, cwd, timeout=60, env=None):
        return CommandResult(command=command, cwd=str(cwd), return_code=1, stdout="[FAIL: invariant violated] test_check()", stderr="1 failed")

    monkeypatch.setattr("sentinel.tools.dynamic.shutil.which", fake_which)
    monkeypatch.setattr("sentinel.tools.dynamic.run_command", fake_run)
    executor = ToolExecutor(build_default_registry())

    executor.execute("dynamic.generate_validation_artifacts", {"repo_path": str(repo)}, state)
    executed = executor.execute("dynamic.run_validation_artifacts", {"repo_path": str(repo)}, state)

    manifest = run_dir / "artifacts" / "validation-run-result.json"
    assert executed.status == ToolStatus.OK
    assert executed.data["command"] == ["forge", "test", "--match-contract", "Sentinel"]
    assert executed.data["classification"] == "security_invariant_violation_or_test_needs_review"
    assert executed.data["test_names"] == ["SentinelMissingAccessControlemergencyWithdrawTest"]
    assert manifest.exists()
    assert not (repo / "test").exists()
    assert any(artifact.kind == "validation_run_result" for artifact in state["artifacts"])


def test_dynamic_run_validation_artifact_classifies_runtime_error(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")
    (repo / "src" / "Vault.sol").write_text("pragma solidity ^0.8.20; contract Vault {}\n", encoding="utf-8")
    state = initial_audit_state("run-1", str(repo), "Find bugs", str(tmp_path / "runs" / "run-1"))
    state["hypotheses"] = [
        VulnerabilityHypothesis(
            id="hyp-1",
            title="Missing access control",
            vulnerability_class="missing_access_control",
            affected_files=["src/Vault.sol"],
            affected_functions=["emergencyWithdraw"],
            evidence_summary="Sensitive function lacks auth",
            confidence=0.7,
        )
    ]

    monkeypatch.setattr("sentinel.tools.dynamic.shutil.which", lambda name: "/fake/forge")
    monkeypatch.setattr(
        "sentinel.tools.dynamic.run_command",
        lambda command, cwd, timeout=60, env=None: CommandResult(command=command, cwd=str(cwd), return_code=-1, stdout="", stderr="The application panicked (crashed). Attempted to create a NULL object."),
    )
    executor = ToolExecutor(build_default_registry())

    executor.execute("dynamic.generate_validation_artifacts", {"repo_path": str(repo)}, state)
    executed = executor.execute("dynamic.run_validation_artifacts", {"repo_path": str(repo)}, state)

    assert executed.status == ToolStatus.OK
    assert executed.data["classification"] == "validation_runtime_error"


def test_dynamic_parse_and_classify_test_output():
    state = initial_audit_state("run-1", ".", "Find bugs", "runs/run-1")
    executor = ToolExecutor(build_default_registry())

    parsed = executor.execute("dynamic.parse_test_output", {"status": "ok", "data": {"stdout": "1 passed; 0 failed"}}, state)
    classified = executor.execute("dynamic.classify_test_result", parsed.model_dump(mode="json"), state)

    assert parsed.status == ToolStatus.OK
    assert parsed.data["passed"] is True
    assert classified.data["classification"] == "poc_passed"


def test_report_add_evidence_and_rank_severity():
    state = initial_audit_state("run-1", ".", "Find bugs", "runs/run-1")
    state["hypotheses"] = [
        VulnerabilityHypothesis(
            id="hyp-1",
            title="Missing access control",
            vulnerability_class="missing_access_control",
            affected_files=["src/Vault.sol"],
            affected_functions=["emergencyWithdraw"],
            evidence_summary="Sensitive function lacks guard",
            confidence=0.7,
        )
    ]
    executor = ToolExecutor(build_default_registry())

    executor.execute("report.create_finding", {"data": {}}, state)
    evidence = executor.execute("report.add_evidence", {"data": {"kind": "test", "message": "extra evidence"}}, state)
    severity = executor.execute("report.rank_severity", {"data": {}}, state)

    assert evidence.status == ToolStatus.OK
    assert state["findings"][0].evidence[-1].message == "extra evidence"
    assert severity.data["severity"] == "high"


def test_memory_artifact_and_plan_tools():
    state = initial_audit_state("run-1", ".", "Find bugs", "runs/run-1")
    executor = ToolExecutor(build_default_registry())

    artifact = executor.execute("memory.store_artifact_ref", {"data": {"kind": "report", "path": "runs/run-1/report.md"}}, state)
    plan = executor.execute("memory.get_plan_state", {"data": {}}, state)

    assert artifact.status == ToolStatus.OK
    assert artifact.data["artifact_count"] == 1
    assert plan.status == ToolStatus.OK
