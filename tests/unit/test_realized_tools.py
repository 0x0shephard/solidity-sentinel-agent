from pathlib import Path

from sentinel.schemas.common import ToolStatus
from sentinel.schemas.research import VulnerabilityHypothesis
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

