from sentinel.state import initial_audit_state
from sentinel.tools import build_default_registry
from sentinel.tools.executor import ToolExecutor


def test_detect_framework_foundry(tmp_path):
    (tmp_path / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    state = initial_audit_state("run-1", str(tmp_path), "Find bugs", "runs/run-1")
    executor = ToolExecutor(build_default_registry())

    output = executor.execute("build.detect_framework", {"repo_path": str(tmp_path)}, state)

    assert output.framework == "foundry"
    assert output.evidence_files == ["foundry.toml"]


def test_static_extract_functions(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "Vault.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract Vault { function deposit() external {} }\n",
        encoding="utf-8",
    )
    state = initial_audit_state("run-1", str(tmp_path), "Find bugs", "runs/run-1")
    executor = ToolExecutor(build_default_registry())

    output = executor.execute("static.extract_functions", {"repo_path": str(tmp_path)}, state)

    assert output.facts == [{"file_path": "src/Vault.sol", "line": 2, "function": "deposit"}]
