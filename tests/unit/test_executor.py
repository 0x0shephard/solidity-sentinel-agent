from pathlib import Path

import pytest

from sentinel.errors import ToolValidationError
from sentinel.state import initial_audit_state
from sentinel.tools import build_default_registry
from sentinel.tools.executor import ToolExecutor


def test_executor_validates_input_and_records_success(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Vault.sol").write_text("pragma solidity ^0.8.20;\ncontract Vault {}\n", encoding="utf-8")
    state = initial_audit_state("run-1", str(tmp_path), "Find bugs", "runs/run-1")
    executor = ToolExecutor(build_default_registry())

    output = executor.execute("repo.list_files", {"repo_path": str(tmp_path)}, state)

    assert output.status == "ok"
    assert "src/Vault.sol" in output.files
    assert state["tool_call_count"] == 1
    assert state["tool_ledger"][0].tool_name == "repo.list_files"


def test_executor_rejects_invalid_input_and_records_error():
    state = initial_audit_state("run-1", ".", "Find bugs", "runs/run-1")
    executor = ToolExecutor(build_default_registry())

    with pytest.raises(ToolValidationError):
        executor.execute("repo.list_files", {}, state)

    assert state["tool_call_count"] == 1
    assert state["tool_ledger"][0].status == "error"
    assert state["tool_ledger"][0].error_type == "ToolValidationError"


def test_executor_runs_research_tool():
    state = initial_audit_state("run-1", ".", "Find access control bugs", "runs/run-1")
    executor = ToolExecutor(build_default_registry())

    output = executor.execute("research.rank_hypotheses", {"objective": "Find access control bugs"}, state)

    assert output.status == "ok"
    assert output.hypotheses[0].id == "hyp-1"

