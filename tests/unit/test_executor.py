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


def test_state_effects_populate_canonical_state(tmp_path):
    """Leaf tools selected by the model must merge their typed output into the
    canonical state keys the pipeline reads (repo_facts / build_facts / static_facts)."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Vault.sol").write_text("pragma solidity ^0.8.20;\ncontract Vault {}\n", encoding="utf-8")
    (tmp_path / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    state = initial_audit_state("run-effects", str(tmp_path), "Find bugs", "runs/run-effects")
    executor = ToolExecutor(build_default_registry())

    executor.execute("repo.list_files", {"repo_path": str(tmp_path)}, state)
    executor.execute("repo.find_contracts", {"repo_path": str(tmp_path)}, state)
    executor.execute("build.detect_framework", {"repo_path": str(tmp_path)}, state)
    executor.execute("static.extract_functions", {"repo_path": str(tmp_path)}, state)

    assert state["repo_facts"]["files"]
    assert state["repo_facts"]["contracts"]
    assert state["build_facts"]["framework"]["framework"] in {"foundry", "mixed", "unknown"}
    assert isinstance(state["static_facts"]["functions"], list)


def test_composite_tool_drives_milestones(tmp_path):
    """Composite audit.* tools complete pipeline stages and record milestone
    completion, letting an LLM planner drive the audit forward."""
    from sentinel.graphs.parent import _planner_milestones

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Vault.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract Vault { address owner; function setOwner(address o) external { owner = o; } }\n",
        encoding="utf-8",
    )
    (tmp_path / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    state = initial_audit_state("run-composite", str(tmp_path), "Find bugs", "runs/run-composite")
    executor = ToolExecutor(build_default_registry())

    assert not any(_planner_milestones(state).values())

    out = executor.execute("audit.build_protocol_ir", {"repo_path": str(tmp_path)}, state)

    assert out.milestone_satisfied
    # Self-healing: prerequisite stages ran in dependency order and were recorded.
    assert state["completed_stages"] == [
        "repo_inspected",
        "framework_detected",
        "static_facts_extracted",
        "protocol_ir_built",
    ]
    milestones = _planner_milestones(state)
    assert milestones["protocol_ir_built"]
    assert not milestones["contest_reasoning_done"]
    assert state.get("protocol_ir") is not None

