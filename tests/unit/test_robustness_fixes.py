from __future__ import annotations

import pytest

from sentinel.schemas.report import AnalysisCompleteness


# --- #8: validation runtime failures are not reported as tool success ---

def test_validation_failure_classifications_map_to_error():
    from sentinel.schemas.common import ToolStatus
    from sentinel.tools.dynamic import _VALIDATION_FAILURE_CLASSIFICATIONS

    # the failure set is what the run tool maps to ERROR
    assert "validation_timeout" in _VALIDATION_FAILURE_CLASSIFICATIONS
    assert "validation_runtime_error" in _VALIDATION_FAILURE_CLASSIFICATIONS
    assert "validation_execution_failed" in _VALIDATION_FAILURE_CLASSIFICATIONS
    # a passed/violated run is NOT a failure
    assert "security_invariant_held_or_test_passed" not in _VALIDATION_FAILURE_CLASSIFICATIONS
    assert "security_invariant_violation_or_test_needs_review" not in _VALIDATION_FAILURE_CLASSIFICATIONS

    def _status(classification: str) -> ToolStatus:
        return ToolStatus.ERROR if classification in _VALIDATION_FAILURE_CLASSIFICATIONS else ToolStatus.OK

    assert _status("validation_timeout") == ToolStatus.ERROR
    assert _status("validation_runtime_error") == ToolStatus.ERROR
    assert _status("security_invariant_violation_or_test_needs_review") == ToolStatus.OK


# --- #10: run_id cannot path-traverse ---

def test_run_id_rejects_path_traversal(tmp_path, monkeypatch):
    from sentinel.graphs.parent import run_audit

    monkeypatch.chdir(tmp_path)
    for bad in ["../escape", "a/b", "..", "x/../y", "with space"]:
        with pytest.raises(ValueError):
            run_audit(repo=str(tmp_path), objective="x", run_id=bad, mock_llm=True)


# --- #11: Aderyn is no longer tracked in completeness ---

def test_completeness_has_no_aderyn_field():
    assert "aderyn" not in AnalysisCompleteness.model_fields
    completeness = AnalysisCompleteness()
    assert not hasattr(completeness, "aderyn")


# --- build-tier: failed commands surface stderr in the message ---

def test_command_failure_message_includes_stderr_and_timeout():
    from sentinel.reliability.subprocess import CommandResult
    from sentinel.tools.build import _command_output

    timed = _command_output(CommandResult(command=["forge", "build"], cwd=".", return_code=124, stdout="", stderr="killed", timed_out=True))
    assert timed.status.value == "error"
    assert "timed out" in (timed.message or "").lower()

    failed = _command_output(CommandResult(command=["forge", "build"], cwd=".", return_code=1, stdout="", stderr='Error (9582): Member "deposit" not found', timed_out=False))
    assert failed.status.value == "error"
    assert "deposit" in (failed.message or "")

    ok = _command_output(CommandResult(command=["forge", "build"], cwd=".", return_code=0, stdout="ok", stderr="", timed_out=False), ok_message="built")
    assert ok.status.value == "ok"
    assert ok.message == "built"


# --- PoC grounding: reentrancy template only emits when prerequisites exist ---

def test_reentrancy_template_gated_on_missing_deposit(tmp_path):
    from sentinel.schemas.research import VulnerabilityHypothesis
    from sentinel.tools.dynamic import _can_generate_executable_validation

    (tmp_path / "src").mkdir()

    def _hyp(file):
        return VulnerabilityHypothesis(
            id="hyp-r",
            title="Reentrancy",
            vulnerability_class="reentrancy",
            affected_files=[file],
            affected_functions=["callHook"],
            evidence_summary="external call before state update",
            confidence=0.7,
        )

    # No payable deposit() -> not generatable (this is the BasicRedeemHook case).
    (tmp_path / "src" / "Hook.sol").write_text(
        "pragma solidity ^0.8.20; contract Hook { function callHook() external {} }\n", encoding="utf-8"
    )
    ok, reason = _can_generate_executable_validation(str(tmp_path), _hyp("src/Hook.sol"))
    assert ok is False and "deposit" in reason

    # Payable parameterless deposit() + parameterless target fn + zero-arg ctor -> generatable.
    (tmp_path / "src" / "Vault.sol").write_text(
        "pragma solidity ^0.8.20; contract Vault { function deposit() external payable {} function callHook() external {} }\n",
        encoding="utf-8",
    )
    ok2, _ = _can_generate_executable_validation(str(tmp_path), _hyp("src/Vault.sol"))
    assert ok2 is True


# --- confidence calibration: unexecuted findings are capped at 0.85 ---

def test_confidence_capped_without_executed_validation():
    from sentinel.reporting import _calibrated_confidence

    class _Hyp:
        proof_status = "static_proof_complete"

    # No executed validation run in state -> 0.95 candidate is capped to 0.85.
    assert _calibrated_confidence(0.95, _Hyp(), {}) == 0.85
    # A value already under the cap is left untouched.
    assert _calibrated_confidence(0.60, _Hyp(), {}) == 0.60

    # An executed validation that demonstrated the violation lifts the cap.
    state = {
        "last_outputs": {
            "dynamic.run_validation_artifacts": {
                "data": {"classification": "security_invariant_violation_or_test_needs_review"}
            }
        }
    }
    assert _calibrated_confidence(0.95, _Hyp(), state) == 0.95
