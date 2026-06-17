from __future__ import annotations

from sentinel.reporting import _status_with_proof_gate
from sentinel.schemas.research import VulnerabilityHypothesis
from sentinel.tools.research import _detect_missing_access_control, _detect_reentrancy


# --- #5: reentrancy must be function-scoped, not file-scoped ---

def _call(file, line, fn):
    return {"file_path": file, "line": line, "function": fn, "text": "(bool ok, ) = to.call{value: x}('')"}


def _write(file, line, fn):
    return {"file_path": file, "line": line, "function": fn, "text": "balanceOf[msg.sender] = 0"}


def test_reentrancy_requires_same_function():
    functions = [{"file_path": "src/V.sol", "line": 10, "function": "withdraw"}]
    call = _call("src/V.sol", 12, "withdraw")
    # write is in a DIFFERENT function in the same file -> not reentrancy
    cross_fn = _detect_reentrancy(functions, [call], [_write("src/V.sol", 40, "unrelated")])
    assert cross_fn is None
    # write after the call in the SAME function -> flagged
    same_fn = _detect_reentrancy(functions, [call], [_write("src/V.sol", 15, "withdraw")])
    assert same_fn is not None
    assert same_fn.vulnerability_class == "reentrancy"
    assert same_fn.affected_functions == ["withdraw"]


def test_reentrancy_skips_when_call_function_unknown():
    call = {"file_path": "src/V.sol", "line": 12, "function": None, "text": ".call{value: x}('')"}
    assert _detect_reentrancy([], [call], [_write("src/V.sol", 15, "withdraw")]) is None


# --- #6: access-control guard is evaluated per function, not globally ---

def test_missing_access_control_is_per_function():
    functions = [
        {"file_path": "src/V.sol", "line": 10, "function": "adminConfig", "text": "function adminConfig() external onlyOwner {"},
        {"file_path": "src/V.sol", "line": 30, "function": "emergencyWithdraw", "text": "function emergencyWithdraw() external {"},
    ]
    external_calls = [{"file_path": "src/V.sol", "line": 32, "function": "emergencyWithdraw", "text": "to.call{value: bal}('')"}]
    access_facts = [{"file_path": "src/V.sol", "line": 10, "text": "function adminConfig() external onlyOwner {"}]
    # A guarded adminConfig must NOT suppress the unguarded emergencyWithdraw.
    finding = _detect_missing_access_control(functions, external_calls, access_facts)
    assert finding is not None
    assert finding.affected_functions == ["emergencyWithdraw"]


def test_guarded_sensitive_function_is_not_flagged():
    functions = [
        {"file_path": "src/V.sol", "line": 30, "function": "emergencyWithdraw", "text": "function emergencyWithdraw() external onlyOwner {"},
    ]
    external_calls = [{"file_path": "src/V.sol", "line": 32, "function": "emergencyWithdraw", "text": "to.call{value: bal}('')"}]
    assert _detect_missing_access_control(functions, external_calls, []) is None


# --- #4: 'confirmed' requires proof, not reasoning alone ---

def _hyp(proof_status):
    return VulnerabilityHypothesis(
        id="hyp-1", title="x", vulnerability_class="reentrancy",
        affected_files=["src/V.sol"], affected_functions=["withdraw"],
        evidence_summary="x", confidence=0.8, proof_status=proof_status,
    )


def test_confirmed_demoted_without_proof():
    status, notes = _status_with_proof_gate("confirmed", _hyp("strong_local_path"), {"last_outputs": {}})
    assert status == "likely"
    assert notes and "Demoted from confirmed" in notes[0]


def test_confirmed_kept_with_semantic_proof():
    status, notes = _status_with_proof_gate("confirmed", _hyp("static_proof_complete"), {"last_outputs": {}})
    assert status == "confirmed"
    assert notes == []


def test_confirmed_kept_with_executable_validation():
    state = {"last_outputs": {"dynamic.run_validation_artifacts": {"data": {"classification": "security_invariant_violation_or_test_needs_review"}}}}
    status, _ = _status_with_proof_gate("confirmed", _hyp("strong_local_path"), state)
    assert status == "confirmed"


def test_proof_gate_ignores_non_confirmed():
    assert _status_with_proof_gate("likely", _hyp("setup_required"), {"last_outputs": {}}) == ("likely", [])
