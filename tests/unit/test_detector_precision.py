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


# --- new targeted detectors (sentiment-v2 holdout gaps) ---

def test_chainlink_unbounded_price_detector(tmp_path):
    from sentinel.tools.static import detect_chainlink_unbounded_price
    from sentinel.tools.repo import RepoPathInput

    (tmp_path / "src").mkdir()
    # Vulnerable: reads latestRoundData, no min/max bounds check.
    (tmp_path / "src" / "Oracle.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract Oracle {\n"
        "  function getPrice() external view returns (uint256) {\n"
        "    (, int256 price,,,) = feed.latestRoundData();\n    return uint256(price);\n  }\n}\n",
        encoding="utf-8",
    )
    # Safe: bounds the answer.
    (tmp_path / "src" / "SafeOracle.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract SafeOracle {\n"
        "  function getPrice() external view returns (uint256) {\n"
        "    (, int256 price,,,) = feed.latestRoundData();\n"
        "    require(price > minAnswer && price < maxAnswer);\n    return uint256(price);\n  }\n}\n",
        encoding="utf-8",
    )
    out = detect_chainlink_unbounded_price(RepoPathInput(repo_path=str(tmp_path)), {})
    files = {e.file_path for d in out.detections for e in d.evidence}
    assert any("Oracle.sol" in f and "SafeOracle" not in f for f in files)
    assert not any("SafeOracle.sol" in f for f in files)


def test_unsafe_approve_detector(tmp_path):
    from sentinel.tools.static import detect_unsafe_approve
    from sentinel.tools.repo import RepoPathInput

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "A.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract A {\n"
        "  function f() external { IERC20(t).approve(spender, 1); }\n"  # unsafe raw approve
        "  function g() external { IERC20(t).safeApprove(spender, 1); }\n"  # safe -> ignored
        "}\n",
        encoding="utf-8",
    )
    out = detect_unsafe_approve(RepoPathInput(repo_path=str(tmp_path)), {})
    fns = {e.function_name for d in out.detections for e in d.evidence}
    assert "f" in fns and "g" not in fns


def test_pause_not_enforced_detector(tmp_path):
    from sentinel.tools.static import detect_pause_not_enforced
    from sentinel.tools.repo import RepoPathInput

    (tmp_path / "src").mkdir()
    # Pausable but deposit lacks whenNotPaused -> flagged on deposit.
    (tmp_path / "src" / "P.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract P is Pausable {\n"
        "  function togglePause() external { _pause(); }\n"
        "  function deposit(uint256 a) external { x += a; }\n}\n",
        encoding="utf-8",
    )
    # Enforced -> not flagged.
    (tmp_path / "src" / "Q.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract Q is Pausable {\n"
        "  function deposit(uint256 a) external whenNotPaused { x += a; }\n}\n",
        encoding="utf-8",
    )
    out = detect_pause_not_enforced(RepoPathInput(repo_path=str(tmp_path)), {})
    detail = [(e.file_path.split("/")[-1], e.function_name) for d in out.detections for e in d.evidence]
    assert ("P.sol", "deposit") in detail
    assert not any(f == "Q.sol" for f, _ in detail)


def test_oracle_cached_price_risks_detector(tmp_path):
    from sentinel.tools.static import detect_oracle_cached_price_risks
    from sentinel.tools.repo import RepoPathInput

    (tmp_path / "src").mkdir()
    # Push oracle: permissionless cached update + view read with constant threshold.
    (tmp_path / "src" / "Push.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract Push {\n"
        "  uint256 public assetUsdPrice; uint256 public priceTimestamp;\n"
        "  uint256 constant STALE = 3600;\n"
        "  function updatePrice() external { assetUsdPrice = read(); priceTimestamp = block.timestamp - 180; }\n"
        "  function getValueInEth(uint256 a) external view returns (uint256) {\n"
        "    if (priceTimestamp < block.timestamp - STALE) revert();\n    return a * assetUsdPrice;\n  }\n}\n",
        encoding="utf-8",
    )
    # Pull oracle: reads fresh each call, no cached write -> no detection.
    (tmp_path / "src" / "Pull.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract Pull {\n"
        "  function getValueInEth(uint256 a) external view returns (uint256) { return a * read(); }\n}\n",
        encoding="utf-8",
    )
    out = detect_oracle_cached_price_risks(RepoPathInput(repo_path=str(tmp_path)), {})
    by_fn = {(e.function_name) for d in out.detections for e in d.evidence}
    assert "updatePrice" in by_fn          # replay (H-1 class)
    assert "getValueInEth" in by_fn        # stale-read + constant threshold (M-6/M-7)
    assert all("Pull.sol" not in e.file_path for d in out.detections for e in d.evidence)
    titles = " ".join(d.title.lower() for d in out.detections)
    assert "replay" in titles and "threshold" in titles


def test_erc4626_convertto_includes_fees_detector(tmp_path):
    from sentinel.tools.static import detect_erc4626_convertto_includes_fees
    from sentinel.tools.repo import RepoPathInput

    (tmp_path / "src").mkdir()
    # convertToShares accrues fees -> non-compliant.
    (tmp_path / "src" / "V.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract V {\n"
        "  function convertToShares(uint256 a) public view returns (uint256) {\n"
        "    (uint256 feeShares, uint256 nta) = simulateAccrue();\n    return a;\n  }\n}\n",
        encoding="utf-8",
    )
    # Compliant: no fee accrual.
    (tmp_path / "src" / "W.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract W {\n"
        "  function convertToShares(uint256 a) public view returns (uint256) { return a; }\n}\n",
        encoding="utf-8",
    )
    out = detect_erc4626_convertto_includes_fees(RepoPathInput(repo_path=str(tmp_path)), {})
    files = {e.file_path.split("/")[-1] for d in out.detections for e in d.evidence}
    assert "V.sol" in files and "W.sol" not in files
