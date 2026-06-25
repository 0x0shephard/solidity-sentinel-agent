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

    # A static-only proof is capped to 0.85 regardless of state.
    assert _calibrated_confidence(0.95, _Hyp(), {}) == 0.85
    # A value already under the cap is left untouched.
    assert _calibrated_confidence(0.60, _Hyp(), {}) == 0.60

    # A GLOBAL batch validation classification must NOT lift this hypothesis's cap
    # (cross-hypothesis leak): only its own proof_status can.
    leaky_state = {
        "last_outputs": {
            "dynamic.run_validation_artifacts": {
                "data": {"classification": "security_invariant_violation_or_test_needs_review"}
            }
        }
    }
    assert _calibrated_confidence(0.95, _Hyp(), leaky_state) == 0.85

    # Only THIS hypothesis's own executed PoC lifts the cap.
    class _Executed:
        proof_status = "executed_poc_confirmed"

    assert _calibrated_confidence(0.95, _Executed(), {}) == 0.95


# --- adversarial reviewer: guard counterevidence only valid for guard-class bugs ---

def test_guard_counterevidence_only_rejects_guard_classes():
    from sentinel.graphs.research import _rejection_invalid_for_class

    # Real captured case: a fee-accrual (accounting) hypothesis rejected because
    # handleReport is "gated by" the oracle / called immediately -> distrust it.
    assert _rejection_invalid_for_class(
        "accounting_invariant",
        ["calculateFee is only reachable via ShareModule.handleReport, which is gated by the oracle check"],
    ) is True
    assert _rejection_invalid_for_class(
        "accounting",
        ["SignatureDepositQueue.deposit is marked nonReentrant"],
    ) is True

    # Legitimate rejections that must STILL be honored:
    # init front-running refuted by atomic deployment (the Factory.initialize case).
    assert _rejection_invalid_for_class(
        "initialization",
        ["Factory.create deploys every instance atomically via new TransparentUpgradeableProxy"],
    ) is False
    # reentrancy refuted by nonReentrant is valid counterevidence.
    assert _rejection_invalid_for_class("reentrancy", ["callHook callers are nonReentrant"]) is False
    # An accounting rejection with a real math refutation (no guard language) is honored.
    assert _rejection_invalid_for_class(
        "accounting",
        ["the fee is subtracted before minting, so totals reconcile exactly"],
    ) is False


# --- hypothesis targeting: accounting bugs anchor on the entry-point caller ---

def test_entry_point_caller_added_for_accounting_class():
    from sentinel.graphs.parent import _add_entry_point_functions
    from sentinel.schemas.research import VulnerabilityHypothesis

    # Leaf math helper (calculateFee) reached by an entry point (handleReport).
    hyp = VulnerabilityHypothesis(
        id="h", title="fee", vulnerability_class="accounting_invariant",
        affected_files=["src/managers/FeeManager.sol"], affected_functions=["calculateFee"],
        evidence_summary="x", confidence=0.6,
    )
    _add_entry_point_functions(hyp, ["handleReport", "submitReports", "extra3"])
    # entry points are anchored (capped at 2), leaf retained, deduped
    assert "calculateFee" in hyp.affected_functions
    assert "handleReport" in hyp.affected_functions
    assert "submitReports" in hyp.affected_functions
    assert "extra3" not in hyp.affected_functions  # cap=2

    # No duplication when the caller is already present.
    hyp2 = VulnerabilityHypothesis(
        id="h2", title="fee", vulnerability_class="accounting",
        affected_files=["x.sol"], affected_functions=["handleReport"],
        evidence_summary="x", confidence=0.6,
    )
    _add_entry_point_functions(hyp2, ["handleReport"])
    assert hyp2.affected_functions == ["handleReport"]


def test_entry_point_caller_not_added_for_reentrancy_class():
    from sentinel.graphs.parent import _add_entry_point_functions
    from sentinel.schemas.research import VulnerabilityHypothesis

    # Reentrancy/access bugs should name their own vulnerable function, not callers.
    hyp = VulnerabilityHypothesis(
        id="h", title="reentrancy", vulnerability_class="reentrancy",
        affected_files=["src/Vault.sol"], affected_functions=["callHook"],
        evidence_summary="x", confidence=0.6,
    )
    _add_entry_point_functions(hyp, ["deposit", "withdraw"])
    assert hyp.affected_functions == ["callHook"]


# --- reviewer: rejection needs concrete counterevidence ---

def test_rejection_requires_concrete_counterevidence():
    from sentinel.graphs.research import _rejection_has_concrete_counterevidence

    # Empty / vague -> not trustworthy to reject.
    assert _rejection_has_concrete_counterevidence([]) is False
    assert _rejection_has_concrete_counterevidence(["this is safe"]) is False
    assert _rejection_has_concrete_counterevidence(["not exploitable"]) is False
    # Concrete code references -> a real rejection.
    assert _rejection_has_concrete_counterevidence(["Factory.create deploys via new TransparentUpgradeableProxy"]) is True
    assert _rejection_has_concrete_counterevidence(["src/Pool.sol::borrow guards this"]) is True
    assert _rejection_has_concrete_counterevidence(["riskManager.modifyVaultBalance(orderId)"]) is True


# --- dedup: identical class+title hypotheses collapse (numerical_gap bug) ---

def test_dedupe_collapses_same_title_merging_functions():
    from sentinel.schemas.research import VulnerabilityHypothesis
    from sentinel.tools.research import _dedupe_hypotheses

    def _h(fn, file):
        return VulnerabilityHypothesis(
            id="x", title="Integer division can round protocol fees to zero",
            vulnerability_class="accounting_invariant",
            affected_files=[file], affected_functions=[fn], affected_function=fn,
            evidence_summary="x", confidence=0.7,
        )

    out = _dedupe_hypotheses([_h("borrow", "src/Pool.sol"), _h("repay", "src/Pool.sol"), _h("getValueInEth", "src/oracle/O.sol")])
    same_title = [h for h in out if "integer division" in h.title.lower()]
    assert len(same_title) == 1  # collapsed from 3 -> 1
    # coverage preserved: all three functions merged into the survivor
    assert set(same_title[0].affected_functions) >= {"borrow", "repay", "getValueInEth"}


# --- model-integrity: intermittent cloud tag-rejection retries primary, not fallback ---

def test_gateway_model_tag_rejection_is_retryable():
    from sentinel.llm.resilience import is_retryable_error

    # The exact intermittent Ollama Cloud error that was silently downgrading to gemma.
    err = Exception("Bad request: {'message': \"the provider or policy you attempted to "
                    "specify '480b' is not valid.\", 'code': 'model_not_supported'}")
    assert is_retryable_error(err) is True
    # A genuine, non-transient bad request must NOT be retried forever.
    assert is_retryable_error(Exception("invalid json schema for field 'foo'")) is False


def test_count_fallback_usage_flags_contamination():
    from sentinel.graphs.parent import _count_fallback_usage

    class _Result:
        def __init__(self, notes):
            self.notes = notes

    state = {
        "notes": ["Ollama fallback planner applied."],
        "subgraph_results": [
            _Result(["Ollama fallback adversarial reviewer applied.", "some other note"]),
            _Result(["Ollama fallback research refinement applied."]),
        ],
    }
    assert _count_fallback_usage(state) == 3
    assert _count_fallback_usage({"notes": [], "subgraph_results": []}) == 0


# --- path-injection: a model-supplied class with "/" must not crash filename build ---

def test_artifact_test_name_sanitizes_unsafe_class():
    from sentinel.schemas.research import VulnerabilityHypothesis
    from sentinel.tools.dynamic import _artifact_test_name

    h = VulnerabilityHypothesis(
        id="h", title="x", vulnerability_class="External-Call/Accounting Ordering",
        affected_files=["src/V.sol"], affected_functions=["liquidate"], evidence_summary="x", confidence=0.5,
    )
    name = _artifact_test_name(h)
    assert "/" not in name and " " not in name
    assert name.endswith("Test.t.sol")


def test_inferred_invariant_category_sanitized(monkeypatch, tmp_path):
    from sentinel.schemas.research import InferredInvariant, InferredInvariantBatch
    import sentinel.llm.provider as provider
    from sentinel.state import initial_audit_state
    from sentinel.tools import build_default_registry
    from sentinel.tools.executor import ToolExecutor
    from sentinel.tools.research import infer_protocol_invariants

    (tmp_path / "src").mkdir()
    (tmp_path / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    (tmp_path / "src" / "V.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract V {\n    function liquidate() external {\n        uint256 x = 1;\n    }\n}\n",
        encoding="utf-8",
    )
    state = initial_audit_state("inv", str(tmp_path), "x", "runs/inv")
    state["use_llm_refiner"] = True
    ToolExecutor(build_default_registry()).execute("audit.run_static_analysis", {"repo_path": str(tmp_path)}, state)

    class _Inf:
        last_raw = ""
        def infer(self, prompt):
            return InferredInvariantBatch(invariants=[InferredInvariant(statement="x", category="External-Call/Accounting Ordering", functions=["liquidate"], confidence=0.6)])

    monkeypatch.setattr(provider, "get_invariant_inferencer", lambda mock=False: _Inf())
    out = infer_protocol_invariants(state)
    assert out and "/" not in out[0].invariant_type and " " not in out[0].invariant_type


# --- exploit/validation worktrees must not fail on the repo's strict warning policy ---

def test_relax_foundry_warnings_disables_deny(tmp_path):
    from sentinel.tools.dynamic import _relax_foundry_warnings

    (tmp_path / "foundry.toml").write_text("[profile.default]\ndeny_warnings = true\nsrc = 'src'\n", encoding="utf-8")
    _relax_foundry_warnings(tmp_path)
    out = (tmp_path / "foundry.toml").read_text()
    assert "deny_warnings = false" in out
    assert "deny_warnings = true" not in out

    (tmp_path / "foundry.toml").write_text('[profile.default]\ndeny = ["warnings"]\n', encoding="utf-8")
    _relax_foundry_warnings(tmp_path)
    import re as _re
    assert not _re.search(r"(?m)^\s*deny\s*=\s*.*warning", (tmp_path / "foundry.toml").read_text())


# --- executed PoC: a confirmed exploit is the strongest proof (promotes + lifts cap) ---

def test_executed_poc_counts_as_proof_and_lifts_confidence():
    from sentinel.reporting import _has_validation_proof, _has_executed_validation_proof, _calibrated_confidence

    class _Hyp:
        proof_status = "executed_poc_confirmed"

    assert _has_validation_proof(_Hyp(), {}) is True
    assert _has_executed_validation_proof(_Hyp(), {}) is True
    # an executed PoC lifts the 0.85 cap (raw confidence kept)
    assert _calibrated_confidence(0.95, _Hyp(), {}) == 0.95


# --- proof soundness: revert/skip/setup-fail must NOT be read as held/violated ---

def test_classify_validation_run_is_sound():
    from sentinel.tools.dynamic import _classify_validation_run, _VALIDATION_FAILURE_CLASSIFICATIONS

    # A real ASSERTION failure = the asserted invariant broke = violation.
    assert _classify_validation_run(1, "[FAIL: assertion failed: 2 != 1] t()\n0 passed; 1 failed; 0 skipped", "", False) == "security_invariant_violation_or_test_needs_review"
    # A plain revert (broken mock / setup revert) is NOT a proof.
    assert _classify_validation_run(1, "[FAIL: SafeERC20: low-level call failed] t()\n0 passed; 1 failed; 0 skipped", "", False) == "validation_reverted_not_asserted"
    assert _classify_validation_run(1, "[FAIL: USDT: approve not allowed] t()", "", False) == "validation_reverted_not_asserted"
    # A skipped / empty run is NOT "invariant held".
    assert _classify_validation_run(0, "0 passed; 0 failed; 1 skipped", "", False) == "validation_skipped_or_empty"
    assert _classify_validation_run(0, "[SKIP] t()", "", False) == "validation_skipped_or_empty"
    # A genuine pass = invariant held.
    assert _classify_validation_run(0, "1 passed; 0 failed; 0 skipped", "", False) == "security_invariant_held_or_test_passed"

    # Reverts and skips are failure classifications (never confirmed/refuted).
    assert "validation_reverted_not_asserted" in _VALIDATION_FAILURE_CLASSIFICATIONS
    assert "validation_skipped_or_empty" in _VALIDATION_FAILURE_CLASSIFICATIONS


def test_classify_recognizes_dsl_invariant_token():
    # A DSL assertTrue(cond, "SENTINEL_INVARIANT_VIOLATED: ...") failure prints as
    # [FAIL: SENTINEL_INVARIANT_VIOLATED: ...] WITHOUT the literal "assertion failed".
    # Without the token it was misread as a plain revert; with it, it is a violation.
    from sentinel.tools.dynamic import _classify_validation_run

    out = "[FAIL: SENTINEL_INVARIANT_VIOLATED: owner balance must decrease] test_exploit()\n0 passed; 1 failed; 0 skipped"
    assert _classify_validation_run(1, out, "", False) == "security_invariant_violation_or_test_needs_review"
    # a genuine setup revert (no token) is still NOT a proof
    revert = "[FAIL: Ownable: caller is not the owner] test_exploit()\n0 passed; 1 failed; 0 skipped"
    assert _classify_validation_run(1, revert, "", False) == "validation_reverted_not_asserted"
