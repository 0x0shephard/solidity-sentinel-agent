from __future__ import annotations

from sentinel.graphs.parent import _attach_cross_contract_evidence
from sentinel.schemas.research import VulnerabilityHypothesis
from sentinel.schemas.static import SourceEvidence
from sentinel.state import initial_audit_state
from sentinel.tools import build_default_registry
from sentinel.tools.executor import ToolExecutor


def _two_contract_repo(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    (tmp_path / "src" / "Bank.sol").write_text(
        "pragma solidity ^0.8.20;\n"
        "contract Bank {\n"
        "    function withdraw(uint256 amount) external { /* vulnerable */ }\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "Router.sol").write_text(
        "pragma solidity ^0.8.20;\n"
        "interface IBank { function withdraw(uint256 a) external; }\n"
        "contract Router {\n"
        "    function pull(address bank, uint256 a) external { IBank(bank).withdraw(a); }\n"
        "}\n",
        encoding="utf-8",
    )
    return tmp_path


def test_attach_cross_contract_evidence_spans_two_files(tmp_path):
    repo = _two_contract_repo(tmp_path)
    state = initial_audit_state("xc", str(repo), "find bugs", "runs/xc")
    ToolExecutor(build_default_registry()).execute("audit.run_static_analysis", {"repo_path": str(repo)}, state)

    hyp = VulnerabilityHypothesis(
        id="hyp-1", title="Unsafe withdraw", vulnerability_class="reentrancy",
        affected_files=["src/Bank.sol"], affected_functions=["withdraw"], affected_function="withdraw",
        evidence_summary="withdraw has no guard", confidence=0.6,
        evidence_lines=[SourceEvidence(file_path="src/Bank.sol", line_start=3, line_end=3,
            function_name="withdraw", source_text="function withdraw(uint256 amount) external", reason="no guard")],
    )
    state["hypotheses"] = [hyp]

    before_files = {e.file_path for e in hyp.evidence_lines}
    assert before_files == {"src/Bank.sol"}

    _attach_cross_contract_evidence(state)

    after_files = {e.file_path for e in hyp.evidence_lines}
    assert "src/Router.sol" in after_files, "cross-contract caller Router.pull should be attached as evidence"
    assert len(after_files) >= 2


def test_attach_cross_contract_evidence_noop_without_callers(tmp_path):
    repo = _two_contract_repo(tmp_path)
    state = initial_audit_state("xc2", str(repo), "find bugs", "runs/xc2")
    ToolExecutor(build_default_registry()).execute("audit.run_static_analysis", {"repo_path": str(repo)}, state)

    # A function nobody calls cross-contract -> stays single-file (honest, no fabrication).
    hyp = VulnerabilityHypothesis(
        id="hyp-1", title="Lonely", vulnerability_class="business_logic",
        affected_files=["src/Router.sol"], affected_functions=["pull"], affected_function="pull",
        evidence_summary="x", confidence=0.5,
        evidence_lines=[SourceEvidence(file_path="src/Router.sol", line_start=4, line_end=4,
            function_name="pull", source_text="function pull(...)", reason="x")],
    )
    state["hypotheses"] = [hyp]
    _attach_cross_contract_evidence(state)
    assert {e.file_path for e in hyp.evidence_lines} == {"src/Router.sol"}
