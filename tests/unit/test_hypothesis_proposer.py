from __future__ import annotations

import sentinel.llm.provider as provider
from sentinel.llm.ollama import parse_proposed_hypotheses
from sentinel.schemas.research import ProposedHypothesis, ProposedHypothesisBatch
from sentinel.state import initial_audit_state
from sentinel.tools import build_default_registry
from sentinel.tools.executor import ToolExecutor


def _vault_repo(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    (tmp_path / "src" / "Vault.sol").write_text(
        "pragma solidity ^0.8.20;\n"
        "contract Vault {\n"
        "    address owner;\n"
        "    function setOwner(address o) external { owner = o; }\n"
        "}\n",
        encoding="utf-8",
    )
    return tmp_path


def test_parse_proposed_hypotheses_coerces_messy_json():
    raw = (
        '```json\n{"hypotheses":[{"title":"X","class":"reentrancy","file":"A.sol",'
        '"function":"f","preconditions":"attacker reenters","confidence":"0.7"}]}\n```'
    )
    batch = parse_proposed_hypotheses(raw)
    assert len(batch.hypotheses) == 1
    h = batch.hypotheses[0]
    assert h.vulnerability_class == "reentrancy"
    assert h.affected_file == "A.sol"
    assert h.affected_function == "f"
    assert h.exploit_preconditions == ["attacker reenters"]
    assert h.confidence == 0.7


def test_parse_proposed_hypotheses_drops_entries_missing_required_fields():
    batch = parse_proposed_hypotheses('{"hypotheses":[{"title":"only title"}]}')
    assert batch.hypotheses == []


def test_propose_hypotheses_grounds_real_and_drops_hallucinated(monkeypatch, tmp_path):
    repo = _vault_repo(tmp_path)
    state = initial_audit_state("propose", str(repo), "Find access control bugs", "runs/propose")
    state["use_llm_refiner"] = True
    executor = ToolExecutor(build_default_registry())
    executor.execute("audit.run_static_analysis", {"repo_path": str(repo)}, state)

    class FakeProposer:
        def propose(self, prompt):
            return ProposedHypothesisBatch(
                hypotheses=[
                    ProposedHypothesis(
                        title="Unprotected setOwner",
                        vulnerability_class="missing_access_control",
                        affected_file="src/Vault.sol",
                        affected_function="setOwner",
                        reasoning="Anyone can call setOwner and seize ownership.",
                        exploit_preconditions=["attacker calls setOwner"],
                        confidence=0.9,
                    ),
                    ProposedHypothesis(
                        title="Hallucinated bug",
                        vulnerability_class="reentrancy",
                        affected_file="src/Ghost.sol",
                        affected_function="doesNotExist",
                        confidence=0.95,
                    ),
                ]
            )

    monkeypatch.setattr(provider, "get_hypothesis_proposer", lambda mock=False: FakeProposer())

    out = executor.execute(
        "research.propose_hypotheses",
        {"repo_path": str(repo), "objective": "Find access control bugs"},
        state,
    )

    assert out.proposed_count == 2
    assert out.grounded_count == 1
    assert out.dropped_count == 1
    assert len(out.hypotheses) == 1
    kept = out.hypotheses[0]
    assert kept.vulnerability_class == "missing_access_control"
    assert kept.affected_function == "setOwner"
    # Evidence is real source pulled from the repo, not the model's quoted text.
    assert kept.evidence_lines and "setOwner" in kept.evidence_lines[0].source_text
    assert kept.evidence_lines[0].file_path == "src/Vault.sol"
    assert kept.source_detection_ids == ["llm_proposer"]


def test_propose_hypotheses_drops_dependency_scoped_proposals(monkeypatch, tmp_path):
    """A model proposal citing a lib/ dependency (e.g. forge-std mock) must be
    dropped — only the target protocol source is in scope."""
    repo = _vault_repo(tmp_path)
    mock_dir = repo / "lib" / "forge-std" / "src" / "mocks"
    mock_dir.mkdir(parents=True)
    (mock_dir / "MockERC20.sol").write_text(
        "pragma solidity ^0.8.20;\n"
        "contract MockERC20 {\n"
        "    bool initialized;\n"
        "    function initialize() external { initialized = true; }\n"
        "}\n",
        encoding="utf-8",
    )
    state = initial_audit_state("propose-dep", str(repo), "Find bugs", "runs/propose-dep")
    state["use_llm_refiner"] = True
    executor = ToolExecutor(build_default_registry())
    executor.execute("audit.run_static_analysis", {"repo_path": str(repo)}, state)

    class DepProposer:
        def propose(self, prompt):
            return ProposedHypothesisBatch(
                hypotheses=[
                    ProposedHypothesis(
                        title="Uninitialized MockERC20",
                        vulnerability_class="business_logic",
                        affected_file="lib/forge-std/src/mocks/MockERC20.sol",
                        affected_function="initialize",
                        confidence=0.3,
                    )
                ]
            )

    monkeypatch.setattr(provider, "get_hypothesis_proposer", lambda mock=False: DepProposer())

    out = executor.execute("research.propose_hypotheses", {"repo_path": str(repo)}, state)

    assert out.grounded_count == 0
    assert out.dropped_count == 1
    assert out.hypotheses == []


def test_high_value_functions_prioritized_in_proposer_prompt(tmp_path):
    """A fund-moving + upgrading + looping function must be flagged high-value and
    shown to the proposer, even when no static detector fires on it."""
    from sentinel.tools.research import _build_proposer_prompt, _high_value_function_names

    (tmp_path / "src").mkdir()
    (tmp_path / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    (tmp_path / "src" / "School.sol").write_text(
        "pragma solidity ^0.8.20;\n"
        "interface IERC20 { function transfer(address to, uint256 a) external; }\n"
        "contract School {\n"
        "    IERC20 usdc; address[] teachers; uint256 bursary;\n"
        "    function ping() external pure returns (uint256) { return 1; }\n"
        "    function graduateAndUpgrade(address impl) external {\n"
        "        _authorizeUpgrade(impl);\n"
        "        for (uint256 i; i < teachers.length; i++) { usdc.transfer(teachers[i], bursary); }\n"
        "    }\n"
        "    function _authorizeUpgrade(address) internal {}\n"
        "}\n",
        encoding="utf-8",
    )
    state = initial_audit_state("hv", str(tmp_path), "find bugs", "runs/hv")
    state["use_llm_refiner"] = True
    ToolExecutor(build_default_registry()).execute("audit.run_static_analysis", {"repo_path": str(tmp_path)}, state)

    hv = _high_value_function_names(state, str(tmp_path))
    assert "graduateAndUpgrade" in hv
    assert "ping" not in hv  # pure, no funds/upgrade/loop

    prompt = _build_proposer_prompt(state, "find bugs")
    assert "graduateAndUpgrade" in prompt
    assert "focus_functions" in prompt
    assert "_authorizeUpgrade" in prompt  # the risky body is actually shown


def test_propose_hypotheses_skips_when_llm_disabled(tmp_path):
    repo = _vault_repo(tmp_path)
    state = initial_audit_state("propose-off", str(repo), "Find bugs", "runs/propose-off")
    state["use_llm_refiner"] = False
    executor = ToolExecutor(build_default_registry())
    executor.execute("audit.run_static_analysis", {"repo_path": str(repo)}, state)

    out = executor.execute("research.propose_hypotheses", {"repo_path": str(repo)}, state)

    assert out.hypotheses == []
    assert any("disabled" in note.lower() for note in out.notes)
