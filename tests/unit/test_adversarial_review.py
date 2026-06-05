from __future__ import annotations

import sentinel.graphs.research as research_mod
from sentinel.graphs.parent import _caller_context_snippets
from sentinel.llm.ollama import parse_adversarial_verdict
from sentinel.schemas.research import AdversarialVerdict, VulnerabilityHypothesis
from sentinel.schemas.static import SourceEvidence
from sentinel.state import initial_audit_state, initial_research_state
from sentinel.tools import build_default_registry
from sentinel.tools.executor import ToolExecutor


def test_parse_adversarial_verdict_coerces_aliases_and_lists():
    raw = (
        '{"verdict":"mitigated","counterevidence":"wired atomically in Factory.create",'
        '"attack_trace":null,"reasoning":"no window","confidence_delta":"-0.3"}'
    )
    v = parse_adversarial_verdict(raw)
    assert v.verdict == "rejected"
    assert v.counterevidence == ["wired atomically in Factory.create"]
    assert v.attack_trace == []
    assert v.confidence_delta == -0.3


def _managers_repo(tmp_path):
    (tmp_path / "src" / "managers").mkdir(parents=True)
    (tmp_path / "src" / "vaults").mkdir(parents=True)
    (tmp_path / "lib" / "x").mkdir(parents=True)
    (tmp_path / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    (tmp_path / "src" / "managers" / "RiskManager.sol").write_text(
        "pragma solidity ^0.8.20;\n"
        "contract RiskManager {\n"
        "    address vault;\n"
        "    function setVault(address vault_) external { require(vault == address(0)); vault = vault_; }\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "vaults" / "VaultConfigurator.sol").write_text(
        "pragma solidity ^0.8.20;\n"
        "interface IRiskManager { function setVault(address v) external; }\n"
        "contract VaultConfigurator {\n"
        "    function create(address rm, address vault) external { IRiskManager(rm).setVault(vault); }\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "lib" / "x" / "Mock.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract Mock { function setVault(address v) external {} }\n",
        encoding="utf-8",
    )
    return tmp_path


def test_caller_context_finds_cross_contract_caller_and_excludes_lib(tmp_path):
    repo = _managers_repo(tmp_path)
    state = initial_audit_state("adv", str(repo), "find bugs", "runs/adv")
    ToolExecutor(build_default_registry()).execute("audit.run_static_analysis", {"repo_path": str(repo)}, state)

    hyp = VulnerabilityHypothesis(
        id="llm-hyp-1", title="Unprotected setVault", vulnerability_class="access_control",
        affected_files=["src/managers/RiskManager.sol"], affected_functions=["setVault"], affected_function="setVault",
        evidence_summary="external setVault", confidence=0.5,
    )
    callers = _caller_context_snippets(state, hyp)
    caller_files = {c["file_path"] for c in callers}
    assert "src/vaults/VaultConfigurator.sol" in caller_files
    # The lib/ mock that also contains setVault( must be excluded from caller context.
    assert not any("lib/" in f for f in caller_files)


def test_caller_context_finds_indirect_proxy_init_callsite(tmp_path):
    """A factory that initializes via `abi.encodeCall(Iface.initialize, ...)` must
    be surfaced as a caller of `initialize`, even though it is not a direct call."""
    (tmp_path / "src" / "managers").mkdir(parents=True)
    (tmp_path / "src" / "factories").mkdir(parents=True)
    (tmp_path / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    (tmp_path / "src" / "managers" / "FeeManager.sol").write_text(
        "pragma solidity ^0.8.20;\n"
        "contract FeeManager {\n"
        "    function initialize(bytes calldata data) external { }\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "factories" / "Factory.sol").write_text(
        "pragma solidity ^0.8.20;\n"
        "interface IFactoryEntity { function initialize(bytes calldata d) external; }\n"
        "contract Factory {\n"
        "    function create(address impl, bytes calldata p) external returns (address) {\n"
        "        return address(new Proxy(impl, abi.encodeCall(IFactoryEntity.initialize, (p))));\n"
        "    }\n"
        "}\n"
        "contract Proxy { constructor(address i, bytes memory d) {} }\n",
        encoding="utf-8",
    )
    state = initial_audit_state("adv2", str(tmp_path), "find bugs", "runs/adv2")
    ToolExecutor(build_default_registry()).execute("audit.run_static_analysis", {"repo_path": str(tmp_path)}, state)

    hyp = VulnerabilityHypothesis(
        id="llm-hyp-3", title="Unprotected initialize", vulnerability_class="access_control",
        affected_files=["src/managers/FeeManager.sol"], affected_functions=["initialize"], affected_function="initialize",
        evidence_summary="external initialize", confidence=0.5,
    )
    callers = _caller_context_snippets(state, hyp)
    assert any(c["file_path"] == "src/factories/Factory.sol" for c in callers), \
        "Factory.create (encodeCall init) should be found as an initialize caller"


def _hyp():
    return VulnerabilityHypothesis(
        id="llm-hyp-1", title="Unprotected setVault", vulnerability_class="access_control",
        affected_files=["src/managers/RiskManager.sol"], affected_functions=["setVault"], affected_function="setVault",
        evidence_summary="external setVault with only set-once guard", confidence=0.5,
        evidence_lines=[SourceEvidence(file_path="src/managers/RiskManager.sol", line_start=4, line_end=4,
            function_name="setVault", source_text="function setVault(...)", reason="unprotected")],
        source_detection_ids=["llm_proposer"], proof_status="strong_local_path", status="needs_manual_review",
    )


def _research_state(hyp):
    state = initial_research_state(
        subgraph_run_id="r1", parent_run_id="p1", objective="find bugs", hypothesis=hyp,
        selected_snippets=[
            {"kind": "function_body", "file_path": "src/managers/RiskManager.sol", "function": "setVault", "text": "function setVault(address v) external {...}"},
            {"kind": "caller_context", "file_path": "src/vaults/VaultConfigurator.sol", "function": "create", "text": "IRiskManager(rm).setVault(vault);"},
        ],
        allowed_tool_names=["research.retrieve_historical_findings"], use_llm_refiner=True,
    )
    return state


def test_adversarial_review_rejects_with_counterevidence(monkeypatch):
    class FakeReviewer:
        def review(self, prompt):
            return AdversarialVerdict(
                verdict="rejected",
                counterevidence=["VaultConfigurator.create() calls setVault atomically at deployment"],
                reasoning="No front-run window; wired atomically.", confidence_delta=-0.3,
            )

    monkeypatch.setattr(research_mod.llm_provider, "get_adversarial_reviewer", lambda mock=False: FakeReviewer())
    result = research_mod.run_research_subgraph(_research_state(_hyp()))
    assert result.finding_status == "rejected"
    assert any("Counterevidence" in lim for lim in result.limitations)
    assert "atomically" in result.reasoning_summary


def test_adversarial_review_confirms_with_attack_trace(monkeypatch):
    class FakeReviewer:
        def review(self, prompt):
            return AdversarialVerdict(
                verdict="confirmed",
                attack_trace=["Deploy manager", "Attacker calls setVault before configurator", "Attacker controls vault link"],
                reasoning="No atomic wiring; attacker front-runs.", confidence_delta=0.2,
            )

    monkeypatch.setattr(research_mod.llm_provider, "get_adversarial_reviewer", lambda mock=False: FakeReviewer())
    result = research_mod.run_research_subgraph(_research_state(_hyp()))
    assert result.finding_status == "confirmed"
    assert result.exploit_preconditions[0].startswith("Deploy manager")


def test_adversarial_review_skipped_when_llm_disabled(monkeypatch):
    state = _research_state(_hyp())
    state["use_llm_refiner"] = False
    result = research_mod.run_research_subgraph(state)
    assert any("Adversarial review disabled" in note for note in result.notes)
