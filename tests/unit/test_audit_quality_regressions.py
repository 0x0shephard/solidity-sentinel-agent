from pathlib import Path

from sentinel.analysis.contest import build_transaction_race_graph, build_working_memory
from sentinel.analysis.protocol_ir import build_protocol_ir
from sentinel.graphs.parent import _evidence_snippets_for_hypothesis, _select_hypotheses_for_deepening
from sentinel.graphs.research import run_research_subgraph
from sentinel.schemas.common import ToolStatus
from sentinel.schemas.research import VulnerabilityHypothesis
from sentinel.schemas.static import SourceEvidence
from sentinel.state import initial_research_state
from sentinel.tools.repo import RepoPathInput
from sentinel.tools.static import map_function_ranges


def _evidence(line: int = 10, function: str = "target") -> SourceEvidence:
    return SourceEvidence(
        file_path="src/Vault.sol",
        line_start=line,
        line_end=line,
        contract_name="Vault",
        function_name=function,
        source_text="target.call(data);",
        reason="local dangerous source line",
    )


def test_research_does_not_confirm_setup_required_high_confidence_candidate():
    hypothesis = VulnerabilityHypothesis(
        id="hyp-1",
        title="Multi report fee accrual",
        vulnerability_class="accounting_invariant",
        affected_files=["src/Vault.sol"],
        affected_functions=["submitReports", "calculateFee"],
        evidence_summary="Report loop and fee formula coexist.",
        confidence=0.9,
        evidence_lines=[_evidence(10, "submitReports"), _evidence(20, "calculateFee")],
        proof_status="setup_required",
        status="likely",
    )
    state = initial_research_state(
        subgraph_run_id="sub-1",
        parent_run_id="parent-1",
        objective="Find bugs",
        hypothesis=hypothesis,
        selected_snippets=[
            {"kind": "source_evidence", "file_path": "src/Vault.sol", "line": 10, "function": "submitReports", "text": "for (...) handleReport(...);"},
            {"kind": "source_evidence", "file_path": "src/Vault.sol", "line": 20, "function": "calculateFee", "text": "fee = shares * feeD6 / 1e6;"},
        ],
        allowed_tool_names=["research.summarize_known_pattern"],
    )

    result = run_research_subgraph(state)

    assert result.status == ToolStatus.OK
    assert result.finding_status != "confirmed"


def test_research_confirms_complete_static_proof():
    hypothesis = VulnerabilityHypothesis(
        id="hyp-1",
        title="Duplicate signer threshold",
        vulnerability_class="access_control",
        affected_files=["src/Consensus.sol"],
        affected_functions=["verify"],
        evidence_summary="Threshold counts signature array length without uniqueness.",
        confidence=0.86,
        evidence_lines=[_evidence(23, "verify"), _evidence(28, "verify")],
        proof_status="static_proof_complete",
        status="likely",
    )
    state = initial_research_state(
        subgraph_run_id="sub-1",
        parent_run_id="parent-1",
        objective="Find bugs",
        hypothesis=hypothesis,
        selected_snippets=[{"kind": "source_evidence", "file_path": "src/Consensus.sol", "line": 23, "function": "verify", "text": "require(signatures.length >= threshold);"}],
        allowed_tool_names=["research.summarize_known_pattern"],
    )

    result = run_research_subgraph(state)

    assert result.finding_status == "confirmed"


def test_parent_deepening_selector_keeps_diverse_later_semantic_hypotheses():
    hypotheses = []
    for index in range(8):
        hypotheses.append(
            VulnerabilityHypothesis(
                id=f"hyp-{index}",
                title=f"candidate {index}",
                vulnerability_class="accounting" if index < 6 else "business_logic",
                affected_files=["src/Vault.sol"],
                affected_functions=[f"f{index}"],
                evidence_summary="local evidence",
                confidence=0.75,
                evidence_lines=[_evidence(index + 1, f"f{index}")],
                proof_status="strong_local_path",
            )
        )
    hypotheses.append(
        VulnerabilityHypothesis(
            id="hyp-profile",
            title="profile lead",
            vulnerability_class="manual_review",
            evidence_summary="profile only",
            confidence=0.99,
            source_detection_ids=["repo-profile:intent-1"],
        )
    )

    selected = _select_hypotheses_for_deepening(hypotheses, max_items=7)

    assert any(item.id == "hyp-6" for item in selected)
    assert all(item.id != "hyp-profile" for item in selected)


def test_parent_research_snippets_include_full_containing_function_body(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "Vault.sol").write_text(
        "\n".join(
            [
                "pragma solidity ^0.8.20;",
                "contract Vault {",
                "    function withdraw(uint256 amount) external {",
                "        uint256 beforeBalance = balances[msg.sender];",
                "        hook.beforeWithdraw(msg.sender, amount);",
                "        balances[msg.sender] = beforeBalance - amount;",
                "    }",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    ranges = map_function_ranges(RepoPathInput(repo_path=str(tmp_path)), {}).model_dump(mode="json")["ranges"]
    hypothesis = VulnerabilityHypothesis(
        id="hyp-1",
        title="External call before accounting",
        vulnerability_class="external_call_before_accounting",
        affected_files=["src/Vault.sol"],
        affected_functions=["withdraw"],
        evidence_summary="hook before accounting",
        confidence=0.8,
        evidence_lines=[_evidence(5, "withdraw")],
    )
    state = {"repo_path": str(tmp_path), "static_facts": {"function_ranges": ranges}, "proof_packets": []}

    snippets = _evidence_snippets_for_hypothesis(state, hypothesis)

    function_bodies = [snippet for snippet in snippets if snippet["kind"] == "function_body"]
    assert function_bodies
    assert "balances[msg.sender] = beforeBalance - amount" in function_bodies[0]["text"]


def test_working_memory_suppresses_orderbook_lessons_for_vault_repo(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "Vault.sol").write_text(
        "\n".join(
            [
                "pragma solidity ^0.8.20;",
                "contract Vault {",
                "    mapping(address => uint256) public shares;",
                "    function deposit() external payable { shares[msg.sender] += msg.value; }",
                "    function redeem(uint256 amount) external { shares[msg.sender] -= amount; }",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    ranges = map_function_ranges(RepoPathInput(repo_path=str(tmp_path)), {}).model_dump(mode="json")["ranges"]
    ir = build_protocol_ir(str(tmp_path), {"function_ranges": ranges, "contracts": [{"contract": "Vault"}]})

    memory = build_working_memory([], [], ir)

    assert not any("Mutable order terms" in lesson for lesson in memory.benchmark_lessons)


def test_actor_model_does_not_infer_market_roles_from_cancel_deposit(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "Vault.sol").write_text(
        "\n".join(
            [
                "pragma solidity ^0.8.20;",
                "contract Vault {",
                "    function cancelDepositRequest(uint256 requestId) external {}",
                "    function deposit(uint256 assets) external {}",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    ranges = map_function_ranges(RepoPathInput(repo_path=str(tmp_path)), {}).model_dump(mode="json")["ranges"]
    ir = build_protocol_ir(str(tmp_path), {"function_ranges": ranges, "contracts": [{"contract": "Vault"}]})

    graph = build_transaction_race_graph(str(tmp_path), ir)
    roles = {actor.role for actor in graph.actors}

    assert "seller" not in roles
    assert "buyer" not in roles
    assert "mev_searcher" not in roles


def test_protocol_ir_extracts_helper_mediated_asset_flows(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "Vault.sol").write_text(
        "\n".join(
            [
                "pragma solidity ^0.8.20;",
                "library TransferLibrary {",
                "    function sendAssets(address asset, address to, uint256 amount) internal {}",
                "}",
                "contract Vault {",
                "    function withdraw(address asset, address to, uint256 amount) external {",
                "        TransferLibrary.sendAssets(asset, to, amount);",
                "    }",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    ranges = map_function_ranges(RepoPathInput(repo_path=str(tmp_path)), {}).model_dump(mode="json")["ranges"]

    ir = build_protocol_ir(str(tmp_path), {"function_ranges": ranges, "contracts": [{"contract": "Vault"}]})

    assert any(flow.function_name == "withdraw" and flow.to_expr == "to" for flow in ir.asset_flows)
