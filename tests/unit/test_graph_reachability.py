from __future__ import annotations

from sentinel.analysis.protocol_ir import _bounded_reachable, build_protocol_graph
from sentinel.schemas.protocol_ir import AssetFlow, ContractIR, FunctionIR, ProtocolIR
from sentinel.state import initial_audit_state
from sentinel.tools import build_default_registry
from sentinel.tools.executor import ToolExecutor


# --- #7: bounded transitive reachability over internal calls ---

def test_bounded_reachable_follows_chain_and_respects_depth():
    successors = {("C", "a"): {("C", "b")}, ("C", "b"): {("C", "c")}, ("C", "c"): {("C", "a")}}
    assert _bounded_reachable(("C", "a"), successors, 5) == {("C", "a"), ("C", "b"), ("C", "c")}
    # depth bound stops the walk
    assert _bounded_reachable(("C", "a"), successors, 1) == {("C", "a"), ("C", "b")}


def _fn(name, visibility, calls):
    return FunctionIR(
        name=name, contract_name="C", file_path="src/C.sol", start_line=1, end_line=2,
        signature=f"function {name}()", visibility=visibility, calls=calls,
    )


def test_graph_includes_transitive_internal_asset_flow():
    ir = ProtocolIR(
        repo_path=".",
        contracts=[ContractIR(name="C", file_path="src/C.sol", functions=[
            _fn("withdraw", "external", ["_doWithdraw"]),
            _fn("_doWithdraw", "internal", ["_payout"]),
            _fn("_payout", "internal", []),
        ])],
    )
    # the asset transfer lives two internal hops below the entry function
    ir.asset_flows.append(AssetFlow(contract_name="C", function_name="_payout", file_path="src/C.sol", line=2, expression="to.transfer(amount)"))

    graph = build_protocol_graph(ir)
    withdraw_slice = next(s for s in graph.slices if s.entry_function == "withdraw")
    # transitive reachability surfaced both internal helpers...
    assert "C._doWithdraw" in withdraw_slice.reachable_functions
    assert "C._payout" in withdraw_slice.reachable_functions
    # ...and pulled in the deep asset flow that one-hop reachability would miss
    assert any(flow.function_name == "_payout" for flow in withdraw_slice.asset_flows)
    # internal call edges were added to the graph
    assert any(edge.call_kind == "internal" for edge in graph.slices[0].call_edges) or any(
        e.call_kind == "internal" for e in ir.call_edges
    )


# --- #9: every registered static extractor contributes to canonical facts ---

def test_canonical_static_facts_include_all_extractors(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    (tmp_path / "src" / "Base.sol").write_text("pragma solidity ^0.8.20;\ncontract Base {}\n", encoding="utf-8")
    (tmp_path / "src" / "C.sol").write_text(
        "pragma solidity ^0.8.20;\n"
        "contract C is Base {\n"
        "    modifier onlyOwner() { _; }\n"
        "    function f(address a, bytes calldata d) external onlyOwner {\n"
        "        (bool ok, ) = a.delegatecall(d);\n"
        "        oracle.latestRoundData();\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    state = initial_audit_state("g9", str(tmp_path), "find bugs", "runs/g9")
    ToolExecutor(build_default_registry()).execute("audit.run_static_analysis", {"repo_path": str(tmp_path)}, state)

    facts = state["static_facts"]
    for key in ("modifiers", "inheritance", "delegatecalls", "oracle_patterns"):
        assert key in facts, f"canonical static_facts missing '{key}'"
    # the wired extractors actually produced facts for this contract
    assert facts["modifiers"], "expected modifier facts"
    assert facts["inheritance"], "expected inheritance facts"
    assert facts["delegatecalls"], "expected delegatecall facts"
