from sentinel.graphs.research import build_research_graph, run_research_subgraph
from sentinel.schemas.common import ToolStatus
from sentinel.schemas.research import ResearchRefinement, ResearchSubgraphResult, VulnerabilityHypothesis
from sentinel.state import initial_research_state


def _hypothesis() -> VulnerabilityHypothesis:
    return VulnerabilityHypothesis(
        id="hyp-1",
        title="Missing access control candidate",
        vulnerability_class="missing_access_control",
        affected_files=["src/Vault.sol"],
        affected_functions=["emergencyWithdraw"],
        evidence_summary="Privileged-looking function has no visible authorization modifier.",
        confidence=0.6,
    )


def test_research_graph_compiles_and_returns_result():
    graph = build_research_graph()
    state = initial_research_state(
        subgraph_run_id="sub-1",
        parent_run_id="parent-1",
        objective="Find access control bugs",
        hypothesis=_hypothesis(),
        selected_snippets=[{"kind": "external_calls", "file_path": "src/Vault.sol", "line": 16, "function": "emergencyWithdraw", "text": "to.transfer(address(this).balance);"}],
        allowed_tool_names=["research.summarize_known_pattern"],
    )

    result_state = graph.invoke(state)

    assert result_state["result"].status == ToolStatus.OK
    assert result_state["result"].hypothesis_id == "hyp-1"
    assert result_state["result"].evidence[0]["line_start"] == 16
    assert "unauthorized caller" in result_state["result"].likely_impact
    assert "Research subgraph received scoped state only." in result_state["result"].notes


def test_research_subgraph_removes_forbidden_tools_from_scope():
    state = initial_research_state(
        subgraph_run_id="sub-1",
        parent_run_id="parent-1",
        objective="Find bugs",
        hypothesis=_hypothesis(),
        selected_snippets=[],
        allowed_tool_names=["research.summarize_known_pattern", "repo.read_file", "build.foundry_test"],
    )

    result = run_research_subgraph(state)

    assert isinstance(result, ResearchSubgraphResult)
    assert result.status == ToolStatus.OK
    assert any("Rejected non-research tools" in note for note in result.notes)


def test_research_subgraph_applies_llm_refinement(monkeypatch):
    class FakeRefiner:
        def refine(self, prompt):
            assert "emergencyWithdraw" in prompt
            return ResearchRefinement(
                likely_impact="A non-owner can drain the vault balance.",
                exploit_preconditions=["Vault holds ETH", "Caller can reach emergencyWithdraw"],
                recommended_tests=["Assert non-owner emergencyWithdraw reverts."],
                limitations=["Requires confirming intended admin model."],
                confidence_delta=0.05,
            )

    monkeypatch.setattr("sentinel.graphs.research.llm_provider.get_research_refiner", lambda mock=False: FakeRefiner())
    state = initial_research_state(
        subgraph_run_id="sub-1",
        parent_run_id="parent-1",
        objective="Find bugs",
        hypothesis=_hypothesis(),
        selected_snippets=[{"kind": "external_calls", "file_path": "src/Vault.sol", "line": 16, "function": "emergencyWithdraw", "text": "to.transfer(address(this).balance);"}],
        allowed_tool_names=["research.summarize_known_pattern"],
        use_llm_refiner=True,
    )

    result = run_research_subgraph(state)

    assert result.likely_impact == "A non-owner can drain the vault balance."
    assert result.recommended_tests == ["Assert non-owner emergencyWithdraw reverts."]
    assert result.confidence == 0.75
    assert "LLM research refinement applied." in result.notes


def test_research_state_does_not_include_parent_audit_fields():
    state = initial_research_state(
        subgraph_run_id="sub-1",
        parent_run_id="parent-1",
        objective="Find bugs",
        hypothesis=_hypothesis(),
        selected_snippets=[],
        allowed_tool_names=["research.summarize_known_pattern"],
    )

    forbidden_parent_fields = {"repo_path", "tool_ledger", "static_facts", "build_facts", "artifacts", "errors"}

    assert forbidden_parent_fields.isdisjoint(state.keys())
