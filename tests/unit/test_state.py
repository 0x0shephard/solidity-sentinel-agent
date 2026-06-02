from sentinel.state import initial_audit_state


def test_initial_audit_state_has_graph_defaults():
    state = initial_audit_state(
        run_id="run-1",
        repo="./repo",
        objective="Find access control bugs",
        run_dir="runs/run-1",
    )

    assert state["run_id"] == "run-1"
    assert state["repo_path"] == "./repo"
    assert state["current_focus"] == "initialize"
    assert state["tool_call_count"] == 0
    assert state["tool_ledger"] == []
    assert state["hypotheses"] == []
    assert state["subgraph_results"] == []

