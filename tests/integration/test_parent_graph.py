from pathlib import Path
import json

from sentinel.graphs.parent import build_parent_graph, run_audit
from sentinel.state import initial_audit_state


def _write_fixture_repo(path: Path) -> None:
    (path / "src").mkdir(parents=True)
    (path / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")
    (path / "src" / "Vault.sol").write_text(
        "\n".join(
            [
                "// SPDX-License-Identifier: MIT",
                "pragma solidity ^0.8.20;",
                "contract Vault {",
                "    address public owner;",
                "    constructor() { owner = msg.sender; }",
                "    function deposit() external payable {}",
                "    function emergencyWithdraw(address payable to) external {",
                "        to.transfer(address(this).balance);",
                "    }",
                "}",
            ]
        ),
        encoding="utf-8",
    )


def test_parent_graph_compiles_and_finishes(tmp_path):
    repo = tmp_path / "repo"
    run_dir = tmp_path / "runs" / "run-graph"
    _write_fixture_repo(repo)
    graph = build_parent_graph()
    state = initial_audit_state("run-graph", str(repo), "Find access control bugs", str(run_dir))

    result = graph.invoke(state)

    assert result["current_focus"] == "done"
    assert result["tool_call_count"] >= 20
    assert result["compressed_context"]
    assert result["subgraph_results"]
    assert result["subgraph_results"][0].hypothesis_id == "hyp-1"
    assert (run_dir / "state.json").exists()
    assert (run_dir / "report.json").exists()
    assert (run_dir / "report.md").exists()
    assert list((run_dir / "artifacts" / "validation-tests").glob("*.t.sol"))
    assert (run_dir / "tool_ledger.jsonl").exists()
    assert (run_dir / "logs.jsonl").exists()
    assert (run_dir / "trace.jsonl").exists()


def test_run_audit_parent_graph_returns_state(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    _write_fixture_repo(repo)
    monkeypatch.chdir(tmp_path)

    result = run_audit(str(repo), "Find access control bugs", run_id="fixed-run")

    assert result["run_id"] == "fixed-run"
    assert result["current_focus"] == "done"
    assert result["tool_call_count"] >= 20
    assert result["subgraph_results"]
    assert result["findings"]
    assert Path("runs/fixed-run/state.json").exists()
    report = json.loads(Path("runs/fixed-run/report.json").read_text(encoding="utf-8"))
    assert report["run_id"] == "fixed-run"
    assert report["tool_call_count"] >= 20
    assert report["artifacts"]
