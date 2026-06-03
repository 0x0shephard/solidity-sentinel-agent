from pathlib import Path

from sentinel.llm.base import ToolDecision, ToolPlan
from sentinel.graphs.parent import run_audit
from sentinel.schemas.research import ResearchRefinement


class FakePlanner:
    def plan(self, prompt, tools):
        return ToolPlan(
            decisions=[
                ToolDecision(tool_name="repo.list_files", tool_input={}, rationale="inspect files"),
                ToolDecision(tool_name="not.a_tool", tool_input={}, rationale="bad tool"),
                ToolDecision(tool_name="repo.read_file", tool_input={}, rationale="missing required file_path"),
            ]
        )


class FakeRefiner:
    def refine(self, prompt):
        return ResearchRefinement(likely_impact="Fake refined impact.")


def _write_fixture_repo(path: Path) -> None:
    (path / "src").mkdir(parents=True)
    (path / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    (path / "src" / "Vault.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract Vault { function deposit() external {} }\n",
        encoding="utf-8",
    )


def test_real_mode_graph_uses_planner_and_keeps_guardrails(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    _write_fixture_repo(repo)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sentinel.graphs.parent.get_planner", lambda mock=False: FakePlanner())
    monkeypatch.setattr("sentinel.graphs.research.llm_provider.get_research_refiner", lambda mock=False: FakeRefiner())

    state = run_audit(str(repo), "Find bugs", run_id="llm-run", mock_llm=False)

    assert state["current_focus"] == "done"
    assert "LLM selected unknown tool: not.a_tool" in state["errors"]
    assert "LLM omitted required input for repo.read_file" in state["errors"]
    assert any(record.tool_name == "repo.list_files" for record in state["tool_ledger"])
    assert Path("runs/llm-run/state.json").exists()
