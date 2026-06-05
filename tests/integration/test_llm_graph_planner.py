from pathlib import Path

import pytest

from sentinel.llm.base import ToolDecision, ToolPlan
from sentinel.llm.mock import MockHypothesisProposer
from sentinel.graphs.parent import run_audit
from sentinel.schemas.research import ResearchRefinement


@pytest.fixture(autouse=True)
def _hermetic_hypothesis_proposer(monkeypatch):
    """Keep real-LLM-mode audits hermetic: never call a live proposer endpoint."""
    monkeypatch.setattr(
        "sentinel.llm.provider.get_hypothesis_proposer",
        lambda mock=False: MockHypothesisProposer(),
    )


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


class CompositeDrivingPlanner:
    """Plans a single composite tool, then stops — the model drives the whole audit."""

    def __init__(self) -> None:
        self.calls = 0

    def plan(self, prompt, tools):
        self.calls += 1
        if self.calls == 1:
            return ToolPlan(
                decisions=[ToolDecision(tool_name="audit.research_hypotheses", tool_input={}, rationale="drive full pipeline")],
                stop=False,
            )
        return ToolPlan(decisions=[], stop=True)


def test_planner_drives_full_pipeline_via_composite_tool(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    _write_fixture_repo(repo)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sentinel.graphs.parent.get_planner", lambda mock=False: CompositeDrivingPlanner())
    monkeypatch.setattr("sentinel.graphs.research.llm_provider.get_research_refiner", lambda mock=False: FakeRefiner())

    state = run_audit(str(repo), "Find bugs", run_id="composite-run", mock_llm=False)

    assert state["current_focus"] == "done"
    # The model's single composite call completed every milestone during planning.
    plan_record = state["last_outputs"]["llm.plan_with_llm"]
    assert any(d["tool_name"] == "audit.research_hypotheses" for d in plan_record["executed"])
    assert plan_record["stop_reason"] == "milestones_complete"
    assert all(plan_record["milestones"].values())
    # Every pipeline stage was completed during planning (model-driven), so the
    # deterministic chain had nothing left to do.
    assert state["completed_stages"][-1] == "research_completed"
    assert len(state["completed_stages"]) == 11
    assert state.get("protocol_ir") is not None
    assert Path("runs/composite-run/report.md").exists()


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


def test_real_mode_graph_falls_back_when_planner_provider_fails(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    _write_fixture_repo(repo)
    monkeypatch.chdir(tmp_path)

    class FailingPlanner:
        def plan(self, prompt, tools):
            raise RuntimeError("hosted model quota exceeded")

    monkeypatch.setattr("sentinel.graphs.parent.get_planner", lambda mock=False: FailingPlanner())

    state = run_audit(str(repo), "Find bugs", run_id="llm-fallback-run", mock_llm=False)

    assert state["current_focus"] == "done"
    assert state["last_outputs"]["llm.plan_with_llm"]["fallback"] == "deterministic_graph"
    assert any("Primary LLM planner unavailable" in warning for warning in state["warnings"])
    assert Path("runs/llm-fallback-run/report.md").exists()


def test_real_mode_graph_uses_ollama_fallback_when_primary_planner_fails(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    _write_fixture_repo(repo)
    monkeypatch.chdir(tmp_path)

    class FailingPlanner:
        def plan(self, prompt, tools):
            raise RuntimeError("hf credits exhausted")

    monkeypatch.setattr("sentinel.graphs.parent.get_planner", lambda mock=False: FailingPlanner())
    monkeypatch.setattr("sentinel.graphs.parent.get_ollama_fallback_planner", lambda: FakePlanner())
    monkeypatch.setattr("sentinel.graphs.research.llm_provider.get_research_refiner", lambda mock=False: FakeRefiner())

    state = run_audit(str(repo), "Find bugs", run_id="llm-ollama-fallback-run", mock_llm=False)

    assert state["current_focus"] == "done"
    assert state["last_outputs"]["llm.plan_with_llm"]["planner_source"] == "ollama_fallback"
    assert any("Ollama fallback planner succeeded" in warning for warning in state["warnings"])
