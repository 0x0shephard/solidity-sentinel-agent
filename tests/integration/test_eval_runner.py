from pathlib import Path

from sentinel.evals.runner import FIXTURES, run_all, run_fixture, write_eval_summary


def test_eval_runner_scores_all_fixtures(tmp_path, monkeypatch):
    monkeypatch.chdir(Path(__file__).parents[2])

    scores = run_all(mock_llm=True)

    assert len(scores) == len(FIXTURES)
    for score in scores:
        assert score.completed
        assert score.used_20_plus_tools
        assert score.spawned_research_subgraph
        assert score.generated_json_report
        assert score.generated_markdown_report
        assert score.expected_class_found
        assert score.expected_function_found
        assert score.evidence_present
        assert score.composition_chain_present
        assert score.score >= 90


def test_eval_summary_writes_json_and_markdown(tmp_path):
    score = run_fixture("missing-access-control", mock_llm=True)

    out_dir = write_eval_summary([score])

    assert (out_dir / "eval_summary.json").exists()
    assert (out_dir / "eval_summary.md").exists()
