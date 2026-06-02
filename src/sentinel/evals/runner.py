from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path

from sentinel.artifacts import write_json, write_text
from sentinel.evals.scoring import score_run
from sentinel.graphs.parent import run_audit


FIXTURES = ["missing-access-control"]


def fixture_dir(name: str) -> Path:
    return Path("evals") / "fixtures" / name


def run_fixture(name: str, mock_llm: bool = True):
    root = fixture_dir(name)
    expected = json.loads((root / "expected_findings.json").read_text(encoding="utf-8"))
    state = run_audit(str(root / "repo"), f"Find {expected['vulnerability_class']} bugs", run_id=f"eval-{name}", mock_llm=mock_llm)
    return score_run(name, state, expected)


def run_all(mock_llm: bool = True):
    return [run_fixture(name, mock_llm=mock_llm) for name in FIXTURES]


def write_eval_summary(scores: list) -> Path:
    out_dir = Path("runs") / "evals" / datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(out_dir / "eval_summary.json", [score.model_dump(mode="json") for score in scores])
    lines = ["# Eval Summary", ""]
    for score in scores:
        lines.append(f"- {score.fixture}: {score.score:.0f}/100, tools={score.tool_call_count}, subgraph={score.spawned_research_subgraph}")
        for note in score.notes:
            lines.append(f"  - {note}")
    write_text(out_dir / "eval_summary.md", "\n".join(lines) + "\n")
    return out_dir

