from __future__ import annotations

import json

from sentinel.artifacts import write_json
from sentinel.graphs.parent import _state_for_persist


def _fat_state():
    return {
        "run_id": "r1",
        "tool_call_count": 73,
        "completed_stages": ["repo_inspected", "research_completed"],
        "tool_ledger": [{"i": i} for i in range(500)],
        "last_outputs": {
            "static.extract_functions": {"status": "ok", "facts": list(range(10000))},
            "research.rank_hypotheses": {"status": "ok", "hypotheses": list(range(2000))},
        },
        "static_facts": {
            "functions": list(range(8000)),
            "protocol_ir": {f"k{i}": list(range(100)) for i in range(200)},  # big embedded dict
            "_complete": True,
        },
        "protocol_graph": {"slices": list(range(50000))},
        "errors": [],
        "warnings": ["w1"],
    }


def test_state_for_persist_slims_heavy_keys(tmp_path):
    state = _fat_state()
    slim = _state_for_persist(state)

    assert isinstance(slim["tool_ledger"], str) and "tool_ledger.jsonl" in slim["tool_ledger"]
    # last_outputs keeps status + key names, drops the bulky payloads.
    digest = slim["last_outputs"]["static.extract_functions"]
    assert digest["status"] == "ok"
    assert "facts" in digest["keys"]  # key name preserved
    assert "9999" not in json.dumps(digest)  # but the 10k-item payload is dropped
    assert len(json.dumps(digest)) < 200
    assert slim["static_facts"]["functions"] == "<list:8000 items>"
    assert "omitted" in slim["static_facts"]["protocol_ir"]  # big embedded dict summarized
    assert slim["static_facts"]["_complete"] is True
    assert isinstance(slim["protocol_graph"], str)
    # Preserved fields stay intact.
    assert slim["tool_call_count"] == 73
    assert slim["completed_stages"] == ["repo_inspected", "research_completed"]

    # And the slimmed file is dramatically smaller than the full state.
    full_path = tmp_path / "full.json"
    slim_path = tmp_path / "slim.json"
    write_json(full_path, state)
    write_json(slim_path, slim)
    assert slim_path.stat().st_size * 20 < full_path.stat().st_size
