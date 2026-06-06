from __future__ import annotations

from sentinel.evals.recall import (
    Candidate,
    GroundTruthFinding,
    load_ground_truth,
    score_recall,
)


def _gt():
    return [
        GroundTruthFinding(id="H-02", severity="high", title="missing division", file_contains="LevelOne.sol",
                           function="graduateAndUpgrade", match_any=["totalteachers", "divide"]),
        GroundTruthFinding(id="H-03", severity="high", title="uups upgrade", file_contains="LevelOne.sol",
                           function="graduateAndUpgrade", match_any=["upgradeto", "uups"]),
        GroundTruthFinding(id="M-02", severity="medium", title="unprotected init", file_contains="LevelOne.sol",
                           function="initialize", match_any=["_disableinitializers", "front-run"]),
    ]


def test_recall_distinguishes_same_function_bugs_by_keyword():
    candidates = [
        # touches graduateAndUpgrade and clearly describes the division bug (H-02)
        Candidate(functions=["graduateAndUpgrade"], files=["src/LevelOne.sol"],
                  text="payPerTeacher is not divided by totalTeachers", source="hypothesis"),
    ]
    report = score_recall(_gt(), candidates, contest="hawk")
    by_id = {m.id: m for m in report.matches}
    assert by_id["H-02"].recalled is True
    assert by_id["H-02"].matched_keyword == "totalteachers"
    # H-03 shares the function (touched) but the keyword for UUPS is absent -> not recalled
    assert by_id["H-03"].touched is True
    assert by_id["H-03"].recalled is False
    # M-02 is a different function entirely -> not even touched
    assert by_id["M-02"].touched is False
    assert report.recalled == 1
    assert report.by_severity["high"] == {"total": 2, "recalled": 1, "touched": 2}


def test_recall_counts_full_match():
    candidates = [
        Candidate(functions=["initialize"], files=["src/LevelOne.sol"],
                  text="initialize is callable on the logic contract; no _disableInitializers in constructor", source="leads"),
    ]
    report = score_recall([_gt()[2]], candidates)
    assert report.recalled == 1
    assert report.matches[0].matched_by == "leads"


def test_load_real_hawk_ground_truth():
    gt, contest = load_ground_truth("evals/ground_truth/hawk-high.json")
    assert contest == "2025-05-hawk-high"
    ids = {g.id for g in gt}
    assert {"H-01", "H-02", "H-03", "H-04", "H-05", "M-01", "M-02"}.issubset(ids)
    assert len(gt) == 7  # 5 high + 2 medium by default (lows excluded)
