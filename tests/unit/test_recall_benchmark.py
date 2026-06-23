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


# --- stratified funnel: candidate >= reviewed >= delivered >= executed-proof ---

def _one_gt():
    return [GroundTruthFinding(id="H-1", severity="high", title="inflation", file_contains="Vault.sol",
                               function="deposit", vulnerability_class="accounting_invariant",
                               match_any=["inflation"])]


def test_funnel_counts_best_stage_cumulatively():
    # Same bug present as a delivered finding (stage delivered) -> counts for all
    # earlier stages too.
    cands = [
        Candidate(functions=["deposit"], files=["src/Vault.sol"], text="share inflation attack",
                  source="findings", vulnerability_class="accounting_invariant"),
    ]
    report = score_recall(_one_gt(), cands)
    assert report.by_stage == {"candidate": 1, "reviewed": 1, "delivered": 1, "executed_proof": 0}
    assert report.recalled == 1


def test_funnel_rejected_candidate_is_candidate_only():
    cands = [
        Candidate(functions=["deposit"], files=["src/Vault.sol"], text="share inflation attack",
                  source="rejected_hypotheses", vulnerability_class="accounting_invariant"),
    ]
    report = score_recall(_one_gt(), cands)
    # proposed then rejected: counts at candidate, NOT reviewed/delivered
    assert report.by_stage["candidate"] == 1
    assert report.by_stage["reviewed"] == 0
    assert report.by_stage["delivered"] == 0


def test_executed_proof_subset():
    cands = [
        Candidate(functions=["deposit"], files=["src/Vault.sol"], text="share inflation attack",
                  source="findings", vulnerability_class="accounting_invariant", executed_proof=True),
    ]
    report = score_recall(_one_gt(), cands)
    assert report.by_stage["executed_proof"] == 1
    assert report.matches[0].executed_proof is True


def test_mechanism_recall_is_stricter_than_keyword():
    # keyword matches (inflation) but the class is wrong (reentrancy) -> recalled
    # but NOT mechanism-correct.
    cands = [
        Candidate(functions=["deposit"], files=["src/Vault.sol"], text="share inflation attack",
                  source="findings", vulnerability_class="reentrancy"),
    ]
    report = score_recall(_one_gt(), cands)
    assert report.recalled == 1
    assert report.mechanism_recalled == 0
    assert report.matches[0].mechanism_match is False

    # right class group (fee/share -> accounting) -> mechanism-correct
    cands2 = [
        Candidate(functions=["deposit"], files=["src/Vault.sol"], text="share inflation attack",
                  source="findings", vulnerability_class="fee accounting rounding"),
    ]
    report2 = score_recall(_one_gt(), cands2)
    assert report2.mechanism_recalled == 1


def test_novel_recall_excludes_rag_assisted():
    rag = Candidate(functions=["deposit"], files=["src/Vault.sol"], text="share inflation attack",
                    source="findings", vulnerability_class="accounting_invariant", rag_assisted=True)
    report = score_recall(_one_gt(), [rag])
    assert report.recalled == 1
    assert report.novel_recalled == 0  # only a RAG-assisted candidate matched

    novel = Candidate(functions=["deposit"], files=["src/Vault.sol"], text="share inflation attack",
                      source="findings", vulnerability_class="accounting_invariant", rag_assisted=False)
    report2 = score_recall(_one_gt(), [rag, novel])
    assert report2.novel_recalled == 1  # a non-RAG candidate also found it


def test_render_markdown_includes_funnel():
    cands = [Candidate(functions=["deposit"], files=["src/Vault.sol"], text="share inflation attack",
                       source="findings", vulnerability_class="accounting_invariant", executed_proof=True)]
    from sentinel.evals.recall import render_recall_markdown
    md = render_recall_markdown(score_recall(_one_gt(), cands))
    assert "Recall funnel" in md
    assert "executed-proof" in md
    assert "Mechanism-correct" in md
    assert "Novel" in md
