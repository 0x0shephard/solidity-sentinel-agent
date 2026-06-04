from pathlib import Path

from sentinel.analysis.invariants import build_protocol_model, mine_invariant_candidates
from sentinel.schemas.invariants import InvariantCandidate
from sentinel.tools.research import RankHypothesesInput, rank_hypotheses
from sentinel.tools.static import map_function_ranges
from sentinel.tools.repo import RepoPathInput


def test_invariant_miner_uses_production_sources_only(tmp_path: Path):
    src = tmp_path / "src"
    test = tmp_path / "test"
    src.mkdir()
    test.mkdir()
    (src / "School.sol").write_text(
        "\n".join(
            [
                "pragma solidity ^0.8.20;",
                "contract School {",
                "    uint256 public cutOffScore;",
                "    address[] public teachers;",
                "    function setCutOff(uint256 score) external { cutOffScore = score; }",
                "    function payTeachers(uint256 bursary) external {",
                "        for (uint256 i = 0; i < teachers.length; i++) {",
                "            payable(teachers[i]).transfer((bursary * 50) / 100);",
                "        }",
                "    }",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    (test / "School.t.sol").write_text(
        "pragma solidity ^0.8.20; contract SchoolTest { function testCutOffScore() public {} }",
        encoding="utf-8",
    )
    ranges = map_function_ranges(RepoPathInput(repo_path=str(tmp_path)), {}).model_dump(mode="json")["ranges"]
    static_facts = {"function_ranges": ranges, "contracts": [{"contract": "School"}]}

    candidates = mine_invariant_candidates(str(tmp_path), static_facts)
    invariant_types = {candidate.invariant_type for candidate in candidates}

    assert "configured_but_not_enforced" in invariant_types
    assert "percentage_distribution_math" in invariant_types
    assert all(evidence.file_path.startswith("src/") for candidate in candidates for evidence in candidate.production_evidence)


def test_protocol_model_extracts_surface_terms():
    model = build_protocol_model(
        {
            "contracts": [{"contract": "School"}],
            "storage_writes": [{"text": "cutOffScore = score; bursary += amount; owner = msg.sender;"}],
        }
    )

    assert "owner" in model.roles
    assert "score" in model.accounting_terms
    assert "bursary" in model.accounting_terms


def test_rank_hypotheses_converts_invariant_candidates():
    candidate = InvariantCandidate(
        id="inv-configured",
        invariant_type="configured_but_not_enforced",
        description="cutOffScore is configured but not enforced.",
        affected_contracts=["School"],
        affected_functions=["setCutOff"],
        production_evidence=[
            {
                "file_path": "src/School.sol",
                "line_start": 5,
                "line_end": 5,
                "contract_name": "School",
                "function_name": "setCutOff",
                "source_text": "cutOffScore = score;",
                "reason": "state variable is written",
            }
        ],
        suspicious_terms=["cutOffScore", "missing guard"],
        recommended_validation_template="configured_but_not_enforced",
        confidence=0.72,
    )

    output = rank_hypotheses(
        RankHypothesesInput(
            objective="Find bugs",
            static_facts=[{"invariant_candidate": candidate.model_dump(mode="json")}],
        ),
        {},
    )

    assert output.hypotheses
    assert output.hypotheses[0].vulnerability_class == "business_logic"
    assert output.hypotheses[0].status == "needs_manual_review"
    assert output.hypotheses[0].evidence_lines[0].file_path == "src/School.sol"
