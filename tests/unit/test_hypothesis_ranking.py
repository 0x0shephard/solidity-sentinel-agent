from sentinel.schemas.common import ToolStatus
from sentinel.tools.research import RankHypothesesInput, rank_hypotheses


def test_rank_hypotheses_detects_reentrancy_from_call_before_state_write():
    output = rank_hypotheses(
        RankHypothesesInput(
            objective="Find reentrancy bugs",
            static_facts=[
                {"file_path": "src/ReentrantVault.sol", "function": "withdraw"},
                {"file_path": "src/ReentrantVault.sol", "line": 14, "text": '(bool ok,) = msg.sender.call{value: amount}("");'},
                {"file_path": "src/ReentrantVault.sol", "line": 17, "text": "balances[msg.sender] = 0;"},
            ],
        ),
        {},
    )

    assert output.status == ToolStatus.OK
    assert output.hypotheses[0].vulnerability_class == "reentrancy"
    assert output.hypotheses[0].affected_functions == ["withdraw"]


def test_rank_hypotheses_uses_slither_detector_when_available():
    output = rank_hypotheses(
        RankHypothesesInput(
            objective="Find reentrancy bugs",
            static_facts=[
                {"file_path": "src/ReentrantVault.sol", "function": "withdraw"},
                {
                    "check": "reentrancy-eth",
                    "impact": "High",
                    "confidence": "Medium",
                    "description": "Reentrancy in ReentrantVault.withdraw()",
                    "source_files": ["src/ReentrantVault.sol"],
                    "functions": ["withdraw"],
                    "elements": [],
                },
            ],
        ),
        {},
    )

    assert output.status == ToolStatus.OK
    assert output.hypotheses[0].vulnerability_class == "reentrancy"
    assert output.hypotheses[0].affected_files == ["src/ReentrantVault.sol"]
    assert output.hypotheses[0].confidence > 0.7


def test_rank_hypotheses_detects_unchecked_token_transfer():
    output = rank_hypotheses(
        RankHypothesesInput(
            objective="Find unchecked transfer bugs",
            static_facts=[
                {"file_path": "src/UnsafeTokenVault.sol", "function": "withdraw"},
                {"file_path": "src/UnsafeTokenVault.sol", "line": 23, "text": "token.transfer(msg.sender, amount);"},
            ],
        ),
        {},
    )

    assert output.status == ToolStatus.OK
    assert output.hypotheses[0].vulnerability_class == "unchecked_transfer"
    assert output.hypotheses[0].affected_functions == ["withdraw"]


def test_rank_hypotheses_ignores_checked_token_transfer():
    output = rank_hypotheses(
        RankHypothesesInput(
            objective="Find unchecked transfer bugs",
            static_facts=[
                {"file_path": "src/SafeVault.sol", "function": "deposit"},
                {"file_path": "src/SafeVault.sol", "line": 10, "text": "require(token.transferFrom(msg.sender, address(this), amount));"},
            ],
        ),
        {},
    )

    assert output.status == ToolStatus.OK
    assert output.hypotheses[0].vulnerability_class == "manual_review"
