from sentinel.schemas.common import ToolStatus
from sentinel.schemas.static import SourceEvidence, StaticDetection
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


def test_rank_hypotheses_returns_multiple_static_detection_hypotheses():
    detections = [
        StaticDetection(
            detector_id="static.detect_tx_origin_auth",
            vulnerability_class="tx_origin_authorization",
            title="tx.origin auth",
            confidence=0.86,
            evidence=[
                SourceEvidence(
                    file_path="src/Vault.sol",
                    line_start=10,
                    line_end=10,
                    contract_name="Vault",
                    function_name="onlyOwner",
                    source_text="require(tx.origin == owner);",
                    reason="tx.origin in auth",
                )
            ],
            affected_functions=["onlyOwner"],
            root_cause_terms=["tx.origin"],
            recommendation_hint="Remove tx.origin",
            checklist_refs=["solodit-access-tx-origin"],
        ),
        StaticDetection(
            detector_id="static.detect_dangerous_delegatecall",
            vulnerability_class="dangerous_delegatecall",
            title="dangerous delegatecall",
            confidence=0.83,
            evidence=[
                SourceEvidence(
                    file_path="src/Vault.sol",
                    line_start=20,
                    line_end=20,
                    contract_name="Vault",
                    function_name="batch",
                    source_text="target.delegatecall(data);",
                    reason="delegatecall target is caller supplied",
                )
            ],
            affected_functions=["batch"],
            root_cause_terms=["delegatecall"],
            recommendation_hint="Restrict delegatecall",
            checklist_refs=["solodit-delegatecall-control"],
        ),
    ]

    output = rank_hypotheses(
        RankHypothesesInput(
            objective="Find bugs",
            static_facts=[detection.model_dump(mode="json") for detection in detections],
        ),
        {},
    )

    assert output.status == ToolStatus.OK
    assert [hyp.id for hyp in output.hypotheses] == ["hyp-1", "hyp-2"]
    assert {hyp.vulnerability_class for hyp in output.hypotheses} == {
        "tx_origin_authorization",
        "dangerous_delegatecall",
    }
    assert all(hyp.evidence_lines for hyp in output.hypotheses)
