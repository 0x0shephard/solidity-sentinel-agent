from sentinel.reporting import build_report_document, create_findings_from_state, render_markdown_report
from sentinel.schemas.common import ArtifactRef, ToolStatus
from sentinel.schemas.research import ResearchSubgraphResult, VulnerabilityHypothesis
from sentinel.schemas.static import SourceEvidence
from sentinel.state import initial_audit_state


def test_create_findings_from_state_uses_research_result():
    state = initial_audit_state("run-1", "./repo", "Find bugs", "runs/run-1")
    state["hypotheses"] = [
        VulnerabilityHypothesis(
            id="hyp-1",
            title="Missing access control",
            vulnerability_class="missing_access_control",
            affected_files=["src/Vault.sol"],
            affected_functions=["emergencyWithdraw"],
            evidence_summary="Missing modifier",
            confidence=0.7,
        )
    ]
    state["subgraph_results"] = [
        ResearchSubgraphResult(
            status=ToolStatus.OK,
            subgraph_run_id="sub-1",
            hypothesis_id="hyp-1",
            refined_title="Missing access control",
            vulnerability_class="missing_access_control",
            evidence=[
                {
                    "kind": "external_calls",
                    "file_path": "src/Vault.sol",
                    "line_start": 16,
                    "line_end": 16,
                    "function": "emergencyWithdraw",
                    "message": "to.transfer(address(this).balance);",
                }
            ],
            likely_impact="Unauthorized withdrawal",
            confidence=0.8,
            recommended_tests=["Non-owner call should revert"],
        )
    ]

    findings = create_findings_from_state(state)

    assert findings[0].severity == "high"
    assert findings[0].confidence == 0.8
    assert findings[0].affected_functions == ["emergencyWithdraw"]
    assert findings[0].evidence[0].line_start == 16
    assert findings[0].evidence[0].message == "to.transfer(address(this).balance);"


def test_markdown_report_renders_findings():
    state = initial_audit_state("run-1", "./repo", "Find bugs", "runs/run-1")
    state["findings"] = create_findings_from_state(state)
    report = build_report_document(state)

    markdown = render_markdown_report(report)

    assert "# Solidity Sentinel Report" in markdown
    assert "No findings were generated." in markdown


def test_markdown_report_renders_evidence_line_numbers():
    state = initial_audit_state("run-1", "./repo", "Find bugs", "runs/run-1")
    state["hypotheses"] = [
        VulnerabilityHypothesis(
            id="hyp-1",
            title="Unchecked token transfer",
            vulnerability_class="unchecked_transfer",
            affected_files=["src/Vault.sol"],
            affected_functions=["withdraw"],
            evidence_summary="token.transfer ignored",
            confidence=0.7,
        )
    ]
    state["subgraph_results"] = [
        ResearchSubgraphResult(
            status=ToolStatus.OK,
            subgraph_run_id="sub-1",
            hypothesis_id="hyp-1",
            refined_title="Unchecked token transfer",
            vulnerability_class="unchecked_transfer",
            evidence=[
                {
                    "kind": "token_transfers",
                    "file_path": "src/Vault.sol",
                    "line_start": 23,
                    "line_end": 23,
                    "function": "withdraw",
                    "message": "token.transfer(msg.sender, amount);",
                }
            ],
            likely_impact="Ignoring an ERC20 transfer return value can break accounting.",
            confidence=0.8,
        )
    ]
    state["findings"] = create_findings_from_state(state)

    markdown = render_markdown_report(build_report_document(state))

    assert "`src/Vault.sol:23::withdraw`" in markdown
    assert "token.transfer(msg.sender, amount);" in markdown


def test_markdown_report_renders_artifacts():
    state = initial_audit_state("run-1", "./repo", "Find bugs", "runs/run-1")
    state["artifacts"] = [
        ArtifactRef(
            kind="foundry_validation_test",
            path="runs/run-1/artifacts/validation-tests/SentinelTest.t.sol",
            description="Generated Foundry validation test",
        )
    ]

    markdown = render_markdown_report(build_report_document(state))

    assert "## Artifacts" in markdown
    assert "SentinelTest.t.sol" in markdown


def test_report_requires_local_evidence_and_separates_historical_context():
    state = initial_audit_state("run-1", "./repo", "Find bugs", "runs/run-1")
    state["hypotheses"] = [
        VulnerabilityHypothesis(
            id="hyp-1",
            title="Dangerous delegatecall",
            vulnerability_class="dangerous_delegatecall",
            affected_files=["src/Vault.sol"],
            affected_functions=["batch"],
            evidence_summary="delegatecall target controlled",
            confidence=0.8,
            evidence_lines=[
                SourceEvidence(
                    file_path="src/Vault.sol",
                    line_start=42,
                    line_end=42,
                    contract_name="Vault",
                    function_name="batch",
                    source_text="target.delegatecall(payload);",
                    reason="delegatecall target is caller supplied",
                )
            ],
            historical_matches=[
                {
                    "finding": {
                        "id": "hist-1",
                        "title": "Delegatecall to user-controlled target",
                        "source_link": "https://example.test/report",
                    },
                    "final_score": 0.91,
                    "relevance_reason": "same root cause",
                }
            ],
        ),
        VulnerabilityHypothesis(
            id="hyp-2",
            title="RAG only",
            vulnerability_class="manual_review",
            evidence_summary="historical only",
            confidence=0.5,
        ),
    ]

    state["findings"] = create_findings_from_state(state)
    markdown = render_markdown_report(build_report_document(state))

    assert len(state["findings"]) == 1
    assert "Historical Similar Findings" in markdown
    assert "not proof of a bug" in markdown
    assert "Delegatecall to user-controlled target" in markdown


def test_report_renders_actor_model_and_demotes_blocking_counterevidence():
    state = initial_audit_state("run-1", "./repo", "Find bugs", "runs/run-1")
    state["last_outputs"]["analysis.contest_reasoning"] = {
        "actor_model": [{"role": "buyer", "capabilities": ["fill active orders"], "evidence": [{"line_start": 10}]}],
        "race_edges": [
            {
                "edge_id": "race-1",
                "edge_type": "can_mutate_before",
                "affected_state": ["orders.priceInUSDC"],
                "adversarial_trace": ["Seller amends before buyer fill."],
                "confidence": 0.86,
            }
        ],
        "working_memory": {"benchmark_lessons": ["Mutable order terms require slippage or min/max bound reasoning."]},
    }
    state["hypotheses"] = [
        VulnerabilityHypothesis(
            id="hyp-1",
            title="CEI-safe transfer",
            vulnerability_class="business_logic",
            affected_files=["src/OrderBook.sol"],
            affected_functions=["buyOrder"],
            evidence_summary="safe transfer",
            confidence=0.7,
            evidence_lines=[
                SourceEvidence(
                    file_path="src/OrderBook.sol",
                    line_start=33,
                    line_end=33,
                    contract_name="OrderBook",
                    function_name="buyOrder",
                    source_text="order.isActive = false;",
                    reason="state changed before SafeERC20 transfer",
                )
            ],
            counterevidence=["CEI-safe SafeERC20-only candidate with no concrete secondary target"],
            status="likely",
        )
    ]

    state["findings"] = create_findings_from_state(state)
    report = build_report_document(state)
    markdown = render_markdown_report(report)

    assert state["findings"][0].status == "rejected"
    assert "## Actor / Intent Model" in markdown
    assert "## Transaction Race Model" in markdown
    assert "## Audit Memory Notes" in markdown
