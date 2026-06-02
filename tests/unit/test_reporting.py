from sentinel.reporting import build_report_document, create_findings_from_state, render_markdown_report
from sentinel.schemas.common import ToolStatus
from sentinel.schemas.research import ResearchSubgraphResult, VulnerabilityHypothesis
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
            likely_impact="Unauthorized withdrawal",
            confidence=0.8,
            recommended_tests=["Non-owner call should revert"],
        )
    ]

    findings = create_findings_from_state(state)

    assert findings[0].severity == "high"
    assert findings[0].confidence == 0.8
    assert findings[0].affected_functions == ["emergencyWithdraw"]


def test_markdown_report_renders_findings():
    state = initial_audit_state("run-1", "./repo", "Find bugs", "runs/run-1")
    state["findings"] = create_findings_from_state(state)
    report = build_report_document(state)

    markdown = render_markdown_report(report)

    assert "# Solidity Sentinel Report" in markdown
    assert "No findings were generated." in markdown

