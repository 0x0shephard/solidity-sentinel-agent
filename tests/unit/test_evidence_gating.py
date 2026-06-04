from sentinel.evidence import classify_source_path, default_evidence_role
from sentinel.reporting import build_report_document, create_findings_from_state
from sentinel.schemas.common import ToolStatus
from sentinel.schemas.research import ResearchSubgraphResult, VulnerabilityHypothesis
from sentinel.state import initial_audit_state


def test_classify_source_path_distinguishes_production_from_supporting_sources():
    assert classify_source_path("src/Vault.sol") == "production"
    assert classify_source_path("contracts/Vault.sol") == "production"
    assert classify_source_path("test/Vault.t.sol") == "test"
    assert classify_source_path("script/Deploy.s.sol") == "script"
    assert classify_source_path("lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol") == "library"
    assert default_evidence_role("production") == "primary"
    assert default_evidence_role("test") == "behavioral_example"


def test_confirmed_research_is_demoted_without_production_evidence():
    state = initial_audit_state("run-1", "./repo", "Find bugs", "runs/run-1")
    state["hypotheses"] = [
        VulnerabilityHypothesis(
            id="hyp-1",
            title="Suspicious behavior from test",
            vulnerability_class="business_logic",
            affected_files=["test/Vault.t.sol"],
            affected_functions=["testExploit"],
            evidence_summary="test demonstrates suspicious behavior",
            confidence=0.8,
        )
    ]
    state["subgraph_results"] = [
        ResearchSubgraphResult(
            status=ToolStatus.OK,
            subgraph_run_id="sub-1",
            hypothesis_id="hyp-1",
            refined_title="Suspicious behavior from test",
            vulnerability_class="business_logic",
            evidence=[
                {
                    "kind": "test_behavior",
                    "file_path": "test/Vault.t.sol",
                    "line_start": 12,
                    "line_end": 12,
                    "function": "testExploit",
                    "message": "Exploit fixture assertion.",
                }
            ],
            likely_impact="Could be exploitable if production code matches the fixture.",
            confidence=0.9,
            finding_status="confirmed",
        )
    ]

    findings = create_findings_from_state(state)
    report = build_report_document({**state, "findings": findings})

    assert findings[0].status == "needs_manual_review"
    assert findings[0].evidence[0].source_type == "test"
    assert findings[0].evidence[0].evidence_role == "behavioral_example"
    assert not report.findings
    assert report.needs_manual_review
