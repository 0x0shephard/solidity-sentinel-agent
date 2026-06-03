from pathlib import Path

from sentinel.graphs.parent import run_audit


def test_astra_vault_fixture_produces_multiple_evidence_backed_findings(tmp_path, monkeypatch):
    monkeypatch.chdir(Path(__file__).resolve().parents[2])

    state = run_audit(
        "evals/fixtures/astra-vault/repo",
        "Find bugs",
        run_id="test-astra-vault",
        mock_llm=True,
    )

    findings = state["findings"]
    classes = {finding.vulnerability_class for finding in findings}

    assert len(findings) >= 5
    assert {
        "tx_origin_authorization",
        "unguarded_initializer",
        "oracle_staleness_logic",
        "unchecked_erc20_return",
        "dangerous_delegatecall",
    }.issubset(classes)
    assert all(finding.evidence for finding in findings)
    assert all(item.file_path and item.line_start for finding in findings for item in finding.evidence)

