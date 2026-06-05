from pathlib import Path

from sentinel.schemas.common import ToolStatus
from sentinel.schemas.research import VulnerabilityHypothesis
from sentinel.schemas.static import SourceEvidence
from sentinel.tools.dynamic import PocInput, run_semantic_validation


def _hypothesis(term: str, source_text: str) -> VulnerabilityHypothesis:
    return VulnerabilityHypothesis(
        id=f"hyp-{term}",
        title=term,
        vulnerability_class="access_control" if "signature" in term else "accounting_invariant",
        affected_files=["src/Target.sol"],
        affected_functions=["target"],
        evidence_summary=source_text,
        confidence=0.8,
        root_cause_terms=[term],
        evidence_lines=[
            SourceEvidence(
                file_path="src/Target.sol",
                line_start=10,
                line_end=10,
                contract_name="Target",
                function_name="target",
                source_text=source_text,
                reason="semantic local evidence",
            )
        ],
    )


def test_semantic_validation_confirms_signature_threshold_without_uniqueness(tmp_path: Path):
    hyp = _hypothesis("signature_threshold_uniqueness", "require(signatures.length >= threshold);")
    state = {"run_dir": str(tmp_path / "run"), "artifacts": []}

    output = run_semantic_validation(PocInput(repo_path=str(tmp_path), hypothesis=hyp), state)

    assert output.status == ToolStatus.OK
    assert output.data["validated"] is True
    assert output.data["proof_status"] == "static_proof_complete"
    assert Path(state["artifacts"][0].path).exists()


def test_semantic_validation_rejects_signature_uniqueness_counterevidence(tmp_path: Path):
    hyp = _hypothesis("signature_threshold_uniqueness", "require(signatures.length >= threshold); seenSigner[signer] = true;")
    state = {"run_dir": str(tmp_path / "run"), "artifacts": []}

    output = run_semantic_validation(PocInput(repo_path=str(tmp_path), hypothesis=hyp), state)

    assert output.data["validated"] is False
    assert output.data["counterevidence"]


def test_semantic_validation_confirms_fee_formula_dimension_evidence(tmp_path: Path):
    hyp = _hypothesis("fee_formula_dimension_mismatch", "fee = Math.mulDiv(priceD18, performanceFeeD6 * totalShares, 1e24);")
    state = {"run_dir": str(tmp_path / "run"), "artifacts": []}

    output = run_semantic_validation(PocInput(repo_path=str(tmp_path), hypothesis=hyp), state)

    assert output.data["validated"] is True
    assert output.data["proof_status"] == "static_proof_complete"
