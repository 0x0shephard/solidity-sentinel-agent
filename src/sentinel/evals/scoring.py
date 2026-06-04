from __future__ import annotations

from pathlib import Path

from sentinel.schemas.evals import EvalScore


def score_run(fixture: str, state: dict, expected: dict) -> EvalScore:
    run_dir = Path(state["run_dir"])
    generated_json_report = (run_dir / "report.json").exists()
    generated_markdown_report = (run_dir / "report.md").exists()
    findings = state.get("findings", [])
    hypotheses = state.get("hypotheses", [])
    confirmed_findings = [finding for finding in findings if getattr(finding, "status", "likely") in {"confirmed", "likely"}]

    expected_items = expected.get("expected_findings") or [expected]

    def _matches_expected(item: dict) -> bool:
        expected_class = item["vulnerability_class"]
        expected_function = item["affected_function"]
        expected_file_contains = item["affected_file_contains"]
        return any(
            finding.vulnerability_class == expected_class
            and expected_function in finding.affected_functions
            and any(expected_file_contains in file_path for file_path in finding.affected_files)
            and bool(finding.evidence)
            for finding in confirmed_findings
        )

    def _hypothesis_matches_expected(item: dict) -> bool:
        expected_class = item["vulnerability_class"]
        expected_function = item["affected_function"]
        expected_file_contains = item["affected_file_contains"]
        return any(
            hypothesis.vulnerability_class == expected_class
            and expected_function in hypothesis.affected_functions
            and any(expected_file_contains in file_path for file_path in hypothesis.affected_files)
            for hypothesis in hypotheses
        )

    matched_items = [item for item in expected_items if _matches_expected(item)]
    matched_hypotheses = [item for item in expected_items if _hypothesis_matches_expected(item)]
    minimum_expected = int(expected["minimum_expected_findings"]) if "minimum_expected_findings" in expected else len(expected_items)
    expected_class_found = len(matched_items) >= minimum_expected
    expected_function_found = expected_class_found
    allow_no_findings = bool(expected.get("allow_no_findings", False))
    evidence_present = all(finding.evidence for finding in confirmed_findings) if confirmed_findings else allow_no_findings
    expected_file_found = expected_class_found
    composition_chain_present = all(
        tool_name in state.get("last_outputs", {})
        for tool_name in [
            "static.extract_functions",
            "static.extract_external_calls",
            "research.rank_hypotheses",
            "research.subgraph",
        ]
    )

    score = 0
    score += 10 if state.get("current_focus") == "done" else 0
    score += 15 if state.get("tool_call_count", 0) >= 20 else 0
    score += 15 if state.get("subgraph_results") else 0
    score += 10 if generated_json_report else 0
    score += 5 if generated_markdown_report else 0
    false_positive_count = (
        len(confirmed_findings)
        if allow_no_findings
        else sum(1 for finding in confirmed_findings if finding.vulnerability_class not in {item["vulnerability_class"] for item in expected_items})
    )
    hypothesis_recall = 1.0 if allow_no_findings and false_positive_count == 0 else len(matched_hypotheses) / max(1, len(expected_items))
    finding_recall = 1.0 if allow_no_findings and false_positive_count == 0 else len(matched_items) / max(1, len(expected_items))
    evidence_coverage = (
        sum(1 for finding in confirmed_findings if finding.evidence) / len(confirmed_findings)
        if confirmed_findings
        else (1.0 if allow_no_findings else 0.0)
    )
    production_evidence_coverage = (
        sum(
            1
            for finding in confirmed_findings
            if any(getattr(item, "source_type", "unknown") == "production" for item in finding.evidence)
        )
        / len(confirmed_findings)
        if confirmed_findings
        else (1.0 if allow_no_findings else 0.0)
    )
    rag_context_coverage = (
        sum(1 for finding in confirmed_findings if getattr(finding, "historical_matches", [])) / len(confirmed_findings)
        if confirmed_findings
        else 0.0
    )
    cross_contract_evidence_coverage = (
        sum(
            1
            for finding in confirmed_findings
            if len({item.file_path for item in finding.evidence}) >= 2
        )
        / len(confirmed_findings)
        if confirmed_findings
        else (1.0 if allow_no_findings else 0.0)
    )
    validation_compile_output = state.get("last_outputs", {}).get("dynamic.compile_validation_artifacts", {})
    validation_run_output = state.get("last_outputs", {}).get("dynamic.run_validation_artifacts", {})
    validation_compile_status = str(validation_compile_output.get("status", "")).lower()
    validation_compile_message = str(validation_compile_output.get("message", "")).lower()
    validation_artifacts_compile = (
        validation_compile_status.endswith("ok")
        or validation_compile_status.endswith("skipped")
        or "no foundry validation test" in validation_compile_message
    )
    validation_classification = str(validation_run_output.get("data", {}).get("classification", ""))
    proof_success_rate = 1.0 if validation_classification in {"security_invariant_held_or_test_passed", "security_invariant_violation_or_test_needs_review"} else 0.0
    rag_useful_context_rate = rag_context_coverage
    simple_classes = {"missing_access_control", "unchecked_transfer", "unchecked_erc20_return", "reentrancy", "tx_origin_authorization"}
    novel_confirmed = [finding for finding in confirmed_findings if finding.vulnerability_class not in simple_classes]
    novel_pattern_discovery_rate = len(novel_confirmed) / len(confirmed_findings) if confirmed_findings else 0.0
    unsupported_claim_rate = 1.0 - evidence_coverage if confirmed_findings else 0.0
    score += min(20, int(20 * finding_recall))
    score += 15 if expected_function_found and expected_file_found and evidence_present else 0
    score += 10 if composition_chain_present else 0

    notes = []
    if not expected_class_found:
        missing = [item["vulnerability_class"] for item in expected_items if item not in matched_items]
        notes.append(f"Expected recall not met: matched {len(matched_items)}/{len(expected_items)}; missing {missing}")
    if confirmed_findings and not evidence_present:
        notes.append("At least one generated finding is missing local evidence.")
    if confirmed_findings and production_evidence_coverage < 1.0:
        notes.append("At least one confirmed/likely finding lacks production-source evidence.")
    if expected.get("allow_no_findings", False) and false_positive_count:
        notes.append(f"False positives in negative fixture: {false_positive_count}")
    if confirmed_findings and cross_contract_evidence_coverage < 0.8:
        notes.append(f"Cross-contract evidence coverage below target: {cross_contract_evidence_coverage:.2f}")
    if not validation_artifacts_compile:
        notes.append("Generated validation artifacts did not compile or were not safely skipped.")

    return EvalScore(
        fixture=fixture,
        completed=state.get("current_focus") == "done",
        tool_call_count=state.get("tool_call_count", 0),
        used_20_plus_tools=state.get("tool_call_count", 0) >= 20,
        spawned_research_subgraph=bool(state.get("subgraph_results")),
        generated_json_report=generated_json_report,
        generated_markdown_report=generated_markdown_report,
        expected_class_found=expected_class_found,
        expected_function_found=expected_function_found,
        evidence_present=evidence_present,
        composition_chain_present=composition_chain_present,
        hypothesis_recall=hypothesis_recall,
        finding_recall=finding_recall,
        evidence_coverage=evidence_coverage,
        production_evidence_coverage=production_evidence_coverage,
        rag_context_coverage=rag_context_coverage,
        unsupported_claim_rate=unsupported_claim_rate,
        false_positive_count=false_positive_count,
        invariant_candidate_count=len(state.get("invariant_candidates", [])),
        proof_success_rate=proof_success_rate,
        cross_contract_evidence_coverage=cross_contract_evidence_coverage,
        rag_useful_context_rate=rag_useful_context_rate,
        novel_pattern_discovery_rate=novel_pattern_discovery_rate,
        validation_artifacts_compile=validation_artifacts_compile,
        score=float(score),
        notes=notes,
    )
