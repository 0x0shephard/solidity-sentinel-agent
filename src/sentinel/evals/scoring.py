from __future__ import annotations

from pathlib import Path

from sentinel.schemas.evals import EvalScore


def score_run(fixture: str, state: dict, expected: dict) -> EvalScore:
    run_dir = Path(state["run_dir"])
    generated_json_report = (run_dir / "report.json").exists()
    generated_markdown_report = (run_dir / "report.md").exists()
    findings = state.get("findings", [])

    expected_class = expected["vulnerability_class"]
    expected_function = expected["affected_function"]
    expected_file_contains = expected["affected_file_contains"]

    expected_class_found = any(finding.vulnerability_class == expected_class for finding in findings)
    expected_function_found = any(expected_function in finding.affected_functions for finding in findings)
    evidence_present = any(finding.evidence for finding in findings)
    expected_file_found = any(
        any(expected_file_contains in file_path for file_path in finding.affected_files)
        for finding in findings
    )
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
    score += 20 if expected_class_found else 0
    score += 15 if expected_function_found and expected_file_found and evidence_present else 0
    score += 10 if composition_chain_present else 0

    notes = []
    if not expected_class_found:
        notes.append(f"Expected class not found: {expected_class}")
    if not expected_function_found:
        notes.append(f"Expected function not found: {expected_function}")
    if not expected_file_found:
        notes.append(f"Expected file evidence not found: {expected_file_contains}")

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
        score=float(score),
        notes=notes,
    )

