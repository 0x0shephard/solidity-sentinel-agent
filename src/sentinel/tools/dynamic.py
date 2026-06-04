from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from pydantic import BaseModel, Field

from sentinel.reliability.subprocess import run_command
from sentinel.schemas.common import ArtifactRef, SideEffect, ToolStatus
from sentinel.schemas.research import VulnerabilityHypothesis
from sentinel.tools.base import RegisteredTool
from sentinel.tools.repo import RepoPathInput


class DynamicGenericOutput(BaseModel):
    status: ToolStatus
    message: str | None = None
    data: dict = Field(default_factory=dict)


class PocInput(RepoPathInput):
    hypothesis: VulnerabilityHypothesis | None = None
    test_file: str = "test/SentinelGenerated.t.sol"
    test_name: str = "testSentinelGenerated"


class ValidationCompileInput(RepoPathInput):
    artifact_paths: list[str] = Field(default_factory=list)


ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def _clean_output(text: str) -> str:
    return ANSI_ESCAPE.sub("", text)


def _test_contract_name(path: str) -> str:
    name = Path(path).name
    return name[: -len(".t.sol")] if name.endswith(".t.sol") else Path(path).stem


def _contract_name_from_file(file_path: str) -> str:
    return Path(file_path).stem or "Target"


def _artifact_test_name(hypothesis: VulnerabilityHypothesis) -> str:
    function_name = (hypothesis.affected_functions or ["target"])[0]
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", function_name)
    class_name = hypothesis.vulnerability_class.title().replace("_", "")
    return f"Sentinel{class_name}{cleaned[:32]}Test.t.sol"


def _target_details(hypothesis: VulnerabilityHypothesis) -> tuple[str, str, str]:
    target_file = (hypothesis.affected_files or ["src/Target.sol"])[0]
    target_function = (hypothesis.affected_functions or ["targetFunction"])[0]
    target_contract = _contract_name_from_file(target_file)
    return target_file, target_contract, target_function


def _missing_access_control_test(hypothesis: VulnerabilityHypothesis) -> str:
    target_file, target_contract, target_function = _target_details(hypothesis)
    return "\n".join(
        [
            "// SPDX-License-Identifier: MIT",
            "pragma solidity ^0.8.20;",
            "",
            f'import {{{target_contract}}} from "../{target_file}";',
            "",
            "interface Vm {",
            "    function deal(address who, uint256 newBalance) external;",
            "    function expectRevert() external;",
            "    function prank(address msgSender) external;",
            "}",
            "",
            f"contract SentinelMissingAccessControl{target_function}Test {{",
            '    Vm internal constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));',
            f"    {target_contract} internal target;",
            "    address internal attacker = address(0xA11CE);",
            "",
            "    function setUp() public {",
            f"        target = new {target_contract}();",
            "        VM.deal(address(target), 1 ether);",
            "    }",
            "",
            f"    function test_{target_function}_rejectsUnauthorizedCaller() public {{",
            "        VM.prank(attacker);",
            "        VM.expectRevert();",
            f"        target.{target_function}(payable(attacker));",
            "    }",
            "}",
            "",
        ]
    )


def _reentrancy_test(hypothesis: VulnerabilityHypothesis) -> str:
    target_file, target_contract, target_function = _target_details(hypothesis)
    return "\n".join(
        [
            "// SPDX-License-Identifier: MIT",
            "pragma solidity ^0.8.20;",
            "",
            f'import {{{target_contract}}} from "../{target_file}";',
            "",
            "interface Vm {",
            "    function deal(address who, uint256 newBalance) external;",
            "    function expectRevert() external;",
            "}",
            "",
            f"contract SentinelReentrancyAttacker {{",
            f"    {target_contract} internal target;",
            "    uint256 internal depth;",
            "",
            f"    constructor({target_contract} _target) {{",
            "        target = _target;",
            "    }",
            "",
            "    function attack() external payable {",
            "        target.deposit{value: msg.value}();",
            f"        target.{target_function}();",
            "    }",
            "",
            "    receive() external payable {",
            "        if (depth == 0 && address(target).balance >= 1 ether) {",
            "            depth = 1;",
            f"            target.{target_function}();",
            "        }",
            "    }",
            "}",
            "",
            f"contract SentinelReentrancy{target_function}Test {{",
            '    Vm internal constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));',
            f"    {target_contract} internal target;",
            "    SentinelReentrancyAttacker internal attacker;",
            "",
            "    function setUp() public {",
            f"        target = new {target_contract}();",
            "        attacker = new SentinelReentrancyAttacker(target);",
            "        target.deposit{value: 5 ether}();",
            "        VM.deal(address(attacker), 1 ether);",
            "    }",
            "",
            f"    function test_{target_function}_cannotBeReentered() public {{",
            "        VM.expectRevert();",
            "        attacker.attack{value: 1 ether}();",
            "    }",
            "}",
            "",
        ]
    )


def _unchecked_transfer_test(hypothesis: VulnerabilityHypothesis) -> str:
    target_file, target_contract, target_function = _target_details(hypothesis)
    return "\n".join(
        [
            "// SPDX-License-Identifier: MIT",
            "pragma solidity ^0.8.20;",
            "",
            f'import {{{target_contract}, IERC20}} from "../{target_file}";',
            "",
            "interface Vm {",
            "    function expectRevert() external;",
            "}",
            "",
            "contract SentinelFalseReturnToken {",
            "    mapping(address => uint256) public balanceOf;",
            "",
            "    constructor() {",
            "        balanceOf[msg.sender] = 1_000_000 ether;",
            "    }",
            "",
            "    function transfer(address, uint256) external pure returns (bool) {",
            "        return false;",
            "    }",
            "",
            "    function transferFrom(address, address, uint256) external pure returns (bool) {",
            "        return true;",
            "    }",
            "}",
            "",
            f"contract SentinelUncheckedTransfer{target_function}Test {{",
            '    Vm internal constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));',
            "    SentinelFalseReturnToken internal token;",
            f"    {target_contract} internal target;",
            "",
            "    function setUp() public {",
            "        token = new SentinelFalseReturnToken();",
            f"        target = new {target_contract}(IERC20(address(token)));",
            f"        target.deposit(1 ether);",
            "    }",
            "",
            f"    function test_{target_function}_handlesFalseTransferReturn() public {{",
            "        VM.expectRevert();",
            f"        target.{target_function}(1 ether);",
            "    }",
            "}",
            "",
        ]
    )


def _generic_validation_test(hypothesis: VulnerabilityHypothesis) -> str:
    target_file, target_contract, target_function = _target_details(hypothesis)
    return "\n".join(
        [
            "// SPDX-License-Identifier: MIT",
            "pragma solidity ^0.8.20;",
            "",
            "// Generated by Solidity Sentinel as a reviewable validation scaffold.",
            f'import {{{target_contract}}} from "../{target_file}";',
            "",
            f"contract Sentinel{target_contract}{target_function}ValidationTest {{",
            f"    function test_{target_function}_validationScaffold() public {{",
            f"        // TODO: instantiate {target_contract} and assert the intended security invariant for {target_function}.",
            "        require(false, \"Complete setup with project-specific constructor arguments before running this scaffold.\");",
            "    }",
            "}",
            "",
        ]
    )


def _validation_test_content(hypothesis: VulnerabilityHypothesis) -> str:
    if hypothesis.vulnerability_class == "missing_access_control":
        return _missing_access_control_test(hypothesis)
    if hypothesis.vulnerability_class == "reentrancy":
        return _reentrancy_test(hypothesis)
    if hypothesis.vulnerability_class == "unchecked_transfer":
        return _unchecked_transfer_test(hypothesis)
    return _generic_validation_test(hypothesis)


def _validation_plan_content(hypothesis: VulnerabilityHypothesis) -> str:
    target_file, target_contract, target_function = _target_details(hypothesis)
    root_terms = ", ".join(hypothesis.root_cause_terms) or hypothesis.vulnerability_class
    evidence_lines = [
        f"- {item.file_path}:{item.line_start}::{item.function_name or 'unknown'} {item.reason}: {item.source_text}"
        for item in hypothesis.evidence_lines[:6]
    ] or ["- No local source evidence was attached to this hypothesis."]
    recommended = hypothesis.recommended_validation or [f"Create a targeted regression test for {target_function}."]
    template_notes = {
        "accounting_invariant": "Assert accounting conservation before and after the action: total balances, rewards, fees, or payout sums should reconcile.",
        "business_logic": "Assert the intended business rule against an attacker-controlled or boundary-value scenario.",
        "upgradeability": "Assert upgrade authorization, implementation transitions, and initializer/reinitializer constraints.",
        "storage_layout": "Compare storage layouts across versions and assert state variables retain slot/order compatibility.",
        "denial_of_service": "Exercise the largest realistic dynamic collection and assert gas/runtime remains bounded.",
        "external_call_before_accounting": "Use a callback receiver and assert state is updated before observable external interaction.",
    }
    lines = [
        f"# Validation Plan: {hypothesis.title}",
        "",
        f"- Hypothesis ID: {hypothesis.id}",
        f"- Class: {hypothesis.vulnerability_class}",
        f"- Target: {target_file}::{target_contract}.{target_function}",
        f"- Root terms: {root_terms}",
        "",
        "## Local Evidence",
        *evidence_lines,
        "",
        "## Validation Objective",
        template_notes.get(hypothesis.vulnerability_class, "Build a project-specific proof-of-concept or regression test from the cited local evidence."),
        "",
        "## Suggested Checks",
        *[f"- {step}" for step in recommended],
        "",
        "## Expected Outcome",
        "- Confirmed only if a production-source path violates the stated invariant or authorization/accounting rule.",
        "- Otherwise keep the hypothesis in manual review or reject it with the observed counterevidence.",
        "",
    ]
    return "\n".join(lines)


def _validation_artifact_paths(inp: ValidationCompileInput, state) -> list[Path]:
    raw_paths = inp.artifact_paths or [
        artifact.path
        for artifact in state.get("artifacts", [])
        if artifact.kind == "foundry_validation_test" and artifact.path.endswith(".t.sol")
    ]
    return [Path(path) if Path(path).is_absolute() else Path(path).resolve() for path in raw_paths]


def _copy_repo_for_validation(repo_path: str, worktree: Path) -> None:
    if worktree.exists():
        shutil.rmtree(worktree)

    def ignore(_directory: str, names: list[str]) -> set[str]:
        ignored_names = {".git", "out", "cache", "node_modules", "runs", ".venv", "__pycache__"}
        return {name for name in names if name in ignored_names}

    shutil.copytree(repo_path, worktree, ignore=ignore)


def _prepare_validation_worktree(inp: ValidationCompileInput, state) -> tuple[DynamicGenericOutput | None, Path | None, list[str]]:
    artifact_paths = _validation_artifact_paths(inp, state)
    if not artifact_paths:
        return DynamicGenericOutput(status=ToolStatus.SKIPPED, message="No Foundry validation test artifacts available."), None, []
    missing = [str(path) for path in artifact_paths if not path.exists()]
    if missing:
        return DynamicGenericOutput(status=ToolStatus.ERROR, message="Validation artifact path not found.", data={"missing": missing}), None, []
    if shutil.which("forge") is None:
        return DynamicGenericOutput(status=ToolStatus.UNAVAILABLE, message="forge is not installed"), None, []

    run_dir = Path(state.get("run_dir", "runs/tmp"))
    worktree = run_dir / "artifacts" / "validation-worktree"
    _copy_repo_for_validation(inp.repo_path, worktree)
    test_dir = worktree / "test"
    test_dir.mkdir(parents=True, exist_ok=True)

    copied_tests = []
    for artifact_path in artifact_paths:
        target_path = test_dir / artifact_path.name
        shutil.copy2(artifact_path, target_path)
        copied_tests.append(str(target_path))
    return None, worktree, copied_tests


def _classify_validation_run(return_code: int | None, stdout: str, stderr: str, timed_out: bool) -> str:
    combined = f"{stdout}\n{stderr}"
    if timed_out:
        return "validation_timeout"
    if "panicked (crashed)" in combined or "Attempted to create a NULL object" in combined:
        return "validation_runtime_error"
    if return_code == 0:
        return "security_invariant_held_or_test_passed"
    if re.search(r"(\d+)\s+failed", combined, flags=re.IGNORECASE) or "Failing tests" in combined or "[FAIL" in combined:
        return "security_invariant_violation_or_test_needs_review"
    return "validation_execution_failed"


def create_poc_test(inp: PocInput, state) -> DynamicGenericOutput:
    hypothesis = inp.hypothesis or (state.get("hypotheses") or [None])[0]
    affected_function = getattr(hypothesis, "affected_functions", [])[:1]
    affected_file = getattr(hypothesis, "affected_files", [])[:1]
    target_function = affected_function[0] if affected_function else "targetFunction"
    target_file = affected_file[0] if affected_file else "src/Target.sol"
    test_source = "\n".join(
        [
            "// SPDX-License-Identifier: MIT",
            "pragma solidity ^0.8.20;",
            "",
            "// Generated by Solidity Sentinel. Review and adapt constructor/setup before relying on this test.",
            f"// Target file: {target_file}",
            f"// Target function: {target_function}",
            "contract SentinelGenerated {",
            f"    function {inp.test_name}() public {{",
            f"        // TODO: instantiate the target and assert unauthorized access to {target_function} is rejected.",
            "        assert(true);",
            "    }",
            "}",
            "",
        ]
    )
    data = {
        "hypothesis_id": getattr(hypothesis, "id", None),
        "test_file": inp.test_file,
        "test_name": inp.test_name,
        "target_file": target_file,
        "target_function": target_function,
        "content": test_source,
    }
    state.setdefault("last_outputs", {})["dynamic.create_poc_test"] = {"status": ToolStatus.OK.value, "data": data}
    return DynamicGenericOutput(status=ToolStatus.OK, data=data)


def patch_poc_test(inp: PocInput, state) -> DynamicGenericOutput:
    generated = state.get("last_outputs", {}).get("dynamic.create_poc_test", {}).get("data", {})
    content = generated.get("content") or create_poc_test(inp, state).data["content"]
    test_file = generated.get("test_file", inp.test_file)
    target = Path(inp.repo_path) / test_file
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return DynamicGenericOutput(status=ToolStatus.OK, data={"path": str(target), "test_file": test_file})


def run_poc_test(inp: RepoPathInput, state) -> DynamicGenericOutput:
    if shutil.which("forge") is None:
        return DynamicGenericOutput(status=ToolStatus.UNAVAILABLE, message="forge is not installed")
    result = run_command(["forge", "test", "--match-contract", "SentinelGenerated"], cwd=inp.repo_path, timeout=120)
    return DynamicGenericOutput(status=ToolStatus.OK if result.return_code == 0 else ToolStatus.ERROR, data=result.model_dump(mode="json"))


def run_test_verbose(inp: RepoPathInput, state) -> DynamicGenericOutput:
    if shutil.which("forge") is None:
        return DynamicGenericOutput(status=ToolStatus.UNAVAILABLE, message="forge is not installed")
    result = run_command(["forge", "test", "-vvv"], cwd=inp.repo_path, timeout=120)
    return DynamicGenericOutput(status=ToolStatus.OK if result.return_code == 0 else ToolStatus.ERROR, data=result.model_dump(mode="json"))


def parse_test_output(inp: DynamicGenericOutput, state) -> DynamicGenericOutput:
    stdout = str(inp.data.get("stdout", ""))
    stderr = str(inp.data.get("stderr", ""))
    combined = f"{stdout}\n{stderr}"
    passed_count = sum(int(value) for value in re.findall(r"(\d+)\s+passed", combined, flags=re.IGNORECASE))
    failed_counts = [int(value) for value in re.findall(r"(\d+)\s+failed", combined, flags=re.IGNORECASE)]
    failed_count = sum(failed_counts)
    failed = failed_count > 0 or ("FAIL" in combined and not failed_counts)
    passed = passed_count > 0 and not failed
    return DynamicGenericOutput(status=ToolStatus.OK, data={"passed": passed, "failed": failed, "raw_excerpt": combined[-4000:]})


def extract_revert_reason(inp: DynamicGenericOutput, state) -> DynamicGenericOutput:
    text = f"{inp.data.get('stdout', '')}\n{inp.data.get('stderr', '')}\n{inp.data.get('raw_excerpt', '')}"
    matches = re.findall(r"revert(?:ed)?(?: with)?[: ]+([^\n]+)", text, flags=re.IGNORECASE)
    return DynamicGenericOutput(status=ToolStatus.OK, data={"revert_reasons": [match.strip() for match in matches]})


def classify_test_result(inp: DynamicGenericOutput, state) -> DynamicGenericOutput:
    if inp.data.get("passed") is True:
        classification = "poc_passed"
    elif inp.data.get("failed") is True:
        classification = "poc_failed_or_needs_adjustment"
    else:
        classification = "inconclusive"
    return DynamicGenericOutput(status=ToolStatus.OK, data={"classification": classification})


def spawn_poc_subagent(inp: PocInput, state) -> DynamicGenericOutput:
    plan = create_poc_test(inp, state).data
    return DynamicGenericOutput(status=ToolStatus.OK, data={"subagent_kind": "poc_planner", "plan": plan})


def generate_validation_artifacts(inp: PocInput, state) -> DynamicGenericOutput:
    hypothesis = inp.hypothesis or (state.get("hypotheses") or [None])[0]
    if hypothesis is None:
        return DynamicGenericOutput(status=ToolStatus.SKIPPED, message="No hypothesis available for validation artifact generation.")

    run_dir = Path(state.get("run_dir", "runs/tmp"))
    artifact_dir = run_dir / "artifacts" / "validation-tests"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    test_name = _artifact_test_name(hypothesis)
    test_path = artifact_dir / test_name
    content = _validation_test_content(hypothesis)
    test_path.write_text(content, encoding="utf-8")
    plan_path = artifact_dir / f"{test_path.stem}.plan.md"
    plan_content = _validation_plan_content(hypothesis)
    plan_path.write_text(plan_content, encoding="utf-8")

    ref = ArtifactRef(
        kind="foundry_validation_test",
        path=str(test_path),
        description=f"Generated Foundry validation test for {hypothesis.vulnerability_class}; copy into the audited repo's test/ directory before running.",
    )
    state.setdefault("artifacts", []).append(ref)
    state.setdefault("artifacts", []).append(
        ArtifactRef(
            kind="validation_plan",
            path=str(plan_path),
            description=f"Hypothesis-specific validation plan for {hypothesis.vulnerability_class}.",
        )
    )
    data = {
        "path": str(test_path),
        "plan_path": str(plan_path),
        "test_name": test_name,
        "hypothesis_id": hypothesis.id,
        "vulnerability_class": hypothesis.vulnerability_class,
        "content": content,
        "plan": plan_content,
    }
    return DynamicGenericOutput(status=ToolStatus.OK, data=data)


def compile_validation_artifacts(inp: ValidationCompileInput, state) -> DynamicGenericOutput:
    early_output, worktree, copied_tests = _prepare_validation_worktree(inp, state)
    if early_output is not None:
        if early_output.status == ToolStatus.SKIPPED:
            early_output.message = "No Foundry validation test artifacts available to compile."
        return early_output
    assert worktree is not None
    run_dir = Path(state.get("run_dir", "runs/tmp"))
    result = run_command(["forge", "build"], cwd=str(worktree), timeout=120)
    manifest_path = run_dir / "artifacts" / "validation-compile-result.json"
    manifest = {
        "command": result.command,
        "worktree": str(worktree),
        "copied_tests": copied_tests,
        "return_code": result.return_code,
        "stdout": _clean_output(result.stdout[-8000:]),
        "stderr": _clean_output(result.stderr[-8000:]),
        "timed_out": result.timed_out,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    state.setdefault("artifacts", []).append(
        ArtifactRef(
            kind="validation_compile_result",
            path=str(manifest_path),
            description="Result of compiling generated validation tests in a temporary worktree.",
        )
    )
    return DynamicGenericOutput(
        status=ToolStatus.OK if result.return_code == 0 else ToolStatus.ERROR,
        message="Validation artifacts compiled successfully." if result.return_code == 0 else "Validation artifact compile failed.",
        data=manifest,
    )


def run_validation_artifacts(inp: ValidationCompileInput, state) -> DynamicGenericOutput:
    early_output, worktree, copied_tests = _prepare_validation_worktree(inp, state)
    if early_output is not None:
        if early_output.status == ToolStatus.SKIPPED:
            early_output.message = "No Foundry validation test artifacts available to run."
        return early_output
    assert worktree is not None
    run_dir = Path(state.get("run_dir", "runs/tmp"))
    test_names = [_test_contract_name(path) for path in copied_tests]
    result = run_command(["forge", "test", "--match-contract", "Sentinel"], cwd=str(worktree), timeout=120)
    classification = _classify_validation_run(result.return_code, result.stdout, result.stderr, result.timed_out)
    manifest_path = run_dir / "artifacts" / "validation-run-result.json"
    manifest = {
        "command": result.command,
        "worktree": str(worktree),
        "copied_tests": copied_tests,
        "matched_contract_prefix": "Sentinel",
        "test_names": test_names,
        "return_code": result.return_code,
        "stdout": _clean_output(result.stdout[-8000:]),
        "stderr": _clean_output(result.stderr[-8000:]),
        "timed_out": result.timed_out,
        "classification": classification,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    state.setdefault("artifacts", []).append(
        ArtifactRef(
            kind="validation_run_result",
            path=str(manifest_path),
            description=f"Result of executing generated validation tests in a temporary worktree: {classification}.",
        )
    )
    return DynamicGenericOutput(status=ToolStatus.OK, message=f"Validation run classified as {classification}.", data=manifest)


def register(registry) -> None:
    specs = [
        ("create_poc_test", "Create a PoC test plan.", PocInput, create_poc_test),
        ("patch_poc_test", "Patch a generated PoC test.", PocInput, patch_poc_test),
        ("run_poc_test", "Run a PoC test.", RepoPathInput, run_poc_test),
        ("run_test_verbose", "Run tests with verbose output.", RepoPathInput, run_test_verbose),
        ("parse_test_output", "Parse test output.", DynamicGenericOutput, parse_test_output),
        ("extract_revert_reason", "Extract revert reasons from test output.", DynamicGenericOutput, extract_revert_reason),
        ("classify_test_result", "Classify test result.", DynamicGenericOutput, classify_test_result),
        ("spawn_poc_subagent", "Spawn a PoC planning subagent.", PocInput, spawn_poc_subagent),
        ("generate_validation_artifacts", "Generate reviewable Foundry validation test artifacts under the run directory.", PocInput, generate_validation_artifacts),
        ("compile_validation_artifacts", "Compile generated validation tests in a non-mutating temporary worktree.", ValidationCompileInput, compile_validation_artifacts),
        ("run_validation_artifacts", "Run generated validation tests in a non-mutating temporary worktree and classify the result.", ValidationCompileInput, run_validation_artifacts),
    ]
    for name, description, input_model, fn in specs:
        if name in {"compile_validation_artifacts", "run_validation_artifacts"}:
            side_effects = [SideEffect.WRITE_FILES, SideEffect.EXECUTE_LOCAL]
        elif name in {"patch_poc_test", "generate_validation_artifacts"}:
            side_effects = [SideEffect.WRITE_FILES]
        elif name.startswith("run_"):
            side_effects = [SideEffect.EXECUTE_LOCAL]
        else:
            side_effects = [SideEffect.NONE]
        registry.register(RegisteredTool(namespace="dynamic", name=name, description=description, input_model=input_model, output_model=DynamicGenericOutput, fn=fn, side_effects=side_effects))
