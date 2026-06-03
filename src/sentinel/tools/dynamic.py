from __future__ import annotations

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
            '    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));',
            f"    {target_contract} internal target;",
            "    address internal attacker = address(0xA11CE);",
            "",
            "    function setUp() public {",
            f"        target = new {target_contract}();",
            "        vm.deal(address(target), 1 ether);",
            "    }",
            "",
            f"    function test_{target_function}_rejectsUnauthorizedCaller() public {{",
            "        vm.prank(attacker);",
            "        vm.expectRevert();",
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
            '    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));',
            f"    {target_contract} internal target;",
            "    SentinelReentrancyAttacker internal attacker;",
            "",
            "    function setUp() public {",
            f"        target = new {target_contract}();",
            "        attacker = new SentinelReentrancyAttacker(target);",
            "        target.deposit{value: 5 ether}();",
            "        vm.deal(address(attacker), 1 ether);",
            "    }",
            "",
            f"    function test_{target_function}_cannotBeReentered() public {{",
            "        vm.expectRevert();",
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
            '    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));',
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
            "        vm.expectRevert();",
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

    ref = ArtifactRef(
        kind="foundry_validation_test",
        path=str(test_path),
        description=f"Generated Foundry validation test for {hypothesis.vulnerability_class}; copy into the audited repo's test/ directory before running.",
    )
    state.setdefault("artifacts", []).append(ref)
    data = {
        "path": str(test_path),
        "test_name": test_name,
        "hypothesis_id": hypothesis.id,
        "vulnerability_class": hypothesis.vulnerability_class,
        "content": content,
    }
    return DynamicGenericOutput(status=ToolStatus.OK, data=data)


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
    ]
    for name, description, input_model, fn in specs:
        side_effect = SideEffect.WRITE_FILES if name in {"patch_poc_test", "generate_validation_artifacts"} else SideEffect.EXECUTE_LOCAL if name.startswith("run_") else SideEffect.NONE
        registry.register(RegisteredTool(namespace="dynamic", name=name, description=description, input_model=input_model, output_model=DynamicGenericOutput, fn=fn, side_effects=[side_effect]))
