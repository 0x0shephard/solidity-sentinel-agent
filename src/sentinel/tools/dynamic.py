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


def _constructor_arg_count(repo_path: str, target_file: str, target_contract: str) -> int | None:
    source_path = Path(repo_path) / target_file
    if not source_path.exists():
        return None
    text = source_path.read_text(encoding="utf-8", errors="replace")
    contract_match = re.search(rf"\bcontract\s+{re.escape(target_contract)}\b", text)
    start = contract_match.start() if contract_match else 0
    match = re.search(r"\bconstructor\s*\(([^)]*)\)", text[start:], flags=re.DOTALL)
    if not match:
        return 0
    args = match.group(1).strip()
    if not args:
        return 0
    return len([part for part in args.split(",") if part.strip()])


def _constructor_args(repo_path: str, target_file: str, target_contract: str) -> list[str] | None:
    source_path = Path(repo_path) / target_file
    if not source_path.exists():
        return None
    text = source_path.read_text(encoding="utf-8", errors="replace")
    contract_match = re.search(rf"\bcontract\s+{re.escape(target_contract)}\b", text)
    start = contract_match.start() if contract_match else 0
    match = re.search(r"\bconstructor\s*\(([^)]*)\)", text[start:], flags=re.DOTALL)
    if not match:
        return []
    args = match.group(1).strip()
    if not args:
        return []
    return [part.strip() for part in args.split(",") if part.strip()]


def _is_library_or_interface(repo_path: str, target_file: str, target_contract: str) -> bool:
    source_path = Path(repo_path) / target_file
    if not source_path.exists():
        return False
    text = source_path.read_text(encoding="utf-8", errors="replace")
    return bool(re.search(rf"\b(?:library|interface)\s+{re.escape(target_contract)}\b", text))


def _is_orderbook_like_hypothesis(hypothesis: VulnerabilityHypothesis) -> bool:
    functions = {name.lower() for name in hypothesis.affected_functions}
    terms = {term.lower() for term in hypothesis.root_cause_terms}
    if hypothesis.vulnerability_class == "transaction_ordering" and "buyorder" in functions:
        return True
    if hypothesis.vulnerability_class == "accounting_invariant" and "low_price_zero_fee_rounding" in terms:
        return True
    if hypothesis.vulnerability_class == "business_logic" and terms.intersection({"expired_order_non_seller_cancel", "expired_order_remains_active"}):
        return True
    return False


def _can_generate_executable_validation(repo_path: str, hypothesis: VulnerabilityHypothesis) -> tuple[bool, str]:
    target_file, target_contract, _target_function = _target_details(hypothesis)
    if _is_library_or_interface(repo_path, target_file, target_contract):
        return False, f"{target_contract} is a library/interface target; emitting a proof plan instead of generating an invalid executable test."
    semantic_static_templates = {
        "signature_threshold_uniqueness",
        "checkpoint_boundary_mismatch",
        "fee_formula_dimension_mismatch",
        "multi_report_fee_accrual",
        "boolean_policy_inversion",
        "native_asset_receive_mismatch",
        "indexed_structure_key_mismatch",
        "lockup_transfer_bypass",
    }
    if hypothesis.root_cause_terms and semantic_static_templates.intersection(set(hypothesis.root_cause_terms)):
        return False, "Semantic invariant hypothesis detected; emitting a static-proof validation plan unless project-specific constructor setup is inferred elsewhere."
    if _is_orderbook_like_hypothesis(hypothesis):
        args = _constructor_args(repo_path, target_file, target_contract)
        if args is not None and len(args) == 2 and all("IERC20" in arg or "ERC20" in arg for arg in args):
            return True, "OrderBook-like constructor and affected functions were inferred; generating a contest-style executable validation scaffold."
        return False, "OrderBook-like hypothesis detected, but constructor/setup inference was incomplete; emitting a proof plan instead."
    if hypothesis.vulnerability_class not in {"missing_access_control", "reentrancy"}:
        return False, "No safe generic executable template exists for this vulnerability class; emitting a proof plan instead."
    arg_count = _constructor_arg_count(repo_path, target_file, target_contract)
    if arg_count is None:
        return False, f"Could not inspect constructor setup for {target_contract}; emitting a proof plan instead."
    if arg_count > 0:
        return False, f"{target_contract} constructor requires {arg_count} argument(s); setup inference is incomplete, so executable validation is deferred."
    return True, "Target contract has no constructor arguments and a generic executable scaffold is available."


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


def _orderbook_like_validation_test(hypothesis: VulnerabilityHypothesis) -> str:
    target_file, target_contract, _target_function = _target_details(hypothesis)
    contract_name = re.sub(r"[^A-Za-z0-9_]", "", _artifact_test_name(hypothesis).replace(".t.sol", ""))
    terms = {term.lower() for term in hypothesis.root_cause_terms}
    if hypothesis.vulnerability_class == "transaction_ordering":
        test_body = [
            "        uint256 orderId = _createOrder(100, 1, block.timestamp + 1 days);",
            "        book.amendSellOrder(orderId, 100, 10, block.timestamp + 1 days);",
            "        buyerApprove(1_000_000);",
            "        book.buyOrder(orderId);",
            "        require(usdc.balanceOf(seller) == 1000, \"buyer filled amended price without max bound\");",
        ]
    elif "expired_order_non_seller_cancel" in terms:
        test_body = [
            "        uint256 orderId = _createOrder(100, 1, block.timestamp + 1);",
            "        VM.warp(block.timestamp + 2);",
            "        VM.prank(buyer);",
            "        VM.expectRevert();",
            "        book.cancelSellOrder(orderId);",
            "        require(asset.balanceOf(address(book)) == 100, \"expired assets should still be stuck\");",
        ]
    elif "expired_order_remains_active" in terms:
        test_body = [
            "        uint256 orderId = _createOrder(100, 1, block.timestamp + 1);",
            "        VM.warp(block.timestamp + 2);",
            "        buyerApprove(1_000_000);",
            "        VM.expectRevert();",
            "        book.buyOrder(orderId);",
            "        (,,,, bool active) = book.orders(orderId);",
            "        require(active, \"expired order remains active after reverted fill\");",
        ]
    else:
        test_body = [
            "        uint256 orderId = _createOrder(1, 1, block.timestamp + 1 days);",
            "        buyerApprove(1_000_000);",
            "        book.buyOrder(orderId);",
            "        require(book.totalFees() == 0, \"small order should demonstrate zero-fee rounding threshold\");",
        ]
    return "\n".join(
        [
            "// SPDX-License-Identifier: MIT",
            "pragma solidity ^0.8.20;",
            "",
            f'import {{{target_contract}, IERC20}} from "../{target_file}";',
            "",
            "interface Vm {",
            "    function prank(address msgSender) external;",
            "    function expectRevert() external;",
            "    function warp(uint256 newTimestamp) external;",
            "}",
            "",
            "contract SentinelMockERC20 {",
            "    mapping(address => uint256) public balanceOf;",
            "    mapping(address => mapping(address => uint256)) public allowance;",
            "    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }",
            "    function approve(address spender, uint256 amount) external returns (bool) { allowance[msg.sender][spender] = amount; return true; }",
            "    function transfer(address to, uint256 amount) external returns (bool) { require(balanceOf[msg.sender] >= amount, \"balance\"); balanceOf[msg.sender] -= amount; balanceOf[to] += amount; return true; }",
            "    function transferFrom(address from, address to, uint256 amount) external returns (bool) { require(balanceOf[from] >= amount, \"balance\"); require(allowance[from][msg.sender] >= amount, \"allowance\"); allowance[from][msg.sender] -= amount; balanceOf[from] -= amount; balanceOf[to] += amount; return true; }",
            "}",
            "",
            f"contract {contract_name} {{",
            '    Vm internal constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));',
            "    address internal seller = address(0x51);",
            "    address internal buyer = address(0xB0B);",
            "    SentinelMockERC20 internal asset;",
            "    SentinelMockERC20 internal usdc;",
            f"    {target_contract} internal book;",
            "",
            "    function setUp() public {",
            "        asset = new SentinelMockERC20();",
            "        usdc = new SentinelMockERC20();",
            f"        book = new {target_contract}(IERC20(address(asset)), IERC20(address(usdc)));",
            "        asset.mint(seller, 1_000_000);",
            "        usdc.mint(buyer, 1_000_000);",
            "    }",
            "",
            "    function buyerApprove(uint256 amount) internal {",
            "        VM.prank(buyer);",
            "        usdc.approve(address(book), amount);",
            "    }",
            "",
            "    function _createOrder(uint256 amount, uint256 price, uint256 deadline) internal returns (uint256 orderId) {",
            "        VM.prank(seller);",
            "        asset.approve(address(book), amount);",
            "        VM.prank(seller);",
            "        orderId = book.createSellOrder(amount, price, deadline);",
            "    }",
            "",
            f"    function test_{hypothesis.vulnerability_class}_{(hypothesis.affected_functions or ['target'])[0]}() public {{",
            *test_body,
            "    }",
            "}",
            "",
        ]
    )


def _validation_test_content(hypothesis: VulnerabilityHypothesis) -> str:
    if _is_orderbook_like_hypothesis(hypothesis):
        return _orderbook_like_validation_test(hypothesis)
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
        "unchecked_transfer": "Use a mock ERC20 that returns false and assert the target handles the failed token operation.",
        "unchecked_erc20_return": "Use a mock ERC20 that returns false and assert the target handles the failed token operation.",
        "upgradeability": "Assert upgrade authorization, implementation transitions, and initializer/reinitializer constraints.",
        "storage_layout": "Compare storage layouts across versions and assert state variables retain slot/order compatibility.",
        "denial_of_service": "Exercise the largest realistic dynamic collection and assert gas/runtime remains bounded.",
        "external_call_before_accounting": "Use a callback receiver and assert state is updated before observable external interaction.",
        "transaction_ordering": "Model two actors submitting transactions against shared mutable state; assert the victim's expected terms are bound by explicit min/max parameters or the transaction reverts.",
        "signature_threshold_uniqueness": "Submit duplicate signatures from the same signer and assert threshold counting rejects non-unique signers.",
        "checkpoint_boundary_mismatch": "Create paired checkpoint/batch states around the same timestamp and assert all claim/report paths use the same inclusive/exclusive boundary.",
        "fee_formula_dimension_mismatch": "Compute expected fee units independently and compare against the formula for representative D6/D18/share values.",
        "multi_report_fee_accrual": "Process multiple reports that share the same fee period/base and assert fee accrual occurs exactly once for the intended aggregate.",
        "boolean_policy_inversion": "Exercise both allowed and disallowed accounts and assert the guard matches documented transfer/whitelist semantics.",
        "native_asset_receive_mismatch": "Configure the native asset path and assert the receiving contract can accept ETH, or that the path rejects unsupported native configuration.",
        "indexed_structure_key_mismatch": "Insert, lookup, cancel, and claim around adjacent indexes and assert the same key basis is used throughout.",
        "lockup_transfer_bypass": "Mint or transfer locked shares through every transfer path and assert the lockup constraint follows the shares.",
    }
    template_by_validation = {
        "mempool_order_race": "Construct a seller action that amends/cancels mutable order terms immediately before a buyer fill; assert the buyer cannot receive worse price/amount than their signed or parameterized intent.",
        "low_price_zero_fee_rounding": "Compute the smallest successful order amount where `(value * fee) / precision` truncates to zero; assert fee accounting records the intended minimum fee or rejects the split order.",
        "expired_order_non_seller_cancel": "Advance time beyond the deadline, use a non-seller cleanup actor, and assert expired funds can be released or inactive state is cleared.",
        "expired_order_remains_active": "Advance time beyond deadline and call the fill path; assert expired state is marked inactive or a separate cleanup path exists.",
        "mutable_state_assumption": "Show the observed off-chain state can change before execution, then bind the expected state with transaction inputs or reject stale execution.",
    }
    validation_template = next((term for term in hypothesis.root_cause_terms if term in template_by_validation), None)
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
        template_by_validation.get(
            validation_template,
            template_notes.get(validation_template, template_notes.get(hypothesis.vulnerability_class, "Build a project-specific proof-of-concept or regression test from the cited local evidence.")),
        ),
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


def run_semantic_validation(inp: PocInput, state) -> DynamicGenericOutput:
    hypothesis = inp.hypothesis or (state.get("hypotheses") or [None])[0]
    if hypothesis is None:
        return DynamicGenericOutput(status=ToolStatus.SKIPPED, message="No hypothesis available for semantic validation.")
    supported_terms = {
        "signature_threshold_uniqueness",
        "checkpoint_boundary_mismatch",
        "fee_formula_dimension_mismatch",
    }
    matched_terms = sorted(supported_terms.intersection({term.lower() for term in hypothesis.root_cause_terms}))
    if not matched_terms:
        return DynamicGenericOutput(status=ToolStatus.SKIPPED, message="Hypothesis does not use a supported semantic validation class.")

    result = _semantic_validation_result(hypothesis, matched_terms)
    run_dir = Path(state.get("run_dir", "runs/tmp"))
    artifact_dir = run_dir / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", hypothesis.id)
    artifact_path = artifact_dir / f"semantic-validation-{safe_id}.json"
    artifact_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    state.setdefault("artifacts", []).append(
        ArtifactRef(
            kind="semantic_validation_result",
            path=str(artifact_path),
            description=f"Deterministic semantic validation result for {hypothesis.id}.",
        )
    )
    return DynamicGenericOutput(status=ToolStatus.OK, data=result)


def _semantic_validation_result(hypothesis: VulnerabilityHypothesis, matched_terms: list[str]) -> dict:
    evidence_text = "\n".join(item.source_text for item in hypothesis.evidence_lines).lower()
    counterevidence: list[str] = []
    local_facts = [
        {
            "file_path": item.file_path,
            "line_start": item.line_start,
            "line_end": item.line_end,
            "function_name": item.function_name,
            "reason": item.reason,
            "source_text": item.source_text,
        }
        for item in hypothesis.evidence_lines[:8]
    ]
    validated = False
    reason = "No supported semantic proof matched the local evidence."

    if "signature_threshold_uniqueness" in matched_terms:
        has_threshold_length = "threshold" in evidence_text and ".length" in evidence_text
        has_uniqueness_counterevidence = any(term in evidence_text for term in ("usedsigner", "seensigner", "duplicate", "unique"))
        validated = has_threshold_length and not has_uniqueness_counterevidence
        if has_uniqueness_counterevidence:
            counterevidence.append("Local evidence mentions signer uniqueness or duplicate-signature checks.")
        reason = "Signature threshold uses signature array length without local uniqueness evidence." if validated else "Signature uniqueness proof was not complete."
    elif "checkpoint_boundary_mismatch" in matched_terms:
        has_checkpoint = any(term in evidence_text for term in ("checkpoint", "latest", "upper", "lower", "timestamp"))
        has_boundary_mix = any(term in evidence_text for term in ("upper", "lower", "latest")) and any(op in evidence_text for op in ("<", "<=", ">", ">="))
        validated = has_checkpoint and has_boundary_mix
        reason = "Checkpoint evidence contains mixed boundary/latest semantics." if validated else "Checkpoint boundary proof was not complete."
    elif "fee_formula_dimension_mismatch" in matched_terms:
        has_fee = "fee" in evidence_text
        has_mixed_units = sum(1 for term in ("d6", "1e6", "d18", "1e18", "share", "price") if term in evidence_text) >= 3
        has_dimension_denominator = any(term in evidence_text for term in ("1e24", "1e18", "1e6"))
        validated = has_fee and has_mixed_units and has_dimension_denominator
        reason = "Fee formula mixes fee/price/share dimensions with a suspicious denominator." if validated else "Fee formula dimension proof was not complete."

    return {
        "hypothesis_id": hypothesis.id,
        "matched_terms": matched_terms,
        "validated": validated,
        "proof_status": "static_proof_complete" if validated else "setup_required",
        "counterevidence": counterevidence,
        "local_facts": local_facts,
        "reason": reason,
    }


def generate_validation_artifacts(inp: PocInput, state) -> DynamicGenericOutput:
    hypothesis = inp.hypothesis or (state.get("hypotheses") or [None])[0]
    if hypothesis is None:
        return DynamicGenericOutput(status=ToolStatus.SKIPPED, message="No hypothesis available for validation artifact generation.")

    run_dir = Path(state.get("run_dir", "runs/tmp"))
    artifact_dir = run_dir / "artifacts" / "validation-tests"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    test_name = _artifact_test_name(hypothesis)
    test_path = artifact_dir / test_name
    if test_path.exists():
        hyp_id = re.sub(r"[^A-Za-z0-9_]", "_", hypothesis.id)
        test_name = f"{test_path.stem}{hyp_id[:24]}.t.sol"
        test_path = artifact_dir / test_name
    plan_path = artifact_dir / f"{test_path.stem}.plan.md"
    plan_content = _validation_plan_content(hypothesis)
    plan_path.write_text(plan_content, encoding="utf-8")
    state.setdefault("artifacts", []).append(
        ArtifactRef(
            kind="validation_plan",
            path=str(plan_path),
            description=f"Hypothesis-specific validation plan for {hypothesis.vulnerability_class}.",
        )
    )
    can_generate, setup_reason = _can_generate_executable_validation(inp.repo_path, hypothesis)
    content = ""
    generated_test = False
    if can_generate:
        content = _validation_test_content(hypothesis)
        test_path.write_text(content, encoding="utf-8")
        generated_test = True
        state.setdefault("artifacts", []).append(
            ArtifactRef(
                kind="foundry_validation_test",
                path=str(test_path),
                description=f"Generated Foundry validation test for {hypothesis.vulnerability_class}; setup was inferred from local constructor shape.",
            )
        )
    else:
        state.setdefault("warnings", []).append(f"Validation artifact for {hypothesis.id} is plan-only: {setup_reason}")
    data = {
        "path": str(test_path) if generated_test else None,
        "plan_path": str(plan_path),
        "test_name": test_name,
        "hypothesis_id": hypothesis.id,
        "vulnerability_class": hypothesis.vulnerability_class,
        "generated_test": generated_test,
        "setup_reason": setup_reason,
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
    result = run_command(["forge", "build", "--offline"], cwd=str(worktree), timeout=120)
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
    result = run_command(["forge", "test", "--offline", "--match-contract", "Sentinel"], cwd=str(worktree), timeout=120)
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
        ("run_semantic_validation", "Run deterministic semantic validation for supported invariant classes.", PocInput, run_semantic_validation),
        ("generate_validation_artifacts", "Generate reviewable Foundry validation test artifacts under the run directory.", PocInput, generate_validation_artifacts),
        ("compile_validation_artifacts", "Compile generated validation tests in a non-mutating temporary worktree.", ValidationCompileInput, compile_validation_artifacts),
        ("run_validation_artifacts", "Run generated validation tests in a non-mutating temporary worktree and classify the result.", ValidationCompileInput, run_validation_artifacts),
    ]
    for name, description, input_model, fn in specs:
        if name in {"compile_validation_artifacts", "run_validation_artifacts"}:
            side_effects = [SideEffect.WRITE_FILES, SideEffect.EXECUTE_LOCAL]
        elif name in {"patch_poc_test", "generate_validation_artifacts", "run_semantic_validation"}:
            side_effects = [SideEffect.WRITE_FILES]
        elif name.startswith("run_"):
            side_effects = [SideEffect.EXECUTE_LOCAL]
        else:
            side_effects = [SideEffect.NONE]
        registry.register(RegisteredTool(namespace="dynamic", name=name, description=description, input_model=input_model, output_model=DynamicGenericOutput, fn=fn, side_effects=side_effects))
