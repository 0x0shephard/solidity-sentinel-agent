from __future__ import annotations

import collections
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
    # Strip ALL non-alphanumerics from the class: an LLM-inferred class can contain
    # "/" or spaces (e.g. "External-Call/Accounting Ordering"), which would make the
    # filename a bad path and crash write_text.
    class_name = re.sub(r"[^A-Za-z0-9]", "", hypothesis.vulnerability_class.title())
    return f"Sentinel{class_name[:40]}{cleaned[:32]}Test.t.sol"


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


def _function_signature(repo_path: str, target_file: str, target_contract: str, fn_name: str) -> tuple[str, str] | None:
    """Return (params, qualifiers) for a function declared in the target file.

    ``params`` is the raw parameter list and ``qualifiers`` is everything between
    the closing paren and the body/semicolon (visibility, mutability, returns).
    Returns None when the function is not declared, so callers can decide whether
    a hardcoded template that depends on that function would even compile.
    """
    source_path = Path(repo_path) / target_file
    if not source_path.exists():
        return None
    text = source_path.read_text(encoding="utf-8", errors="replace")
    contract_match = re.search(rf"\bcontract\s+{re.escape(target_contract)}\b", text)
    start = contract_match.start() if contract_match else 0
    match = re.search(rf"\bfunction\s+{re.escape(fn_name)}\s*\(([^)]*)\)([^{{;]*)", text[start:], flags=re.DOTALL)
    if not match:
        return None
    return match.group(1).strip(), match.group(2)


def _reentrancy_template_prerequisites_met(repo_path: str, target_file: str, target_contract: str, target_function: str) -> str | None:
    """Return a reason string if the reentrancy template can't compile, else None.

    The template hardcodes ``target.deposit{value: ...}()`` and a parameterless
    ``target.<fn>()``; emit a proof plan instead of a broken test when the target
    contract doesn't actually expose those members.
    """
    deposit = _function_signature(repo_path, target_file, target_contract, "deposit")
    if deposit is None or deposit[0] != "" or "payable" not in deposit[1]:
        return f"{target_contract} has no payable parameterless deposit(); the reentrancy template would not compile."
    fn = _function_signature(repo_path, target_file, target_contract, target_function)
    if fn is None or fn[0] != "":
        return f"{target_contract}.{target_function} is not a parameterless function the reentrancy template can call."
    return None


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
    if hypothesis.vulnerability_class == "reentrancy":
        unmet = _reentrancy_template_prerequisites_met(repo_path, target_file, target_contract, _target_function)
        if unmet:
            return False, f"{unmet} Emitting a proof plan instead."
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


def _relax_foundry_warnings(worktree: Path) -> None:
    """Stop the repo's strict warning/lint policy from failing our generated tests.

    Many repos set ``deny_warnings = true`` (or ``deny = ["warnings"]``), so a
    benign warning in an authored PoC (e.g. "function can be view", a lint) fails
    `forge build` even though the test is correct. This was the dominant cause of
    the exploit loop never running. The worktree is a throwaway copy, so relaxing
    its config is safe and changes nothing about the audited code.
    """
    toml = worktree / "foundry.toml"
    if not toml.exists():
        return
    text = toml.read_text(encoding="utf-8", errors="replace")
    text = re.sub(r"(?m)^(\s*)deny_warnings\s*=\s*true", r"\1deny_warnings = false", text)
    text = re.sub(r"(?m)^(\s*)deny\s*=\s*.*warning.*$", r"\1deny = []", text)
    toml.write_text(text, encoding="utf-8")


def _copy_repo_for_validation(repo_path: str, worktree: Path) -> None:
    if worktree.exists():
        shutil.rmtree(worktree)

    def ignore(_directory: str, names: list[str]) -> set[str]:
        ignored_names = {".git", "out", "cache", "node_modules", "runs", ".venv", "__pycache__"}
        return {name for name in names if name in ignored_names}

    shutil.copytree(repo_path, worktree, ignore=ignore)
    _relax_foundry_warnings(worktree)


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


# Classifications that mean the validation did NOT produce a sound result — these
# are tool/runtime/test-soundness failures, NOT a passed (held) or violated result.
# A revert that is not an assertion (broken mock, setup revert, failure before the
# target call) and a skipped/empty run are explicitly here so they can never be
# misread as "invariant held" or "invariant violated".
_VALIDATION_FAILURE_CLASSIFICATIONS = {
    "validation_timeout",
    "validation_runtime_error",
    "validation_execution_failed",
    "validation_skipped_or_empty",
    "validation_reverted_not_asserted",
}


def _is_assertion_failure(text_lower: str) -> bool:
    """True only when a forge/forge-std ASSERTION failed (the invariant the test
    asserts was actually violated) — not a plain revert from setup or a broken mock.

    ``sentinel_invariant_violated`` is the token the exploit DSL embeds in its
    ``assertTrue`` message: forge prints a custom assert message as ``[FAIL: <msg>]``
    WITHOUT the literal "assertion failed", so without this token our own sound
    DSL proofs were misread as plain reverts. The token appears only in that one
    assertion's message, so a setup revert (which prints a different reason) can
    never trip it."""
    return any(
        marker in text_lower
        for marker in ("assertion failed", "not satisfied", "panic: assertion", "panic: assert", "[assertion]", "sentinel_invariant_violated")
    )


def _classify_validation_run(return_code: int | None, stdout: str, stderr: str, timed_out: bool) -> str:
    combined = f"{stdout}\n{stderr}"
    low = combined.lower()
    if timed_out:
        return "validation_timeout"
    if "panicked (crashed)" in combined or "Attempted to create a NULL object" in combined:
        return "validation_runtime_error"

    counts = re.search(r"(\d+)\s+passed[;,]\s*(\d+)\s+failed[;,]\s*(\d+)\s+skipped", low)
    passed = int(counts.group(1)) if counts else None
    failed = int(counts.group(2)) if counts else None
    skipped = int(counts.group(3)) if counts else None

    # Nothing meaningfully executed (vm.skip, all-skipped, or empty) is NOT a result.
    if "[skip]" in low or (counts and passed == 0 and failed == 0):
        return "validation_skipped_or_empty"

    if return_code == 0:
        if counts and passed is not None and passed >= 1 and (failed or 0) == 0:
            return "security_invariant_held_or_test_passed"
        if not counts and ("[pass" in low or " passed" in low):
            return "security_invariant_held_or_test_passed"
        # Exit 0 but no test actually passed (e.g. only skipped) — not a held result.
        return "validation_skipped_or_empty"

    # Non-zero exit: a real proof requires an ASSERTION failure (the invariant the
    # test asserts broke). A bare revert is setup/mock/other failure, not a proof.
    failed_present = (failed is not None and failed >= 1) or "[fail" in low or "failing tests" in low
    if failed_present:
        if _is_assertion_failure(low):
            return "security_invariant_violation_or_test_needs_review"
        return "validation_reverted_not_asserted"
    return "validation_execution_failed"


def _extract_forge_result_summary(stdout: str, stderr: str = "") -> str:
    """Pull the human-meaningful result from forge output: the FAIL/revert reason
    or the pass line, so the verdict is grounded in what actually executed."""
    text = f"{stdout}\n{stderr}"
    for pattern in (
        r"\[FAIL[^\]]*\][^\n]*",
        r"\d+ (?:passed|failed)[^\n]*",
        r"(?:revert|Revert|panic|Panic|Error|assertion failed)[^\n]*",
    ):
        match = re.search(pattern, text)
        if match:
            return match.group(0).strip()[:240]
    return (stdout.strip().splitlines()[-1][:240] if stdout.strip() else "no output")


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


def _foundry_test_dir(repo_path: str) -> str:
    """Resolve the Foundry test directory (from foundry.toml, default 'test')."""
    toml = Path(repo_path) / "foundry.toml"
    if toml.exists():
        match = re.search(r'^\s*test\s*=\s*[\'"]([^\'"]+)[\'"]', toml.read_text(encoding="utf-8", errors="replace"), flags=re.MULTILINE)
        if match:
            return match.group(1)
    return "test"


def _extract_pragma(text: str) -> str:
    match = re.search(r"pragma solidity[^;]+;", text)
    return match.group(0) if match else "pragma solidity ^0.8.20;"


def _fixture_surface(source: str) -> str:
    """What a test inheriting this fixture can use: its state variables (already
    deployed instances + actors) and helper function signatures."""
    body = source
    # State variables declared at contract scope (deployed instances, actors).
    state_vars = []
    for line in body.splitlines():
        stripped = line.strip()
        m = re.match(r"^([A-Za-z_][\w\.]*(?:\[\])?)\s+(?:public\s+|internal\s+|private\s+|immutable\s+|constant\s+)*([A-Za-z_]\w*)\s*(?:=|;)", stripped)
        if m and m.group(1) not in {"function", "return", "emit", "require", "if", "for", "while", "using", "import", "pragma"}:
            state_vars.append(f"  {m.group(1)} {m.group(2)}")
    # Helper/exposed function signatures (skip setUp; keep public/internal).
    helpers = []
    for m in re.finditer(r"function\s+(\w+)\s*\(([^)]*)\)([^{;]*)", body):
        name, params, quals = m.group(1), m.group(2).strip(), m.group(3)
        if name == "setUp":
            continue
        vis = "public" if "public" in quals else "external" if "external" in quals else "internal" if "internal" in quals else ""
        helpers.append(f"  function {name}({params}) {vis}".rstrip())
    parts = []
    if state_vars:
        parts.append("State variables available (already deployed in setUp — USE THESE, do not redeploy):\n" + "\n".join(dict.fromkeys(state_vars))[:2000])
    if helpers:
        parts.append("Helper functions available:\n" + "\n".join(dict.fromkeys(helpers))[:1500])
    return "\n\n".join(parts)


_TYPE_LINE_RE = re.compile(r"^\s+([A-Z]\w*)\s+([A-Za-z_]\w*)\s*$", re.MULTILINE)


def _contract_public_members(body: str) -> list[str]:
    """Public/external function names + public state-variable getters of a contract
    body. The getters (e.g. ``SuperPoolFactory public superPoolFactory;``) are the
    members the model needs to navigate (``protocol.superPoolFactory()``) and which
    the plain function-signature extractor misses."""
    fns = re.findall(r"function\s+(\w+)\s*\([^)]*\)[^;{]*\b(?:public|external)\b", body)
    getters = re.findall(r"\b[A-Za-z_][\w\.\[\]]*\s+public\s+(?:immutable\s+|constant\s+)?([A-Za-z_]\w*)\s*[;=]", body)
    return list(dict.fromkeys(fns + getters))


def _instance_interfaces(repo_path: str, surface: str, max_types: int = 14) -> tuple[str, set[str]]:
    """Map each fixture instance to the public members of its contract type.

    The dominant exploit-loop failure is the model calling a function on the wrong
    instance (``protocol.deploySuperPool`` where ``protocol`` is the ``Deploy``
    harness that merely *exposes* ``superPoolFactory``). Giving the model
    "instance <name> (type T) exposes: ..." — and admitting those member names —
    lets it navigate ``protocol.superPoolFactory().deploySuperPool(...)``.
    Returns (prompt_block, member_name_set)."""
    pairs = _TYPE_LINE_RE.findall(surface or "")
    if not pairs:
        return "", set()
    wanted = {t for t, _ in pairs}
    # Scan the protocol's own source (not lib deps) once for each needed type body.
    bodies: dict[str, str] = {}
    root = Path(repo_path)
    for sol in list(root.rglob("*.sol")):
        rel = sol.as_posix()
        if "/lib/" in rel or "/node_modules/" in rel:
            continue
        try:
            text = sol.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in re.finditer(r"(?:abstract\s+)?(?:contract|interface)\s+(\w+)", text):
            name = m.group(1)
            if name in wanted and name not in bodies:
                bodies[name] = text[m.start(): m.start() + 6000]
        if len(bodies) >= len(wanted):
            break
    lines: list[str] = []
    members: set[str] = set()
    for typ, name in pairs:
        if typ not in bodies:
            continue
        mem = _contract_public_members(bodies[typ])
        if not mem:
            continue
        members.update(mem)
        lines.append(f"  {name} (type {typ}) exposes: {', '.join(mem[:18])}")
        if len(lines) >= max_types:
            break
    block = "\n".join(lines)
    return block, members


def _extract_contract_interface(source: str, contract: str) -> str:
    """The target contract's real ABI surface: function signatures, structs,
    enums, custom errors — so the author uses only signatures that exist."""
    start = source.find(f"contract {contract}")
    if start == -1:
        start = source.find(f"abstract contract {contract}")
    body = source[start:] if start != -1 else source
    funcs = [f"  function {m.group(1)}({m.group(2).strip()}){m.group(3).rstrip()}".rstrip() for m in re.finditer(r"function\s+(\w+)\s*\(([^)]*)\)([^{;]*)", body)][:60]
    structs = re.findall(r"struct\s+\w+\s*\{[^}]*\}", body)[:15]
    errors = re.findall(r"error\s+\w+\s*\([^)]*\)\s*;", body)[:20]
    enums = re.findall(r"enum\s+\w+\s*\{[^}]*\}", body)[:10]
    parts = []
    if funcs:
        parts.append("Functions:\n" + "\n".join(funcs))
    if structs:
        parts.append("Structs:\n" + "\n".join(structs))
    if enums:
        parts.append("Enums:\n" + "\n".join(enums))
    if errors:
        parts.append("Custom errors:\n" + "\n".join(errors))
    return "\n".join(parts)


def _find_example_test(repo_path: str, fixture_file: str) -> str:
    """A real, compiling test function from the suite for the author to mimic."""
    test_dir = Path(repo_path) / _foundry_test_dir(repo_path)
    if not test_dir.exists():
        return ""
    fixture = Path(fixture_file)
    for path in sorted(test_dir.rglob("*.sol")):
        if path == fixture:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # Grab the imports + the first test function body as a concrete pattern.
        imports = "\n".join(re.findall(r"^import[^;]+;", text, flags=re.MULTILINE)[:8])
        m = re.search(r"function\s+test\w*\s*\([^)]*\)[^{]*\{", text)
        if not m:
            continue
        # balance braces to capture the function body
        depth, end = 0, None
        for i in range(m.start(), min(len(text), m.start() + 2500)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        if end:
            return f"{imports}\n\n{text[m.start():end]}"
    return ""


def _resolve_reachable_instances(repo_path: str, fixture: dict) -> str:
    """Map fixture orchestrator instances to the core contracts they expose via
    public getters, e.g. ``Deploy protocol`` -> ``protocol.pool()``,
    ``protocol.riskEngine()``.

    Foundry suites commonly deploy through a script/harness that holds every core
    contract as a ``public`` var (auto-getter). The real call path is then
    ``protocol.<getter>()``, not a bare ``pool`` instance — which is exactly the
    name the model keeps inventing. Surfacing this map is what lets a cross-contract
    exploit reach the contract under test.
    """
    src = fixture.get("source", "") or ""
    # Fixture state vars: `Type name;` (Type uppercase-led, name lowercase-led).
    state_vars: dict[str, str] = {}
    for m in re.finditer(r"^\s+([A-Z]\w*)\s+(?:public\s+|internal\s+)?([a-z]\w*)\s*;", src, flags=re.MULTILINE):
        state_vars[m.group(2)] = m.group(1)
    wanted = set(state_vars.values())
    if not wanted:
        return ""
    # Index each wanted orchestrator type -> its public state vars (the getters).
    members: dict[str, list[tuple[str, str]]] = {}
    for path in Path(repo_path).rglob("*.sol"):
        if len(members) >= len(wanted):
            break
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for cm in re.finditer(r"\bcontract\s+(\w+)", text):
            tname = cm.group(1)
            if tname not in wanted or tname in members:
                continue
            body = text[cm.end(): cm.end() + 6000]
            pubs = re.findall(r"\b([A-Z]\w*)\s+public\s+([a-z]\w*)\s*;", body)
            if pubs:
                members[tname] = pubs[:20]
    lines = [
        f"  {name}.{subname}() -> {subtype}"
        for name, typ in state_vars.items()
        for subtype, subname in members.get(typ, [])
    ]
    if not lines:
        return ""
    return (
        "Core contracts reachable via getters (use these chains as the call \"target\"):\n"
        + "\n".join(lines[:40])
        + "\n(These getters return CONTRACT types. When passing one where an ADDRESS is expected — e.g. an "
        "approve/transfer spender or a function's address arg — wrap it: address(protocol.pool()).)"
    )


def _detect_test_fixture(repo_path: str, max_source_chars: int = 16000) -> dict | None:
    """Find the protocol's own base test fixture for PoC inheritance.

    Real protocols deploy via proxies/initializers, so a meaningful PoC must reuse
    the project's deployment harness. Picks the test contract that is most often
    inherited (``is <Name>``) and has the richest deploy setup (``new``/
    ``initialize`` calls). Returns its name, the import path relative to the test
    dir, and its (capped) source for grounding the author prompt.
    """
    test_dir = Path(repo_path) / _foundry_test_dir(repo_path)
    if not test_dir.exists():
        return None
    inherit_counts: collections.Counter = collections.Counter()
    contract_defs: dict[str, tuple[Path, str]] = {}
    for path in test_dir.rglob("*.sol"):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in re.finditer(r"\b(?:abstract\s+)?contract\s+(\w+)", text):
            contract_defs.setdefault(match.group(1), (path, text))
        for match in re.finditer(r"\bis\s+([A-Za-z0-9_,\s]+?)\s*\{", text):
            for base in match.group(1).split(","):
                inherit_counts[base.strip()] += 1

    def deploy_score(text: str) -> int:
        return len(re.findall(r"\bnew\s+\w+\(", text)) + len(re.findall(r"\.initialize\(", text))

    candidates = [
        (name, path, text)
        for name, (path, text) in contract_defs.items()
        if "function setUp" in text or deploy_score(text) >= 3
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda item: (inherit_counts.get(item[0], 0), deploy_score(item[2])), reverse=True)
    name, path, text = candidates[0]
    if deploy_score(text) < 3 and inherit_counts.get(name, 0) == 0:
        return None
    rel = path.relative_to(test_dir).as_posix()
    return {
        "name": name,
        # Generated tests are written at the test-dir root, so the relative import
        # to the fixture is exactly its path under test/ (e.g. ./integration/Base.t.sol).
        "import_path": f"./{rel}",
        "file": str(path),
        "rel": rel,
        "pragma": _extract_pragma(text),
        "surface": _fixture_surface(text),
        "example_test": _find_example_test(repo_path, str(path)),
        "source": text[:max_source_chars],
    }


def _compilable_test_prompt(hypothesis: VulnerabilityHypothesis, target_source: str, fixture: dict, task: str, skeleton: str = "") -> list[str]:
    """Shared, heavily-grounded context so the authored test actually COMPILES."""
    target_file, target_contract, target_function = _target_details(hypothesis)
    interface = _extract_contract_interface(target_source, target_contract)
    test_contract = f"Sentinel{re.sub(r'[^A-Za-z0-9]', '', target_function)[:24]}Test"
    lines = [
        f"Hypothesis: {hypothesis.title}",
        f"Affected: {target_contract}.{target_function} ({target_file})",
        f"Why it may be exploitable: {hypothesis.evidence_summary}",
        "",
        "Write a Foundry test that COMPILES and runs. Follow these rules EXACTLY:",
        f"  - First line: {fixture.get('pragma', 'pragma solidity ^0.8.20;')}",
        f"  - Import the fixture VERBATIM: import {{{fixture['name']}}} from \"{fixture['import_path']}\";",
        f"  - Declare exactly: contract {test_contract} is {fixture['name']} {{ ... }}",
        "  - The fixture's setUp() already deploys the whole system — DO NOT redeploy. Use the exposed state variables.",
        "  - Call ONLY functions/structs/errors that appear in the interfaces below — never invent members.",
        "  - Declare every contract/interface/library at FILE SCOPE; NEVER nest one inside another.",
        "  - You inherit forge-std Test, so use vm.* cheatcodes (vm.prank, vm.deal, vm.expectRevert, etc.) directly.",
        "",
        f"=== WHAT THE FIXTURE {fixture['name']} EXPOSES ===",
        fixture.get("surface") or "(parse fixture source below)",
    ]
    if fixture.get("example_test"):
        lines += [
            "",
            "=== A REAL TEST FROM THIS REPO THAT COMPILES — mimic its setup/cheatcode/fixture-usage style "
            "(but use the EXACT import line specified above, not this example's) ===",
            fixture["example_test"][:2500],
        ]
    lines += [
        "",
        f"=== TARGET CONTRACT {target_contract} INTERFACE (use only these signatures) ===",
        interface or "(interface unavailable)",
        "",
        "=== fixture source (for reference) ===",
        (fixture.get("source") or "")[:9000],
    ]
    if skeleton:
        lines += [
            "",
            "=== THIS MINIMAL TEST ALREADY COMPILES IN THIS REPO. Start from it verbatim (keep its pragma, import, "
            "contract declaration and setUp usage) and ADD the attack + assertion inside the test function. Do not "
            "change the imports or contract header. ===",
            skeleton[:4000],
        ]
    lines += [
        "",
        task,
        "Return ONLY the corrected Solidity test in a single ```solidity block, no prose.",
    ]
    return lines


def _build_minimal_skeleton_prompt(hypothesis: VulnerabilityHypothesis, target_source: str, fixture: dict) -> str:
    """Prompt for the SMALLEST test that compiles — locks in imports/fixture/pragma
    before the model has to get the full attack right."""
    task = (
        "TASK: write the SMALLEST possible test that COMPILES — nothing else. The test body should make ONE simple "
        "call to a real function on a fixture-exposed contract (or just read one value) and end with assertTrue(true). "
        "No attack, no complex logic. The ONLY goal is a clean compile that establishes correct imports/fixture/pragma."
    )
    return "\n".join(_compilable_test_prompt(hypothesis, target_source, fixture, task))


def _build_poc_author_prompt(hypothesis: VulnerabilityHypothesis, target_source: str, fixture: dict) -> str:
    return "\n".join(
        _compilable_test_prompt(
            hypothesis, target_source, fixture,
            "TASK: drive the target via the fixture-deployed contracts and assert the security invariant.",
        )
    )


def _author_executable_poc(repo_path: str, hypothesis: VulnerabilityHypothesis, state) -> tuple[str, str] | None:
    """Author an executable, fixture-inheriting PoC via the LLM.

    Returns (source, note) on success, or None when no fixture is available or no
    PoC could be authored. Falls back to the Ollama author on provider errors.
    """
    fixture = _detect_test_fixture(repo_path)
    if not fixture:
        return None
    target_file, _contract, _fn = _target_details(hypothesis)
    target_source = ""
    target_path = Path(repo_path) / target_file
    if target_path.exists():
        target_source = target_path.read_text(encoding="utf-8", errors="replace")[:14000]
    prompt = _build_poc_author_prompt(hypothesis, target_source, fixture)

    from sentinel.llm import provider as llm_provider

    try:
        author = llm_provider.get_poc_author(mock=False)
        code = author.author(prompt)
    except Exception:
        try:
            code = llm_provider.get_ollama_fallback_poc_author().author(prompt)
        except Exception:
            return None
    if not code or "pragma solidity" not in code:
        return None
    return code, f"LLM-authored executable PoC inheriting fixture {fixture['name']}."


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
    authored = False
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
    elif state.get("use_llm_refiner", False):
        # Templates can't set up this contract (proxy/initializer deployment), so
        # author an executable PoC that inherits the protocol's own test fixture.
        # compile_validation_artifacts + the self-repair loop validate/fix it.
        authored_result = _author_executable_poc(inp.repo_path, hypothesis, state)
        if authored_result is not None:
            content, author_note = authored_result
            test_path.write_text(content, encoding="utf-8")
            generated_test = True
            authored = True
            state.setdefault("artifacts", []).append(
                ArtifactRef(kind="foundry_validation_test", path=str(test_path), description=author_note)
            )
        else:
            state.setdefault("warnings", []).append(f"Validation artifact for {hypothesis.id} is plan-only: {setup_reason}")
    else:
        state.setdefault("warnings", []).append(f"Validation artifact for {hypothesis.id} is plan-only: {setup_reason}")
    data = {
        "path": str(test_path) if generated_test else None,
        "plan_path": str(plan_path),
        "test_name": test_name,
        "hypothesis_id": hypothesis.id,
        "vulnerability_class": hypothesis.vulnerability_class,
        "generated_test": generated_test,
        "authored_by_llm": authored,
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
    # A runtime/compile/timeout failure is a tool error, not a successful run —
    # report it as ERROR so completeness and eval scoring don't treat a crashed
    # validation as a clean result.
    run_status = ToolStatus.ERROR if classification in _VALIDATION_FAILURE_CLASSIFICATIONS else ToolStatus.OK
    return DynamicGenericOutput(status=run_status, message=f"Validation run classified as {classification}.", data=manifest)


def _resolve_imported_sources(repo_path: str, test_source: str, max_chars: int = 12000) -> str:
    """Read the real target-contract source(s) a generated test imports.

    Resolves ``import {X} from "../<path>";`` (relative to the worktree ``test/``
    dir, i.e. the repo root) and concatenates the referenced files, capped, so the
    repairer can ground its fix in the contract's actual API.
    """
    chunks: list[str] = []
    seen: set[str] = set()
    for raw in re.findall(r'import\s*\{[^}]*\}\s*from\s*"([^"]+)"', test_source):
        rel = re.sub(r"^(\.\./)+", "", raw)
        candidate = Path(repo_path) / rel
        if not candidate.exists() or str(candidate) in seen:
            continue
        seen.add(str(candidate))
        try:
            chunks.append(f"// file: {rel}\n{candidate.read_text(encoding='utf-8', errors='replace')}")
        except OSError:
            continue
    return "\n\n".join(chunks)[:max_chars]


def _build_poc_repair_prompt(test_source: str, target_source: str, compiler_stderr: str) -> str:
    return "\n".join(
        [
            "A generated Foundry test FAILED to compile. Fix it so it compiles against the real contract API.",
            "",
            "=== solc error ===",
            (compiler_stderr or "").strip()[:4000] or "(no stderr captured)",
            "",
            "=== failing test ===",
            test_source.strip(),
            "",
            "=== real target contract source (use only signatures that appear here) ===",
            target_source or "(target source unavailable)",
            "",
            "Return ONLY the corrected Solidity test in a single ```solidity block.",
        ]
    )


def _writeback_repaired_artifact(state, inp: "ValidationCompileInput", filename: str, code: str) -> None:
    """Mirror a repaired worktree test back to its source artifact so the
    subsequent run uses the fixed version."""
    for path in _validation_artifact_paths(inp, state):
        if path.name == filename:
            path.write_text(code, encoding="utf-8")
            return


def repair_validation_artifacts(inp: "ValidationCompileInput", state) -> DynamicGenericOutput:
    """Self-repair loop: when a generated PoC won't compile, feed solc's error and
    the real target source back to the LLM and retry until it compiles.

    Runs only when the LLM is enabled. Edits the temporary worktree and mirrors any
    fix back to the source artifact so the validation run uses the repaired test.
    """
    if not state.get("use_llm_refiner", False):
        return DynamicGenericOutput(status=ToolStatus.SKIPPED, message="LLM disabled; PoC repair skipped.")
    from sentinel.config import get_settings

    settings = get_settings()
    if settings.poc_repair_max_attempts <= 0:
        return DynamicGenericOutput(status=ToolStatus.SKIPPED, message="PoC repair disabled (poc_repair_max_attempts=0).")
    early_output, worktree, copied_tests = _prepare_validation_worktree(inp, state)
    if early_output is not None:
        return early_output
    assert worktree is not None
    timeout = settings.forge_command_timeout
    result = run_command(["forge", "build", "--offline"], cwd=str(worktree), timeout=timeout)
    if result.return_code == 0:
        return DynamicGenericOutput(status=ToolStatus.OK, message="Validation artifacts already compile; no repair needed.", data={"return_code": 0, "attempts": 0})

    from sentinel.llm import provider as llm_provider

    try:
        repairer = llm_provider.get_poc_repairer(mock=False)
    except Exception as exc:
        return DynamicGenericOutput(status=ToolStatus.ERROR, message=f"PoC repairer unavailable: {type(exc).__name__}: {exc}")

    history: list[str] = []
    repaired_files: list[str] = []
    for attempt in range(1, settings.poc_repair_max_attempts + 1):
        produced = False
        for test_str in copied_tests:
            test_path = Path(test_str)
            if not test_path.exists():
                continue
            src = test_path.read_text(encoding="utf-8", errors="replace")
            prompt = _build_poc_repair_prompt(src, _resolve_imported_sources(inp.repo_path, src), result.stderr)
            try:
                fixed = repairer.repair(prompt)
            except Exception:
                try:
                    fixed = llm_provider.get_ollama_fallback_poc_repairer().repair(prompt)
                except Exception:
                    fixed = ""
            if fixed and fixed.strip() != src.strip():
                test_path.write_text(fixed, encoding="utf-8")
                _writeback_repaired_artifact(state, inp, test_path.name, fixed)
                produced = True
                if test_path.name not in repaired_files:
                    repaired_files.append(test_path.name)
        if not produced:
            history.append(f"attempt {attempt}: no repair produced; stopping.")
            break
        result = run_command(["forge", "build", "--offline"], cwd=str(worktree), timeout=timeout)
        history.append(f"attempt {attempt}: recompiled return_code={result.return_code}")
        if result.return_code == 0:
            break

    run_dir = Path(state.get("run_dir", "runs/tmp"))
    manifest = {
        "return_code": result.return_code,
        "repaired": result.return_code == 0,
        "attempts": len([entry for entry in history if "recompiled" in entry]),
        "repaired_files": repaired_files,
        "history": history,
        "stderr": _clean_output(result.stderr[-8000:]),
    }
    manifest_path = run_dir / "artifacts" / "validation-repair-result.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    state.setdefault("artifacts", []).append(
        ArtifactRef(kind="validation_repair_result", path=str(manifest_path), description="Result of LLM-driven PoC compile repair.")
    )
    if result.return_code == 0:
        return DynamicGenericOutput(status=ToolStatus.OK, message="PoC repaired and now compiles.", data=manifest)
    return DynamicGenericOutput(status=ToolStatus.ERROR, message="PoC repair attempted but compile still fails.", data=manifest)


def _build_exploit_author_prompt(hypothesis: VulnerabilityHypothesis, target_source: str, fixture: dict, prior: dict | None, skeleton: str = "") -> str:
    invariant = (getattr(hypothesis, "required_proof", "") or "").strip() or f"the protocol guarantee implied by: {hypothesis.title}"
    task = (
        f"TASK: execute the concrete attack sequence (multi-step / specific values), then ASSERT the invariant: "
        f"{invariant}. If the bug is real the assertion MUST FAIL when the test runs — a failing test means the "
        "invariant is broken and the bug is CONFIRMED. Do NOT use vm.expectRevert to hide the break. "
        "The FINAL assertion that proves the bug MUST be a state assertion (assertEq/assertGt/assertLt/assertTrue "
        "comparing before/after values) whose message BEGINS with the exact token 'SENTINEL_INVARIANT_VIOLATED: ' "
        "followed by a one-line description — this is how the harness recognizes a genuine invariant break (a plain "
        "revert is NOT a proof). Snapshot the relevant state before and after the attack and assert on the delta."
    )
    lines = _compilable_test_prompt(hypothesis, target_source, fixture, task, skeleton=skeleton)
    if prior is not None:
        lines = lines[:-1] + [
            "",
            "=== YOUR PREVIOUS ATTEMPT ===",
            (prior.get("code") or "")[:4000],
            "=== WHAT HAPPENED WHEN IT RAN ===",
            prior.get("observation", "")[:1800],
            "Refine: if it failed to compile, fix the EXACT solc error (use only real signatures listed above). If the "
            "test PASSED (invariant held), your sequence/values did not trigger the bug — try a materially different attack.",
            "Return ONLY the corrected Solidity test in a single ```solidity block, no prose.",
        ]
    return "\n".join(lines)


def author_and_run_exploit(inp: PocInput, state) -> DynamicGenericOutput:
    """Execution-grounded reasoning loop for one hypothesis.

    Authors a runnable Foundry test that asserts the hypothesis's invariant, runs
    it in an isolated worktree, observes whether the invariant breaks (a failing
    assertion = confirmed bug), and iterates — feeding the compile error or run
    outcome back to the author to refine the exploit. This proves multi-step
    economic bugs by *running numbers*, which prose reasoning alone cannot.
    """
    if not state.get("use_llm_refiner", False):
        return DynamicGenericOutput(status=ToolStatus.SKIPPED, message="LLM disabled; exploit loop skipped.")
    hypothesis = inp.hypothesis or (state.get("hypotheses") or [None])[0]
    if hypothesis is None:
        return DynamicGenericOutput(status=ToolStatus.SKIPPED, message="No hypothesis for exploit loop.")
    if shutil.which("forge") is None:
        return DynamicGenericOutput(status=ToolStatus.UNAVAILABLE, message="forge is not installed.")
    from sentinel.config import get_settings

    settings = get_settings()
    max_iters = settings.exploit_loop_max_iterations
    if max_iters <= 0:
        return DynamicGenericOutput(status=ToolStatus.SKIPPED, message="Exploit loop disabled (max_iterations=0).")
    fixture = _detect_test_fixture(inp.repo_path)
    if not fixture:
        return DynamicGenericOutput(status=ToolStatus.SKIPPED, message="No test fixture to inherit; exploit loop skipped.")

    from sentinel.llm import provider as llm_provider
    from sentinel.llm.ollama import extract_solidity_code

    try:
        author = llm_provider.get_poc_author(mock=False)
    except Exception as exc:
        return DynamicGenericOutput(status=ToolStatus.ERROR, message=f"PoC author unavailable: {type(exc).__name__}: {exc}")

    run_dir = Path(state.get("run_dir", "runs/tmp"))
    hyp_slug = re.sub(r"[^A-Za-z0-9_]", "_", hypothesis.id)[:24]
    worktree = run_dir / "artifacts" / f"exploit-worktree-{hyp_slug}"
    _copy_repo_for_validation(inp.repo_path, worktree)
    test_dir = worktree / "test"
    test_dir.mkdir(parents=True, exist_ok=True)
    _, _contract, target_function = _target_details(hypothesis)
    test_path = test_dir / f"Sentinel{re.sub(r'[^A-Za-z0-9_]', '', target_function)[:24]}Exploit_{hyp_slug}.t.sol"
    target_file = _target_details(hypothesis)[0]
    target_path = Path(inp.repo_path) / target_file
    target_source = target_path.read_text(encoding="utf-8", errors="replace")[:14000] if target_path.exists() else ""
    repair_contract = _target_details(hypothesis)[1]
    repair_interface = _extract_contract_interface(target_source, repair_contract)
    # Resolve orchestrator getters (protocol.pool() -> Pool) once, so the plan
    # author knows the real cross-contract call paths instead of inventing names.
    if "reachable" not in fixture:
        fixture["reachable"] = _resolve_reachable_instances(inp.repo_path, fixture)
    timeout = settings.forge_command_timeout

    try:
        repairer = llm_provider.get_poc_repairer(mock=False)
    except Exception:
        repairer = None
    max_compile_fixes = max(1, settings.poc_repair_max_attempts + 1)

    def _compile_until_ok(code: str) -> tuple[bool, str, str]:
        """Mechanical compile-repair sub-loop: fix solc errors until it builds.

        Separating this from semantic refinement means a *near-correct* PoC is
        driven to a compiling state (feeding solc errors + the real target source
        back to the repairer) instead of being skipped on the first error.
        """
        last_err = ""
        for fix in range(max_compile_fixes):
            test_path.write_text(code, encoding="utf-8")
            result = run_command(["forge", "build", "--offline"], cwd=str(worktree), timeout=timeout)
            if result.return_code == 0:
                return True, code, ""
            last_err = _clean_output(result.stderr[-1800:] or result.stdout[-1800:])
            history.append(f"  compile fix {fix + 1}/{max_compile_fixes}")
            if repairer is None or fix == max_compile_fixes - 1:
                break
            # Feed the repairer the REAL target ABI + what the fixture exposes — not
            # the test's own imports. The dominant compile failure is a hallucinated
            # member (e.g. Pool.setPaused), which is only fixable if the repairer can
            # see the contract's actual signatures and the fixture's deployed members.
            grounding = "\n\n".join(
                section for section in [
                    f"=== {repair_contract} real interface (use ONLY these member names) ===\n{repair_interface}" if repair_interface else "",
                    f"=== fixture exposes (already-deployed members) ===\n{fixture.get('surface', '')}" if fixture.get("surface") else "",
                ] if section
            )
            repair_prompt = _build_poc_repair_prompt(code, grounding, last_err)
            try:
                fixed = extract_solidity_code(repairer.repair(repair_prompt))
            except Exception:
                fixed = ""
            if not fixed or fixed.strip() == code.strip():
                break
            code = fixed
        return False, code, last_err

    history: list[str] = []
    verdict = "inconclusive"
    classification = "not_run"
    result_summary = ""
    prior: dict | None = None

    # Phase 0 — minimal-test-first: get a TINY test compiling to lock in the correct
    # imports/fixture/pragma, then hand that proven base to the full exploit author.
    # The dominant compile failures come from the large surface of a full PoC; a
    # compiling skeleton removes the imports/setup from the equation.
    skeleton = ""
    try:
        raw0 = author.author(_build_minimal_skeleton_prompt(hypothesis, target_source, fixture))
        skel_code = extract_solidity_code(raw0) or raw0
        if skel_code and "pragma solidity" in skel_code:
            ok0, skel_code, _ = _compile_until_ok(skel_code)
            if ok0:
                skeleton = skel_code
                history.append("skeleton: compiled")
            else:
                history.append("skeleton: did not compile")
    except Exception:
        history.append("skeleton: author unavailable")

    # Phase 1 — structured exploit DSL (preferred): the model fills a validated
    # plan; we render the Solidity (so the before/after assertion is guaranteed)
    # and reject hallucinated members BEFORE compiling. Free-form is the fallback
    # below if the DSL never produces a runnable test.
    author_plan_fn = getattr(author, "author_plan", None)
    if settings.exploit_dsl_enabled and callable(author_plan_fn):
        from sentinel.tools import exploit_dsl as _dsl

        # Admit the whole protocol's function names (not just the target's), so a
        # legitimate cross-contract call is not mistaken for a hallucination.
        protocol_functions = {
            str(r.get("function_name"))
            for r in (state.get("static_facts", {}) or {}).get("function_ranges", [])
            if isinstance(r, dict) and r.get("function_name")
        }
        known_targets = _dsl.extract_instance_names(fixture.get("surface", ""))
        # Map each instance to its type's public members so the model can navigate
        # getters (protocol.superPoolFactory().deploySuperPool(...)) instead of
        # calling protocol functions that live on a different contract.
        instance_iface_text, instance_members = _instance_interfaces(inp.repo_path, fixture.get("surface", ""))
        fixture = {**fixture, "instance_interfaces": instance_iface_text}
        protocol_functions |= instance_members
        known_functions = _dsl.collect_known_functions(repair_interface, fixture.get("surface", ""), extra_function_names=protocol_functions)
        plan_errors: list[str] | None = None
        for attempt in range(1, max_iters + 1):
            prompt = _dsl.build_plan_prompt(hypothesis, repair_interface, fixture, prior_errors=plan_errors)
            try:
                raw = author_plan_fn(prompt)
            except Exception:
                history.append(f"dsl iter {attempt}: author unavailable")
                break
            if not raw:
                history.append("dsl: plan authoring unsupported -> free-form")
                break
            plan = _dsl.parse_plan(raw)
            if plan is None:
                history.append(f"dsl iter {attempt}: unparseable plan (preview: {raw[:120]!r})")
                plan_errors = [
                    "Your previous response was not a valid JSON object matching the plan schema. Return ONLY a JSON "
                    "object with keys actors, setup_calls, attack_calls, before, after, and invariant (with description "
                    "and assertion). No prose, no code fence, no Solidity."
                ]
                continue
            plan_errors = _dsl.validate_plan(plan, known_functions, known_targets=known_targets)
            if plan_errors:
                history.append(f"dsl iter {attempt}: invalid plan ({len(plan_errors)} errors): {'; '.join(plan_errors)[:300]}")
                continue
            code = _dsl.render_plan(plan, fixture, fixture.get("pragma") or _extract_pragma(target_source) or "^0.8.20", test_path.stem)
            # Compile the render directly — do NOT run the free-form Solidity repairer
            # here: it restructures our deterministic, sound test (it has rewritten
            # renders into try/catch + bogus imports). Instead, feed the solc error
            # back to the PLAN author, which knows the intent and preserves structure.
            test_path.write_text(code, encoding="utf-8")
            build = run_command(["forge", "build", "--offline"], cwd=str(worktree), timeout=timeout)
            if build.return_code != 0:
                compile_err = _clean_output(build.stderr[-1800:] or build.stdout[-1800:])
                plan_errors = [
                    "the rendered plan failed to compile — adjust the plan (targets, args, and state-read expressions) so "
                    f"the generated Solidity compiles. solc error:\n{compile_err[-700:]}"
                ]
                history.append(f"dsl iter {attempt}: not compiling | {compile_err[-240:]}")
                # Persist the exact failing render so the compile failure is diagnosable
                # post-hoc (test_path is later overwritten by the free-form fallback).
                try:
                    (run_dir / "artifacts" / f"exploit-dsl-render-{hyp_slug}-iter{attempt}.t.sol").write_text(code, encoding="utf-8")
                except OSError:
                    pass
                continue
            run_result = run_command(["forge", "test", "--offline", "--match-contract", "Sentinel"], cwd=str(worktree), timeout=timeout)
            classification = _classify_validation_run(run_result.return_code, run_result.stdout, run_result.stderr, run_result.timed_out)
            result_summary = _extract_forge_result_summary(run_result.stdout, run_result.stderr)
            history.append(f"dsl iter {attempt}: ran -> {classification} | {result_summary}")
            if classification == "security_invariant_violation_or_test_needs_review":
                verdict = "confirmed"  # the asserted invariant broke when executed
                break
            if classification == "security_invariant_held_or_test_passed":
                verdict = "refuted"
                plan_errors = ["the invariant HELD (test passed) — your sequence/values did not trigger the bug; try a materially different attack."]
                continue
            # reverted / skipped / runtime error: refine the plan with guidance.
            plan_errors = [
                f"the test did not produce a clean assertion ({classification}): {result_summary}. "
                "Reach the target call without a setup revert and prove the bug via the before/after assertion."
            ]
        if verdict == "confirmed":
            return _finalize_exploit(state, run_dir, hyp_slug, hypothesis, test_path, verdict, classification, result_summary, history)
        history.append("dsl phase inconclusive -> free-form fallback")

    for attempt in range(1, max_iters + 1):
        prompt = _build_exploit_author_prompt(hypothesis, target_source, fixture, prior, skeleton=skeleton)
        try:
            raw = author.author(prompt)
        except Exception:
            try:
                raw = llm_provider.get_ollama_fallback_poc_author().author(prompt)
            except Exception:
                history.append(f"iter {attempt}: author unavailable")
                break
        code = extract_solidity_code(raw) or raw
        if not code or "pragma solidity" not in code:
            history.append(f"iter {attempt}: no test authored")
            break
        # 1) Drive it to a COMPILING state (mechanical, retried hard).
        compiled, code, compile_err = _compile_until_ok(code)
        if not compiled:
            prior = {"code": code, "observation": f"STILL FAILS TO COMPILE after repair attempts:\n{compile_err}"}
            history.append(f"iter {attempt}: not compiling | {_clean_output(compile_err)[-240:]}")
            continue
        # 2) Run it and INFER the result from what actually executed.
        run_result = run_command(["forge", "test", "--offline", "--match-contract", "Sentinel"], cwd=str(worktree), timeout=timeout)
        classification = _classify_validation_run(run_result.return_code, run_result.stdout, run_result.stderr, run_result.timed_out)
        result_summary = _extract_forge_result_summary(run_result.stdout, run_result.stderr)
        history.append(f"iter {attempt}: ran -> {classification} | {result_summary}")
        if classification == "security_invariant_violation_or_test_needs_review":
            verdict = "confirmed"  # the asserted invariant broke when executed
            break
        if classification in _VALIDATION_FAILURE_CLASSIFICATIONS:
            if classification == "validation_reverted_not_asserted":
                guidance = (
                    "The test FAILED on a plain revert, NOT a failed assertion — this is NOT a proof (it usually means "
                    "a broken mock ABI or a setup revert BEFORE reaching the target). Use a complete, vetted ERC20/oracle "
                    "mock (implement transfer/transferFrom/approve/balanceOf as the real flow needs), make setUp succeed, "
                    "reach the target call, and prove the bug with an ASSERTION on before/after state — not by reverting."
                )
            elif classification == "validation_skipped_or_empty":
                guidance = "The test was SKIPPED / nothing executed — remove any vm.skip and write a real test that runs and asserts."
            else:
                guidance = "Runtime error before a clean assertion."
            prior = {"code": code, "observation": f"{guidance}\nResult: {result_summary}\n{_clean_output(run_result.stderr[-1000:] or run_result.stdout[-1000:])}"}
            continue
        # 3) Compiled + ran + passed -> invariant HELD. Refine the attack.
        verdict = "refuted"
        prior = {"code": code, "observation": f"TEST PASSED — invariant HELD ({result_summary}). Your attack did not trigger the bug; try a materially different sequence/values."}

    return _finalize_exploit(state, run_dir, hyp_slug, hypothesis, test_path, verdict, classification, result_summary, history)


def _finalize_exploit(state, run_dir, hyp_slug, hypothesis, test_path, verdict, classification, result_summary, history) -> DynamicGenericOutput:
    """Persist the exploit-loop manifest and (on a real confirmation) mark the
    hypothesis as executed-proof. Shared by the DSL and free-form paths."""
    manifest = {
        "hypothesis_id": hypothesis.id,
        "verdict": verdict,
        "classification": classification,
        "result_summary": result_summary,
        "iterations": len(history),
        "history": history,
        "test_path": str(test_path) if test_path.exists() else None,
    }
    manifest_path = run_dir / "artifacts" / f"exploit-result-{hyp_slug}.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    state.setdefault("artifacts", []).append(
        ArtifactRef(kind="exploit_loop_result", path=str(manifest_path), description=f"Execution-grounded exploit loop for {hypothesis.id}: {verdict}.")
    )
    if verdict == "confirmed":
        # An executed PoC broke the invariant: this is real proof.
        hypothesis.proof_status = "executed_poc_confirmed"
        state.setdefault("artifacts", []).append(
            ArtifactRef(kind="foundry_exploit_test", path=str(test_path), description=f"Executed PoC that breaks the invariant for {hypothesis.id}.")
        )
    return DynamicGenericOutput(status=ToolStatus.OK, message=f"Exploit loop verdict: {verdict} ({classification}).", data=manifest)


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
        ("repair_validation_artifacts", "Repair a non-compiling generated PoC by feeding the solc error and real target source back to the LLM.", ValidationCompileInput, repair_validation_artifacts),
        ("author_and_run_exploit", "Execution-grounded loop: author a runnable test asserting the invariant, run it, observe if it breaks, and refine.", PocInput, author_and_run_exploit),
        ("run_validation_artifacts", "Run generated validation tests in a non-mutating temporary worktree and classify the result.", ValidationCompileInput, run_validation_artifacts),
    ]
    for name, description, input_model, fn in specs:
        if name in {"compile_validation_artifacts", "run_validation_artifacts", "repair_validation_artifacts", "author_and_run_exploit"}:
            side_effects = [SideEffect.WRITE_FILES, SideEffect.EXECUTE_LOCAL]
        elif name in {"patch_poc_test", "generate_validation_artifacts", "run_semantic_validation"}:
            side_effects = [SideEffect.WRITE_FILES]
        elif name.startswith("run_"):
            side_effects = [SideEffect.EXECUTE_LOCAL]
        else:
            side_effects = [SideEffect.NONE]
        registry.register(RegisteredTool(namespace="dynamic", name=name, description=description, input_model=input_model, output_model=DynamicGenericOutput, fn=fn, side_effects=side_effects))
