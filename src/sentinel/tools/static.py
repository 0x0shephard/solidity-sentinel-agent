from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path

from pydantic import BaseModel, Field

from sentinel.evidence import classify_source_path
from sentinel.reliability.subprocess import run_command, sanitized_env
from sentinel.rag.checklist import checklist_by_id, write_generated_checklists
from sentinel.schemas.common import SideEffect, ToolStatus
from sentinel.schemas.research import SlitherFinding
from sentinel.schemas.static import FunctionRange, SourceEvidence, StaticDetection, StaticDetectionsOutput
from sentinel.solidity.ranges import build_function_ranges, containing_function
from sentinel.tools.base import RegisteredTool, StateEffect
from sentinel.tools.repo import RepoPathInput


class StaticFactsOutput(BaseModel):
    status: ToolStatus
    facts: list[dict] = Field(default_factory=list)


class RunSlitherOutput(BaseModel):
    status: ToolStatus
    command: list[str]
    raw_json_path: str | None = None
    return_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    message: str | None = None


class ParseSlitherInput(BaseModel):
    raw_json_path: str


class ParseSlitherOutput(BaseModel):
    status: ToolStatus
    findings: list[SlitherFinding] = Field(default_factory=list)
    finding_count: int = Field(ge=0)
    message: str | None = None


class FunctionRangesOutput(BaseModel):
    status: ToolStatus
    ranges: list[FunctionRange] = Field(default_factory=list)


class ChecklistBuildOutput(BaseModel):
    status: ToolStatus
    data: dict = Field(default_factory=dict)


def _normalize_slither_path(filename: str | None) -> str | None:
    if not filename:
        return None
    path = Path(filename)
    parts = path.parts
    for marker in ["src", "contracts", "test", "tests", "script", "scripts", "lib", "libs", "node_modules"]:
        if marker in parts:
            return str(Path(*parts[parts.index(marker) :]))
    if "src" in parts:
        return str(Path(*parts[parts.index("src") :]))
    if "contracts" in parts:
        return str(Path(*parts[parts.index("contracts") :]))
    return path.name


def _extract_slither_locations(elements: list[dict]) -> tuple[list[str], list[str]]:
    files: list[str] = []
    functions: list[str] = []
    for element in elements:
        source_mapping = element.get("source_mapping") or {}
        filename = _normalize_slither_path(source_mapping.get("filename_relative") or source_mapping.get("filename_absolute"))
        if filename and filename not in files:
            files.append(filename)

        element_type = str(element.get("type", "")).lower()
        name = element.get("name")
        if name and "function" in element_type and str(name) not in functions:
            functions.append(str(name).split("(")[0])

        parent = element.get("parent") or {}
        parent_type = str(parent.get("type", "")).lower()
        parent_name = parent.get("name")
        if parent_name and "function" in parent_type and str(parent_name) not in functions:
            functions.append(str(parent_name).split("(")[0])
    return files, functions


def _solidity_files(repo_path: str) -> list[Path]:
    files = []
    for path in Path(repo_path).rglob("*.sol"):
        if not path.is_file() or "out" in path.parts or "cache" in path.parts:
            continue
        relative_path = str(path.relative_to(Path(repo_path))).replace("\\", "/")
        source_type = classify_source_path(relative_path)
        if source_type in {"test", "script", "library", "dependency", "docs"}:
            continue
        files.append(path)
    return files


def _source_line(repo_path: str, relative_path: str, line_no: int) -> str:
    path = Path(repo_path) / relative_path
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if line_no < 1 or line_no > len(lines):
        return ""
    return lines[line_no - 1].strip()


def _evidence(repo_path: str, ranges: list[FunctionRange], file_path: str, line_no: int, reason: str) -> SourceEvidence:
    fn = containing_function(ranges, file_path, line_no)
    return SourceEvidence(
        file_path=file_path,
        line_start=line_no,
        line_end=line_no,
        contract_name=fn.contract_name if fn else None,
        function_name=fn.function_name if fn else None,
        source_text=_source_line(repo_path, file_path, line_no),
        reason=reason,
    )


def _affected_functions(evidence: list[SourceEvidence]) -> list[str]:
    seen: list[str] = []
    for item in evidence:
        if item.function_name and item.function_name not in seen:
            seen.append(item.function_name)
    return seen


def _detection(
    detector_id: str,
    vulnerability_class: str,
    title: str,
    confidence: float,
    evidence: list[SourceEvidence],
    root_cause_terms: list[str],
    recommendation_hint: str,
    checklist_refs: list[str],
) -> StaticDetection:
    return StaticDetection(
        detector_id=detector_id,
        vulnerability_class=vulnerability_class,
        title=title,
        confidence=confidence,
        evidence=evidence,
        affected_functions=_affected_functions(evidence),
        root_cause_terms=root_cause_terms,
        recommendation_hint=recommendation_hint,
        checklist_refs=checklist_refs,
    )


def _line_has_any(line: str, terms: tuple[str, ...]) -> bool:
    lower = line.lower()
    return any(term.lower() in lower for term in terms)


def _strip_inline_comment(line: str) -> str:
    return line.split("//", 1)[0].strip()


def _is_comment_or_empty(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith(("//", "/*", "*", "*/"))


def _iter_source_lines(repo_path: str):
    for path in _solidity_files(repo_path):
        rel = str(path.relative_to(repo_path))
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for line_no, line in enumerate(lines, start=1):
            yield rel, line_no, line


def _function_context_by_line(lines: list[str]) -> dict[int, str]:
    context: dict[int, str] = {}
    current_function: str | None = None
    brace_depth = 0
    declaration = re.compile(r"\bfunction\s+(\w+)|\bconstructor\s*\(")
    for line_no, line in enumerate(lines, start=1):
        if current_function is None:
            match = declaration.search(line)
            if match:
                current_function = match.group(1) or "constructor"
                brace_depth = line.count("{") - line.count("}")
                context[line_no] = current_function
                if brace_depth <= 0:
                    current_function = None
                continue
        if current_function is not None:
            context[line_no] = current_function
            brace_depth += line.count("{") - line.count("}")
            if brace_depth <= 0:
                current_function = None
    return context


def extract_contracts(inp: RepoPathInput, state) -> StaticFactsOutput:
    facts = []
    for path in _solidity_files(inp.repo_path):
        text = path.read_text(encoding="utf-8", errors="replace")
        facts.append({"file_path": str(path.relative_to(inp.repo_path)), "contracts": re.findall(r"\bcontract\s+(\w+)", text)})
    return StaticFactsOutput(status=ToolStatus.OK, facts=facts)


def extract_functions(inp: RepoPathInput, state) -> StaticFactsOutput:
    facts = []
    for path in _solidity_files(inp.repo_path):
        for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            match = re.search(r"\bfunction\s+(\w+)", line)
            if match:
                facts.append({"file_path": str(path.relative_to(inp.repo_path)), "line": line_no, "function": match.group(1)})
    return StaticFactsOutput(status=ToolStatus.OK, facts=facts)


def find_access_control_terms(inp: RepoPathInput, state) -> StaticFactsOutput:
    facts = []
    for path in _solidity_files(inp.repo_path):
        for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            if any(term in line for term in ["owner", "onlyOwner", "hasRole", "AccessControl"]):
                facts.append({"file_path": str(path.relative_to(inp.repo_path)), "line": line_no, "text": line.strip()})
    return StaticFactsOutput(status=ToolStatus.OK, facts=facts)


def extract_inheritance(inp: RepoPathInput, state) -> StaticFactsOutput:
    facts = []
    for path in _solidity_files(inp.repo_path):
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in re.finditer(r"\bcontract\s+(\w+)\s+is\s+([^{]+)", text):
            facts.append({"file_path": str(path.relative_to(inp.repo_path)), "contract": match.group(1), "inherits": [item.strip() for item in match.group(2).split(",")]})
    return StaticFactsOutput(status=ToolStatus.OK, facts=facts)


def extract_modifiers(inp: RepoPathInput, state) -> StaticFactsOutput:
    facts = []
    for path in _solidity_files(inp.repo_path):
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in re.finditer(r"\bmodifier\s+(\w+)", text):
            facts.append({"file_path": str(path.relative_to(inp.repo_path)), "modifier": match.group(1)})
    return StaticFactsOutput(status=ToolStatus.OK, facts=facts)


def extract_external_calls(inp: RepoPathInput, state) -> StaticFactsOutput:
    facts = []
    for path in _solidity_files(inp.repo_path):
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        function_context = _function_context_by_line(lines)
        for line_no, line in enumerate(lines, start=1):
            if any(term in line for term in [".call(", ".call{", ".delegatecall(", ".delegatecall{", ".transfer(", ".send("]):
                facts.append({"file_path": str(path.relative_to(inp.repo_path)), "line": line_no, "function": function_context.get(line_no), "text": line.strip()})
    return StaticFactsOutput(status=ToolStatus.OK, facts=facts)


def extract_delegatecalls(inp: RepoPathInput, state) -> StaticFactsOutput:
    facts = []
    for path in _solidity_files(inp.repo_path):
        for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            if ".delegatecall(" in line:
                facts.append({"file_path": str(path.relative_to(inp.repo_path)), "line": line_no, "text": line.strip()})
    return StaticFactsOutput(status=ToolStatus.OK, facts=facts)


def extract_token_transfers(inp: RepoPathInput, state) -> StaticFactsOutput:
    facts = []
    for path in _solidity_files(inp.repo_path):
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        function_context = _function_context_by_line(lines)
        for line_no, line in enumerate(lines, start=1):
            if ".transfer(" in line or ".transferFrom(" in line:
                facts.append({"file_path": str(path.relative_to(inp.repo_path)), "line": line_no, "function": function_context.get(line_no), "text": line.strip()})
    return StaticFactsOutput(status=ToolStatus.OK, facts=facts)


def extract_storage_writes(inp: RepoPathInput, state) -> StaticFactsOutput:
    facts = []
    assignment = re.compile(r"(?<![=!<>])=(?![=>])|\+=|-=")
    local_declaration = re.compile(r"^(u?int\d*|address|bool|string|bytes\d*|\w+\s+memory|\w+\s+calldata)\s+\w+\s*=")
    for path in _solidity_files(inp.repo_path):
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        function_context = _function_context_by_line(lines)
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if assignment.search(stripped) and function_context.get(line_no) and not stripped.startswith(("require", "assert", "if ", "for ")) and not local_declaration.search(stripped):
                facts.append({"file_path": str(path.relative_to(inp.repo_path)), "line": line_no, "function": function_context.get(line_no), "text": stripped})
    return StaticFactsOutput(status=ToolStatus.OK, facts=facts)


def find_oracle_patterns(inp: RepoPathInput, state) -> StaticFactsOutput:
    facts = []
    for path in _solidity_files(inp.repo_path):
        for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            if any(term in line.lower() for term in ["oracle", "latestanswer", "latestrounddata", "getprice", "price"]):
                facts.append({"file_path": str(path.relative_to(inp.repo_path)), "line": line_no, "text": line.strip()})
    return StaticFactsOutput(status=ToolStatus.OK, facts=facts)


def extract_token_types(inp: RepoPathInput, state) -> StaticFactsOutput:
    return StaticFactsOutput(status=ToolStatus.OK, facts=_token_type_facts(inp.repo_path))


def map_function_ranges(inp: RepoPathInput, state) -> FunctionRangesOutput:
    return FunctionRangesOutput(status=ToolStatus.OK, ranges=build_function_ranges(inp.repo_path))


def build_solodit_checklist(inp: RepoPathInput, state) -> ChecklistBuildOutput:
    path = write_generated_checklists()
    return ChecklistBuildOutput(status=ToolStatus.OK, data={"path": str(path)})


def detect_tx_origin_auth(inp: RepoPathInput, state) -> StaticDetectionsOutput:
    ranges = build_function_ranges(inp.repo_path)
    evidence = []
    for rel, line_no, line in _iter_source_lines(inp.repo_path):
        if "tx.origin" not in line:
            continue
        if not _line_has_any(line, ("require", "if", "owner", "keeper", "role", "auth", "delay")):
            continue
        evidence.append(_evidence(inp.repo_path, ranges, rel, line_no, "tx.origin participates in an authorization or bypass condition."))
    detections = []
    if evidence:
        detections.append(
            _detection(
                "static.detect_tx_origin_auth",
                "tx_origin_authorization",
                "tx.origin is used in authorization logic",
                0.86,
                evidence,
                ["tx.origin", "authorization bypass", "caller identity"],
                "Replace tx.origin checks with explicit msg.sender authorization and remove origin-based bypass branches.",
                ["solodit-access-tx-origin"],
            )
        )
    return StaticDetectionsOutput(status=ToolStatus.OK, detections=detections)


def detect_unguarded_initializer(inp: RepoPathInput, state) -> StaticDetectionsOutput:
    ranges = build_function_ranges(inp.repo_path)
    privileged_terms = ("owner", "keeper", "treasury", "admin", "asset", "oracle", "initialized")
    guard_terms = ("initializer", "onlyinitializing", "reinitializer", "require(!initialized", "require(initialized == false", "if (!initialized")
    detections = []
    for fn in ranges:
        if fn.function_name.lower() != "initialize":
            continue
        lines = (Path(inp.repo_path) / fn.file_path).read_text(encoding="utf-8", errors="replace").splitlines()
        body = "\n".join(lines[fn.start_line - 1 : fn.end_line])
        signature = fn.signature.lower()
        if "external" not in signature and "public" not in signature:
            continue
        if any(term in body.replace(" ", "").lower() or term in signature for term in guard_terms):
            continue
        write_lines = []
        for offset, line in enumerate(lines[fn.start_line - 1 : fn.end_line], start=fn.start_line):
            compact = line.replace(" ", "").lower()
            if "=" in line and any(f"{term}=" in compact or f"{term}_" in compact for term in privileged_terms):
                write_lines.append(_evidence(inp.repo_path, ranges, fn.file_path, offset, "Initializer writes privileged configuration without a one-time guard."))
        if write_lines:
            detections.append(
                _detection(
                    "static.detect_unguarded_initializer",
                    "unguarded_initializer",
                    "External initializer lacks a one-time guard",
                    0.84,
                    write_lines[:6],
                    ["initializer", "privileged state", "one-time guard"],
                    "Add an initializer/reinitializer modifier or require(!initialized) before privileged writes.",
                    ["solodit-initializer-unguarded"],
                )
            )
    return StaticDetectionsOutput(status=ToolStatus.OK, detections=detections)


def detect_oracle_staleness_logic(inp: RepoPathInput, state) -> StaticDetectionsOutput:
    ranges = build_function_ranges(inp.repo_path)
    detections = []
    evidence = []
    for rel, line_no, line in _iter_source_lines(inp.repo_path):
        lower = line.lower()
        if "require" in lower and "||" in line and any(term in lower for term in ["oracle", "price", "updatedat", "timestamp", "latest"]):
            evidence.append(_evidence(inp.repo_path, ranges, rel, line_no, "Oracle value/freshness validation is OR-combined, allowing one branch to pass without the other."))
    if evidence:
        detections.append(
            _detection(
                "static.detect_oracle_staleness_logic",
                "oracle_staleness_logic",
                "Oracle validation may accept stale or incomplete data",
                0.81,
                evidence,
                ["oracle", "stale price", "unsafe OR", "freshness"],
                "Require both positive/valid price data and fresh timestamps with AND-combined checks.",
                ["solodit-oracle-staleness", "solodit-unsafe-or-guard"],
            )
        )
    return StaticDetectionsOutput(status=ToolStatus.OK, detections=detections)


def detect_unchecked_erc20_returns(inp: RepoPathInput, state) -> StaticDetectionsOutput:
    ranges = build_function_ranges(inp.repo_path)
    token_types = _token_type_map(inp.repo_path)
    evidence = []
    for rel, line_no, line in _iter_source_lines(inp.repo_path):
        if _is_comment_or_empty(line):
            continue
        code = _strip_inline_comment(line)
        compact = code.replace(" ", "")
        lower = code.lower()
        if "safeTransfer".lower() in lower or "safeapprove" in lower:
            continue
        direct_call = any(term in compact for term in [".transfer(", ".transferFrom(", ".approve("])
        if direct_call and compact.startswith("to.transfer("):
            continue
        receiver = _call_receiver(code, ("transfer", "transferFrom", "approve"))
        receiver_kind = _receiver_token_kind(receiver, token_types)
        if direct_call and receiver_kind in {"erc721", "erc1155"}:
            continue
        low_level_token_call = "call(" in code and any(term in code for term in ["IERC20", "ERC20", "transfer.selector", "transferFrom.selector", "approve(", "approve.selector"])
        if direct_call and receiver_kind not in {"erc20", "unknown"}:
            continue
        ignores_return = (
            direct_call
            and not compact.startswith("require(")
            and "require(" not in compact
            and "=" not in compact.split(".transfer", 1)[0]
        )
        low_level_checks_only_status = low_level_token_call and "abi.decode" not in line and "returndata" not in lower
        if ignores_return or low_level_checks_only_status:
            evidence.append(_evidence(inp.repo_path, ranges, rel, line_no, "ERC20 operation return data is ignored or only low-level call status is checked."))
    detections = []
    if evidence:
        detections.append(
            _detection(
                "static.detect_unchecked_erc20_returns",
                "unchecked_erc20_return",
                "ERC20 return value may be unchecked",
                0.78,
                evidence[:10],
                ["unchecked ERC20 return", "low-level token call", "SafeERC20"],
                "Use SafeERC20 or decode and require the returned boolean when return data is present.",
                ["solodit-token-return"],
            )
        )
    return StaticDetectionsOutput(status=ToolStatus.OK, detections=detections)


def detect_weak_randomness(inp: RepoPathInput, state) -> StaticDetectionsOutput:
    ranges = build_function_ranges(inp.repo_path)
    evidence = []
    entropy_terms = ("block.timestamp", "block.prevrandao", "blockhash", "msg.sender", "tx.origin", "block.number")
    random_terms = ("keccak256", "random", "rand", "%")
    reward_terms = ("mint", "win", "reward", "prize", "egg", "lottery", "claim", "payout")
    for fn in ranges:
        lines = (Path(inp.repo_path) / fn.file_path).read_text(encoding="utf-8", errors="replace").splitlines()
        fn_lines = [(line_no, _strip_inline_comment(line)) for line_no, line in enumerate(lines[fn.start_line - 1 : fn.end_line], start=fn.start_line)]
        body = "\n".join(line for _, line in fn_lines).lower()
        if not any(term in body for term in entropy_terms):
            continue
        if not any(term in body for term in random_terms):
            continue
        if not any(term in body for term in reward_terms):
            continue
        for line_no, code in fn_lines:
            lower = code.lower()
            if any(term in lower for term in entropy_terms) or "keccak256" in lower or "%" in code:
                evidence.append(_evidence(inp.repo_path, ranges, fn.file_path, line_no, "Predictable on-chain values are used for reward/game randomness."))
    detections = []
    if evidence:
        detections.append(
            _detection(
                "static.detect_weak_randomness",
                "weak_randomness",
                "Game or reward randomness uses predictable chain/user inputs",
                0.84,
                evidence[:8],
                ["weak randomness", "predictable entropy", "miner/user influence", "modulo randomness"],
                "Use a commit-reveal scheme or verifiable randomness source for user-reward decisions.",
                ["solodit-weak-randomness"],
            )
        )
    return StaticDetectionsOutput(status=ToolStatus.OK, detections=detections)


def detect_dangerous_delegatecall(inp: RepoPathInput, state) -> StaticDetectionsOutput:
    ranges = build_function_ranges(inp.repo_path)
    evidence = []
    for rel, line_no, line in _iter_source_lines(inp.repo_path):
        if ".delegatecall(" not in line and ".delegatecall{" not in line:
            continue
        reason = "delegatecall executes target code in caller storage context."
        if any(term in line.lower() for term in ["target", "payload", "data", "calls[", "migration", "strategy"]):
            reason = "delegatecall target or payload appears externally supplied or insufficiently constrained."
        evidence.append(_evidence(inp.repo_path, ranges, rel, line_no, reason))
    detections = []
    if evidence:
        detections.append(
            _detection(
                "static.detect_dangerous_delegatecall",
                "dangerous_delegatecall",
                "Delegatecall target or payload may be dangerous",
                0.83,
                evidence,
                ["delegatecall", "storage corruption", "user-controlled target"],
                "Restrict delegatecall targets to trusted immutable implementations and validate payload scope.",
                ["solodit-delegatecall-control"],
            )
        )
    return StaticDetectionsOutput(status=ToolStatus.OK, detections=detections)


def detect_public_vault_accounting_spoof(inp: RepoPathInput, state) -> StaticDetectionsOutput:
    ranges = build_function_ranges(inp.repo_path)
    evidence = []
    for fn in ranges:
        signature = fn.signature.lower()
        if not ("public" in signature or "external" in signature):
            continue
        if any(term in signature for term in ["onlyowner", "onlyrole", "auth", "internal"]):
            continue
        lines = (Path(inp.repo_path) / fn.file_path).read_text(encoding="utf-8", errors="replace").splitlines()
        body_lines = list(enumerate(lines[fn.start_line - 1 : fn.end_line], start=fn.start_line))
        body = "\n".join(_strip_inline_comment(line) for _, line in body_lines).lower()
        if "ownerof(" not in body or "address(this)" not in body:
            continue
        if not any(term in body for term in ["depositor", "beneficiary", "recipient", "owner", "account"]):
            continue
        if not any(term in body for term in ["depositors[", "stored", "deposited", "ownerof"]):
            continue
        for line_no, line in body_lines:
            lower = _strip_inline_comment(line).lower()
            if "ownerof(" in lower or "depositor" in lower or "stored" in lower:
                evidence.append(_evidence(inp.repo_path, ranges, fn.file_path, line_no, "Public vault accounting records caller-supplied ownership/depositor metadata after asset custody check."))
    detections = []
    if evidence:
        detections.append(
            _detection(
                "static.detect_public_vault_accounting_spoof",
                "vault_accounting_spoof",
                "Public vault accounting may allow depositor attribution spoofing",
                0.76,
                evidence[:10],
                ["vault accounting", "depositor spoofing", "asset custody", "authorization"],
                "Bind deposits to msg.sender or require a trusted game/vault entrypoint for depositor attribution.",
                ["solodit-vault-accounting"],
            )
        )
    return StaticDetectionsOutput(status=ToolStatus.OK, detections=detections)


def _token_type_facts(repo_path: str) -> list[dict]:
    facts = []
    files = _solidity_files(repo_path)
    repo_contract_kinds: dict[str, str] = {}
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        for contract_match in re.finditer(r"\bcontract\s+(\w+)\s*(?:is\s+([^{]+))?", text):
            inherits = contract_match.group(2) or ""
            lower = f"{contract_match.group(1)} {inherits}".lower()
            if "erc721" in lower:
                repo_contract_kinds[contract_match.group(1)] = "erc721"
            elif "erc1155" in lower:
                repo_contract_kinds[contract_match.group(1)] = "erc1155"
            elif "erc20" in lower:
                repo_contract_kinds[contract_match.group(1)] = "erc20"

    for path in files:
        rel = str(path.relative_to(repo_path))
        text = path.read_text(encoding="utf-8", errors="replace")
        imports_erc721 = "ERC721" in text or "IERC721" in text
        imports_erc1155 = "ERC1155" in text or "IERC1155" in text
        imports_erc20 = "ERC20" in text or "IERC20" in text or "SafeERC20" in text
        for contract_match in re.finditer(r"\bcontract\s+(\w+)\s*(?:is\s+([^{]+))?", text):
            token_kind = repo_contract_kinds.get(contract_match.group(1))
            if token_kind:
                facts.append({"file_path": rel, "symbol": contract_match.group(1), "kind": token_kind, "source": "contract"})
        for match in re.finditer(r"\b([A-Za-z_]\w*)\s+(?:public|private|internal|external)?\s*(\w+)\s*;", text):
            type_name, var_name = match.group(1), match.group(2)
            lower_type = type_name.lower()
            kind = None
            if type_name in repo_contract_kinds:
                kind = repo_contract_kinds[type_name]
            elif "erc721" in lower_type or (imports_erc721 and "nft" in lower_type):
                kind = "erc721"
            elif "erc1155" in lower_type:
                kind = "erc1155"
            elif "erc20" in lower_type or lower_type in {"ierc20", "token"}:
                kind = "erc20"
            elif imports_erc20 and var_name.lower() in {"token", "asset", "underlying"}:
                kind = "erc20"
            if kind:
                facts.append({"file_path": rel, "symbol": var_name, "type": type_name, "kind": kind, "source": "state_variable"})
    return facts


def _token_type_map(repo_path: str) -> dict[str, str]:
    token_types: dict[str, str] = {}
    for fact in _token_type_facts(repo_path):
        symbol = str(fact.get("symbol") or "")
        kind = str(fact.get("kind") or "")
        if symbol and kind:
            token_types[symbol] = kind
    return token_types


def _call_receiver(line: str, method_names: tuple[str, ...]) -> str | None:
    for method in method_names:
        match = re.search(rf"\b([A-Za-z_]\w*)\s*\.\s*{re.escape(method)}\s*\(", line)
        if match:
            return match.group(1)
    cast_match = re.search(r"\b(I?ERC20)\s*\([^)]+\)\s*\.\s*(?:transfer|transferFrom|approve)\s*\(", line)
    if cast_match:
        return cast_match.group(1)
    return None


def _receiver_token_kind(receiver: str | None, token_types: dict[str, str]) -> str:
    if not receiver:
        return "unknown"
    lower = receiver.lower()
    if lower in {"ierc20", "erc20"}:
        return "erc20"
    if lower in {"ierc721", "erc721"}:
        return "erc721"
    if lower in {"ierc1155", "erc1155"}:
        return "erc1155"
    if receiver in token_types:
        return token_types[receiver]
    if "nft" in lower or "erc721" in lower:
        return "erc721"
    if "erc1155" in lower:
        return "erc1155"
    if "token" in lower or "erc20" in lower or "asset" in lower:
        return "erc20"
    return "unknown"


def detect_unsafe_or_guards(inp: RepoPathInput, state) -> StaticDetectionsOutput:
    ranges = build_function_ranges(inp.repo_path)
    evidence = []
    sensitive_terms = ("owner", "keeper", "role", "fee", "limit", "max", "min", "oracle", "updatedat", "timestamp", "paused", "trusted")
    for rel, line_no, line in _iter_source_lines(inp.repo_path):
        lower = line.lower()
        if "require" not in lower or "||" not in line:
            continue
        if not any(term in lower for term in sensitive_terms):
            continue
        evidence.append(_evidence(inp.repo_path, ranges, rel, line_no, "Security-sensitive require uses OR, so one weak branch may bypass other intended constraints."))
    detections = []
    if evidence:
        detections.append(
            _detection(
                "static.detect_unsafe_or_guards",
                "unsafe_or_guard",
                "Security guard uses unsafe OR logic",
                0.74,
                evidence,
                ["unsafe OR", "guard bypass", "constraint bypass"],
                "Split independent constraints into separate requires or use AND where all conditions must hold.",
                ["solodit-unsafe-or-guard"],
            )
        )
    return StaticDetectionsOutput(status=ToolStatus.OK, detections=detections)


def detect_external_call_before_accounting(inp: RepoPathInput, state) -> StaticDetectionsOutput:
    ranges = build_function_ranges(inp.repo_path)
    evidence = []
    external_terms = (".call(", ".call{", ".transfer(", ".send(", "beforeWithdraw", "onFlashLoan", ".withdraw(", ".deposit(")
    accounting_terms = ("_burn(", "_mint(", "balanceOf[", "totalSupply", "totalManagedDebt", ".debt", "rewardDebt", "allowance[", "lastDepositAt")
    for fn in ranges:
        lines = (Path(inp.repo_path) / fn.file_path).read_text(encoding="utf-8", errors="replace").splitlines()
        fn_lines = list(enumerate(lines[fn.start_line - 1 : fn.end_line], start=fn.start_line))
        call_line = next(((line_no, line) for line_no, line in fn_lines if any(term in line for term in external_terms)), None)
        if not call_line:
            continue
        later_accounting = next(((line_no, line) for line_no, line in fn_lines if line_no > call_line[0] and any(term in line for term in accounting_terms)), None)
        if not later_accounting:
            continue
        evidence.extend(
            [
                _evidence(inp.repo_path, ranges, fn.file_path, call_line[0], "External control flow occurs before related accounting is finalized."),
                _evidence(inp.repo_path, ranges, fn.file_path, later_accounting[0], "Accounting update occurs after the external call."),
            ]
        )
    detections = []
    if evidence:
        detections.append(
            _detection(
                "static.detect_external_call_before_accounting",
                "external_call_before_accounting",
                "External call occurs before accounting is finalized",
                0.79,
                evidence[:12],
                ["external call before state update", "reentrancy", "accounting order"],
                "Move accounting before external control flow or add a reentrancy guard plus invariant-preserving ordering.",
                ["solodit-external-before-accounting"],
            )
        )
    return StaticDetectionsOutput(status=ToolStatus.OK, detections=detections)


def detect_strategy_accounting_trust(inp: RepoPathInput, state) -> StaticDetectionsOutput:
    ranges = build_function_ranges(inp.repo_path)
    evidence = []
    for fn in ranges:
        lines = (Path(inp.repo_path) / fn.file_path).read_text(encoding="utf-8", errors="replace").splitlines()
        body = "\n".join(lines[fn.start_line - 1 : fn.end_line]).lower()
        if "strategy" not in body:
            continue
        if not any(term in body for term in ["estimatedtotalassets", ".withdraw(", ".call(", "trusted", "totalmanageddebt", ".debt"]):
            continue
        for offset, line in enumerate(lines[fn.start_line - 1 : fn.end_line], start=fn.start_line):
            lower = line.lower()
            if any(term in lower for term in ["estimatedtotalassets", ".withdraw(", ".call(", "trusted", "totalmanageddebt", ".debt"]):
                evidence.append(_evidence(inp.repo_path, ranges, fn.file_path, offset, "Strategy-controlled value or call result affects accounting/trust decisions."))
    detections = []
    if evidence:
        detections.append(
            _detection(
                "static.detect_strategy_accounting_trust",
                "strategy_accounting_trust",
                "Strategy accounting trusts external strategy state",
                0.72,
                evidence[:12],
                ["strategy trust", "debt accounting", "external report", "reconciliation"],
                "Reconcile strategy-reported values with token balance deltas and avoid trusted branches that mask failed calls.",
                ["solodit-strategy-accounting-trust"],
            )
        )
    return StaticDetectionsOutput(status=ToolStatus.OK, detections=detections)


def run_slither(inp: RepoPathInput, state) -> RunSlitherOutput:
    command = ["slither", inp.repo_path, "--json", ""]
    if shutil.which("slither") is None:
        return RunSlitherOutput(status=ToolStatus.UNAVAILABLE, command=command, message="slither is not installed")

    run_dir = Path(state.get("run_dir", "runs/tmp"))
    artifact_dir = run_dir / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    raw_json_path = artifact_dir / "slither.json"
    slither_home = artifact_dir / "slither-home"
    slither_home.mkdir(parents=True, exist_ok=True)

    command = ["slither", inp.repo_path, "--json", str(raw_json_path)]
    env = sanitized_env(home=slither_home)
    result = run_command(command, cwd=".", timeout=180, env=env)

    if not raw_json_path.exists():
        raw_json_path.write_text(json.dumps({"success": False, "results": {"detectors": []}}), encoding="utf-8")

    # Slither exits non-zero when it *finds* issues, so the exit code alone is not
    # a failure signal — a successful analysis with detectors returns non-zero.
    # Trust the JSON 'success' flag; only fall back to the exit code when no
    # successful JSON was produced. Surface stderr on a real failure (it was
    # previously reported as a blank error).
    analysis_succeeded = False
    try:
        analysis_succeeded = bool(json.loads(raw_json_path.read_text(encoding="utf-8")).get("success"))
    except (json.JSONDecodeError, OSError):
        analysis_succeeded = False
    ok = analysis_succeeded or result.return_code == 0
    failure_message = None
    if not ok:
        tail = (result.stderr or result.stdout or "").strip()[-600:]
        failure_message = (f"slither failed (return_code {result.return_code}). {tail}").strip() or None

    return RunSlitherOutput(
        status=ToolStatus.OK if ok else ToolStatus.ERROR,
        command=result.command,
        raw_json_path=str(raw_json_path),
        return_code=result.return_code,
        stdout=result.stdout[-8000:],
        stderr=result.stderr[-8000:],
        timed_out=result.timed_out,
        message=failure_message,
    )


def parse_slither(inp: ParseSlitherInput, state) -> ParseSlitherOutput:
    path = Path(inp.raw_json_path)
    if not path.exists():
        return ParseSlitherOutput(status=ToolStatus.ERROR, finding_count=0, message=f"Slither JSON not found: {inp.raw_json_path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return ParseSlitherOutput(status=ToolStatus.ERROR, finding_count=0, message=f"Invalid Slither JSON: {exc}")

    findings = []
    for detector in data.get("results", {}).get("detectors", []):
        source_files, functions = _extract_slither_locations(detector.get("elements", []))
        findings.append(
            SlitherFinding(
                check=detector.get("check", "unknown"),
                impact=detector.get("impact"),
                confidence=detector.get("confidence"),
                description=detector.get("description", ""),
                elements=detector.get("elements", []),
                source_files=source_files,
                functions=functions,
            )
        )
    return ParseSlitherOutput(status=ToolStatus.OK, findings=findings, finding_count=len(findings))


def register(registry) -> None:
    for tool in [
        RegisteredTool(namespace="static", name="extract_contracts", description="Extract Solidity contract declarations.", input_model=RepoPathInput, output_model=StaticFactsOutput, fn=extract_contracts, side_effects=[SideEffect.READ_FILES], state_effects=[StateEffect(output_path="facts", state_path="static_facts.contracts", merge="set")]),
        RegisteredTool(namespace="static", name="extract_inheritance", description="Extract Solidity inheritance declarations.", input_model=RepoPathInput, output_model=StaticFactsOutput, fn=extract_inheritance, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="extract_functions", description="Extract Solidity function declarations.", input_model=RepoPathInput, output_model=StaticFactsOutput, fn=extract_functions, side_effects=[SideEffect.READ_FILES], state_effects=[StateEffect(output_path="facts", state_path="static_facts.functions", merge="set")]),
        RegisteredTool(namespace="static", name="map_function_ranges", description="Map Solidity functions to source ranges.", input_model=RepoPathInput, output_model=FunctionRangesOutput, fn=map_function_ranges, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="extract_modifiers", description="Extract Solidity modifier declarations.", input_model=RepoPathInput, output_model=StaticFactsOutput, fn=extract_modifiers, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="find_access_control_terms", description="Find access-control related source terms.", input_model=RepoPathInput, output_model=StaticFactsOutput, fn=find_access_control_terms, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="extract_external_calls", description="Extract low-level/external call sites.", input_model=RepoPathInput, output_model=StaticFactsOutput, fn=extract_external_calls, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="extract_delegatecalls", description="Extract delegatecall sites.", input_model=RepoPathInput, output_model=StaticFactsOutput, fn=extract_delegatecalls, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="extract_token_transfers", description="Extract token transfer patterns.", input_model=RepoPathInput, output_model=StaticFactsOutput, fn=extract_token_transfers, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="extract_token_types", description="Infer ERC20/ERC721/ERC1155 receiver types from Solidity declarations.", input_model=RepoPathInput, output_model=StaticFactsOutput, fn=extract_token_types, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="extract_storage_writes", description="Extract likely storage write lines.", input_model=RepoPathInput, output_model=StaticFactsOutput, fn=extract_storage_writes, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="find_oracle_patterns", description="Find oracle and price-read patterns.", input_model=RepoPathInput, output_model=StaticFactsOutput, fn=find_oracle_patterns, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="build_solodit_checklist", description="Build Solodit-informed detector checklists from local RAG cache.", input_model=RepoPathInput, output_model=ChecklistBuildOutput, fn=build_solodit_checklist, side_effects=[SideEffect.WRITE_FILES]),
        RegisteredTool(namespace="static", name="detect_tx_origin_auth", description="Detect tx.origin authorization and bypass patterns.", input_model=RepoPathInput, output_model=StaticDetectionsOutput, fn=detect_tx_origin_auth, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="detect_unguarded_initializer", description="Detect public/external initializers without one-time guards.", input_model=RepoPathInput, output_model=StaticDetectionsOutput, fn=detect_unguarded_initializer, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="detect_oracle_staleness_logic", description="Detect stale or incomplete oracle validation logic.", input_model=RepoPathInput, output_model=StaticDetectionsOutput, fn=detect_oracle_staleness_logic, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="detect_unchecked_erc20_returns", description="Detect unchecked ERC20 transfer/approve return handling.", input_model=RepoPathInput, output_model=StaticDetectionsOutput, fn=detect_unchecked_erc20_returns, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="detect_weak_randomness", description="Detect predictable on-chain randomness in games/reward flows.", input_model=RepoPathInput, output_model=StaticDetectionsOutput, fn=detect_weak_randomness, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="detect_dangerous_delegatecall", description="Detect dangerous delegatecall target and payload patterns.", input_model=RepoPathInput, output_model=StaticDetectionsOutput, fn=detect_dangerous_delegatecall, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="detect_unsafe_or_guards", description="Detect security-sensitive OR-combined guards.", input_model=RepoPathInput, output_model=StaticDetectionsOutput, fn=detect_unsafe_or_guards, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="detect_external_call_before_accounting", description="Detect external calls before related accounting updates.", input_model=RepoPathInput, output_model=StaticDetectionsOutput, fn=detect_external_call_before_accounting, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="detect_strategy_accounting_trust", description="Detect strategy accounting that trusts external strategy state.", input_model=RepoPathInput, output_model=StaticDetectionsOutput, fn=detect_strategy_accounting_trust, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="detect_public_vault_accounting_spoof", description="Detect public vault accounting attribution that can be spoofed.", input_model=RepoPathInput, output_model=StaticDetectionsOutput, fn=detect_public_vault_accounting_spoof, side_effects=[SideEffect.READ_FILES]),
        RegisteredTool(namespace="static", name="run_slither", description="Run Slither and write JSON artifact.", input_model=RepoPathInput, output_model=RunSlitherOutput, fn=run_slither, side_effects=[SideEffect.EXECUTE_LOCAL], chaining_hints=["Use raw_json_path as static.parse_slither.raw_json_path."]),
        RegisteredTool(namespace="static", name="parse_slither", description="Parse Slither JSON artifact into typed findings.", input_model=ParseSlitherInput, output_model=ParseSlitherOutput, fn=parse_slither, side_effects=[SideEffect.READ_FILES]),
    ]:
        registry.register(tool)
