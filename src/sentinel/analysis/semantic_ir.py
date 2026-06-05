from __future__ import annotations

import re
from pathlib import Path

from sentinel.evidence import classify_source_path
from sentinel.schemas.protocol_ir import (
    AssetFlow,
    AssetCompatibilityPath,
    CheckpointLookupIR,
    DataFlowEdge,
    DocumentationClaim,
    FeeFormulaIR,
    LoopIR,
    ProtocolIR,
    SemanticCallEdge,
    StatementIR,
)
from sentinel.schemas.static import FunctionRange, SourceEvidence
from sentinel.solidity.ranges import containing_function


WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
CALL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_]*))?\s*\(")
ASSIGN = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]+\])?(?:\.[A-Za-z_][A-Za-z0-9_]*)?)\s*(=|\+=|-=|\*=|/=|\+\+|--)")
CHECKPOINT_METHODS = {"lowerLookup", "upperLookup", "upperLookupRecent", "latestCheckpoint", "latest", "push"}
SIGNATURE_TERMS = {"signature", "signatures", "signer", "signers", "threshold", "recover", "isValidSignature"}
FEE_TERMS = {"fee", "fees", "performanceFee", "managementFee", "depositFee", "redeemFee", "protocolFee"}
NATIVE_TRANSFER_TERMS = (".send(", ".transfer(", ".call{value:", ".call{ value:")


def enrich_semantic_ir(repo_path: str, ir: ProtocolIR, ranges: list[FunctionRange]) -> ProtocolIR:
    """Attach source-derived semantic facts to a ProtocolIR.

    This intentionally stays parser-light. It gives later invariant queries a
    reusable audit substrate without pretending to be a full Solidity AST.
    """
    contract_capabilities = _contract_capabilities(repo_path)
    state_names = {
        (contract.file_path, contract.name): {state.name for state in contract.state_variables}
        for contract in ir.contracts
    }
    for path in _production_solidity_files(repo_path):
        rel = _relative(repo_path, path)
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        pending_docs: list[tuple[int, str]] = []
        for line_no, raw in enumerate(lines, start=1):
            stripped = raw.strip()
            if stripped.startswith(("///", "/**", "*")):
                pending_docs.append((line_no, stripped.strip("/* ")))
                continue
            code = _strip_inline_comment(raw)
            if not code:
                continue
            fn = containing_function(ranges, rel, line_no)
            contract_name = fn.contract_name if fn else _contract_at_line(ir, rel, line_no)
            function_name = fn.function_name if fn else None
            if pending_docs and fn:
                for doc_line, claim in pending_docs[-3:]:
                    ir.documentation_claims.append(_documentation_claim(rel, doc_line, fn.contract_name, fn.function_name, claim))
                pending_docs = []
            ir.statements.append(_statement(rel, line_no, contract_name, function_name, code))
            ir.data_flows.extend(_data_flows(rel, line_no, contract_name, function_name, code))
            ir.semantic_calls.extend(_semantic_calls(rel, line_no, contract_name, function_name, code))
            ir.asset_flows.extend(_helper_asset_flows(rel, line_no, contract_name, function_name, code))
            ir.checkpoint_lookups.extend(_checkpoint_lookups(rel, line_no, contract_name, function_name, code))
            ir.fee_formulas.extend(_fee_formulas(rel, line_no, contract_name, function_name, code, state_names.get((rel, contract_name), set())))
            ir.asset_compatibility_paths.extend(_asset_paths(rel, line_no, contract_name, function_name, code, contract_capabilities))
        ir.loops.extend(_loops_for_file(rel, lines, ranges))
    if not ir.statements:
        ir.completeness_gaps.append("Semantic IR extraction found no statements; downstream invariant queries may be shallow.")
    return ir


def _production_solidity_files(repo_path: str) -> list[Path]:
    root = Path(repo_path)
    return [
        path
        for path in root.rglob("*.sol")
        if path.is_file() and "out" not in path.parts and "cache" not in path.parts and classify_source_path(_relative(repo_path, path)) == "production"
    ]


def _relative(repo_path: str, path: Path) -> str:
    return str(path.relative_to(Path(repo_path))).replace("\\", "/")


def _strip_inline_comment(line: str) -> str:
    return line.split("//", 1)[0].strip()


def _contract_at_line(ir: ProtocolIR, file_path: str, line_no: int) -> str | None:
    candidates = [
        contract.name
        for contract in ir.contracts
        if contract.file_path == file_path
        and any(function.start_line and function.end_line and function.start_line <= line_no <= function.end_line for function in contract.functions)
    ]
    return candidates[0] if candidates else next((contract.name for contract in ir.contracts if contract.file_path == file_path), None)


def _contract_capabilities(repo_path: str) -> dict[str, dict[str, bool]]:
    capabilities: dict[str, dict[str, bool]] = {}
    for path in _production_solidity_files(repo_path):
        rel = _relative(repo_path, path)
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        current = None
        for line in lines:
            code = _strip_inline_comment(line)
            match = re.search(r"\b(?:contract|library|interface)\s+(\w+)", code)
            if match:
                current = match.group(1)
                capabilities.setdefault(current, {"receive": False, "fallback": False, "file_path": rel})
            if current and re.search(r"\breceive\s*\(", code):
                capabilities[current]["receive"] = True
            if current and re.search(r"\bfallback\s*\(", code):
                capabilities[current]["fallback"] = True
    return capabilities


def _statement(file_path: str, line_no: int, contract: str | None, function: str | None, code: str) -> StatementIR:
    lower = code.lower()
    if re.search(r"\brequire\s*\(", code):
        kind = "require"
    elif re.search(r"\bif\s*\(", code):
        kind = "if"
    elif re.search(r"\bfor\s*\(", code):
        kind = "for"
    elif ASSIGN.search(code):
        kind = "assignment"
    elif CALL.search(code):
        kind = "call"
    elif lower.startswith("return"):
        kind = "return"
    elif lower.startswith("emit"):
        kind = "emit"
    else:
        kind = "other"
    return StatementIR(
        statement_id=f"stmt:{file_path}:{line_no}",
        contract_name=contract,
        function_name=function,
        file_path=file_path,
        line_start=line_no,
        line_end=line_no,
        statement_kind=kind,
        source_text=code,
        normalized_terms=_terms(code),
    )


def _data_flows(file_path: str, line_no: int, contract: str | None, function: str | None, code: str) -> list[DataFlowEdge]:
    flows: list[DataFlowEdge] = []
    for match in ASSIGN.finditer(code):
        left = re.sub(r"\s+", "", match.group(1))
        right = code[match.end() :].strip().rstrip(";")
        flows.append(
            DataFlowEdge(
                from_expr=right or match.group(2),
                to_expr=left,
                contract_name=contract,
                function_name=function,
                file_path=file_path,
                line=line_no,
                expression=code,
                flow_kind="assignment",
            )
        )
    storage_alias = re.search(r"\b[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]+\])?\s+storage\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+)", code)
    if storage_alias:
        flows.append(
            DataFlowEdge(
                from_expr=storage_alias.group(2).strip(),
                to_expr=storage_alias.group(1),
                contract_name=contract,
                function_name=function,
                file_path=file_path,
                line=line_no,
                expression=code,
                flow_kind="storage_alias",
            )
        )
    return flows


def _semantic_calls(file_path: str, line_no: int, contract: str | None, function: str | None, code: str) -> list[SemanticCallEdge]:
    calls: list[SemanticCallEdge] = []
    for match in CALL.finditer(code):
        receiver, method = match.group(1), match.group(2)
        callee = method or receiver
        if callee in {"if", "for", "while", "require", "assert", "return", "revert", "emit"}:
            continue
        lower = callee.lower()
        expression = code
        if callee in CHECKPOINT_METHODS:
            kind = "checkpoint"
        elif any(term.lower() in lower or term.lower() in code.lower() for term in SIGNATURE_TERMS):
            kind = "signature"
        elif callee in {"transfer", "transferFrom", "safeTransfer", "safeTransferFrom", "mint", "burn", "sendAssets", "receiveAssets"}:
            kind = "token"
        elif any(term in code for term in NATIVE_TRANSFER_TERMS):
            kind = "native_transfer"
        elif receiver and receiver[:1].isupper():
            kind = "library"
        elif receiver:
            kind = "external"
        else:
            kind = "internal"
        calls.append(
            SemanticCallEdge(
                contract_name=contract,
                function_name=function,
                callee=callee,
                receiver_symbol=receiver if method else None,
                file_path=file_path,
                line=line_no,
                expression=expression,
                call_kind=kind,
                value_flow=_call_args(code, callee),
            )
        )
    return calls


def _checkpoint_lookups(file_path: str, line_no: int, contract: str | None, function: str | None, code: str) -> list[CheckpointLookupIR]:
    lookups: list[CheckpointLookupIR] = []
    for method in CHECKPOINT_METHODS:
        if f".{method}(" not in code:
            continue
        direction = "lower" if method.startswith("lower") else "upper" if method.startswith("upper") else "latest" if "latest" in method else "unknown"
        index_adjustment = "decrement" if "--" in code else "increment" if "++" in code else "none"
        lookups.append(
            CheckpointLookupIR(
                lookup_id=f"checkpoint:{file_path}:{line_no}:{method}",
                contract_name=contract,
                function_name=function,
                file_path=file_path,
                line=line_no,
                expression=code,
                lookup_kind=method,
                boundary_direction=direction,
                timestamp_expr=_first_call_arg(code, method),
                index_adjustment=index_adjustment,
                evidence=[_evidence(file_path, line_no, contract, function, code, "checkpoint lookup or boundary adjustment")],
            )
        )
    if re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\s*(?:--|\+\+)", code) and any(term in code.lower() for term in ["index", "iterator", "batch"]):
        lookups.append(
            CheckpointLookupIR(
                lookup_id=f"checkpoint-adjust:{file_path}:{line_no}",
                contract_name=contract,
                function_name=function,
                file_path=file_path,
                line=line_no,
                expression=code,
                lookup_kind="index_adjustment",
                index_adjustment="decrement" if "--" in code else "increment",
                evidence=[_evidence(file_path, line_no, contract, function, code, "checkpoint/index boundary adjustment")],
            )
        )
    return lookups


def _fee_formulas(file_path: str, line_no: int, contract: str | None, function: str | None, code: str, state_vars: set[str]) -> list[FeeFormulaIR]:
    lower = code.lower()
    if not any(term.lower() in lower for term in FEE_TERMS) or not any(op in code for op in ("*", "/", "mulDiv")):
        return []
    denominator = None
    if "mulDiv" in code:
        args = _split_args(_first_call_arg_span(code, "mulDiv"))
        denominator = args[-1] if len(args) >= 3 else None
        numerator_terms = args[:2]
    else:
        denom_match = re.search(r"/\s*([A-Za-z0-9_]+)", code)
        denominator = denom_match.group(1) if denom_match else None
        numerator_terms = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", code)
    unit_terms = [term for term in re.findall(r"[A-Za-z_][A-Za-z0-9_]*(?:D6|D18|Shares|Assets|Price)?", code) if re.search(r"(D6|D18|Shares|Assets|Price|shares|assets|price)", term)]
    return [
        FeeFormulaIR(
            formula_id=f"fee:{file_path}:{line_no}",
            contract_name=contract,
            function_name=function,
            file_path=file_path,
            line=line_no,
            expression=code,
            numerator_terms=list(dict.fromkeys(numerator_terms))[:12],
            denominator=denominator,
            unit_terms=list(dict.fromkeys(unit_terms))[:12],
            state_dependencies=sorted(state_vars.intersection(set(_terms(code)))),
            evidence=[_evidence(file_path, line_no, contract, function, code, "fee or accounting formula")],
        )
    ]


def _asset_paths(
    file_path: str,
    line_no: int,
    contract: str | None,
    function: str | None,
    code: str,
    capabilities: dict[str, dict[str, bool]],
) -> list[AssetCompatibilityPath]:
    lower = code.lower()
    compact = lower.replace(" ", "")
    helper_native = any(term in compact for term in ["sendassets(", "receiveassets("]) and "native" in lower
    native_call = any(term in compact for term in [".call{value:", ".send(", ".transfer("])
    native = (helper_native or native_call) and not any(token in lower for token in ["safetransfer", "transferfrom"])
    if not native:
        return []
    receiver = _native_receiver(code)
    receiver_contract = receiver if receiver in capabilities else None
    caps = capabilities.get(receiver_contract or "", {})
    return [
        AssetCompatibilityPath(
            path_id=f"asset-path:{file_path}:{line_no}",
            contract_name=contract,
            function_name=function,
            file_path=file_path,
            line=line_no,
            asset_kind="native",
            transfer_expression=code,
            receiver_contract=receiver_contract,
            receiver_has_receive=caps.get("receive") if caps else None,
            receiver_has_fallback=caps.get("fallback") if caps else None,
            evidence=[_evidence(file_path, line_no, contract, function, code, "native asset transfer path")],
        )
    ]


def _helper_asset_flows(file_path: str, line_no: int, contract: str | None, function: str | None, code: str) -> list[AssetFlow]:
    lower = code.lower()
    flows: list[AssetFlow] = []
    if not any(term in lower for term in ["sendassets", "receiveassets", "safetransfer", "transferfrom", ".transfer("]):
        return flows
    args = _split_args(_first_call_arg_span(code, "sendAssets") or _first_call_arg_span(code, "receiveAssets") or _first_call_arg_span(code, "safeTransferFrom") or _first_call_arg_span(code, "safeTransfer") or _first_call_arg_span(code, "transferFrom") or _first_call_arg_span(code, "transfer"))
    asset_kind = "native" if "native" in lower or "msg.value" in lower else "erc721" if "erc721" in lower or "nft" in lower else "erc20"
    from_expr = args[0] if len(args) >= 3 else None
    to_expr = args[1] if len(args) >= 3 else args[0] if args else None
    amount_expr = args[2] if len(args) >= 3 else args[1] if len(args) >= 2 else None
    flows.append(
        AssetFlow(
            contract_name=contract,
            function_name=function,
            asset_kind=asset_kind,
            from_expr=from_expr,
            to_expr=to_expr,
            amount_expr=amount_expr,
            file_path=file_path,
            line=line_no,
            expression=code,
        )
    )
    return flows


def _loops_for_file(file_path: str, lines: list[str], ranges: list[FunctionRange]) -> list[LoopIR]:
    loops: list[LoopIR] = []
    line_no = 1
    while line_no <= len(lines):
        code = _strip_inline_comment(lines[line_no - 1])
        if not re.search(r"\bfor\s*\(", code):
            line_no += 1
            continue
        start = line_no
        depth = code.count("{") - code.count("}")
        end = start
        body = [code]
        while depth > 0 and end < len(lines):
            end += 1
            next_code = _strip_inline_comment(lines[end - 1])
            body.append(next_code)
            depth += next_code.count("{") - next_code.count("}")
        fn = containing_function(ranges, file_path, start)
        header = code
        iterator = re.search(r"\b(?:uint256|uint|int256|int)\s+([A-Za-z_][A-Za-z0-9_]*)", header)
        collection = re.search(r"<\s*([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?)\.length", header)
        text = " ".join(body)
        loops.append(
            LoopIR(
                loop_id=f"loop:{file_path}:{start}",
                contract_name=fn.contract_name if fn else None,
                function_name=fn.function_name if fn else None,
                file_path=file_path,
                start_line=start,
                end_line=end,
                iterator=iterator.group(1) if iterator else None,
                collection=collection.group(1) if collection else None,
                body_terms=_terms(text)[:40],
                evidence=[_evidence(file_path, start, fn.contract_name if fn else None, fn.function_name if fn else None, code, "loop over collection")],
            )
        )
        line_no = max(line_no + 1, end + 1)
    return loops


def _documentation_claim(file_path: str, line_no: int, contract: str | None, function: str | None, claim: str) -> DocumentationClaim:
    return DocumentationClaim(
        claim_id=f"doc:{file_path}:{line_no}",
        contract_name=contract,
        function_name=function,
        file_path=file_path,
        line=line_no,
        claim_text=claim,
        claim_terms=_terms(claim),
        evidence=[_evidence(file_path, line_no, contract, function, claim, "documentation/interface policy claim")],
    )


def _terms(text: str) -> list[str]:
    stop = {"uint256", "uint224", "uint32", "address", "memory", "storage", "calldata", "return", "returns", "public", "external", "internal"}
    return [term for term in WORD.findall(text) if term not in stop]


def _call_args(code: str, callee: str) -> str | None:
    args = _first_call_arg_span(code, callee)
    return args or None


def _first_call_arg(code: str, callee: str) -> str | None:
    args = _split_args(_first_call_arg_span(code, callee))
    return args[0] if args else None


def _first_call_arg_span(code: str, callee: str) -> str:
    needle = f"{callee}("
    start = code.find(needle)
    if start < 0:
        return ""
    pos = start + len(needle)
    depth = 1
    chars = []
    while pos < len(code) and depth:
        char = code[pos]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                break
        chars.append(char)
        pos += 1
    return "".join(chars)


def _split_args(args: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for char in args:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        if char == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if current:
        parts.append("".join(current).strip())
    return [part for part in parts if part]


def _native_receiver(code: str) -> str | None:
    match = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(?:call|send|transfer)\b", code)
    if match:
        return match.group(1)
    cast_match = re.search(r"payable\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", code)
    return cast_match.group(1) if cast_match else None


def _evidence(file_path: str, line: int, contract: str | None, function: str | None, text: str, reason: str) -> SourceEvidence:
    return SourceEvidence(
        file_path=file_path,
        line_start=max(1, line),
        line_end=max(1, line),
        contract_name=contract,
        function_name=function,
        source_text=text.strip(),
        reason=reason,
    )
