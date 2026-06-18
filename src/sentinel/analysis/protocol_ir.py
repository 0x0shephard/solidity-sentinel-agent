from __future__ import annotations

import re
from pathlib import Path

from sentinel.analysis.contest import build_transaction_race_graph
from sentinel.analysis.semantic_ir import enrich_semantic_ir
from sentinel.evidence import classify_source_path
from sentinel.schemas.protocol_ir import (
    AttackPathCandidate,
    AssetFlow,
    AuthConstraint,
    CallEdge,
    ContractIR,
    FunctionIR,
    GraphSlice,
    IRCompletenessReport,
    LifecycleTransition,
    ModifierIR,
    ProtocolGraph,
    ProtocolIR,
    StateVariableIR,
    StorageAccess,
    TrustBoundary,
)
from sentinel.schemas.static import FunctionRange, SourceEvidence
from sentinel.solidity.ranges import containing_function


ASSIGNMENT = re.compile(r"\b([A-Za-z_]\w*)\s*(?:\[[^\]]+\])?\s*(?:=|\+=|-=|\*=|/=|\+\+|--)")
STATE_DECL = re.compile(r"^\s*(?:mapping\s*\([^;]+\)|[A-Za-z_]\w*(?:\[\])?)\s+(?:(public|private|internal|external)\s+)?([A-Za-z_]\w*)\s*(?:=|;)")
CALL_EXPR = re.compile(r"\b([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\(")
INTERNAL_CALL = re.compile(r"(?<![.\w])([A-Za-z_]\w*)\s*\(")
STORAGE_ALIAS = re.compile(r"\b[A-Za-z_]\w*(?:\s*\[[^\]]+\])?\s+storage\s+([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*(?:\[|;|$)")
MEMBER_ASSIGNMENT = re.compile(r"\b([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*(?:=|\+=|-=|\*=|/=|\+\+|--)")
AUTH_TERMS = ("onlyOwner", "onlyRole", "hasRole", "owner", "admin", "msg.sender", "tx.origin", "_checkOwner")
LIFECYCLE_TERMS = ("initialize", "start", "end", "pause", "unpause", "deposit", "withdraw", "claim", "mint", "burn", "upgrade")


def build_protocol_ir(repo_path: str, static_facts: dict) -> ProtocolIR:
    ranges = [FunctionRange.model_validate(item) for item in static_facts.get("function_ranges", [])]
    contracts_by_name: dict[str, ContractIR] = {}
    contract_ranges_by_file = {rel: _contract_ranges(path, repo_path) for path in _production_solidity_files(repo_path) for rel in [_relative(repo_path, path)]}
    state_vars_by_scope: dict[tuple[str, str | None], set[str]] = {}
    state_var_types_by_scope: dict[tuple[str, str | None], dict[str, str]] = {}
    token_kinds = {
        str(item.get("symbol")): str(item.get("kind"))
        for item in static_facts.get("token_types", [])
        if item.get("symbol") and item.get("kind")
    }
    storage_aliases_by_function: dict[tuple[str, str | None, str], dict[str, str]] = {}

    for path in _production_solidity_files(repo_path):
        rel = _relative(repo_path, path)
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        current_contract = None
        for line_no, line in enumerate(lines, start=1):
            code = _strip_comment(line)
            current_contract = _contract_at_line(contract_ranges_by_file.get(rel, []), line_no) or current_contract
            contract_match = re.search(r"\b(?:contract|library|interface)\s+(\w+)\s*(?:is\s+([^{]+))?", code)
            if contract_match:
                current_contract = contract_match.group(1)
                inherits = [item.strip().split()[0] for item in (contract_match.group(2) or "").split(",") if item.strip()]
                contracts_by_name.setdefault(current_contract, ContractIR(name=current_contract, file_path=rel, inherits=inherits))
            if containing_function(ranges, rel, line_no):
                continue
            modifier_match = re.search(r"\bmodifier\s+(\w+)", code)
            if modifier_match:
                contract = _contract_for_line(contracts_by_name, rel, current_contract)
                contract.modifiers.append(ModifierIR(name=modifier_match.group(1), contract_name=contract.name, file_path=rel, line=line_no))
            state_var = _state_variable(code)
            if current_contract and state_var:
                type_name, visibility, name = state_var
                scope = (rel, current_contract)
                state_vars_by_scope.setdefault(scope, set()).add(name)
                state_var_types_by_scope.setdefault(scope, {})[name] = type_name
                contract = _contract_for_line(contracts_by_name, rel, current_contract)
                contract.state_variables.append(
                    StateVariableIR(name=name, type_name=type_name, visibility=visibility, contract_name=contract.name, file_path=rel, line=line_no)
                )

        for fn in [item for item in ranges if item.file_path == rel]:
            contract = _contract_for_line(contracts_by_name, rel, fn.contract_name)
            scope = (rel, fn.contract_name)
            fn_lines = lines[fn.start_line - 1 : fn.end_line]
            body = "\n".join(_strip_comment(line) for line in fn_lines)
            storage_aliases = _storage_aliases_for_body(body, state_vars_by_scope.get(scope, set()))
            storage_aliases_by_function[(rel, fn.contract_name, fn.function_name)] = storage_aliases
            function_ir = FunctionIR(
                name=fn.function_name,
                contract_name=contract.name,
                file_path=rel,
                start_line=fn.start_line,
                end_line=fn.end_line,
                signature=fn.signature,
                visibility=_visibility(fn.signature),
                modifiers=_modifiers(fn.signature),
                reads=_reads_for_body(body, state_vars_by_scope.get(scope, set()), storage_aliases),
                writes=_writes_for_body(body, state_vars_by_scope.get(scope, set()), storage_aliases),
                calls=_calls_for_body(body),
                parameters=_parameters(fn.signature),
                payable="payable" in fn.signature,
            )
            contract.functions.append(function_ir)

    ir = ProtocolIR(repo_path=repo_path, contracts=list(contracts_by_name.values()))
    for path in _production_solidity_files(repo_path):
        rel = _relative(repo_path, path)
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for line_no, line in enumerate(lines, start=1):
            code = _strip_comment(line)
            if not code:
                continue
            fn = containing_function(ranges, rel, line_no)
            contract_name = fn.contract_name if fn else _contract_at_line(contract_ranges_by_file.get(rel, []), line_no) or _contract_name_for_file(contracts_by_name, rel)
            function_name = fn.function_name if fn else None
            scope = (rel, contract_name)
            storage_aliases = storage_aliases_by_function.get((rel, contract_name, function_name or ""), {})
            ir.storage_accesses.extend(_storage_accesses(contract_name, function_name, rel, line_no, code, state_vars_by_scope.get(scope, set()), storage_aliases))
            ir.call_edges.extend(_call_edges(contract_name, function_name, rel, line_no, code, state_var_types_by_scope.get(scope, {})))
            ir.asset_flows.extend(_asset_flows(contract_name, function_name, rel, line_no, code, token_kinds))
            ir.auth_constraints.extend(_auth_constraints(contract_name, function_name, rel, line_no, code))
            ir.lifecycle_transitions.extend(_lifecycle_transitions(contract_name, function_name, rel, line_no, code, state_vars_by_scope.get(scope, set())))
            ir.trust_boundaries.extend(_trust_boundaries(contract_name, function_name, rel, line_no, code))

    if not static_facts.get("slither_findings"):
        ir.completeness_gaps.append("Slither/AST-enriched call/dataflow was unavailable; Protocol IR was built from source/range/static facts.")
    if not ir.contracts:
        ir.completeness_gaps.append("No production contract declarations were extracted.")
    ir = enrich_semantic_ir(repo_path, ir, ranges)
    ir.transaction_race_graph = build_transaction_race_graph(repo_path, ir)
    return ir


def _bounded_reachable(start: tuple, successors: dict[tuple, set[tuple]], max_depth: int) -> set[tuple]:
    """Functions reachable from ``start`` within ``max_depth`` call hops (BFS).

    Args:
        start: The entry ``(contract, function)`` key.
        successors: Adjacency map of callee keys per caller key.
        max_depth: Maximum number of call hops to follow (bounds cost and cycles).
    Returns:
        The set of reachable ``(contract, function)`` keys, including ``start``.
    """
    seen = {start}
    frontier = [start]
    for _ in range(max_depth):
        nxt: list[tuple] = []
        for node in frontier:
            for target in successors.get(node, set()):
                if target not in seen:
                    seen.add(target)
                    nxt.append(target)
        if not nxt:
            break
        frontier = nxt
    return seen


def build_protocol_graph(ir: ProtocolIR, max_depth: int = 5) -> ProtocolGraph:
    slices: list[GraphSlice] = []
    function_index = {
        (function.contract_name, function.name): function
        for contract in ir.contracts
        for function in contract.functions
    }
    # Build the call adjacency: cross-contract/member edges from the IR PLUS
    # internal same-contract calls (which the member-call regex misses), so
    # reachability follows internal/transitive paths, not just one direct hop.
    successors: dict[tuple, set[tuple]] = {}
    internal_edges: list[CallEdge] = []
    for edge in ir.call_edges:
        target_key = (edge.to_contract, edge.to_function)
        if target_key in function_index:
            successors.setdefault((edge.from_contract, edge.from_function), set()).add(target_key)
    for contract in ir.contracts:
        for function in contract.functions:
            src_key = (contract.name, function.name)
            for callee in function.calls:
                target_key = (contract.name, callee)
                if target_key == src_key or target_key not in function_index:
                    continue
                successors.setdefault(src_key, set()).add(target_key)
                internal_edges.append(
                    CallEdge(
                        from_contract=contract.name,
                        from_function=function.name,
                        to_contract=contract.name,
                        to_function=callee,
                        receiver_symbol=None,
                        file_path=function.file_path,
                        line=function.start_line,
                        expression=f"{function.name} -> {callee}()",
                        call_kind="internal",
                    )
                )
    ir.call_edges.extend(internal_edges)
    edges_by_src: dict[tuple, list[CallEdge]] = {}
    for edge in ir.call_edges:
        edges_by_src.setdefault((edge.from_contract, edge.from_function), []).append(edge)

    for contract in ir.contracts:
        for function in contract.functions:
            if function.visibility not in {"public", "external"}:
                continue
            local_key = (contract.name, function.name)
            # Bounded transitive reachability over internal + member call edges.
            reachable_keys = _bounded_reachable(local_key, successors, max_depth)
            # Edges from ANY reachable function (e.g. an external call buried in a
            # transitively-called internal helper), not just the entry function.
            local_edges = [edge for key in reachable_keys for edge in edges_by_src.get(key, [])]
            storage = [item for item in ir.storage_accesses if (item.contract_name, item.function_name) in reachable_keys]
            flows = [item for item in ir.asset_flows if (item.contract_name, item.function_name) in reachable_keys]
            auth = [item for item in ir.auth_constraints if (item.contract_name, item.function_name) in reachable_keys]
            lifecycle = [item for item in ir.lifecycle_transitions if (item.contract_name, item.function_name) in reachable_keys]
            boundaries = [item for item in ir.trust_boundaries if (item.contract_name, item.function_name) in reachable_keys]
            evidence = _slice_evidence(function, local_edges, storage, flows, auth, boundaries)
            proof_status, missing_proof, counterevidence = _slice_proof_status(function, storage, flows, auth, lifecycle, boundaries)
            slice_id = f"slice-{len(slices) + 1}"
            slices.append(
                GraphSlice(
                    slice_id=slice_id,
                    entry_contract=contract.name,
                    entry_function=function.name,
                    entry_file=function.file_path,
                    entry_line=function.start_line,
                    reachable_functions=[f"{item[0]}.{item[1]}" for item in sorted(reachable_keys) if item[0] and item[1]],
                    call_edges=local_edges,
                    storage_accesses=storage,
                    asset_flows=flows,
                    auth_constraints=auth,
                    lifecycle_transitions=lifecycle,
                    trust_boundaries=boundaries,
                    evidence=evidence,
                    proof_status=proof_status,
                    missing_proof=missing_proof,
                    counterevidence=counterevidence,
                )
            )
    attack_paths = _attack_paths_from_slices(slices)
    completeness = IRCompletenessReport(
        source_mode="regex_fallback",
        missing_capabilities=[
            "No full SSA/dataflow proof; graph slices are source-derived approximations.",
            *ir.completeness_gaps,
        ],
    )
    return ProtocolGraph(repo_path=ir.repo_path, slices=slices, attack_paths=attack_paths, completeness=completeness)


def protocol_ir_summary(ir: ProtocolIR) -> dict:
    return {
        "contracts": ir.contract_names(),
        "functions": ir.function_names()[:40],
        "call_edges": len(ir.call_edges),
        "storage_accesses": len(ir.storage_accesses),
        "asset_flows": len(ir.asset_flows),
        "auth_constraints": len(ir.auth_constraints),
        "lifecycle_transitions": len(ir.lifecycle_transitions),
        "trust_boundaries": len(ir.trust_boundaries),
        "statements": len(ir.statements),
        "data_flows": len(ir.data_flows),
        "semantic_calls": len(ir.semantic_calls),
        "loops": len(ir.loops),
        "checkpoint_lookups": len(ir.checkpoint_lookups),
        "fee_formulas": len(ir.fee_formulas),
        "asset_compatibility_paths": len(ir.asset_compatibility_paths),
        "documentation_claims": len(ir.documentation_claims),
        "transaction_actions": len(ir.transaction_race_graph.actions),
        "transaction_race_edges": len(ir.transaction_race_graph.race_edges),
        "completeness_gaps": ir.completeness_gaps,
    }


def _production_solidity_files(repo_path: str) -> list[Path]:
    root = Path(repo_path)
    return [
        path
        for path in root.rglob("*.sol")
        if path.is_file() and "out" not in path.parts and "cache" not in path.parts and classify_source_path(_relative(repo_path, path)) == "production"
    ]


def _relative(repo_path: str, path: Path) -> str:
    return str(path.relative_to(Path(repo_path))).replace("\\", "/")


def _strip_comment(line: str) -> str:
    stripped = line.split("//", 1)[0].strip()
    if stripped.startswith(("/*", "*", "*/")):
        return ""
    return stripped


def _contract_for_line(contracts: dict[str, ContractIR], file_path: str, name: str | None) -> ContractIR:
    contract_name = name or Path(file_path).stem
    return contracts.setdefault(contract_name, ContractIR(name=contract_name, file_path=file_path))


def _contract_ranges(path: Path, repo_path: str) -> list[tuple[str, int, int]]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    ranges: list[tuple[str, int, int]] = []
    active: tuple[str, int, int] | None = None
    pending_name = None
    pending_start = 0
    depth = 0
    for line_no, raw in enumerate(lines, start=1):
        code = _strip_comment(raw)
        match = re.search(r"\b(?:contract|library|interface)\s+(\w+)", code)
        if match and active is None:
            pending_name = match.group(1)
            pending_start = line_no
        if pending_name and "{" in code and active is None:
            active = (pending_name, pending_start, line_no)
            depth = code.count("{") - code.count("}")
            pending_name = None
            if depth <= 0:
                name, start, _ = active
                ranges.append((name, start, line_no))
                active = None
            continue
        if active is not None:
            depth += code.count("{") - code.count("}")
            if depth <= 0:
                name, start, _ = active
                ranges.append((name, start, line_no))
                active = None
                depth = 0
    return ranges


def _contract_at_line(ranges: list[tuple[str, int, int]], line_no: int) -> str | None:
    for name, start, end in ranges:
        if start <= line_no <= end:
            return name
    return None


def _contract_name_for_file(contracts: dict[str, ContractIR], file_path: str) -> str | None:
    for contract in contracts.values():
        if contract.file_path == file_path:
            return contract.name
    return None


def _state_variable(line: str) -> tuple[str, str | None, str] | None:
    if not line.startswith("mapping") and (
        "(" in line or line.startswith(("function ", "constructor", "if ", "for ", "while ", "return ", "require"))
    ):
        return None
    match = STATE_DECL.search(line)
    if not match:
        return None
    type_name = line.split()[0]
    visibility = match.group(1)
    name = match.group(2)
    return type_name, visibility, name


def _visibility(signature: str) -> str | None:
    for value in ("external", "public", "internal", "private"):
        if re.search(rf"\b{value}\b", signature):
            return value
    return None


def _modifiers(signature: str) -> list[str]:
    known = {"function", "constructor", "external", "public", "internal", "private", "view", "pure", "payable", "returns", "virtual", "override"}
    tail = signature.split(")")[-1] if ")" in signature else signature
    return [word for word in re.findall(r"\b[A-Za-z_]\w*\b", tail) if word not in known]


def _parameters(signature: str) -> list[str]:
    match = re.search(r"\((.*?)\)", signature)
    if not match:
        return []
    params = []
    for raw in match.group(1).split(","):
        parts = raw.strip().split()
        if parts:
            params.append(parts[-1])
    return params


def _storage_aliases_for_body(body: str, state_vars: set[str]) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for match in STORAGE_ALIAS.finditer(body):
        alias, root = match.group(1), match.group(2)
        if root in state_vars:
            aliases[alias] = root
    return aliases


def _member_state_terms(body: str, storage_aliases: dict[str, str]) -> list[str]:
    terms = []
    for alias, member in re.findall(r"\b([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\b", body):
        root = storage_aliases.get(alias)
        if root:
            terms.append(f"{root}.{member}")
    return list(dict.fromkeys(terms))


def _writes_for_body(body: str, state_vars: set[str] | None = None, storage_aliases: dict[str, str] | None = None) -> list[str]:
    names = [match.group(1) for match in ASSIGNMENT.finditer(body) if match.group(1) not in {"return", "if", "for", "while", "require"}]
    aliases = storage_aliases or {}
    member_writes = [f"{aliases[match.group(1)]}.{match.group(2)}" for match in MEMBER_ASSIGNMENT.finditer(body) if match.group(1) in aliases]
    if state_vars is None:
        return list(dict.fromkeys([*names, *member_writes]))
    state_writes = [name for name in names if name in state_vars]
    return list(dict.fromkeys([*state_writes, *member_writes]))


def _reads_for_body(body: str, state_vars: set[str], storage_aliases: dict[str, str] | None = None) -> list[str]:
    words = set(re.findall(r"\b[A-Za-z_]\w*\b", body))
    return sorted(set(words.intersection(state_vars)).union(_member_state_terms(body, storage_aliases or {})))


def _calls_for_body(body: str) -> list[str]:
    calls = [f"{match.group(1)}.{match.group(2)}" for match in CALL_EXPR.finditer(body)]
    for match in INTERNAL_CALL.finditer(body):
        name = match.group(1)
        if name not in {"if", "for", "while", "require", "assert", "return", "emit", "revert", "mapping"}:
            calls.append(name)
    return list(dict.fromkeys(calls))


def _storage_accesses(contract: str | None, function: str | None, file_path: str, line: int, code: str, state_vars: set[str], storage_aliases: dict[str, str] | None = None) -> list[StorageAccess]:
    accesses = []
    writes = set(_writes_for_body(code))
    for name in sorted(state_vars.intersection(set(re.findall(r"\b[A-Za-z_]\w*\b", code)))):
        is_write = name in writes or bool(re.search(rf"\b{re.escape(name)}\s*(?:\[[^\]]+\])?\s*(?:=|\+=|-=|\*=|/=|\+\+|--)", code))
        accesses.append(
            StorageAccess(
                contract_name=contract,
                function_name=function,
                variable_name=name,
                access="write" if is_write else "read",
                file_path=file_path,
                line=line,
                expression=code,
            )
        )
    aliases = storage_aliases or {}
    for alias, member in re.findall(r"\b([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\b", code):
        root = aliases.get(alias)
        if not root:
            continue
        variable_name = f"{root}.{member}"
        accesses.append(
            StorageAccess(
                contract_name=contract,
                function_name=function,
                variable_name=variable_name,
                access="write" if variable_name in _writes_for_body(code, state_vars, aliases) else "read",
                file_path=file_path,
                line=line,
                expression=code,
            )
        )
    return accesses


def _call_edges(contract: str | None, function: str | None, file_path: str, line: int, code: str, state_var_types: dict[str, str]) -> list[CallEdge]:
    edges = []
    for match in CALL_EXPR.finditer(code):
        receiver, callee = match.group(1), match.group(2)
        receiver_type = state_var_types.get(receiver)
        if _is_builtin_storage_method(receiver_type, callee):
            continue
        kind = "delegatecall" if callee == "delegatecall" else "low_level" if callee in {"call", "send"} else "external"
        edges.append(
            CallEdge(
                from_contract=contract,
                from_function=function,
                to_contract=state_var_types.get(receiver, receiver),
                to_function=callee,
                receiver_symbol=receiver,
                file_path=file_path,
                line=line,
                expression=code,
                call_kind=kind,
            )
        )
    return edges


def _asset_flows(contract: str | None, function: str | None, file_path: str, line: int, code: str, token_kinds: dict[str, str]) -> list[AssetFlow]:
    flows = []
    for match in CALL_EXPR.finditer(code):
        receiver, callee = match.group(1), match.group(2)
        if callee not in {"transfer", "transferFrom", "safeTransfer", "safeTransferFrom", "mint", "mintEgg", "_mint", "burn", "_burn"}:
            continue
        kind = token_kinds.get(receiver, "native" if callee in {"send", "transfer"} and receiver in {"payable", "to"} else "unknown")
        args = _args_for_call(code, callee)
        flows.append(
            AssetFlow(
                contract_name=contract,
                function_name=function,
                asset_symbol=receiver,
                asset_kind=kind if kind in {"erc20", "erc721", "erc1155", "native"} else "unknown",
                from_expr=args[0] if callee in {"transferFrom", "safeTransferFrom"} and args else None,
                to_expr=args[1] if callee in {"transferFrom", "safeTransferFrom"} and len(args) > 1 else args[0] if args else None,
                amount_expr=args[2] if len(args) > 2 else args[1] if len(args) > 1 else None,
                file_path=file_path,
                line=line,
                expression=code,
            )
        )
    return flows


def _args_for_call(code: str, callee: str) -> list[str]:
    match = re.search(rf"\.{re.escape(callee)}\s*\((.*)\)", code)
    if not match:
        return []
    return [part.strip() for part in match.group(1).split(",")]


def _auth_constraints(contract: str | None, function: str | None, file_path: str, line: int, code: str) -> list[AuthConstraint]:
    if not any(term.lower() in code.lower() for term in AUTH_TERMS):
        return []
    role = "owner" if "owner" in code.lower() or "onlyowner" in code.lower() else "role" if "role" in code.lower() else None
    return [AuthConstraint(contract_name=contract, function_name=function, role=role, expression=code, file_path=file_path, line=line)]


def _lifecycle_transitions(contract: str | None, function: str | None, file_path: str, line: int, code: str, state_vars: set[str]) -> list[LifecycleTransition]:
    lower = f"{function or ''} {code}".lower()
    if not any(term in lower for term in LIFECYCLE_TERMS):
        return []
    variables = [match.group(1) for match in ASSIGNMENT.finditer(code) if match.group(1) in state_vars]
    variables.extend(member for _alias, member in re.findall(r"\b([A-Za-z_]\w*)\s*\.\s*(isActive|active|deadline\w*)\s*=", code))
    if not variables:
        return []
    return [LifecycleTransition(contract_name=contract, function_name=function, transition=function or "state_transition", state_variables=variables, file_path=file_path, line=line, expression=code)]


def _trust_boundaries(contract: str | None, function: str | None, file_path: str, line: int, code: str) -> list[TrustBoundary]:
    lower = code.lower()
    boundaries = []
    if ".delegatecall" in lower:
        boundaries.append("delegatecall")
    elif ".call" in lower:
        boundaries.append("external_call")
    if any(term in lower for term in ["transfer", "mint", "burn"]):
        boundaries.append("asset_transfer")
    if any(term in lower for term in ["latestanswer", "latestrounddata", "oracle", "getprice"]):
        boundaries.append("oracle_read")
    return [TrustBoundary(contract_name=contract, function_name=function, boundary_kind=kind, expression=code, file_path=file_path, line=line) for kind in dict.fromkeys(boundaries)]


def _is_builtin_storage_method(receiver_type: str | None, callee: str) -> bool:
    if callee in {"push", "pop"}:
        return True
    if not receiver_type:
        return False
    normalized = receiver_type.lower()
    return normalized in {"address", "uint256", "uint", "bool", "bytes32", "string"} or normalized.endswith("[]")


def _evidence(file_path: str, line: int | None, contract: str | None, function: str | None, expression: str, reason: str) -> SourceEvidence:
    return SourceEvidence(
        file_path=file_path,
        line_start=max(1, line or 1),
        line_end=max(1, line or 1),
        contract_name=contract,
        function_name=function,
        source_text=expression,
        reason=reason,
    )


def _slice_evidence(
    function: FunctionIR,
    edges: list[CallEdge],
    storage: list[StorageAccess],
    flows: list[AssetFlow],
    auth: list[AuthConstraint],
    boundaries: list[TrustBoundary],
) -> list[SourceEvidence]:
    evidence = [
        _evidence(function.file_path, function.start_line, function.contract_name, function.name, function.signature, "public/external graph entrypoint"),
    ]
    for item in [*flows[:2], *[access for access in storage if access.access == "write"][:2], *edges[:2], *boundaries[:1], *auth[:1]]:
        evidence.append(
            _evidence(
                item.file_path,
                item.line,
                getattr(item, "contract_name", None) or getattr(item, "from_contract", None),
                getattr(item, "function_name", None) or getattr(item, "from_function", None),
                item.expression,
                f"graph slice includes {item.__class__.__name__}",
            )
        )
    seen = set()
    deduped = []
    for item in evidence:
        key = (item.file_path, item.line_start, item.source_text)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped[:8]


def _slice_proof_status(
    function: FunctionIR,
    storage: list[StorageAccess],
    flows: list[AssetFlow],
    auth: list[AuthConstraint],
    lifecycle: list[LifecycleTransition],
    boundaries: list[TrustBoundary],
) -> tuple[str, list[str], list[str]]:
    writes = [item for item in storage if item.access == "write"]
    external_boundary = any(item.boundary_kind in {"external_call", "delegatecall", "asset_transfer"} for item in boundaries)
    has_asset_and_accounting = bool(flows and writes)
    has_auth = bool(auth or function.modifiers)
    counterevidence = []
    if has_auth:
        counterevidence.append("Detected auth constraint or modifier on the graph slice.")
    if any("safe" in flow.expression.lower() for flow in flows):
        counterevidence.append("Detected safe token transfer helper on the graph slice.")
    missing = []
    if not has_asset_and_accounting:
        missing.append("Need both asset-flow evidence and accounting/state-write evidence.")
    if external_boundary and writes:
        missing.append("Need ordering proof between external control flow and accounting writes.")
    if lifecycle and not has_auth:
        missing.append("Need transition authorization/monotonicity proof.")
    if has_asset_and_accounting and not counterevidence:
        return "strong_local_path", missing, counterevidence
    if has_asset_and_accounting:
        return "missing_counterevidence", missing, counterevidence
    if writes or flows or external_boundary:
        return "setup_required", missing, counterevidence
    return "rejected_by_counterevidence", ["No meaningful asset, state, lifecycle, or boundary facts in this slice."], counterevidence


def _attack_paths_from_slices(slices: list[GraphSlice]) -> list[AttackPathCandidate]:
    paths: list[AttackPathCandidate] = []
    for item in slices:
        writes = [access.variable_name for access in item.storage_accesses if access.access == "write"]
        if item.asset_flows and writes:
            family = "custody/accounting consistency"
            summary = f"{item.entry_contract}.{item.entry_function} combines asset flow with writes to {', '.join(writes[:3])}."
            confidence = 0.74 if item.proof_status == "strong_local_path" else 0.60
        elif item.lifecycle_transitions and not item.auth_constraints:
            family = "lifecycle monotonicity and transition gating"
            summary = f"{item.entry_contract}.{item.entry_function} performs lifecycle transition without detected auth in graph slice."
            confidence = 0.62
        elif item.trust_boundaries and writes:
            family = "external-call/accounting ordering"
            summary = f"{item.entry_contract}.{item.entry_function} combines trust boundary with state writes."
            confidence = 0.64
        else:
            continue
        paths.append(
            AttackPathCandidate(
                attack_path_id=f"path-{len(paths) + 1}",
                invariant_family=family,
                graph_slice_id=item.slice_id,
                summary=summary,
                proof_status=item.proof_status,
                confidence=confidence,
            )
        )
    return paths[:20]
