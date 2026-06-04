from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

from sentinel.evidence import classify_source_path
from sentinel.schemas.invariants import InvariantCandidate, ProtocolModel
from sentinel.schemas.static import FunctionRange, SourceEvidence
from sentinel.solidity.ranges import containing_function


ACCOUNTING_TERMS = {
    "balance",
    "balances",
    "supply",
    "debt",
    "reward",
    "rewards",
    "bursary",
    "wage",
    "fee",
    "fees",
    "score",
    "count",
    "share",
    "shares",
}
LIFECYCLE_TERMS = {"start", "end", "deadline", "session", "epoch", "round", "graduate", "enroll", "review"}
UPGRADE_TERMS = {"upgrade", "authorizeupgrade", "uups", "implementation", "initializer"}
ROLE_TERMS = {"owner", "admin", "role", "teacher", "student", "manager", "governor"}
ASSET_TERMS = {"token", "erc20", "ether", "eth", "weth", "usdc", "asset"}


def build_protocol_model(static_facts: dict) -> ProtocolModel:
    texts = _all_fact_texts(static_facts)
    contracts = sorted({str(item.get("contract")) for item in static_facts.get("contracts", []) if item.get("contract")})
    haystack = " ".join(texts).lower()
    return ProtocolModel(
        contracts=contracts,
        roles=sorted(term for term in ROLE_TERMS if term in haystack),
        assets=sorted(term for term in ASSET_TERMS if term in haystack),
        accounting_terms=sorted(term for term in ACCOUNTING_TERMS if term in haystack),
        lifecycle_terms=sorted(term for term in LIFECYCLE_TERMS if term in haystack),
        upgrade_terms=sorted(term for term in UPGRADE_TERMS if term in haystack),
        notes=[f"Profiled {len(contracts)} contracts from static facts."],
    )


def mine_invariant_candidates(repo_path: str, static_facts: dict) -> list[InvariantCandidate]:
    ranges = [FunctionRange.model_validate(item) for item in static_facts.get("function_ranges", [])]
    candidates: list[InvariantCandidate] = []
    files = _production_solidity_files(repo_path)
    variable_writes: dict[str, list[SourceEvidence]] = defaultdict(list)
    variable_reads: dict[str, list[SourceEvidence]] = defaultdict(list)
    contract_state_vars: dict[str, list[str]] = defaultdict(list)

    for path in files:
        rel = _relative(repo_path, path)
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        contract_name = None
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            contract_match = re.match(r"(?:abstract\s+)?contract\s+(\w+)|library\s+(\w+)", stripped)
            if contract_match:
                contract_name = contract_match.group(1) or contract_match.group(2)
            state_var = _state_variable_name(stripped)
            if contract_name and state_var:
                contract_state_vars[contract_name].append(state_var)
            for name in _assigned_variables(stripped):
                ev = _evidence(repo_path, ranges, rel, line_no, "state/accounting variable is written")
                variable_writes[name].append(ev)
            for name in _guard_variables(stripped):
                ev = _evidence(repo_path, ranges, rel, line_no, "variable participates in a guard or branch")
                variable_reads[name].append(ev)

            evidence = _evidence(repo_path, ranges, rel, line_no, "suspicious protocol invariant pattern")
            if _looks_like_distribution_math(stripped):
                candidates.append(
                    _candidate(
                        "percentage_distribution_math",
                        "Distribution math mixes percentages, looped recipients, or precision constants; verify total payout cannot exceed funds or leave unsafe residue.",
                        [evidence],
                        ["percentage", "loop", "total payout", "precision"],
                        "percentage_distribution_math",
                        0.70,
                    )
                )
            if _looks_like_upgrade_authorizer(stripped) and not _file_contains(lines, ("upgradeTo(", "upgradeToAndCall(")):
                candidates.append(
                    _candidate(
                        "upgrade_authorization_without_upgrade",
                        "Upgrade authorization logic exists but no explicit upgrade execution path was found in the same source file; verify upgrade lifecycle and access boundaries.",
                        [evidence],
                        ["upgrade authorization", "implementation lifecycle"],
                        "upgrade_authorization_without_upgrade",
                        0.66,
                    )
                )
            if _looks_like_unbounded_loop(stripped):
                candidates.append(
                    _candidate(
                        "unbounded_loop_dos",
                        "Public or external logic appears to iterate over a dynamic collection; verify gas bounds and denial-of-service resistance.",
                        [evidence],
                        ["unbounded loop", "dynamic array", "gas griefing"],
                        "unbounded_loop_dos",
                        0.62,
                    )
                )
            if _looks_like_external_balance_trust(stripped):
                candidates.append(
                    _candidate(
                        "external_state_accounting_trust",
                        "Accounting logic appears to trust external balance/state reads; verify reconciliation and manipulation resistance.",
                        [evidence],
                        ["external state", "accounting trust", "reconciliation"],
                        "external_state_accounting_trust",
                        0.64,
                    )
                )

    candidates.extend(_configured_but_not_enforced(variable_writes, variable_reads))
    candidates.extend(_checked_but_not_updated(variable_reads, variable_writes))
    candidates.extend(_storage_layout_candidates(contract_state_vars, files, repo_path, ranges))
    return _dedupe_candidates(candidates)[:12]


def _production_solidity_files(repo_path: str) -> list[Path]:
    root = Path(repo_path)
    return [
        path
        for path in root.rglob("*.sol")
        if path.is_file()
        and "out" not in path.parts
        and "cache" not in path.parts
        and classify_source_path(_relative(repo_path, path)) == "production"
    ]


def _relative(repo_path: str, path: Path) -> str:
    try:
        return str(path.relative_to(Path(repo_path))).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def _all_fact_texts(static_facts: dict) -> list[str]:
    texts: list[str] = []
    for facts in static_facts.values():
        if not isinstance(facts, list):
            continue
        for fact in facts:
            if isinstance(fact, dict):
                texts.append(" ".join(str(value) for value in fact.values() if isinstance(value, (str, int, float))))
    return texts


def _source_line(repo_path: str, relative_path: str, line_no: int) -> str:
    path = Path(repo_path) / relative_path
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return lines[line_no - 1].strip() if 1 <= line_no <= len(lines) else ""


def _evidence(repo_path: str, ranges: list[FunctionRange], relative_path: str, line_no: int, reason: str) -> SourceEvidence:
    fn = containing_function(ranges, relative_path, line_no)
    return SourceEvidence(
        file_path=relative_path,
        line_start=line_no,
        line_end=line_no,
        contract_name=fn.contract_name if fn else None,
        function_name=fn.function_name if fn else None,
        source_text=_source_line(repo_path, relative_path, line_no),
        reason=reason,
    )


def _candidate(
    invariant_type: str,
    description: str,
    evidence: list[SourceEvidence],
    suspicious_terms: list[str],
    template: str,
    confidence: float,
) -> InvariantCandidate:
    return InvariantCandidate(
        id=f"inv-{invariant_type}-{evidence[0].file_path.replace('/', '-')}-{evidence[0].line_start}",
        invariant_type=invariant_type,
        description=description,
        affected_contracts=sorted({item.contract_name for item in evidence if item.contract_name}),
        affected_functions=sorted({item.function_name for item in evidence if item.function_name}),
        production_evidence=evidence,
        missing_guard_terms=[],
        suspicious_terms=suspicious_terms,
        recommended_validation_template=template,
        confidence=confidence,
    )


def _state_variable_name(line: str) -> str | None:
    if "(" in line or line.startswith(("function ", "constructor", "if ", "for ", "while ", "return ")):
        return None
    match = re.match(r"(?:mapping\s*\([^;]+\)|[\w\[\]]+)\s+(?:public|private|internal|external)?\s*(\w+)\s*(?:=|;)", line)
    return match.group(1) if match else None


def _assigned_variables(line: str) -> list[str]:
    if "==" in line or "!=" in line or "<=" in line or ">=" in line:
        line = re.sub(r"==|!=|<=|>=", " ", line)
    names = []
    for match in re.finditer(r"\b([A-Za-z_]\w*)\s*(?:=|\+=|-=|\*=|/=|\+\+|--)", line):
        name = match.group(1)
        if name not in {"return", "if", "for", "while", "require", "assert"}:
            names.append(name)
    return names


def _guard_variables(line: str) -> list[str]:
    if not re.search(r"\b(require|assert|if)\s*\(", line):
        return []
    return [
        name
        for name in re.findall(r"\b[A-Za-z_]\w*\b", line)
        if name not in {"require", "assert", "if", "msg", "sender", "block", "timestamp", "true", "false"}
    ]


def _looks_like_distribution_math(line: str) -> bool:
    lower = line.lower()
    return (
        any(term in lower for term in ["percentage", "percent", "precision", "basis", "bps", "wage", "share", "bursary", "reward", "payout", "transfer"])
        and any(op in line for op in ["*", "/", "%"])
    ) or bool(re.search(r"\bfor\s*\(.+\)\s*{?", line) and any(term in lower for term in ["transfer", "pay", "reward", "bursary"]))


def _looks_like_upgrade_authorizer(line: str) -> bool:
    return "_authorizeupgrade" in line.lower()


def _file_contains(lines: list[str], needles: tuple[str, ...]) -> bool:
    haystack = "\n".join(lines)
    return any(needle in haystack for needle in needles)


def _looks_like_unbounded_loop(line: str) -> bool:
    lower = line.lower()
    return bool(re.search(r"\bfor\s*\(", lower) and any(term in lower for term in [".length", "list", "array", "students", "teachers", "users"]))


def _looks_like_external_balance_trust(line: str) -> bool:
    lower = line.lower()
    return any(term in lower for term in [".balanceof(", ".balance", "totalassets(", "latestanswer("]) and any(
        term in lower for term in ACCOUNTING_TERMS
    )


def _configured_but_not_enforced(
    variable_writes: dict[str, list[SourceEvidence]],
    variable_reads: dict[str, list[SourceEvidence]],
) -> list[InvariantCandidate]:
    candidates = []
    config_terms = ("limit", "cap", "threshold", "cutoff", "cut_off", "fee", "max", "min", "score")
    for name, writes in variable_writes.items():
        lower = name.lower()
        if not any(term in lower for term in config_terms):
            continue
        if variable_reads.get(name):
            continue
        candidates.append(
            _candidate(
                "configured_but_not_enforced",
                f"`{name}` is written as a configuration/accounting variable, but no guard using it was found in production sources.",
                writes[:2],
                [name, "configured but not enforced", "missing guard"],
                "configured_but_not_enforced",
                0.72,
            )
        )
    return candidates


def _checked_but_not_updated(
    variable_reads: dict[str, list[SourceEvidence]],
    variable_writes: dict[str, list[SourceEvidence]],
) -> list[InvariantCandidate]:
    candidates = []
    for name, reads in variable_reads.items():
        lower = name.lower()
        if not any(term in lower for term in ["count", "nonce", "review", "epoch", "round", "attempt"]):
            continue
        if variable_writes.get(name):
            continue
        candidates.append(
            _candidate(
                "checked_but_never_updated",
                f"`{name}` is checked in guard logic, but no production write/update was found.",
                reads[:2],
                [name, "checked but not updated", "stale guard"],
                "checked_but_never_updated",
                0.68,
            )
        )
    return candidates


def _storage_layout_candidates(
    contract_state_vars: dict[str, list[str]],
    files: list[Path],
    repo_path: str,
    ranges: list[FunctionRange],
) -> list[InvariantCandidate]:
    names = sorted(contract_state_vars)
    candidates = []
    for left in names:
        for right in names:
            if left >= right:
                continue
            common_prefix = _common_alpha_prefix(left.lower(), right.lower())
            if len(common_prefix) < 4 and not any(term in (left + right).lower() for term in ["level", "v1", "v2", "upgrade"]):
                continue
            if contract_state_vars[left] == contract_state_vars[right]:
                continue
            evidence = _contract_evidence(files, repo_path, ranges, left) + _contract_evidence(files, repo_path, ranges, right)
            if not evidence:
                continue
            candidates.append(
                _candidate(
                    "storage_layout_mismatch",
                    f"`{left}` and `{right}` look related but have different state-variable ordering; verify upgrade/storage-layout compatibility.",
                    evidence[:2],
                    ["storage layout", "upgrade compatibility", left, right],
                    "storage_layout_mismatch",
                    0.60,
                )
            )
    return candidates


def _common_alpha_prefix(left: str, right: str) -> str:
    chars = []
    for l_char, r_char in zip(left, right):
        if l_char != r_char or not l_char.isalpha():
            break
        chars.append(l_char)
    return "".join(chars)


def _contract_evidence(files: list[Path], repo_path: str, ranges: list[FunctionRange], contract_name: str) -> list[SourceEvidence]:
    evidence = []
    pattern = re.compile(rf"\bcontract\s+{re.escape(contract_name)}\b")
    for path in files:
        rel = _relative(repo_path, path)
        for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            if pattern.search(line):
                evidence.append(_evidence(repo_path, ranges, rel, line_no, "related contract declaration for storage-layout review"))
                return evidence
    return evidence


def _dedupe_candidates(candidates: list[InvariantCandidate]) -> list[InvariantCandidate]:
    deduped = []
    seen = set()
    for candidate in sorted(candidates, key=lambda item: item.confidence, reverse=True):
        key = (
            candidate.invariant_type,
            tuple((item.file_path, item.line_start, item.source_text) for item in candidate.production_evidence),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)
    return deduped
