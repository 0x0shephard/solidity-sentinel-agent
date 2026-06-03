from __future__ import annotations

import re
from pathlib import Path

from sentinel.schemas.static import FunctionRange


CONTRACT_DECLARATION = re.compile(r"\b(?:contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)")
FUNCTION_DECLARATION = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\b|\bconstructor\s*\(|\breceive\s*\(|\bfallback\s*\(")


def _strip_line_comment(line: str) -> str:
    if "//" not in line:
        return line
    return line.split("//", 1)[0]


def _brace_delta(line: str) -> int:
    cleaned = _strip_line_comment(line)
    return cleaned.count("{") - cleaned.count("}")


def _declared_function_name(text: str) -> str | None:
    match = FUNCTION_DECLARATION.search(text)
    if not match:
        return None
    if match.group(1):
        return match.group(1)
    token = match.group(0).split("(", 1)[0].strip()
    return token or "constructor"


def build_function_ranges_for_file(file_path: Path, repo_path: str | Path) -> list[FunctionRange]:
    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    relative = str(file_path.relative_to(repo_path))
    ranges: list[FunctionRange] = []
    current_contract: str | None = None
    contract_depth = 0
    in_function = False
    fn_start = 0
    fn_name = ""
    fn_signature_lines: list[str] = []
    fn_depth = 0

    for line_no, raw_line in enumerate(lines, start=1):
        line = _strip_line_comment(raw_line)
        if not in_function:
            contract_match = CONTRACT_DECLARATION.search(line)
            if contract_match:
                current_contract = contract_match.group(1)
                contract_depth = max(contract_depth, 0) + _brace_delta(line)
                continue
            if current_contract:
                contract_depth += _brace_delta(line)
                if contract_depth <= 0:
                    current_contract = None
                    contract_depth = 0
                    continue

            name = _declared_function_name(line)
            if not name:
                continue
            fn_start = line_no
            fn_name = name
            fn_signature_lines = [raw_line.strip()]
            if ";" in line and "{" not in line:
                continue
            in_function = True
            fn_depth = _brace_delta(line)
            if "{" in line and fn_depth <= 0:
                ranges.append(
                    FunctionRange(
                        file_path=relative,
                        contract_name=current_contract,
                        function_name=fn_name,
                        start_line=fn_start,
                        end_line=line_no,
                        signature=" ".join(fn_signature_lines),
                    )
                )
                in_function = False
            continue

        fn_signature_lines.append(raw_line.strip())
        if "{" not in " ".join(fn_signature_lines):
            if ";" in line:
                in_function = False
            continue
        fn_depth += _brace_delta(line)
        if fn_depth <= 0:
            ranges.append(
                FunctionRange(
                    file_path=relative,
                    contract_name=current_contract,
                    function_name=fn_name,
                    start_line=fn_start,
                    end_line=line_no,
                    signature=" ".join(fn_signature_lines),
                )
            )
            in_function = False
            fn_start = 0
            fn_name = ""
            fn_signature_lines = []
            fn_depth = 0

    return ranges


def build_function_ranges(repo_path: str | Path) -> list[FunctionRange]:
    repo = Path(repo_path)
    ranges: list[FunctionRange] = []
    for path in repo.rglob("*.sol"):
        if not path.is_file() or "out" in path.parts or "cache" in path.parts:
            continue
        ranges.extend(build_function_ranges_for_file(path, repo))
    return ranges


def containing_function(ranges: list[FunctionRange], file_path: str, line_no: int) -> FunctionRange | None:
    for item in ranges:
        if item.file_path == file_path and item.start_line <= line_no <= item.end_line:
            return item
    return None
