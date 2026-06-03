from __future__ import annotations

import re
import json
from typing import Any

from sentinel.schemas.rag import HistoricalFinding


CLASS_TERMS = {
    "reentrancy": ["reentrancy", "external call", "cross-function"],
    "oracle": ["oracle", "price manipulation", "stale price", "twap"],
    "access_control": ["access control", "unauthorized", "onlyowner", "owner"],
    "unchecked_transfer": ["unchecked", "transfer return", "safetransfer", "erc20"],
    "upgradeability": ["upgrade", "proxy", "initializer", "storage collision"],
    "flash_loan": ["flash loan", "flashloan"],
}


def _tag_titles(raw: dict[str, Any]) -> list[str]:
    tags = []
    for item in raw.get("issues_issuetagscore") or []:
        title = ((item.get("tags_tag") or {}).get("title")) if isinstance(item, dict) else None
        if title:
            tags.append(str(title))
    return sorted(set(tags))


def _protocol_categories(raw: dict[str, Any]) -> list[str]:
    protocol = raw.get("protocols_protocol") or {}
    categories = []
    for item in protocol.get("protocols_protocolcategoryscore") or []:
        title = (((item.get("protocols_protocolcategory") or {}).get("title"))) if isinstance(item, dict) else None
        if title:
            categories.append(str(title))
    return sorted(set(categories))


def _string_or_none(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, dict) and not value:
        return None
    return json.dumps(value, sort_keys=True, default=str)


def _derive_class(text: str, tags: list[str]) -> tuple[str, list[str]]:
    haystack = f"{text} {' '.join(tags)}".lower()
    hits: list[str] = []
    for vuln_class, terms in CLASS_TERMS.items():
        matched = [term for term in terms if term in haystack]
        if matched:
            hits.extend(matched)
            return vuln_class, sorted(set(hits))
    words = re.findall(r"[a-zA-Z][a-zA-Z0-9_-]{3,}", haystack)
    return "manual_review", sorted(set(words[:12]))


def normalize_finding(raw: dict[str, Any]) -> HistoricalFinding:
    tags = _tag_titles(raw)
    categories = _protocol_categories(raw)
    content = str(raw.get("content") or "")
    summary = _string_or_none(raw.get("summary"))
    search_text = "\n".join(
        part
        for part in [
            str(raw.get("title") or ""),
            str(summary or ""),
            content[:20_000],
            " ".join(tags),
            " ".join(categories),
            str(raw.get("protocol_name") or ""),
            str(raw.get("firm_name") or ""),
        ]
        if part
    )
    vulnerability_class, root_terms = _derive_class(search_text, tags)
    return HistoricalFinding(
        id=str(raw.get("id") or raw.get("slug") or raw.get("title")),
        slug=_string_or_none(raw.get("slug")),
        title=str(raw.get("title") or "Untitled finding"),
        content=content,
        summary=summary,
        impact=_string_or_none(raw.get("impact")),
        quality_score=float(raw.get("quality_score") or 0.0),
        general_score=float(raw.get("general_score") or 0.0),
        report_date=_string_or_none(raw.get("report_date")),
        firm_name=_string_or_none(raw.get("firm_name") or ((raw.get("auditfirms_auditfirm") or {}).get("name"))),
        protocol_name=_string_or_none(raw.get("protocol_name") or ((raw.get("protocols_protocol") or {}).get("name"))),
        tags=tags,
        protocol_categories=categories,
        source_link=_string_or_none(raw.get("source_link")),
        github_link=_string_or_none(raw.get("github_link")),
        pdf_link=_string_or_none(raw.get("pdf_link")),
        vulnerability_class=vulnerability_class,
        root_cause_terms=root_terms,
        search_text=search_text,
    )
