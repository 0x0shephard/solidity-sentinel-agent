from __future__ import annotations

import hashlib
import json

from sentinel.schemas.rag import HistoricalFinding
from sentinel.schemas.research import VulnerabilityHypothesis


NORMALIZED_CORPUS_VERSION = "solodit-normalized-v1"
CHUNKING_VERSION = "finding-semantic-units-v1"
CANONICAL_TEXT_VERSION = "canonical-finding-text-v1"
VIEW_TYPES = ["summary_view", "root_cause_view", "impact_view", "recommendation_view", "exploit_precondition_view"]


def _join(values: list[str]) -> str:
    return ", ".join(str(value) for value in values if value)


def _fix_pattern(finding: HistoricalFinding) -> str:
    text = f"{finding.summary or ''}\n{finding.content}".lower()
    if "safeerc20" in text or "return value" in text:
        return "Use safe token transfer helpers and check external call return values."
    if "upgrade" in text or "storage layout" in text:
        return "Use a complete upgrade flow and preserve upgradeable storage layout compatibility."
    if "oracle" in text or "stale" in text:
        return "Validate oracle freshness, bounds, and independent failure conditions."
    if "access" in text or "authorization" in text:
        return "Restrict privileged actions with explicit authorization and negative tests."
    if "accounting" in text or "balance" in text:
        return "Reconcile accounting state before and after value movement."
    return "Review root cause and add a targeted regression test for the vulnerable path."


def _preconditions(finding: HistoricalFinding) -> str:
    terms = set(term.lower() for term in finding.root_cause_terms)
    text = f"{finding.title} {finding.summary or ''} {finding.content[:1000]}".lower()
    if "delegatecall" in terms or "delegatecall" in text:
        return "Attacker can influence delegatecall target or calldata."
    if "reentrancy" in terms or "callback" in text:
        return "External callback can observe or mutate state before accounting completes."
    if "oracle" in terms or "stale" in text:
        return "Consumer accepts stale, manipulated, or incomplete oracle data."
    if "upgrade" in text:
        return "Upgrade lifecycle is reachable and implementation/storage assumptions are wrong."
    return "Exploitability depends on reaching the affected component with the documented root cause."


def build_canonical_finding_text(finding: HistoricalFinding) -> str:
    sections = [
        ("Title", finding.title),
        ("Vulnerability Class", finding.vulnerability_class),
        ("Root Cause Terms", _join(finding.root_cause_terms)),
        ("Impact", finding.impact or "unknown"),
        ("Exploit Preconditions", _preconditions(finding)),
        ("Affected Component / Protocol Type", _join([finding.protocol_name or "", *finding.protocol_categories])),
        ("Recommendation / Fix Pattern", _fix_pattern(finding)),
        ("Tags", _join(finding.tags)),
        ("Normalized Summary", finding.summary or finding.content[:1200]),
    ]
    return "\n\n".join(f"[{name}]\n{value}".strip() for name, value in sections if value)


def build_finding_documents(finding: HistoricalFinding) -> list[dict]:
    base_meta = {
        "finding_id": finding.id,
        "title": finding.title,
        "project": finding.protocol_name or "",
        "vulnerability_class": finding.vulnerability_class,
        "root_cause_terms": ",".join(finding.root_cause_terms),
        "tags": ",".join(finding.tags),
        "quality_score": finding.quality_score,
        "source_url": finding.source_link or finding.github_link or finding.pdf_link or "",
    }
    views = {
        "summary_view": f"[Title]\n{finding.title}\n\n[Summary]\n{finding.summary or finding.content[:1200]}\n\n[Tags]\n{_join(finding.tags)}",
        "root_cause_view": f"[Vulnerability Class]\n{finding.vulnerability_class}\n\n[Root Cause Terms]\n{_join(finding.root_cause_terms)}\n\n[Details]\n{finding.content[:1000]}",
        "impact_view": f"[Impact]\n{finding.impact or 'unknown'}\n\n[Impact Context]\n{finding.summary or finding.content[:900]}",
        "recommendation_view": f"[Recommendation / Fix Pattern]\n{_fix_pattern(finding)}\n\n[Related Finding]\n{finding.title}",
        "exploit_precondition_view": f"[Exploit Preconditions]\n{_preconditions(finding)}\n\n[Root Cause Terms]\n{_join(finding.root_cause_terms)}",
    }
    return [
        {
            "id": f"{finding.id}:{view_type}",
            "text": " ".join(text.split()),
            "metadata": {**base_meta, "view_type": view_type},
        }
        for view_type, text in views.items()
    ]


def build_canonical_query_text(
    hypothesis: VulnerabilityHypothesis,
    query_intent: str,
    source_evidence: list[str] | None = None,
    root_cause_terms: list[str] | None = None,
    exploit_precondition_terms: list[str] | None = None,
) -> str:
    parts = [
        f"Intent: {query_intent}",
        f"Vulnerability class: {hypothesis.vulnerability_class}",
        f"Root cause: {_join(root_cause_terms or hypothesis.root_cause_terms)}",
        f"Exploit preconditions: {_join(exploit_precondition_terms or hypothesis.exploit_precondition_terms)}",
        f"Affected component: {_join([hypothesis.affected_contract or '', hypothesis.affected_function or '', *hypothesis.affected_functions])}",
        f"Local evidence: {' '.join(source_evidence or [item.source_text for item in hypothesis.evidence_lines[:3]])}",
        f"Hypothesis: {hypothesis.title}",
    ]
    return " ".join(" ".join(part.split()) for part in parts if part and not part.endswith(": "))


def source_cache_hash(findings: list[HistoricalFinding]) -> str:
    payload = [
        {
            "id": finding.id,
            "title": finding.title,
            "search_text": finding.search_text,
            "class": finding.vulnerability_class,
            "terms": finding.root_cause_terms,
        }
        for finding in findings
    ]
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
