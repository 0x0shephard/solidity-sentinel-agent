from __future__ import annotations

from datetime import UTC, datetime
import math
import re

from sentinel.schemas.rag import HistoricalFinding, HistoricalFindingMatch, HistoricalFindingQuery


def _terms(text: str) -> set[str]:
    return {term.lower() for term in re.findall(r"[a-zA-Z][a-zA-Z0-9_-]{2,}", text)}


def keyword_score(query_terms: set[str], finding: HistoricalFinding) -> tuple[float, list[str]]:
    finding_terms = _terms(f"{finding.title} {' '.join(finding.tags)} {' '.join(finding.root_cause_terms)} {finding.search_text[:8000]}")
    hits = sorted(query_terms.intersection(finding_terms))
    if not query_terms:
        return 0.0, []
    return min(1.0, len(hits) / max(4, len(query_terms))), hits


def class_protocol_score(query: HistoricalFindingQuery, finding: HistoricalFinding) -> float:
    score = 0.0
    if query.vulnerability_class and query.vulnerability_class == finding.vulnerability_class:
        score += 0.55
    tag_hits = {tag.lower() for tag in query.tags}.intersection({tag.lower() for tag in finding.tags})
    if tag_hits:
        score += min(0.25, 0.08 * len(tag_hits))
    protocol_text = f"{finding.protocol_name or ''} {' '.join(finding.protocol_categories)}".lower()
    if any(hint.lower() in protocol_text for hint in query.protocol_hints):
        score += 0.20
    return min(1.0, score)


def quality_recency_score(finding: HistoricalFinding) -> float:
    quality = min(1.0, max(finding.quality_score, finding.general_score) / 5.0)
    impact_bonus = {"HIGH": 0.15, "MEDIUM": 0.08, "LOW": 0.03}.get(str(finding.impact or "").upper(), 0.0)
    recency = 0.0
    if finding.report_date:
        try:
            dt = datetime.fromisoformat(finding.report_date.replace("Z", "+00:00"))
            years = max(0.0, (datetime.now(UTC) - dt).days / 365.0)
            recency = 0.15 * math.exp(-years / 3)
        except ValueError:
            recency = 0.0
    return min(1.0, quality + impact_bonus + recency)


def rank_matches(query: HistoricalFindingQuery, candidates: list[tuple[HistoricalFinding, float]]) -> list[HistoricalFindingMatch]:
    query_terms = _terms(" ".join([query.query, query.vulnerability_class or "", " ".join(query.tags), " ".join(query.protocol_hints)]))
    matches: list[HistoricalFindingMatch] = []
    for finding, semantic in candidates:
        kw_score, hits = keyword_score(query_terms, finding)
        cp_score = class_protocol_score(query, finding)
        qr_score = quality_recency_score(finding)
        final = (0.40 * semantic) + (0.30 * kw_score) + (0.20 * cp_score) + (0.10 * qr_score)
        reason = f"semantic={semantic:.2f}, keyword={kw_score:.2f}, class_protocol={cp_score:.2f}, quality_recency={qr_score:.2f}"
        matches.append(
            HistoricalFindingMatch(
                finding=finding,
                semantic_score=round(semantic, 4),
                keyword_score=round(kw_score, 4),
                class_protocol_score=round(cp_score, 4),
                quality_recency_score=round(qr_score, 4),
                final_score=round(final, 4),
                matched_terms=hits[:20],
                relevance_reason=reason,
            )
        )
    return sorted(matches, key=lambda match: match.final_score, reverse=True)[: query.top_k]
