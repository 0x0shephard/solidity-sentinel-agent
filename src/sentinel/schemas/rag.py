from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field

from sentinel.schemas.common import ToolStatus


class HistoricalFinding(BaseModel):
    id: str
    slug: str | None = None
    title: str
    content: str
    summary: str | None = None
    impact: str | None = None
    quality_score: float = 0.0
    general_score: float = 0.0
    report_date: str | None = None
    firm_name: str | None = None
    protocol_name: str | None = None
    tags: list[str] = Field(default_factory=list)
    protocol_categories: list[str] = Field(default_factory=list)
    source_link: str | None = None
    github_link: str | None = None
    pdf_link: str | None = None
    vulnerability_class: str = "manual_review"
    root_cause_terms: list[str] = Field(default_factory=list)
    search_text: str


class HistoricalFindingMatch(BaseModel):
    finding: HistoricalFinding
    semantic_score: float = Field(ge=0.0, le=1.0)
    keyword_score: float = Field(ge=0.0, le=1.0)
    class_protocol_score: float = Field(ge=0.0, le=1.0)
    quality_recency_score: float = Field(ge=0.0, le=1.0)
    final_score: float = Field(ge=0.0, le=1.0)
    matched_terms: list[str] = Field(default_factory=list)
    relevance_reason: str


class SoloditSyncState(BaseModel):
    status: ToolStatus
    synced_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    finding_count: int = 0
    page_count: int = 0
    cache_path: str | None = None
    normalized_path: str | None = None
    chroma_path: str | None = None
    message: str | None = None
    stale_ok: bool = False


class RagSyncOutput(BaseModel):
    status: ToolStatus
    state: SoloditSyncState


class HistoricalFindingQuery(BaseModel):
    query: str
    vulnerability_class: str | None = None
    tags: list[str] = Field(default_factory=list)
    protocol_hints: list[str] = Field(default_factory=list)
    top_k: int = Field(default=5, ge=1, le=20)


class HistoricalFindingSearchOutput(BaseModel):
    status: ToolStatus
    matches: list[HistoricalFindingMatch] = Field(default_factory=list)
    message: str | None = None


class RepoRAGSearchIntent(BaseModel):
    intent_id: str
    query: str
    purpose: str
    vulnerability_class: str | None = None
    tags: list[str] = Field(default_factory=list)


class RepoRAGProfile(BaseModel):
    repo_id: str
    protocol_domain: str = "unknown"
    contract_names: list[str] = Field(default_factory=list)
    function_names: list[str] = Field(default_factory=list)
    role_terms: list[str] = Field(default_factory=list)
    asset_terms: list[str] = Field(default_factory=list)
    upgrade_terms: list[str] = Field(default_factory=list)
    lifecycle_terms: list[str] = Field(default_factory=list)
    invariant_candidates: list[str] = Field(default_factory=list)
    search_intents: list[RepoRAGSearchIntent] = Field(default_factory=list)


class TargetedRAGState(BaseModel):
    status: ToolStatus
    repo_id: str
    profile_path: str | None = None
    normalized_path: str | None = None
    chroma_path: str | None = None
    finding_count: int = 0
    fetched_count: int = 0
    selected_from_global_count: int = 0
    message: str | None = None


class RAGQuery(BaseModel):
    hypothesis_id: str
    query: str
    intent: str
    vulnerability_class: str | None = None
    root_cause_terms: list[str] = Field(default_factory=list)
    top_k: int = Field(default=5, ge=1, le=20)


class RetrievalQualityGrade(BaseModel):
    grade: Literal["good", "weak", "bad"]
    score: float = Field(ge=0.0, le=1.0)
    reason: str
    repair_hint: str | None = None


class HistoricalMatchCritique(BaseModel):
    match: HistoricalFindingMatch
    shared_root_cause: bool = False
    shared_exploit_preconditions: bool = False
    important_differences: list[str] = Field(default_factory=list)
    safe_to_cite: bool = False
    reason: str


class RAGContextBundle(BaseModel):
    hypothesis_id: str
    queries: list[RAGQuery] = Field(default_factory=list)
    raw_match_count: int = 0
    quality_grade: RetrievalQualityGrade
    safe_matches: list[HistoricalMatchCritique] = Field(default_factory=list)
    rejected_matches: list[HistoricalMatchCritique] = Field(default_factory=list)
    used_repair: bool = False
    notes: list[str] = Field(default_factory=list)
