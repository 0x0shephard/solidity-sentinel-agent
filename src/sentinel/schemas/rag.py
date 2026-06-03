from __future__ import annotations

from datetime import UTC, datetime

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
