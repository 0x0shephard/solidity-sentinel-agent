from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json

from sentinel.config import Settings, get_settings
from sentinel.errors import SentinelError
from sentinel.rag.normalize import normalize_finding
from sentinel.rag.solodit import SoloditClient
from sentinel.rag.store import HistoricalFindingStore, load_findings, rag_paths, write_findings
from sentinel.schemas.common import ToolStatus
from sentinel.schemas.rag import SoloditSyncState


def _fresh(settings: Settings) -> bool:
    state_path = rag_paths(settings)["sync_state"]
    if not rag_paths(settings)["index_metadata"].exists():
        return False
    if not state_path.exists():
        return False
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
        synced_at = datetime.fromisoformat(data["synced_at"])
    except Exception:
        return False
    return datetime.now(UTC) - synced_at < timedelta(hours=settings.rag_stale_after_hours)


def rag_index_available(settings: Settings | None = None) -> bool:
    cfg = settings or get_settings()
    return bool(load_findings(cfg))


def sync_solodit(stale_ok: bool = True, settings: Settings | None = None) -> SoloditSyncState:
    cfg = settings or get_settings()
    paths = rag_paths(cfg)
    paths["root"].mkdir(parents=True, exist_ok=True)
    if stale_ok and _fresh(cfg) and rag_index_available(cfg):
        data = json.loads(paths["sync_state"].read_text(encoding="utf-8"))
        stale_message = str(data.get("message") or "")
        if cfg.solodit_api_key and "SOLODIT_API_KEY is not configured" not in stale_message:
            return SoloditSyncState.model_validate({**data, "status": ToolStatus.OK, "stale_ok": True})
        if not cfg.solodit_api_key:
            return SoloditSyncState.model_validate({**data, "status": ToolStatus.OK, "stale_ok": True})
    if not cfg.solodit_api_key:
        if rag_index_available(cfg) and not paths["index_metadata"].exists():
            HistoricalFindingStore(cfg).build(load_findings(cfg))
        status = ToolStatus.SKIPPED if rag_index_available(cfg) else ToolStatus.UNAVAILABLE
        state = SoloditSyncState(status=status, finding_count=len(load_findings(cfg)), cache_path=str(paths["raw"]), normalized_path=str(paths["normalized"]), chroma_path=str(paths["chroma"]), message="SOLODIT_API_KEY is not configured", stale_ok=rag_index_available(cfg))
        paths["sync_state"].write_text(json.dumps(state.model_dump(mode="json"), indent=2) + "\n", encoding="utf-8")
        return state
    try:
        raw, page_count = SoloditClient(cfg).fetch_all()
        normalized = [normalize_finding(item) for item in raw]
        write_findings(cfg, raw, normalized)
        chroma_path = HistoricalFindingStore(cfg).build(normalized)
        state = SoloditSyncState(status=ToolStatus.OK, finding_count=len(normalized), page_count=page_count, cache_path=str(paths["raw"]), normalized_path=str(paths["normalized"]), chroma_path=chroma_path)
    except SentinelError as exc:
        if stale_ok and rag_index_available(cfg):
            if not paths["index_metadata"].exists():
                HistoricalFindingStore(cfg).build(load_findings(cfg))
            state = SoloditSyncState(status=ToolStatus.OK, finding_count=len(load_findings(cfg)), cache_path=str(paths["raw"]), normalized_path=str(paths["normalized"]), chroma_path=str(paths["chroma"]), message=f"Using stale RAG cache after sync failure: {exc}", stale_ok=True)
        else:
            state = SoloditSyncState(status=ToolStatus.UNAVAILABLE, cache_path=str(paths["raw"]), normalized_path=str(paths["normalized"]), chroma_path=str(paths["chroma"]), message=str(exc))
    paths["sync_state"].write_text(json.dumps(state.model_dump(mode="json"), indent=2) + "\n", encoding="utf-8")
    return state
