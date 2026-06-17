"""Ingest an AuditVault (Obsidian) knowledge base into the historical corpus.

AuditVault (https://github.com/Auditware/AuditVault) is a tag-structured vault of
HIGH/CRITICAL audit findings and rekt post-mortems, with rich frontmatter
(``severity/*``, ``sector/*``, ``vuln/*``, ``trigger/*``, ``fix/*``, ``lang/*``,
``protocol: [[X]]``, ``report: <url>``). Its note shape maps almost 1:1 onto
``HistoricalFinding``, so ingesting its ``findings/`` and ``hacks/`` markdown into
Sentinel's *global* normalized corpus broadens the agent everywhere it consults
history at once:

- semantic retrieval (``research.retrieve_historical_findings`` + the research
  subagent's ``retrieve_historical_context``), and
- the stage-7 sector checklist (``build_targeted_rag`` selects from the same
  global corpus and ``build_rag_checklist`` derives checks from each finding's
  ``vulnerability_class`` / ``tags`` / ``protocol_categories``).

Point ``SENTINEL_AUDITVAULT_DIR`` at a local clone; the vault is not vendored.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from sentinel.config import Settings, get_settings
from sentinel.rag.normalize import _derive_class
from sentinel.rag.store import HistoricalFindingStore, load_findings, rag_paths, write_findings
from sentinel.schemas.rag import HistoricalFinding

_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", re.DOTALL)

# AuditVault ``vuln/<x>/...`` first segment -> Sentinel vulnerability class.
_VULN_CLASS_MAP = {
    "reentrancy": "reentrancy",
    "access-control": "missing_access_control",
    "authorization": "missing_access_control",
    "access": "missing_access_control",
    "initialization": "unguarded_initializer",
    "initializer": "unguarded_initializer",
    "oracle": "oracle_staleness_logic",
    "price": "oracle_staleness_logic",
    "erc20": "unchecked_erc20_return",
    "token": "unchecked_erc20_return",
    "delegatecall": "dangerous_delegatecall",
    "accounting": "accounting",
    "rounding": "accounting",
    "fee": "accounting",
    "share": "accounting",
    "upgrade": "unguarded_initializer",
    "upgradeability": "unguarded_initializer",
}


def _clean(value: str) -> str:
    return str(value).strip().strip('"').strip("'").strip()


def _strip_wikilink(value) -> str | None:
    if value is None:
        return None
    match = re.search(r"\[\[(.*?)\]\]", str(value))
    return match.group(1).strip() if match else _clean(str(value)) or None


def _parse_frontmatter_fallback(raw: str) -> dict:
    """Minimal YAML-frontmatter parser for ``key: scalar`` and block lists."""
    data: dict = {}
    key: str | None = None
    for line in raw.splitlines():
        if not line.strip():
            continue
        list_item = re.match(r"^\s*-\s+(.*)$", line)
        if list_item and key is not None:
            data.setdefault(key, [])
            if isinstance(data[key], list):
                data[key].append(_clean(list_item.group(1)))
            continue
        if ":" in line and not line.startswith((" ", "\t")):
            name, _, value = line.partition(":")
            key = name.strip()
            value = value.strip()
            data[key] = _clean(value) if value else []
            if value:
                key = None
    return data


def _parse_frontmatter(text: str) -> tuple[dict, str]:
    """Split a note into (frontmatter dict, body), preferring PyYAML if present."""
    match = _FRONTMATTER_RE.match(text)
    if not match:
        return {}, text
    raw_fm, body = match.group(1), match.group(2)
    try:
        import yaml

        data = yaml.safe_load(raw_fm)
        if isinstance(data, dict):
            return data, body
    except Exception:
        pass
    return _parse_frontmatter_fallback(raw_fm), body


def _tags(frontmatter: dict) -> list[str]:
    raw = frontmatter.get("tags") or []
    if isinstance(raw, str):
        raw = [raw]
    return [str(item).strip() for item in raw if str(item).strip()]


def _tag_values(tags: list[str], prefix: str) -> list[str]:
    return [tag[len(prefix):] for tag in tags if tag.startswith(prefix)]


def _first_title(body: str) -> str | None:
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("# "):
            return stripped[2:].strip()
    return None


def _vulnerability_class(tags: list[str], body: str) -> str:
    for vuln_tag in _tag_values(tags, "vuln/"):
        first = vuln_tag.split("/")[0]
        if first in _VULN_CLASS_MAP:
            return _VULN_CLASS_MAP[first]
    vuln_tags = _tag_values(tags, "vuln/")
    if vuln_tags:
        return vuln_tags[0].split("/")[0].replace("-", "_")
    derived, _ = _derive_class(body, tags)
    return derived


def _severity_quality(tags: list[str]) -> float:
    severities = _tag_values(tags, "severity/")
    if any(s == "critical" for s in severities):
        return 1.0
    if any(s == "high" for s in severities):
        return 0.8
    if any(s == "medium" for s in severities):
        return 0.5
    return 0.3


def _make_id(path: Path, frontmatter: dict) -> str:
    basis = str(frontmatter.get("report") or path.stem)
    digest = hashlib.sha1(basis.encode("utf-8")).hexdigest()[:10]
    return f"auditvault-{path.stem[:40]}-{digest}"


def parse_note(path: Path) -> tuple[dict, HistoricalFinding]:
    """Parse one AuditVault markdown note into a raw dict + a HistoricalFinding.

    Args:
        path: Path to a ``findings/`` or ``hacks/`` markdown note.
    Returns:
        ``(raw_record, finding)`` — ``raw_record`` keeps provenance; ``finding``
        is the normalized ``HistoricalFinding`` ready for the global corpus.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    frontmatter, body = _parse_frontmatter(text)
    tags = _tags(frontmatter)
    title = _first_title(body) or _clean(str(frontmatter.get("title") or path.stem))
    cls = _vulnerability_class(tags, body)
    _, derived_terms = _derive_class(body, tags)
    root_cause = sorted(
        {*_tag_values(tags, "vuln/"), *_tag_values(tags, "trigger/"), *_tag_values(tags, "fix/"), *derived_terms[:8]}
    )
    sectors = _tag_values(tags, "sector/")
    platform = _tag_values(tags, "platform/")
    impact = _tag_values(tags, "impact/")
    search_text = " ".join([title, *tags, body[:4000]])
    raw = {"_source": "auditvault", "path": str(path), "frontmatter": frontmatter, "title": title}
    finding = HistoricalFinding(
        id=_make_id(path, frontmatter),
        slug=path.stem,
        title=title[:300],
        content=body[:20000],
        summary=(body.strip().split("\n\n", 1)[0][:600] or None),
        impact=", ".join(impact) or None,
        quality_score=_severity_quality(tags),
        general_score=0.0,
        report_date=_clean(str(frontmatter.get("date") or frontmatter.get("report_date") or "")) or None,
        firm_name=(platform[0] if platform else None),
        protocol_name=_strip_wikilink(frontmatter.get("protocol")),
        tags=tags,
        protocol_categories=sectors,
        source_link=_clean(str(frontmatter.get("report") or "")) or None,
        vulnerability_class=cls,
        root_cause_terms=root_cause[:15],
        search_text=search_text[:8000],
    )
    return raw, finding


def load_auditvault_findings(
    vault_dir: str | Path,
    subdirs: tuple[str, ...] = ("findings", "hacks"),
    limit: int | None = None,
) -> tuple[list[dict], list[HistoricalFinding]]:
    """Load and parse all AuditVault notes under the given subdirectories.

    Args:
        vault_dir: Path to a local AuditVault clone.
        subdirs: Which subdirectories to ingest (default findings + hacks).
        limit: Optional cap on the number of notes (for quick runs/tests).
    Returns:
        ``(raw_records, findings)`` parsed from the vault.
    """
    root = Path(vault_dir)
    files: list[Path] = []
    for sub in subdirs:
        directory = root / sub
        if directory.exists():
            files.extend(sorted(directory.rglob("*.md")))
    if limit is not None:
        files = files[:limit]
    raws: list[dict] = []
    findings: list[HistoricalFinding] = []
    for path in files:
        try:
            raw, finding = parse_note(path)
        except Exception:
            continue
        raws.append(raw)
        findings.append(finding)
    return raws, findings


def ingest_auditvault(
    vault_dir: str | Path,
    settings: Settings | None = None,
    subdirs: tuple[str, ...] = ("findings", "hacks"),
    limit: int | None = None,
) -> dict:
    """Merge AuditVault findings into the global corpus and rebuild the index.

    De-duplicates against the existing corpus by finding id, rewrites the
    normalized + raw caches, and rebuilds the historical-finding store so both
    semantic retrieval and the stage-7 sector checklist immediately see the new
    findings.

    Args:
        vault_dir: Path to a local AuditVault clone.
        settings: Optional settings override (defaults to env-resolved settings).
        subdirs: Which subdirectories to ingest.
        limit: Optional cap on the number of notes.
    Returns:
        A summary dict: ``{source_files, added, total, chroma}``.
    """
    cfg = settings or get_settings()
    raws, av_findings = load_auditvault_findings(vault_dir, subdirs, limit)

    paths = rag_paths(cfg)
    existing = load_findings(cfg)
    by_id = {finding.id: finding for finding in existing}
    added = 0
    for finding in av_findings:
        if finding.id not in by_id:
            by_id[finding.id] = finding
            added += 1
        else:
            by_id[finding.id] = finding  # refresh on re-ingest
    merged = list(by_id.values())

    existing_raw: list[dict] = []
    if paths["raw"].exists():
        for line in paths["raw"].read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    existing_raw.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    # Keep the raw cache consistent with the merged normalized corpus.
    seen_av = {raw["path"] for raw in raws}
    kept_raw = [raw for raw in existing_raw if raw.get("path") not in seen_av]
    write_findings(cfg, [*kept_raw, *raws], merged)
    chroma_path = HistoricalFindingStore(cfg).build(merged)

    return {"source_files": len(raws), "added": added, "total": len(merged), "chroma": chroma_path}
