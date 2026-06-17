from __future__ import annotations

from pathlib import Path

from sentinel.config import get_settings
from sentinel.rag.auditvault import ingest_auditvault, load_auditvault_findings, parse_note
from sentinel.rag.store import HistoricalFindingStore, load_findings

_NOTE = """---
tags:
  - severity/critical
  - lang/solidity
  - blockchain/evm
  - sector/lending
  - platform/code4rena
  - vuln/reentrancy/read-only
  - impact/loss-of-funds/direct-drain
  - trigger/flash-loan
  - fix/use-reentrancy-guard
protocol: "[[Aave]]"
report: "https://example.com/report"
---
# Read-only reentrancy drains lending pool

The view function returns stale state during a flash-loan callback, letting an
attacker borrow against an inflated balance.
"""


def _vault(tmp_path: Path) -> Path:
    note = tmp_path / "vault" / "findings" / "ro-reentrancy.md"
    note.parent.mkdir(parents=True)
    note.write_text(_NOTE, encoding="utf-8")
    return tmp_path / "vault"


def test_parse_note_maps_frontmatter(tmp_path):
    vault = _vault(tmp_path)
    _raw, finding = parse_note(vault / "findings" / "ro-reentrancy.md")
    assert finding.vulnerability_class == "reentrancy"
    assert finding.protocol_categories == ["lending"]
    assert finding.protocol_name == "Aave"
    assert finding.source_link == "https://example.com/report"
    assert finding.quality_score == 1.0  # severity/critical
    assert finding.title.startswith("Read-only reentrancy")
    assert "severity/critical" in finding.tags
    assert any("flash-loan" in term for term in finding.root_cause_terms)


def test_load_finds_notes(tmp_path):
    vault = _vault(tmp_path)
    raws, findings = load_auditvault_findings(vault)
    assert len(raws) == 1 and len(findings) == 1
    assert findings[0].id.startswith("auditvault-")


def test_ingest_merges_dedupes_and_feeds_both_surfaces(tmp_path, monkeypatch):
    vault = _vault(tmp_path)
    monkeypatch.setenv("SENTINEL_RAG_DIR", str(tmp_path / "rag"))
    # Avoid loading the embedding model / Chroma in a unit test.
    monkeypatch.setattr(HistoricalFindingStore, "build", lambda self, findings: "stub-index")

    first = ingest_auditvault(str(vault))
    assert first["added"] == 1
    assert first["total"] == 1

    # Surface 1: the global historical-findings corpus now contains it.
    corpus = load_findings(get_settings())
    assert any(f.id.startswith("auditvault-") for f in corpus)

    # Surface 2: the stage-7 checklist derivation reads the same corpus and now
    # produces a check for the ingested class.
    from sentinel.rag.checklist import build_solodit_checklists_from_cache

    classes = {item.vulnerability_class for item in build_solodit_checklists_from_cache()}
    assert "reentrancy" in classes

    # Re-ingesting the same vault does not duplicate findings.
    second = ingest_auditvault(str(vault))
    assert second["added"] == 0
