"""Ground-truth recall benchmark.

Scores an audit run against a contest's published findings to answer the only
question that matters for users: *did it find the real bugs?* Matching is
two-tier and deliberately honest:

- ``touched``: the agent produced any hypothesis/finding on the affected
  function (it looked in the right place).
- ``recalled``: the agent touched the function AND its text matches a
  distinguishing keyword for that specific bug (it found the right issue) — this
  is necessary because several Highs can share one function.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class GroundTruthFinding(BaseModel):
    id: str
    severity: str
    title: str
    file_contains: str
    function: str
    vulnerability_class: str = "unknown"
    match_any: list[str] = Field(default_factory=list)


class FindingMatch(BaseModel):
    id: str
    severity: str
    title: str
    touched: bool
    recalled: bool
    matched_by: str | None = None
    matched_keyword: str | None = None


class RecallReport(BaseModel):
    contest: str
    total: int
    recalled: int
    touched: int
    by_severity: dict[str, dict[str, int]] = Field(default_factory=dict)
    matches: list[FindingMatch] = Field(default_factory=list)

    def recall(self) -> float:
        return self.recalled / self.total if self.total else 0.0


class Candidate(BaseModel):
    """A normalized agent output (hypothesis or finding) used for matching."""

    functions: list[str] = Field(default_factory=list)
    files: list[str] = Field(default_factory=list)
    text: str = ""
    source: str = "hypothesis"


def _norm(value: str | None) -> str:
    return (value or "").strip().lower()


def candidate_matches_function(candidate: Candidate, gt: GroundTruthFinding) -> bool:
    fn = _norm(gt.function)
    file_ok = (not gt.file_contains) or any(_norm(gt.file_contains) in _norm(f) for f in candidate.files)
    fn_ok = any(fn == _norm(c) or fn in _norm(c) or _norm(c) in fn for c in candidate.functions if c)
    # Function names are distinctive; accept a function hit even if files are sparse,
    # but require the file to be consistent when both are present.
    if fn_ok and (file_ok or not candidate.files):
        return True
    return False


def evaluate_finding(gt: GroundTruthFinding, candidates: list[Candidate]) -> FindingMatch:
    touched = False
    for cand in candidates:
        if not candidate_matches_function(cand, gt):
            continue
        touched = True
        text = _norm(cand.text)
        if not gt.match_any:
            return FindingMatch(id=gt.id, severity=gt.severity, title=gt.title, touched=True, recalled=True, matched_by=cand.source)
        for keyword in gt.match_any:
            if _norm(keyword) and _norm(keyword) in text:
                return FindingMatch(id=gt.id, severity=gt.severity, title=gt.title, touched=True, recalled=True, matched_by=cand.source, matched_keyword=keyword)
    return FindingMatch(id=gt.id, severity=gt.severity, title=gt.title, touched=touched, recalled=False)


def score_recall(ground_truth: list[GroundTruthFinding], candidates: list[Candidate], contest: str = "") -> RecallReport:
    matches = [evaluate_finding(gt, candidates) for gt in ground_truth]
    by_severity: dict[str, dict[str, int]] = {}
    for match in matches:
        bucket = by_severity.setdefault(match.severity, {"total": 0, "recalled": 0, "touched": 0})
        bucket["total"] += 1
        bucket["recalled"] += int(match.recalled)
        bucket["touched"] += int(match.touched)
    return RecallReport(
        contest=contest,
        total=len(matches),
        recalled=sum(m.recalled for m in matches),
        touched=sum(m.touched for m in matches),
        by_severity=by_severity,
        matches=matches,
    )


# --- loading helpers -------------------------------------------------------

def load_ground_truth(path: str | Path, include_low: bool = False) -> tuple[list[GroundTruthFinding], str]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    items = list(data.get("findings", []))
    if include_low:
        items += list(data.get("low_findings", []))
    return [GroundTruthFinding.model_validate(item) for item in items], str(data.get("contest", ""))


def _candidate_from_hypothesis(raw: dict, source: str) -> Candidate:
    functions = list(raw.get("affected_functions", []) or [])
    if raw.get("affected_function"):
        functions.append(raw["affected_function"])
    files = list(raw.get("affected_files", []) or [])
    evidence = raw.get("evidence_lines", []) or raw.get("evidence", []) or []
    for item in evidence:
        if isinstance(item, dict) and item.get("file_path"):
            files.append(item["file_path"])
    text_parts = [
        str(raw.get("title", "")),
        str(raw.get("evidence_summary", "")),
        str(raw.get("reasoning_summary", "")),
        " ".join(str(t) for t in raw.get("root_cause_terms", []) or []),
        " ".join(str(t) for t in raw.get("exploit_precondition_terms", []) or []),
    ]
    return Candidate(functions=functions, files=files, text=" ".join(text_parts), source=source)


def candidates_from_run(run_dir: str | Path) -> list[Candidate]:
    """Collect all agent outputs from a run directory for matching."""

    run = Path(run_dir)
    candidates: list[Candidate] = []

    trace = run / "candidate_rank_trace.json"
    if trace.exists():
        data = json.loads(trace.read_text(encoding="utf-8"))
        for hypothesis in data.get("hypotheses", []) or []:
            candidates.append(_candidate_from_hypothesis(hypothesis, "hypothesis"))

    report = run / "report.json"
    if report.exists():
        data = json.loads(report.read_text(encoding="utf-8"))
        for bucket in ("findings", "leads", "needs_manual_review", "suspicious_hypotheses", "rejected_hypotheses"):
            for item in data.get(bucket, []) or []:
                if isinstance(item, dict):
                    candidates.append(_candidate_from_hypothesis(item, bucket))
    return candidates


def render_recall_markdown(report: RecallReport) -> str:
    lines = [
        f"# Recall benchmark — {report.contest}",
        "",
        f"- **Recall (found the bug): {report.recalled}/{report.total} = {report.recall():.0%}**",
        f"- Touched (looked at the function): {report.touched}/{report.total} = {report.touched / report.total:.0%}" if report.total else "- no findings",
        "",
        "| severity | recalled | touched | total |",
        "|---|---|---|---|",
    ]
    for severity in ("high", "medium", "low"):
        bucket = report.by_severity.get(severity)
        if bucket:
            lines.append(f"| {severity} | {bucket['recalled']} | {bucket['touched']} | {bucket['total']} |")
    lines += ["", "| id | severity | result | matched by | title |", "|---|---|---|---|---|"]
    for match in report.matches:
        result = "recalled" if match.recalled else ("touched" if match.touched else "missed")
        lines.append(f"| {match.id} | {match.severity} | {result} | {match.matched_by or '—'} | {match.title[:60]} |")
    return "\n".join(lines) + "\n"
