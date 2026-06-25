"""Ground-truth recall benchmark.

Scores an audit run against a contest's published findings to answer the only
question that matters for users: *did it find the real bugs?* Matching is
two-tier and deliberately honest:

- ``touched``: the agent produced any hypothesis/finding on the affected
  function (it looked in the right place).
- ``recalled``: the agent touched the function AND its text matches a
  distinguishing keyword for that specific bug (it found the right issue) — this
  is necessary because several Highs can share one function.

A single recall number is misleading because a bug "found" as one of 40 raw
candidates and then rejected at review is not the same as a bug *delivered* in
the report, which in turn is not the same as a bug backed by an *executed*
proof. So recall is reported as a funnel:

- ``candidate``: recalled by any proposed hypothesis (widest net, inflated).
- ``reviewed``: survived adversarial review into a triage bucket.
- ``delivered``: actually reported as a finding (what a user receives).
- ``executed_proof``: backed by an executed PoC that broke the invariant.

Two orthogonal cuts are also reported: ``mechanism`` recall (the candidate's
vulnerability class aligns with the bug's real root cause, not just a keyword
hit) and ``novel`` recall (found by a candidate that did *not* lean on a RAG /
historical match — i.e. discovered rather than recalled from the brain).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from pydantic import BaseModel, Field, model_validator

# Pipeline stage a candidate represents, ordered widest -> narrowest. A bug
# recalled at a later stage implicitly counts for all earlier ones.
_STAGE_RANK = {"candidate": 0, "reviewed": 1, "delivered": 2}

# Which report bucket / trace source maps to which stage. A rejected hypothesis
# was still *proposed*, so it counts at candidate stage but not reviewed.
_SOURCE_STAGE = {
    "hypothesis": "candidate",
    "rejected_hypotheses": "candidate",
    "suspicious_hypotheses": "reviewed",
    "needs_manual_review": "reviewed",
    "leads": "reviewed",
    "findings": "delivered",
}


class GroundTruthFinding(BaseModel):
    id: str
    severity: str
    title: str
    file_contains: str
    function: str
    vulnerability_class: str = "unknown"
    match_any: list[str] = Field(default_factory=list)
    # Optional: the essential root-cause concepts a candidate must mention to count
    # as mechanism-correct. When set, mechanism is concept-based (root cause), not
    # just vulnerability-class alignment.
    mechanism_concepts: list[str] = Field(default_factory=list)


class FindingMatch(BaseModel):
    id: str
    severity: str
    title: str
    touched: bool
    recalled: bool
    stage: str | None = None  # furthest stage the bug reached (candidate/reviewed/delivered)
    matched_by: str | None = None
    matched_keyword: str | None = None
    executed_proof: bool = False  # backed by an executed PoC (sound proof)
    mechanism_match: bool = False  # root-cause concepts present (or class-aligned fallback)
    novel: bool = False  # first source is llm_proposer/invariant_reasoner, no detector equivalent
    novel_proof: bool = False  # novel AND backed by an executed proof


class RecallReport(BaseModel):
    contest: str
    total: int
    recalled: int
    touched: int
    # Cumulative recall funnel: candidate >= reviewed >= delivered, plus the
    # executed_proof (sound-proof) subset. Keyed by stage name (+ "executed_proof").
    by_stage: dict[str, int] = Field(default_factory=dict)
    mechanism_recalled: int = 0
    novel_recalled: int = 0
    novel_proof_recalled: int = 0
    by_severity: dict[str, dict[str, int]] = Field(default_factory=dict)
    matches: list[FindingMatch] = Field(default_factory=list)

    def recall(self) -> float:
        return self.recalled / self.total if self.total else 0.0


# Discovery origin of a candidate, derived from its source_detection_ids. "novel"
# means the agent reasoned the bug out (llm_proposer / invariant_reasoner) rather
# than a static detector pattern-matching it.
def _origin_from_sources(source_ids: list[str]) -> str:
    blob = " ".join(str(s) for s in (source_ids or [])).lower()
    if "invariant_reasoner" in blob or "invariant_inferencer" in blob:
        return "invariant_reasoner"
    if "llm_proposer" in blob:
        return "llm_proposer"
    if source_ids:  # any other detection id is a static/heuristic detector
        return "detector"
    return "other"


class Candidate(BaseModel):
    """A normalized agent output (hypothesis or finding) used for matching."""

    functions: list[str] = Field(default_factory=list)
    files: list[str] = Field(default_factory=list)
    text: str = ""
    source: str = "hypothesis"
    stage: str = "candidate"
    vulnerability_class: str = ""
    executed_proof: bool = False
    rag_assisted: bool = False
    origin: str = "other"  # detector | llm_proposer | invariant_reasoner | other

    @model_validator(mode="after")
    def _derive_stage(self) -> "Candidate":
        # The pipeline stage is a function of where the candidate came from, so it
        # is always derived from ``source`` — callers never have to keep them in sync.
        self.stage = _SOURCE_STAGE.get(self.source, "candidate")
        return self


def _norm(value: str | None) -> str:
    return (value or "").strip().lower()


# --- root-cause (mechanism) alignment -------------------------------------
# Curated class groups so "accounting_invariant" aligns with "fee accrual" but
# not with "reentrancy". Deliberately specific — mechanism recall is meant to be
# stricter than keyword recall (which overcounts shared functions).
_CLASS_GROUPS: dict[str, set[str]] = {
    "reentrancy": {"reentrancy", "reentrant", "callback", "hook"},
    "access_control": {"access", "control", "authorization", "auth", "permission", "onlyowner", "privilege", "unauthorized", "role"},
    "accounting": {"accounting", "fee", "share", "rounding", "inflation", "donation", "solvency", "debt", "interest", "yield", "redemption"},
    "oracle": {"oracle", "price", "chainlink", "twap", "stale", "feed"},
    "initialization": {"initialization", "initialize", "frontrun", "frontrunning", "uninitialized", "proxy"},
    "dos": {"denial", "unbounded", "griefing"},
    "slippage": {"slippage", "sandwich", "minamount", "deadline"},
    "signature": {"signature", "replay", "permit", "ecrecover", "nonce"},
}

_STOPWORDS = {"the", "and", "via", "with", "missing", "incorrect", "wrong", "bad", "issue", "bug", "invariant", "unknown", "error"}


def _tokens(name: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", _norm(name)) if len(t) >= 4 and t not in _STOPWORDS}


def _class_groups(name: str) -> set[str]:
    toks = _tokens(name)
    return {group for group, members in _CLASS_GROUPS.items() if toks & members}


def _class_aligned(a: str, b: str) -> bool:
    na, nb = _norm(a), _norm(b)
    if not na or not nb or na == "unknown" or nb == "unknown":
        return False
    if na == nb:
        return True
    ta, tb = _tokens(na), _tokens(nb)
    if ta & tb:  # a shared meaningful token (e.g. both mention "oracle")
        return True
    return bool(_class_groups(na) & _class_groups(nb))


def candidate_matches_function(candidate: Candidate, gt: GroundTruthFinding) -> bool:
    fn = _norm(gt.function)
    file_ok = (not gt.file_contains) or any(_norm(gt.file_contains) in _norm(f) for f in candidate.files)
    fn_ok = any(fn == _norm(c) or fn in _norm(c) or _norm(c) in fn for c in candidate.functions if c)
    # Function names are distinctive; accept a function hit even if files are sparse,
    # but require the file to be consistent when both are present.
    if fn_ok and (file_ok or not candidate.files):
        return True
    return False


def _recalls_keyword(candidate: Candidate, gt: GroundTruthFinding) -> tuple[bool, str | None]:
    if not gt.match_any:
        return True, None
    text = _norm(candidate.text)
    for keyword in gt.match_any:
        if _norm(keyword) and _norm(keyword) in text:
            return True, keyword
    return False, None


def _mechanism_correct(candidate: Candidate, gt: GroundTruthFinding) -> bool:
    """Root-cause agreement. When the ground truth lists ``mechanism_concepts``,
    require ALL of them to appear in the candidate text (true root cause); else
    fall back to vulnerability-class alignment (coarser)."""
    if gt.mechanism_concepts:
        text = _norm(candidate.text)
        return all(_norm(concept) in text for concept in gt.mechanism_concepts if _norm(concept))
    return _class_aligned(candidate.vulnerability_class, gt.vulnerability_class)


def evaluate_finding(gt: GroundTruthFinding, candidates: list[Candidate]) -> FindingMatch:
    touched = False
    best_rank = -1
    best_stage: str | None = None
    matched_by: str | None = None
    matched_keyword: str | None = None
    executed = False
    mechanism = False
    origins: set[str] = set()
    for cand in candidates:
        if not candidate_matches_function(cand, gt):
            continue
        touched = True
        recalled_here, keyword = _recalls_keyword(cand, gt)
        if not recalled_here:
            continue
        rank = _STAGE_RANK.get(cand.stage, 0)
        if rank > best_rank:
            best_rank, best_stage, matched_by, matched_keyword = rank, cand.stage, cand.source, keyword
        executed = executed or cand.executed_proof
        mechanism = mechanism or _mechanism_correct(cand, gt)
        origins.add(cand.origin)
    recalled = best_rank >= 0
    # Novel = the agent reasoned it out (llm_proposer / invariant_reasoner) and NO
    # static detector found the same thing. A detector hit disqualifies novelty.
    novel = recalled and bool(origins & {"llm_proposer", "invariant_reasoner"}) and "detector" not in origins
    return FindingMatch(
        id=gt.id,
        severity=gt.severity,
        title=gt.title,
        touched=touched,
        recalled=recalled,
        stage=best_stage,
        matched_by=matched_by,
        matched_keyword=matched_keyword,
        executed_proof=executed and recalled,
        mechanism_match=mechanism and recalled,
        novel=novel,
        novel_proof=novel and executed,
    )


def score_recall(ground_truth: list[GroundTruthFinding], candidates: list[Candidate], contest: str = "") -> RecallReport:
    matches = [evaluate_finding(gt, candidates) for gt in ground_truth]
    by_severity: dict[str, dict[str, int]] = {}
    by_stage = {"candidate": 0, "reviewed": 0, "delivered": 0, "executed_proof": 0}
    for match in matches:
        bucket = by_severity.setdefault(match.severity, {"total": 0, "recalled": 0, "touched": 0})
        bucket["total"] += 1
        bucket["recalled"] += int(match.recalled)
        bucket["touched"] += int(match.touched)
        if match.recalled and match.stage is not None:
            reached = _STAGE_RANK[match.stage]
            for stage, rank in _STAGE_RANK.items():
                if rank <= reached:  # cumulative: delivered implies reviewed implies candidate
                    by_stage[stage] += 1
            if match.executed_proof:
                by_stage["executed_proof"] += 1
    return RecallReport(
        contest=contest,
        total=len(matches),
        recalled=sum(m.recalled for m in matches),
        touched=sum(m.touched for m in matches),
        by_stage=by_stage,
        mechanism_recalled=sum(m.mechanism_match for m in matches),
        novel_recalled=sum(m.novel for m in matches),
        novel_proof_recalled=sum(m.novel_proof for m in matches),
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
    return Candidate(
        functions=functions,
        files=files,
        text=" ".join(text_parts),
        source=source,
        vulnerability_class=str(raw.get("vulnerability_class", "")),
        executed_proof=_norm(raw.get("proof_status")) == "executed_poc_confirmed",
        rag_assisted=bool(raw.get("historical_matches")),
        origin=_origin_from_sources(raw.get("source_detection_ids", []) or []),
    )


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
    total = report.total

    def pct(n: int) -> str:
        return f"{n}/{total} = {n / total:.0%}" if total else "—"

    stage = report.by_stage
    lines = [
        f"# Recall benchmark — {report.contest}",
        "",
        "## Recall funnel (cumulative)",
        f"- **candidate** (any proposed hypothesis): {pct(stage.get('candidate', 0))}",
        f"- **reviewed** (survived adversarial review): {pct(stage.get('reviewed', 0))}",
        f"- **delivered** (reported as a finding): {pct(stage.get('delivered', 0))}",
        f"- **sound-proof** (PoC broke the invariant, control-validated): {pct(stage.get('executed_proof', 0))}",
        "",
        f"- Touched (looked at the function): {pct(report.touched)}",
        f"- **Mechanism-correct** (root-cause concepts when defined, else class-aligned): {pct(report.mechanism_recalled)}",
        f"- **Novel** (reasoned by llm_proposer/invariant_reasoner, no detector found it): {pct(report.novel_recalled)}",
        f"- **Novel-proof** (novel AND control-validated PoC): {pct(report.novel_proof_recalled)}",
        "",
        "| severity | recalled | touched | total |",
        "|---|---|---|---|",
    ]
    for severity in ("high", "medium", "low"):
        bucket = report.by_severity.get(severity)
        if bucket:
            lines.append(f"| {severity} | {bucket['recalled']} | {bucket['touched']} | {bucket['total']} |")
    lines += ["", "| id | severity | stage | proof | mechanism | novel | matched by | title |", "|---|---|---|---|---|---|---|---|"]
    for match in report.matches:
        stage_label = match.stage if match.recalled else ("touched" if match.touched else "missed")
        proof = "✓" if match.executed_proof else "—"
        mech = "✓" if match.mechanism_match else "—"
        nov = "✓" if match.novel else "—"
        lines.append(
            f"| {match.id} | {match.severity} | {stage_label} | {proof} | {mech} | {nov} | {match.matched_by or '—'} | {match.title[:50]} |"
        )
    return "\n".join(lines) + "\n"
