from __future__ import annotations

from collections import Counter
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from sentinel.config import Settings, get_settings
from sentinel.errors import SentinelError
from sentinel.rag.normalize import normalize_finding
from sentinel.rag.ranking import rank_matches
from sentinel.rag.solodit import SoloditClient
from sentinel.rag.store import HistoricalFindingStore, load_findings, rag_paths, write_findings
from sentinel.schemas.common import ToolStatus
from sentinel.schemas.rag import HistoricalFinding, HistoricalFindingQuery, RepoRAGProfile, RepoRAGSearchIntent, TargetedRAGState


DOMAIN_HINTS = {
    "vault": ("vault", "deposit", "withdraw", "share", "redeem", "strategy"),
    "lending": ("borrow", "repay", "debt", "collateral", "liquidat"),
    "staking": ("stake", "unstake", "reward", "claim"),
    "amm": ("swap", "pool", "liquidity", "reserve"),
    "governance": ("vote", "proposal", "delegate", "quorum"),
    "bridge": ("bridge", "message", "relayer", "endpoint"),
    "upgradeable": ("uups", "upgrade", "initializer", "reinitializer", "proxy"),
    "education_lifecycle": ("student", "teacher", "principal", "session", "graduate", "review", "score"),
}

ROLE_TERMS = ("owner", "admin", "principal", "teacher", "student", "keeper", "operator", "guardian", "manager", "role")
ASSET_TERMS = ("usdc", "token", "erc20", "bursary", "fee", "balance", "payment", "wage", "fund", "treasury")
UPGRADE_TERMS = ("uups", "upgrade", "authorizeupgrade", "implementation", "initializer", "reinitializer", "proxy")
LIFECYCLE_TERMS = ("initialize", "start", "end", "session", "graduate", "enroll", "expel", "review", "claim", "withdraw")
INVARIANT_TERMS = ("cutoff", "score", "bursary", "wage", "precision", "sessionend", "reviewcount", "totalsupply", "balance")


def repo_profile_root(settings: Settings, repo_id: str) -> Path:
    return settings.rag_dir / "repo_profiles" / repo_id


def repo_id_for_path(repo_path: str) -> str:
    normalized = str(Path(repo_path)).strip("/").replace("\\", "/")
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", normalized.split("/")[-1] or "repo").strip("-").lower()
    digest = hashlib.sha1(normalized.encode("utf-8")).hexdigest()[:8]
    return f"{slug}-{digest}"


def _terms_from_names(names: list[str], vocabulary: tuple[str, ...]) -> list[str]:
    lowered = " ".join(names).lower()
    return [term for term in vocabulary if term in lowered]


def _dominant_domain(names: list[str], source_terms: list[str]) -> str:
    haystack = " ".join([*names, *source_terms]).lower()
    scores = {
        domain: sum(1 for term in terms if term in haystack)
        for domain, terms in DOMAIN_HINTS.items()
    }
    domain, score = max(scores.items(), key=lambda item: item[1])
    return domain if score else "unknown"


def _source_terms(static_facts: dict[str, Any]) -> list[str]:
    texts = []
    for group in ["storage_writes", "external_calls", "token_transfers", "access_control"]:
        texts.extend(str(fact.get("text", "")) for fact in static_facts.get(group, []))
    words = re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", " ".join(texts).lower())
    stop = {"public", "external", "internal", "private", "uint256", "address", "require", "return", "memory", "storage"}
    counts = Counter(word for word in words if word not in stop)
    return [word for word, _ in counts.most_common(30)]


def _intent(intent_id: str, query: str, purpose: str, vulnerability_class: str | None = None, tags: list[str] | None = None) -> RepoRAGSearchIntent:
    return RepoRAGSearchIntent(
        intent_id=intent_id,
        query=" ".join(query.split()),
        purpose=purpose,
        vulnerability_class=vulnerability_class,
        tags=tags or [],
    )


def build_repo_rag_profile(repo_path: str, static_facts: dict[str, Any]) -> RepoRAGProfile:
    contract_names = sorted({
        str(fact.get("contract"))
        for fact in static_facts.get("contracts", [])
        if fact.get("contract")
    })
    function_names = sorted({
        str(fact.get("function"))
        for fact in static_facts.get("functions", [])
        if fact.get("function")
    })
    all_names = [*contract_names, *function_names]
    source_terms = _source_terms(static_facts)
    role_terms = sorted(set(_terms_from_names([*all_names, *source_terms], ROLE_TERMS)))
    asset_terms = sorted(set(_terms_from_names([*all_names, *source_terms], ASSET_TERMS)))
    upgrade_terms = sorted(set(_terms_from_names([*all_names, *source_terms], UPGRADE_TERMS)))
    lifecycle_terms = sorted(set(_terms_from_names([*all_names, *source_terms], LIFECYCLE_TERMS)))
    invariant_terms = sorted(set(_terms_from_names([*all_names, *source_terms], INVARIANT_TERMS)))
    protocol_domain = _dominant_domain(all_names, source_terms)

    invariant_candidates = []
    for term in invariant_terms[:10]:
        invariant_candidates.append(f"{term} is written or configured and should be enforced across lifecycle transitions")
    if asset_terms:
        invariant_candidates.append(f"{', '.join(asset_terms[:4])} accounting should conserve collected and distributed funds")
    if upgrade_terms:
        invariant_candidates.append("upgrade path should execute the actual proxy upgrade and preserve storage layout")
    if lifecycle_terms:
        invariant_candidates.append(f"{', '.join(lifecycle_terms[:5])} lifecycle checks should gate state transitions")

    intents = [
        _intent(
            "repo-domain",
            f"{protocol_domain} Solidity audit {' '.join(contract_names[:5])} {' '.join(function_names[:12])}",
            "Find historical findings in similar protocol domains and surfaces.",
            tags=[protocol_domain],
        )
    ]
    if upgrade_terms:
        intents.extend(
            [
                _intent("upgrade-flow", "UUPS upgrade authorizeUpgrade without upgradeTo upgradeToAndCall", "Find broken upgrade execution findings.", "upgradeability", list(upgrade_terms)),
                _intent("storage-layout", f"upgradeable storage layout mismatch {' '.join(contract_names[:6])}", "Find storage layout compatibility findings.", "storage_layout", list(upgrade_terms)),
            ]
        )
    if asset_terms:
        intents.append(
            _intent("accounting", f"Solidity accounting invariant percentage payout loop {' '.join(asset_terms)}", "Find accounting and distribution invariant failures.", "accounting", list(asset_terms))
        )
    if lifecycle_terms or invariant_terms:
        intents.append(
            _intent("lifecycle-invariants", f"Solidity lifecycle invariant {' '.join(lifecycle_terms)} {' '.join(invariant_terms)}", "Find lifecycle guards and invariant enforcement failures.", "business_logic", [*lifecycle_terms, *invariant_terms])
        )
    if role_terms:
        intents.append(
            _intent("role-conflicts", f"Solidity role conflict authorization {' '.join(role_terms)}", "Find role/permission model findings.", "access_control", list(role_terms))
        )

    seen = set()
    unique_intents = []
    for intent in intents:
        key = intent.query.lower()
        if key in seen:
            continue
        seen.add(key)
        unique_intents.append(intent)

    return RepoRAGProfile(
        repo_id=repo_id_for_path(repo_path),
        protocol_domain=protocol_domain,
        contract_names=contract_names,
        function_names=function_names,
        role_terms=role_terms,
        asset_terms=asset_terms,
        upgrade_terms=upgrade_terms,
        lifecycle_terms=lifecycle_terms,
        invariant_candidates=invariant_candidates[:12],
        search_intents=unique_intents[:8],
    )


def _targeted_filters(settings: Settings, intent: RepoRAGSearchIntent) -> dict[str, Any]:
    filters = SoloditClient(settings).default_filters()
    # Solodit deployments may evolve their search/filter contract. These
    # search-like fields are intentionally fail-soft; 400 responses fall back
    # to the global cache selection path.
    filters["search"] = intent.query
    filters["query"] = intent.query
    return filters


def _fetch_targeted(settings: Settings, profile: RepoRAGProfile) -> tuple[list[dict[str, Any]], int]:
    if not settings.solodit_api_key:
        return [], 0
    client = SoloditClient(settings)
    raw_by_key: dict[str, dict[str, Any]] = {}
    fetched = 0
    for intent in profile.search_intents[:5]:
        try:
            data = client.fetch_page(page=1, page_size=25, filters=_targeted_filters(settings, intent))
            raw = data.get("findings", [])
        except SentinelError:
            continue
        fetched += len(raw)
        for item in raw:
            key = str(item.get("id") or item.get("slug") or item.get("title") or json.dumps(item, sort_keys=True)[:120])
            raw_by_key[key] = item
    return list(raw_by_key.values()), fetched


def _select_from_global(settings: Settings, profile: RepoRAGProfile, limit: int = 250) -> list[HistoricalFinding]:
    global_findings = load_findings(settings)
    if not global_findings:
        return []
    selected: dict[str, HistoricalFinding] = {}
    store = HistoricalFindingStore(settings)
    for intent in profile.search_intents:
        query = HistoricalFindingQuery(
            query=intent.query,
            vulnerability_class=intent.vulnerability_class,
            tags=intent.tags,
            protocol_hints=[profile.protocol_domain, *profile.contract_names[:3]],
            top_k=20,
        )
        for match in rank_matches(query, store.search(query, candidate_k=60)):
            selected[match.finding.id] = match.finding
            if len(selected) >= limit:
                return list(selected.values())
    return list(selected.values())


def build_targeted_rag(repo_path: str, static_facts: dict[str, Any], settings: Settings | None = None) -> TargetedRAGState:
    cfg = settings or get_settings()
    profile = build_repo_rag_profile(repo_path, static_facts)
    root = repo_profile_root(cfg, profile.repo_id)
    paths = rag_paths(cfg, root)
    root.mkdir(parents=True, exist_ok=True)
    profile_path = root / "profile.json"
    profile_path.write_text(json.dumps(profile.model_dump(mode="json"), indent=2) + "\n", encoding="utf-8")

    raw, fetched_count = _fetch_targeted(cfg, profile)
    normalized = [normalize_finding(item) for item in raw]
    selected = _select_from_global(cfg, profile)
    by_id = {finding.id: finding for finding in [*normalized, *selected]}
    findings = list(by_id.values())
    if not findings:
        return TargetedRAGState(
            status=ToolStatus.SKIPPED,
            repo_id=profile.repo_id,
            profile_path=str(profile_path),
            normalized_path=str(paths["normalized"]),
            chroma_path=str(paths["chroma"]),
            message="No targeted Solodit findings available; global RAG will be used.",
        )

    write_findings(cfg, raw, findings, root=root)
    chroma_path = HistoricalFindingStore(cfg, root=root).build(findings)
    state = TargetedRAGState(
        status=ToolStatus.OK,
        repo_id=profile.repo_id,
        profile_path=str(profile_path),
        normalized_path=str(paths["normalized"]),
        chroma_path=chroma_path,
        finding_count=len(findings),
        fetched_count=fetched_count,
        selected_from_global_count=len(selected),
    )
    (root / "targeted_state.json").write_text(json.dumps(state.model_dump(mode="json"), indent=2) + "\n", encoding="utf-8")
    return state
