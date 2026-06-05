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
from sentinel.schemas.protocol_ir import ProtocolIR
from sentinel.schemas.rag import HistoricalFinding, HistoricalFindingQuery, RAGChecklistItem, RepoRAGProfile, RepoRAGSearchIntent, TargetedRAGState


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
SEMANTIC_PATTERN_TERMS = (
    "duplicate signer",
    "signature threshold",
    "checkpoint boundary",
    "lowerLookup upperLookup",
    "batch claim eligibility",
    "fee formula dimension",
    "multi report fee accrual",
    "native receive fallback",
    "boolean whitelist inversion",
    "indexed structure key mismatch",
    "lockup transfer bypass",
)


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
    protocol_ir = _protocol_ir_from_facts(static_facts)
    contract_names = sorted({
        str(contract)
        for fact in static_facts.get("contracts", [])
        for contract in _contract_names_from_fact(fact)
        if contract
    })
    if protocol_ir:
        contract_names = sorted(set([*contract_names, *protocol_ir.contract_names()]))
    function_names = sorted({
        str(fact.get("function"))
        for fact in static_facts.get("functions", [])
        if fact.get("function")
    })
    if protocol_ir:
        function_names = sorted(set([*function_names, *protocol_ir.function_names()]))
    all_names = [*contract_names, *function_names]
    source_terms = _source_terms(static_facts)
    if protocol_ir:
        source_terms.extend(_source_terms_from_ir(protocol_ir))
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
    if protocol_ir:
        invariant_candidates.extend(_semantic_invariant_candidates(protocol_ir))

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
    if protocol_ir:
        intents.extend(_semantic_search_intents(protocol_ir))

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


def build_rag_checklist(profile: RepoRAGProfile, findings: list[HistoricalFinding]) -> list[RAGChecklistItem]:
    items: dict[str, RAGChecklistItem] = {}
    for finding in findings[:80]:
        cls = finding.vulnerability_class if finding.vulnerability_class != "manual_review" else _class_from_finding_terms(finding)
        terms = [*finding.root_cause_terms, *finding.tags, *finding.protocol_categories]
        key = f"{cls}:{','.join(sorted(term.lower() for term in terms[:4]))}"[:120]
        required = _required_local_evidence(cls, profile)
        if not required:
            continue
        current = items.get(key)
        if not current:
            current = RAGChecklistItem(
                checklist_id=f"rag-{len(items) + 1}",
                historical_pattern=finding.title,
                vulnerability_class=cls,
                required_local_evidence=required,
                negative_indicators=_negative_indicators(cls),
                exploit_preconditions=_exploit_preconditions(cls),
                validation_questions=_validation_questions(cls),
                safe_to_cite=True,
                source_finding_ids=[],
            )
            items[key] = current
        if finding.id not in current.source_finding_ids:
            current.source_finding_ids.append(finding.id)
    return list(items.values())[:20]


def _protocol_ir_from_facts(static_facts: dict[str, Any]) -> ProtocolIR | None:
    raw = static_facts.get("protocol_ir")
    if not raw:
        return None
    try:
        return ProtocolIR.model_validate(raw)
    except Exception:
        return None


def _contract_names_from_fact(fact: dict[str, Any]) -> list[str]:
    names: list[str] = []
    if fact.get("contract"):
        names.append(str(fact["contract"]))
    for name in fact.get("contracts") or []:
        names.append(str(name))
    return names


def _source_terms_from_ir(ir: ProtocolIR) -> list[str]:
    texts = [
        *[edge.expression for edge in ir.call_edges],
        *[flow.expression for flow in ir.asset_flows],
        *[auth.expression for auth in ir.auth_constraints],
        *[transition.expression for transition in ir.lifecycle_transitions],
        *[statement.source_text for statement in ir.statements[:200]],
        *[lookup.expression for lookup in ir.checkpoint_lookups],
        *[formula.expression for formula in ir.fee_formulas],
        *[path.transfer_expression for path in ir.asset_compatibility_paths],
        *[claim.claim_text for claim in ir.documentation_claims],
    ]
    terms = re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", " ".join(texts).lower())
    pattern_terms = [term for pattern in _semantic_patterns_from_ir(ir) for term in pattern.split()]
    return [*terms[:80], *pattern_terms[:80]]


def _semantic_invariant_candidates(ir: ProtocolIR) -> list[str]:
    return [f"{pattern} should be validated against local semantic evidence" for pattern in _semantic_patterns_from_ir(ir)][:12]


def _semantic_search_intents(ir: ProtocolIR) -> list[RepoRAGSearchIntent]:
    intents: list[RepoRAGSearchIntent] = []
    for index, pattern in enumerate(_semantic_patterns_from_ir(ir)[:8], start=1):
        vulnerability_class = "accounting" if any(term in pattern for term in ["checkpoint", "fee", "batch", "index"]) else "access_control" if "signature" in pattern else "business_logic"
        intents.append(
            _intent(
                f"semantic-{index}",
                f"Solidity {pattern} historical audit finding root cause exploit preconditions",
                f"Find historical findings for semantic protocol pattern: {pattern}.",
                vulnerability_class,
                pattern.split(),
            )
        )
    return intents


def _semantic_patterns_from_ir(ir: ProtocolIR) -> list[str]:
    patterns: list[str] = []
    statement_text = " ".join(statement.source_text for statement in ir.statements).lower()
    if "signature" in statement_text and "threshold" in statement_text:
        patterns.append("signature threshold duplicate signer uniqueness")
    if any(lookup.boundary_direction == "lower" for lookup in ir.checkpoint_lookups) and any(
        lookup.boundary_direction in {"upper", "latest"} for lookup in ir.checkpoint_lookups
    ):
        patterns.append("checkpoint boundary lowerLookup upperLookup batch claim eligibility")
    if ir.fee_formulas:
        patterns.append("fee formula dimension D6 D18 shares assets")
    if any(loop for loop in ir.loops if any(term.lower().startswith("report") for term in loop.body_terms)):
        patterns.append("multi report fee accrual repeated handleReport")
    if ir.asset_compatibility_paths:
        patterns.append("native asset receive fallback transfer compatibility")
    if any("cantransfer" in statement.source_text.lower() or "whitelist" in statement.source_text.lower() for statement in ir.statements):
        patterns.append("boolean whitelist canTransfer policy inversion")
    if any("fenwick" in statement.source_text.lower() or "lookup" in statement.source_text.lower() for statement in ir.statements):
        patterns.append("indexed structure key mismatch lookup off by one")
    if any("lockup" in statement.source_text.lower() or "locked" in statement.source_text.lower() for statement in ir.statements):
        patterns.append("lockup transfer bypass minted shares")
    return list(dict.fromkeys(patterns))


def _class_from_finding_terms(finding: HistoricalFinding) -> str:
    text = " ".join([finding.title, finding.summary or "", " ".join(finding.tags), " ".join(finding.root_cause_terms)]).lower()
    if "random" in text or "entropy" in text:
        return "weak_randomness"
    if "access" in text or "owner" in text or "role" in text:
        return "access_control"
    if "account" in text or "vault" in text or "balance" in text:
        return "accounting"
    if "oracle" in text or "price" in text:
        return "oracle_staleness_logic"
    return "business_logic"


def _required_local_evidence(vulnerability_class: str, profile: RepoRAGProfile) -> list[str]:
    if vulnerability_class == "weak_randomness":
        return ["reward/game decision", "predictable chain or caller entropy", "mint/claim/payout effect"]
    if vulnerability_class in {"accounting", "accounting_invariant", "vault_accounting_spoof"}:
        return ["asset flow", "storage accounting write", "withdraw/deposit/custody relation"]
    if vulnerability_class in {"access_control", "missing_access_control"}:
        return ["privileged state write or sensitive external call", "missing or bypassable auth constraint"]
    if vulnerability_class in {"oracle_staleness_logic"}:
        return ["oracle/price read", "freshness/value validation"]
    if profile.asset_terms:
        return ["local asset/accounting evidence", "reachable production function"]
    return []


def _negative_indicators(vulnerability_class: str) -> list[str]:
    if vulnerability_class == "weak_randomness":
        return ["commit-reveal", "VRF/verifiable randomness", "owner-only non-reward path"]
    if vulnerability_class in {"access_control", "missing_access_control"}:
        return ["onlyOwner/onlyRole modifier", "explicit msg.sender authorization"]
    if vulnerability_class in {"accounting", "accounting_invariant", "vault_accounting_spoof"}:
        return ["accounting bound to msg.sender", "balance-delta reconciliation", "trusted-only deposit entrypoint"]
    return ["local counterevidence defeats historical analogy"]


def _exploit_preconditions(vulnerability_class: str) -> list[str]:
    if vulnerability_class == "weak_randomness":
        return ["attacker can influence timing/caller input", "reward outcome depends on predictable entropy"]
    if vulnerability_class in {"accounting", "accounting_invariant", "vault_accounting_spoof"}:
        return ["attacker can reach custody/accounting transition", "accounting and asset custody can diverge"]
    if vulnerability_class in {"access_control", "missing_access_control"}:
        return ["unauthorized caller can reach sensitive function"]
    return ["historical root cause matches local evidence"]


def _validation_questions(vulnerability_class: str) -> list[str]:
    if vulnerability_class == "weak_randomness":
        return ["Can attacker bias or predict the reward branch?"]
    if vulnerability_class in {"accounting", "accounting_invariant", "vault_accounting_spoof"}:
        return ["Can accounting state be assigned to a party different from asset owner/custodian?"]
    if vulnerability_class in {"access_control", "missing_access_control"}:
        return ["Can an unauthorized account execute the sensitive transition?"]
    return ["What local fact proves the historical analogy applies?"]


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
    checklist_items = build_rag_checklist(profile, findings)
    state = TargetedRAGState(
        status=ToolStatus.OK,
        repo_id=profile.repo_id,
        profile_path=str(profile_path),
        normalized_path=str(paths["normalized"]),
        chroma_path=chroma_path,
        finding_count=len(findings),
        fetched_count=fetched_count,
        selected_from_global_count=len(selected),
        checklist_items=checklist_items,
    )
    (root / "targeted_state.json").write_text(json.dumps(state.model_dump(mode="json"), indent=2) + "\n", encoding="utf-8")
    return state
