from __future__ import annotations

from collections import Counter, defaultdict
import json
from pathlib import Path

from sentinel.config import get_settings
from sentinel.schemas.static import SoloditChecklistItem


SEED_CHECKLISTS = [
    SoloditChecklistItem(
        checklist_id="solodit-access-tx-origin",
        vulnerability_class="tx_origin_authorization",
        historical_titles=["Authorization bypasses caused by weak caller identity checks"],
        root_cause_terms=["tx.origin", "authorization bypass", "caller identity"],
        code_indicators=["tx.origin", "owner", "keeper", "role", "onlyOwner", "onlyKeeper"],
        required_local_evidence=["tx.origin appears in an authorization or bypass condition"],
        negative_indicators=["tx.origin only emitted or logged"],
        validation_questions=["Can a malicious intermediary satisfy the tx.origin branch?"],
        reporting_guidance="Report only when tx.origin participates in access control or a security bypass.",
    ),
    SoloditChecklistItem(
        checklist_id="solodit-initializer-unguarded",
        vulnerability_class="unguarded_initializer",
        historical_titles=["Initialization functions can be re-run or front-run"],
        root_cause_terms=["initializer", "owner initialization", "one-time guard"],
        code_indicators=["initialize", "owner =", "initialized =", "treasury =", "keeper ="],
        required_local_evidence=["public or external initializer writes privileged state without a one-time guard"],
        negative_indicators=["initializer modifier", "onlyInitializing", "require(!initialized)", "reinitializer"],
        validation_questions=["Can initialize be called after deployment by a non-owner or called twice?"],
        reporting_guidance="Cite the initializer signature and privileged writes.",
    ),
    SoloditChecklistItem(
        checklist_id="solodit-oracle-staleness",
        vulnerability_class="oracle_staleness_logic",
        historical_titles=["Oracle validation accepts stale, incomplete, or inverted checks"],
        root_cause_terms=["oracle", "stale price", "freshness", "unsafe OR"],
        code_indicators=["oracle", "price", "updatedAt", "latestRoundData", "block.timestamp", "||"],
        required_local_evidence=["oracle read and freshness/value checks are incomplete or OR-combined"],
        negative_indicators=["p > 0 &&", "updatedAt != 0 &&", "block.timestamp - updatedAt <"],
        validation_questions=["Can either value validity or freshness pass alone?"],
        reporting_guidance="Separate the oracle read from the unsafe validation line.",
    ),
    SoloditChecklistItem(
        checklist_id="solodit-token-return",
        vulnerability_class="unchecked_erc20_return",
        historical_titles=["Token call succeeds while ERC20 return value is ignored"],
        root_cause_terms=["unchecked ERC20 return", "low-level token call", "SafeERC20"],
        code_indicators=["transfer(", "transferFrom(", "approve(", "abi.encodeWithSelector", "call("],
        required_local_evidence=["ERC20 transfer/approve return data is ignored or only low-level call success is checked"],
        negative_indicators=["SafeERC20", "safeTransfer", "safeTransferFrom", "abi.decode", "require(token.transfer"],
        validation_questions=["What happens when the token returns false with successful call status?"],
        reporting_guidance="Cite the ignored token operation and the accounting that assumes success.",
    ),
    SoloditChecklistItem(
        checklist_id="solodit-delegatecall-control",
        vulnerability_class="dangerous_delegatecall",
        historical_titles=["Delegatecall to user-controlled or plugin-controlled target corrupts caller storage"],
        root_cause_terms=["delegatecall", "user-controlled target", "storage corruption"],
        code_indicators=["delegatecall", "abi.decode", "bytes calldata", "migration", "batch", "plugin", "strategy"],
        required_local_evidence=["delegatecall target or payload is externally controlled or insufficiently constrained"],
        negative_indicators=["delegatecall to immutable trusted implementation"],
        validation_questions=["Can caller-provided data choose code that executes in this contract context?"],
        reporting_guidance="Cite target derivation and the delegatecall line.",
    ),
    SoloditChecklistItem(
        checklist_id="solodit-unsafe-or-guard",
        vulnerability_class="unsafe_or_guard",
        historical_titles=["OR-combined guards allow one weak branch to bypass intended constraints"],
        root_cause_terms=["unsafe OR", "parameter guard", "freshness guard", "authorization guard"],
        code_indicators=["require(", "||", "owner", "fee", "limit", "updatedAt", "block.timestamp"],
        required_local_evidence=["security-sensitive require uses OR where all constraints appear intended"],
        negative_indicators=["intentional alternative access path with equivalent strength"],
        validation_questions=["Can an attacker satisfy only the weakest branch?"],
        reporting_guidance="Explain why the guard likely needs AND or separate checks.",
    ),
    SoloditChecklistItem(
        checklist_id="solodit-external-before-accounting",
        vulnerability_class="external_call_before_accounting",
        historical_titles=["External control flow occurs before balance or debt accounting is finalized"],
        root_cause_terms=["external call before state update", "reentrancy", "accounting order"],
        code_indicators=["call(", "transfer(", "onFlashLoan", "hook", "beforeWithdraw", "_burn", "balanceOf", "totalSupply"],
        required_local_evidence=["external call precedes related balance, supply, debt, or reward update in same function"],
        negative_indicators=["nonReentrant", "state update before external call"],
        validation_questions=["Can callback observe or alter stale accounting state?"],
        reporting_guidance="Cite both the external call line and the later accounting line.",
    ),
    SoloditChecklistItem(
        checklist_id="solodit-strategy-accounting-trust",
        vulnerability_class="strategy_accounting_trust",
        historical_titles=["Strategy reports or calls are trusted without reconciliation"],
        root_cause_terms=["strategy trust", "debt accounting", "external report", "unreconciled assets"],
        code_indicators=["strategy", "debt", "estimatedTotalAssets", "trusted", "totalManagedDebt", "withdraw("],
        required_local_evidence=["external strategy value or call result drives accounting without strict reconciliation"],
        negative_indicators=["balance delta reconciliation", "trusted immutable strategy allowlist"],
        validation_questions=["Can a strategy over-report, under-return, or pass a trusted branch after call failure?"],
        reporting_guidance="Cite the external strategy read/call and the resulting accounting mutation.",
    ),
]


def seed_checklists() -> list[SoloditChecklistItem]:
    return [SoloditChecklistItem.model_validate(item.model_dump(mode="json")) for item in SEED_CHECKLISTS]


def checklist_by_id() -> dict[str, SoloditChecklistItem]:
    return {item.checklist_id: item for item in seed_checklists()}


def build_solodit_checklists_from_cache(limit_titles: int = 5) -> list[SoloditChecklistItem]:
    settings = get_settings()
    normalized_path = Path(settings.rag_dir) / "solodit_normalized_findings.jsonl"
    if not normalized_path.exists():
        return seed_checklists()

    grouped: dict[str, list[dict]] = defaultdict(list)
    with normalized_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            item = json.loads(line)
            grouped[str(item.get("vulnerability_class") or "manual_review")].append(item)

    generated = seed_checklists()
    existing_classes = {item.vulnerability_class for item in generated}
    for vulnerability_class, findings in grouped.items():
        if vulnerability_class in existing_classes or vulnerability_class == "manual_review":
            continue
        terms = Counter(term for finding in findings for term in finding.get("root_cause_terms", []))
        titles = [str(finding.get("title")) for finding in findings[:limit_titles] if finding.get("title")]
        common_terms = [term for term, _ in terms.most_common(10)]
        generated.append(
            SoloditChecklistItem(
                checklist_id=f"solodit-derived-{vulnerability_class.replace('_', '-')}",
                vulnerability_class=vulnerability_class,
                historical_titles=titles,
                root_cause_terms=common_terms,
                code_indicators=common_terms[:8],
                required_local_evidence=["local source evidence matching historical root-cause terms"],
                negative_indicators=[],
                validation_questions=[f"Does local evidence prove the {vulnerability_class} root cause?"],
                reporting_guidance="Use derived Solodit class as context only; cite local source evidence.",
            )
        )
    return generated


def write_generated_checklists() -> Path:
    settings = get_settings()
    out_path = Path(settings.rag_dir) / "solodit_checklists.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    items = build_solodit_checklists_from_cache()
    out_path.write_text(json.dumps([item.model_dump(mode="json") for item in items], indent=2), encoding="utf-8")
    return out_path

