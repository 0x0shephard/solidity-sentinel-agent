from sentinel.rag.checklist import seed_checklists


def test_seed_checklists_cover_required_detector_classes():
    classes = {item.vulnerability_class for item in seed_checklists()}

    assert {
        "tx_origin_authorization",
        "unguarded_initializer",
        "oracle_staleness_logic",
        "unchecked_erc20_return",
        "dangerous_delegatecall",
        "unsafe_or_guard",
        "external_call_before_accounting",
        "strategy_accounting_trust",
    }.issubset(classes)
    assert all(item.required_local_evidence for item in seed_checklists())

