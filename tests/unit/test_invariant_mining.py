from pathlib import Path

from sentinel.analysis.invariants import build_invariant_proof_packets, build_protocol_model, mine_invariant_candidates
from sentinel.analysis.protocol_ir import build_protocol_ir
from sentinel.schemas.invariants import InvariantCandidate
from sentinel.tools.research import RankHypothesesInput, rank_hypotheses
from sentinel.tools.static import map_function_ranges
from sentinel.tools.repo import RepoPathInput


def test_invariant_miner_uses_production_sources_only(tmp_path: Path):
    src = tmp_path / "src"
    test = tmp_path / "test"
    src.mkdir()
    test.mkdir()
    (src / "School.sol").write_text(
        "\n".join(
            [
                "pragma solidity ^0.8.20;",
                "contract School {",
                "    uint256 public cutOffScore;",
                "    address[] public teachers;",
                "    function setCutOff(uint256 score) external { cutOffScore = score; }",
                "    function payTeachers(uint256 bursary) external {",
                "        for (uint256 i = 0; i < teachers.length; i++) {",
                "            payable(teachers[i]).transfer((bursary * 50) / 100);",
                "        }",
                "    }",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    (test / "School.t.sol").write_text(
        "pragma solidity ^0.8.20; contract SchoolTest { function testCutOffScore() public {} }",
        encoding="utf-8",
    )
    ranges = map_function_ranges(RepoPathInput(repo_path=str(tmp_path)), {}).model_dump(mode="json")["ranges"]
    static_facts = {"function_ranges": ranges, "contracts": [{"contract": "School"}]}

    candidates = mine_invariant_candidates(str(tmp_path), static_facts)
    invariant_types = {candidate.invariant_type for candidate in candidates}

    assert "configured_but_not_enforced" in invariant_types
    assert "percentage_distribution_math" in invariant_types
    assert all(evidence.file_path.startswith("src/") for candidate in candidates for evidence in candidate.production_evidence)


def test_protocol_model_extracts_surface_terms():
    model = build_protocol_model(
        {
            "contracts": [{"contract": "School"}],
            "storage_writes": [{"text": "cutOffScore = score; bursary += amount; owner = msg.sender;"}],
        }
    )

    assert "owner" in model.roles
    assert "score" in model.accounting_terms
    assert "bursary" in model.accounting_terms


def test_invariant_miner_ignores_comment_only_percentage_terms(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "Game.sol").write_text(
        "\n".join(
            [
                "pragma solidity ^0.8.20;",
                "contract Game {",
                "    /// Chance (in percent) to find a reward.",
                "    // The player must first approve the transfer.",
                "    uint256 public eggFindThreshold = 20;",
                "    function setThreshold(uint256 threshold) external {",
                "        eggFindThreshold = threshold;",
                "    }",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    ranges = map_function_ranges(RepoPathInput(repo_path=str(tmp_path)), {}).model_dump(mode="json")["ranges"]

    candidates = mine_invariant_candidates(str(tmp_path), {"function_ranges": ranges, "contracts": [{"contract": "Game"}]})

    assert "percentage_distribution_math" not in {candidate.invariant_type for candidate in candidates}


def test_rank_hypotheses_converts_invariant_candidates():
    candidate = InvariantCandidate(
        id="inv-configured",
        invariant_type="configured_but_not_enforced",
        description="cutOffScore is configured but not enforced.",
        affected_contracts=["School"],
        affected_functions=["setCutOff"],
        production_evidence=[
            {
                "file_path": "src/School.sol",
                "line_start": 5,
                "line_end": 5,
                "contract_name": "School",
                "function_name": "setCutOff",
                "source_text": "cutOffScore = score;",
                "reason": "state variable is written",
            }
        ],
        suspicious_terms=["cutOffScore", "missing guard"],
        recommended_validation_template="configured_but_not_enforced",
        confidence=0.72,
    )

    output = rank_hypotheses(
        RankHypothesesInput(
            objective="Find bugs",
            static_facts=[{"invariant_candidate": candidate.model_dump(mode="json")}],
        ),
        {},
    )

    assert output.hypotheses
    assert output.hypotheses[0].vulnerability_class == "business_logic"
    assert output.hypotheses[0].status == "needs_manual_review"
    assert output.hypotheses[0].evidence_lines[0].file_path == "src/School.sol"


def test_invariant_miner_consumes_protocol_ir_and_checklist_items(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "Vault.sol").write_text(
        "\n".join(
            [
                "pragma solidity ^0.8.20;",
                "interface IERC721 { function transferFrom(address from, address to, uint256 id) external; }",
                "contract Vault {",
                "    IERC721 public nft;",
                "    mapping(uint256 => address) public depositedBy;",
                "    function deposit(uint256 tokenId, address creditedTo) external {",
                "        nft.transferFrom(msg.sender, address(this), tokenId);",
                "        depositedBy[tokenId] = creditedTo;",
                "    }",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    ranges = map_function_ranges(RepoPathInput(repo_path=str(tmp_path)), {}).model_dump(mode="json")["ranges"]
    ir = build_protocol_ir(
        str(tmp_path),
        {
            "function_ranges": ranges,
            "token_types": [{"symbol": "nft", "kind": "erc721", "source": "state_variable"}],
        },
    )

    candidates = mine_invariant_candidates(
        str(tmp_path),
        {
            "function_ranges": ranges,
            "protocol_ir": ir.model_dump(mode="json"),
            "rag_checklist_items": [
                {
                    "checklist_id": "rag-1",
                    "historical_pattern": "Vault accounting attribution can diverge from NFT custody.",
                    "vulnerability_class": "accounting",
                    "required_local_evidence": ["asset flow", "storage accounting write"],
                    "negative_indicators": [],
                    "validation_questions": ["Can creditedTo differ from msg.sender?"],
                }
            ],
        },
    )
    types = {candidate.invariant_type for candidate in candidates}

    assert "custody_accounting_consistency" in types
    assert any(candidate.rag_checklist_refs == ["rag-1"] for candidate in candidates)


def test_invariant_miner_builds_debuggable_proof_packets(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "School.sol").write_text(
        "\n".join(
            [
                "pragma solidity ^0.8.20;",
                "contract School {",
                "    uint256 public cutOffScore;",
                "    function start(uint256 score) external { cutOffScore = score; }",
                "    function graduate() external { }",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    ranges = map_function_ranges(RepoPathInput(repo_path=str(tmp_path)), {}).model_dump(mode="json")["ranges"]
    candidates = mine_invariant_candidates(str(tmp_path), {"function_ranges": ranges, "contracts": [{"contract": "School"}]})

    packets = build_invariant_proof_packets(candidates, {})

    assert packets
    configured = next(packet for packet in packets if packet.invariant_type == "configured_but_not_enforced")
    assert configured.packet_id.startswith("proof-")
    assert configured.proof_obligations
    assert configured.source_evidence[0].file_path == "src/School.sol"


def test_semantic_invariant_miner_finds_signature_and_checkpoint_classes(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "Queues.sol").write_text(
        "\n".join(
            [
                "pragma solidity ^0.8.20;",
                "library Checkpoints { struct Trace224 {} function lowerLookup(Trace224 storage, uint32) internal returns (uint256) {} function upperLookupRecent(Trace224 storage, uint32) internal returns (uint256) {} function latestCheckpoint(Trace224 storage) internal returns (bool,uint32,uint224) {} }",
                "contract Consensus {",
                "    uint256 public threshold;",
                "    mapping(address => uint256) public signers;",
                "    struct Signature { address signer; bytes signature; }",
                "    function checkSignatures(bytes32 orderHash, Signature[] calldata signatures) external view returns (bool) {",
                "        if (signatures.length == 0 || signatures.length < threshold) return false;",
                "        for (uint256 i = 0; i < signatures.length; i++) {",
                "            address signer = signatures[i].signer;",
                "            if (signers[signer] == 0) return false;",
                "        }",
                "        return true;",
                "    }",
                "}",
                "contract RedeemQueue {",
                "    using Checkpoints for Checkpoints.Trace224;",
                "    Checkpoints.Trace224 private prices;",
                "    function claim(uint32 timestamp) external { uint256 index = prices.lowerLookup(timestamp); }",
                "    function handle(uint32 timestamp) external { (, uint32 latestTimestamp, uint224 latestIndex) = prices.latestCheckpoint(); uint256 i = prices.upperLookupRecent(timestamp); i--; }",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    ranges = map_function_ranges(RepoPathInput(repo_path=str(tmp_path)), {}).model_dump(mode="json")["ranges"]
    ir = build_protocol_ir(str(tmp_path), {"function_ranges": ranges})

    candidates = mine_invariant_candidates(str(tmp_path), {"function_ranges": ranges, "protocol_ir": ir.model_dump(mode="json")})
    types = {candidate.invariant_type for candidate in candidates}

    assert "signature_threshold_uniqueness" in types
    assert "checkpoint_boundary_mismatch" in types
    signature = next(candidate for candidate in candidates if candidate.invariant_type == "signature_threshold_uniqueness")
    assert signature.proof_status == "static_proof_complete"
    assert signature.detector_ids == ["semantic.signature_threshold_uniqueness"]


def test_semantic_invariant_miner_finds_fee_formula_and_policy_inversion(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "Managers.sol").write_text(
        "\n".join(
            [
                "pragma solidity ^0.8.20;",
                "library Math { function mulDiv(uint256, uint256, uint256) internal pure returns (uint256) {} }",
                "contract FeeManager {",
                "    uint256 public performanceFeeD6;",
                "    /// Returns true when both accounts are allowed to transfer.",
                "    function updateChecks(address from, address to) external view {",
                "        if (accounts[from].canTransfer || !accounts[to].canTransfer) revert();",
                "    }",
                "    struct Account { bool canTransfer; }",
                "    mapping(address => Account) public accounts;",
                "    function calculateFee(uint256 minPriceD18_, uint256 priceD18, uint256 totalShares) external view returns (uint256 shares) {",
                "        shares = Math.mulDiv(minPriceD18_ - priceD18, performanceFeeD6 * totalShares, 1e24);",
                "    }",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    ranges = map_function_ranges(RepoPathInput(repo_path=str(tmp_path)), {}).model_dump(mode="json")["ranges"]
    ir = build_protocol_ir(str(tmp_path), {"function_ranges": ranges})

    candidates = mine_invariant_candidates(str(tmp_path), {"function_ranges": ranges, "protocol_ir": ir.model_dump(mode="json")})
    types = {candidate.invariant_type for candidate in candidates}

    assert "fee_formula_dimension_mismatch" in types
    assert "boolean_policy_inversion" in types


def test_multi_report_fee_accrual_requires_real_call_path(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "Managers.sol").write_text(
        "\n".join(
            [
                "pragma solidity ^0.8.20;",
                "contract FeeManager {",
                "    uint256 public performanceFeeD6;",
                "    function calculateFee(uint256 priceD18, uint256 totalShares) external view returns (uint256) {",
                "        return (priceD18 * performanceFeeD6 * totalShares) / 1e24;",
                "    }",
                "}",
                "contract Oracle {",
                "    function submitReports(uint256[] calldata reports) external {",
                "        for (uint256 i = 0; i < reports.length; i++) {",
                "            handleReport(reports[i]);",
                "        }",
                "    }",
                "    function handleReport(uint256 report) internal {}",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    ranges = map_function_ranges(RepoPathInput(repo_path=str(tmp_path)), {}).model_dump(mode="json")["ranges"]
    ir = build_protocol_ir(str(tmp_path), {"function_ranges": ranges})

    candidates = mine_invariant_candidates(str(tmp_path), {"function_ranges": ranges, "protocol_ir": ir.model_dump(mode="json")})
    candidate = next(candidate for candidate in candidates if candidate.invariant_type == "multi_report_fee_accrual")

    assert candidate.proof_status == "setup_required"
    assert candidate.confidence < 0.7


def test_multi_report_fee_accrual_strong_only_with_report_share_fee_path(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "Managers.sol").write_text(
        "\n".join(
            [
                "pragma solidity ^0.8.20;",
                "contract FeeManager {",
                "    uint256 public performanceFeeD6;",
                "    function calculateFee(uint256 priceD18, uint256 totalShares) external view returns (uint256) {",
                "        return (priceD18 * performanceFeeD6 * totalShares) / 1e24;",
                "    }",
                "}",
                "contract ShareModule {",
                "    FeeManager public feeManager;",
                "    function handleReport(uint256 report) external { feeManager.calculateFee(report, 1e18); }",
                "}",
                "contract Vault {",
                "    ShareModule public shareModule;",
                "    function handleReport(uint256 report) external { shareModule.handleReport(report); }",
                "}",
                "contract Oracle {",
                "    Vault public vault;",
                "    function submitReports(uint256[] calldata reports) external {",
                "        for (uint256 i = 0; i < reports.length; i++) {",
                "            vault.handleReport(reports[i]);",
                "        }",
                "    }",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    ranges = map_function_ranges(RepoPathInput(repo_path=str(tmp_path)), {}).model_dump(mode="json")["ranges"]
    ir = build_protocol_ir(str(tmp_path), {"function_ranges": ranges})

    candidates = mine_invariant_candidates(str(tmp_path), {"function_ranges": ranges, "protocol_ir": ir.model_dump(mode="json")})
    candidate = next(candidate for candidate in candidates if candidate.invariant_type == "multi_report_fee_accrual")

    assert candidate.proof_status == "strong_local_path"
    assert candidate.confidence >= 0.8


def test_rank_hypotheses_prioritizes_semantic_candidates_over_detector_only():
    semantic = InvariantCandidate(
        id="semantic-signature",
        invariant_type="signature_threshold_uniqueness",
        invariant_family="semantic protocol invariant",
        description="Signature threshold lacks uniqueness.",
        affected_contracts=["Consensus"],
        affected_functions=["checkSignatures"],
        production_evidence=[
            {
                "file_path": "src/Consensus.sol",
                "line_start": 8,
                "line_end": 8,
                "contract_name": "Consensus",
                "function_name": "checkSignatures",
                "source_text": "if (signatures.length < threshold) return false;",
                "reason": "threshold is checked against signature array length",
            }
        ],
        suspicious_terms=["signature threshold", "duplicate signer"],
        detector_ids=["semantic.signature_threshold_uniqueness"],
        recommended_validation_template="signature_uniqueness_threshold",
        confidence=0.86,
        proof_status="strong_local_path",
    )
    weak = InvariantCandidate(
        id="inv-configured",
        invariant_type="configured_but_not_enforced",
        description="role constant is configured but not enforced.",
        production_evidence=[
            {
                "file_path": "src/RiskManager.sol",
                "line_start": 11,
                "line_end": 11,
                "contract_name": "RiskManager",
                "function_name": None,
                "source_text": "bytes32 public constant SET_ROLE = keccak256('SET_ROLE');",
                "reason": "state/accounting variable is written",
            }
        ],
        suspicious_terms=["role", "missing guard"],
        recommended_validation_template="configured_but_not_enforced",
        confidence=0.42,
        is_detector_only=True,
    )

    output = rank_hypotheses(
        RankHypothesesInput(
            objective="Find bugs",
            static_facts=[
                {"invariant_candidate": weak.model_dump(mode="json")},
                {"invariant_candidate": semantic.model_dump(mode="json")},
            ],
        ),
        {},
    )

    assert output.hypotheses[0].vulnerability_class == "access_control"
    assert output.hypotheses[0].source_detection_ids == ["semantic-signature", "semantic.signature_threshold_uniqueness"]
    assert output.hypotheses[0].status == "likely"


# --- stratified invariant reasoning: LLM-inferred candidates are not starved ---

def test_stratify_invariants_gives_llm_inferred_fair_share():
    from sentinel.schemas.invariants import InvariantCandidate
    from sentinel.tools.research import _invariant_source, _stratify_invariants

    def _c(cid, detector_ids=None):
        return InvariantCandidate(
            id=cid, invariant_type="accounting", description="d",
            recommended_validation_template="generic", confidence=0.4,
            detector_ids=detector_ids or [],
        )

    # 10 template-mined + 2 LLM-inferred, appended AFTER (the real ordering).
    template = [_c(f"tmpl-{i}", ["template_miner"]) for i in range(10)]
    llm = [_c("llm-inv-1", ["invariant_inferencer"]), _c("llm-inv-2", ["invariant_inferencer"])]
    candidates = [*template, *llm]

    assert _invariant_source(template[0]) == "template"
    assert _invariant_source(llm[0]) == "llm"

    # The old [:8] slice would never reach the LLM ones; stratified selection does.
    selected = _stratify_invariants(candidates, cap=8)
    assert len(selected) == 8
    ids = {c.id for c in selected}
    assert "llm-inv-1" in ids and "llm-inv-2" in ids  # both LLM-inferred reached
    # and LLM leads the rotation (first picked)
    assert selected[0].id.startswith("llm-inv")


def test_stratify_invariants_respects_cap_and_empty():
    from sentinel.tools.research import _stratify_invariants
    assert _stratify_invariants([], 8) == []
    from sentinel.schemas.invariants import InvariantCandidate
    one = InvariantCandidate(id="x", invariant_type="t", description="d", recommended_validation_template="g", confidence=0.3)
    assert _stratify_invariants([one], 0) == []
    assert len(_stratify_invariants([one], 8)) == 1
