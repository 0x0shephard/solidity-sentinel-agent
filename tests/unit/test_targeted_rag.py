from sentinel.config import Settings
from sentinel.rag.store import HistoricalFindingStore, write_findings
from sentinel.rag.targeted import build_repo_rag_profile, build_targeted_rag
from sentinel.schemas.common import ToolStatus
from sentinel.schemas.rag import HistoricalFinding


def _static_facts():
    return {
        "contracts": [{"contract": "LevelOne"}, {"contract": "LevelTwo"}],
        "functions": [
            {"file_path": "src/LevelOne.sol", "line": 250, "contract": "LevelOne", "function": "graduateAndUpgrade", "text": "function graduateAndUpgrade(address _levelTwo, bytes memory) public onlyPrincipal {"},
            {"file_path": "src/LevelOne.sol", "line": 236, "contract": "LevelOne", "function": "startSession", "text": "function startSession(uint256 _cutOffScore) public onlyPrincipal notYetInSession {"},
        ],
        "storage_writes": [
            {"file_path": "src/LevelOne.sol", "line": 239, "contract": "LevelOne", "function": "startSession", "text": "cutOffScore = _cutOffScore;"},
            {"file_path": "src/LevelOne.sol", "line": 257, "contract": "LevelOne", "function": "graduateAndUpgrade", "text": "uint256 payPerTeacher = (bursary * TEACHER_WAGE) / PRECISION;"},
            {"file_path": "src/LevelOne.sol", "line": 260, "contract": "LevelOne", "function": "graduateAndUpgrade", "text": "_authorizeUpgrade(_levelTwo);"},
        ],
        "external_calls": [
            {"file_path": "src/LevelOne.sol", "line": 263, "contract": "LevelOne", "function": "graduateAndUpgrade", "text": "usdc.safeTransfer(listOfTeachers[n], payPerTeacher);"}
        ],
        "token_transfers": [],
        "access_control": [{"file_path": "src/LevelOne.sol", "line": 88, "contract": "LevelOne", "function": "onlyPrincipal", "text": "if (msg.sender != principal) {"}],
    }


def _finding(finding_id: str, title: str, text: str, vuln_class: str) -> HistoricalFinding:
    return HistoricalFinding(
        id=finding_id,
        title=title,
        content=text,
        summary=text,
        vulnerability_class=vuln_class,
        root_cause_terms=text.lower().split()[:8],
        search_text=f"{title} {text}",
    )


def test_repo_profile_extracts_domain_and_targeted_intents():
    profile = build_repo_rag_profile("Test/2025-05-hawk-high", _static_facts())

    assert profile.protocol_domain in {"education_lifecycle", "upgradeable"}
    assert "principal" in profile.role_terms
    assert "bursary" in profile.asset_terms
    assert "upgrade" in profile.upgrade_terms
    assert any(intent.intent_id == "upgrade-flow" for intent in profile.search_intents)
    assert any("bursary" in candidate for candidate in profile.invariant_candidates)


def test_targeted_rag_builds_repo_cache_from_global_fallback(tmp_path, monkeypatch):
    settings = Settings(rag_dir=tmp_path / "rag", solodit_api_key=None)
    global_findings = [
        _finding("upgrade-1", "UUPS authorizeUpgrade does not upgrade", "authorizeUpgrade without upgradeTo breaks upgrade flow", "upgradeability"),
        _finding("accounting-1", "Percentage payout loop overpays", "bursary wage percentage payout missing division by recipients", "accounting"),
    ]
    write_findings(settings, [], global_findings)

    def fake_build(self, findings):
        return str(self.root / "chroma")

    monkeypatch.setattr(HistoricalFindingStore, "build", fake_build)
    result = build_targeted_rag("Test/2025-05-hawk-high", _static_facts(), settings=settings)

    assert result.status == ToolStatus.OK
    assert result.finding_count >= 1
    assert result.selected_from_global_count >= 1
    assert result.profile_path
    assert result.normalized_path
