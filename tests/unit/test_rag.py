from sentinel.config import Settings
from sentinel.rag.normalize import normalize_finding
from sentinel.rag.ranking import rank_matches
from sentinel.rag.solodit import SoloditClient
from sentinel.schemas.rag import HistoricalFindingQuery


def _raw_finding():
    return {
        "id": "finding-1",
        "slug": "oracle-price",
        "title": "Oracle price can be manipulated",
        "content": "A stale oracle price lets an attacker manipulate collateral accounting.",
        "summary": "Oracle manipulation",
        "impact": "HIGH",
        "quality_score": 4,
        "general_score": 3,
        "report_date": "2025-01-01T00:00:00Z",
        "firm_name": "Cyfrin",
        "protocol_name": "Example lending",
        "issues_issuetagscore": [{"tags_tag": {"title": "Oracle"}}],
        "protocols_protocol": {
            "name": "Example lending",
            "protocols_protocolcategoryscore": [{"protocols_protocolcategory": {"title": "DeFi"}, "score": 1}],
        },
        "source_link": "https://example.test/finding",
    }


def test_solodit_client_posts_key_and_default_filters(monkeypatch):
    captured = {}

    class FakeResponse:
        status_code = 200
        headers = {"X-RateLimit-Remaining": "10"}

        def json(self):
            return {"findings": [], "metadata": {"totalPages": 1}, "rateLimit": {"remaining": 10}}

        def raise_for_status(self):
            return None

    def fake_post(url, headers, json, timeout):
        captured.update({"url": url, "headers": headers, "json": json, "timeout": timeout})
        return FakeResponse()

    monkeypatch.setattr("sentinel.rag.solodit.httpx.post", fake_post)
    settings = Settings(solodit_api_key="test-key")

    SoloditClient(settings, sleep_fn=lambda _: None).fetch_page(page=1)

    assert captured["url"].endswith("/findings")
    assert captured["headers"]["X-Cyfrin-API-Key"] == "test-key"
    assert captured["json"]["filters"]["impact"] == ["HIGH", "MEDIUM"]
    assert captured["json"]["filters"]["languages"] == [{"value": "Solidity"}]


def test_normalize_finding_derives_search_fields():
    finding = normalize_finding(_raw_finding())

    assert finding.id == "finding-1"
    assert finding.tags == ["Oracle"]
    assert finding.protocol_categories == ["DeFi"]
    assert finding.vulnerability_class == "oracle"
    assert "Oracle price" in finding.search_text


def test_hybrid_ranking_uses_balanced_score():
    finding = normalize_finding(_raw_finding())
    query = HistoricalFindingQuery(query="oracle price manipulation lending", vulnerability_class="oracle", tags=["Oracle"], protocol_hints=["DeFi"])

    matches = rank_matches(query, [(finding, 0.8)])

    assert matches[0].semantic_score == 0.8
    assert matches[0].final_score > 0.6
    assert "oracle" in matches[0].matched_terms
