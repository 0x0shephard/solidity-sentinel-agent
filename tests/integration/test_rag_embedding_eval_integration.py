from sentinel.config import Settings
from sentinel.evals.rag_embeddings import RAGEvalFixture, RAGEvalQuery, evaluate_embedding_models
from sentinel.rag.canonical import build_finding_documents
from sentinel.rag.store import HistoricalFindingStore, load_findings, write_findings
from sentinel.schemas.rag import EmbeddingModelInfo, HistoricalFinding


def _finding(finding_id: str, title: str, vuln_class: str, text: str) -> HistoricalFinding:
    return HistoricalFinding(
        id=finding_id,
        title=title,
        content=text,
        summary=text,
        vulnerability_class=vuln_class,
        root_cause_terms=text.lower().split()[:6],
        tags=[vuln_class],
        search_text=f"{title} {text}",
    )


def test_rag_embedding_eval_writes_reports_and_metadata(tmp_path, monkeypatch):
    settings = Settings(rag_dir=tmp_path / "rag")
    corpus = [
        _finding("f1", "UUPS upgrade bug", "upgradeability", "authorizeUpgrade upgradeTo implementation slot"),
        _finding("f2", "Accounting overpayment", "accounting", "percentage distribution overpayment recipient count"),
        _finding("f3", "Oracle stale price", "oracle", "stale oracle price freshness"),
        _finding("f4", "Access control missing", "access_control", "missing authorization admin role"),
        _finding("f5", "Storage layout mismatch", "storage_layout", "upgradeable storage layout proxy corruption"),
    ]
    write_findings(settings, [], corpus)

    def fake_build(self, findings):
        self._write_metadata(
            findings,
            document_count=len(findings) * 5,
            model_info=EmbeddingModelInfo(model_name=self.settings.rag_embed_model, dimension=384, provider="sentence_transformers"),
        )
        return str(self.root / "chroma")

    def fake_search_documents(self, query, candidate_k=25):
        findings = load_findings(self.settings, self.root)
        query_terms = set(query.query.lower().split())
        rows = []
        for finding in findings:
            for doc in build_finding_documents(finding):
                hits = sum(1 for term in query_terms if term in doc["text"].lower())
                if hits:
                    rows.append({"finding": finding, "score": min(1.0, hits / 4), "view_type": doc["metadata"]["view_type"], "metadata": doc["metadata"]})
        return sorted(rows, key=lambda row: row["score"], reverse=True)[:candidate_k]

    monkeypatch.setattr(HistoricalFindingStore, "build", fake_build)
    monkeypatch.setattr(HistoricalFindingStore, "search_documents", fake_search_documents)

    fixture = RAGEvalFixture(
        fixture_name="tiny",
        queries=[
            RAGEvalQuery(
                query_id="q1",
                hypothesis_class="upgradeability",
                query="authorizeUpgrade upgradeTo implementation slot",
                root_cause_terms=["authorizeUpgrade", "upgradeTo"],
                expected_vulnerability_classes=["upgradeability"],
                expected_terms=["authorizeUpgrade", "upgradeTo"],
                relevant_finding_ids=["f1"],
            )
        ],
    )

    report = evaluate_embedding_models(
        fixture,
        ["sentence-transformers/all-MiniLM-L6-v2"],
        rebuild=True,
        settings=settings,
        output_dir=tmp_path / "rag_eval",
    )

    assert (tmp_path / "rag_eval" / "results.json").exists()
    assert (tmp_path / "rag_eval" / "results.md").exists()
    assert report.models[0].dimension == 384
    assert 0.0 <= report.models[0].canonical_query.metrics.recall_at_10 <= 1.0
    assert report.best_balanced_model == "sentence-transformers/all-MiniLM-L6-v2"
