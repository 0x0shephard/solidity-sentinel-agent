---
name: blind-eval
description: Recall benchmarks are now blind-gated; pre-2026-06-24 numbers were inflated by answer leakage
metadata:
  type: project
---

As of 2026-06-24 the recall eval is **blind-gated**, so numbers from before that are NOT comparable
to later ones — earlier runs could read the answers.

Two leaks were closed:
- **Repo audit reports**: target repos ship their own audit (`Test/protocol-v2/audits/sentiment_v2_zobront.md`).
  `repo._safe_files` now hides audit/findings/known-issue dirs+docs when `blind_audit_eval` (default on).
- **Same-project RAG**: the Solodit brain contains the target project's own published findings (16 for
  Sentiment). `rag/store.py::search_documents` drops findings matching `settings.rag_exclude_terms`
  (protocol_name/source/slug/title). The ground-truth JSON declares the terms (e.g. sentiment-v2.json has
  `"rag_exclude_terms": ["sentiment"]`); the `benchmark` CLI sets the env var from it automatically.

To run a blind benchmark: just `sentinel benchmark --ground-truth <gt.json> --real-llm` — exclusion is
automatic if the gt file declares it. A real bug-bounty target won't have either leak. Replay artifacts
are now immutable: `exploit-replay/<ts>-<hyp>/` with a `replay-meta.json` (model, commit, verdict, plan).
Related: [[dsl-proof-token]], [[never-commit]].
