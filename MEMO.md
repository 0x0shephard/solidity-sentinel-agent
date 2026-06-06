# Solidity Sentinel Memo

## What I Built

Solidity Sentinel is a LangGraph/LangChain autonomous agent for Solidity repository triage. It is a **reason→verify auditor**, not a static-detector wrapper: the model drives an 11-stage audit pipeline, proposes code-grounded hypotheses, and adversarially verifies each one against its cross-contract callers.

- **107 tools across 8 namespaces** (`repo`, `build`, `static`, `research`, `dynamic`, `report`, `memory`, and composite `audit`) behind one typed `RegisteredTool` model and a single `ToolExecutor` enforcement boundary (schema-validate in → run → schema-validate out → ledger → declarative `state_effects` → budget check). No conditional dispatch chain.
- **Model-driven control.** With `--real-llm`, `plan_with_llm` is the spine: it loops (up to `planner_max_rounds`) calling self-healing composite `audit.*` tools that run the pipeline through any milestone. Each of the 11 stage nodes is idempotent (`@_stage` guards skip completed milestones), so the deterministic chain is a guarded gap-filler, not the default path. Anti-repeat + per-milestone tool hints keep the planner from looping.
- **Two real subagents in isolated contexts.** The research subagent (`ResearchState`, scoped `research.*` tools enforced by `validate_scope`) runs propose-refine-**adversarial review**-result and returns a structured `ResearchSubgraphResult`; a RAG subagent grades historical-finding context (self-RAG).
- **Hypothesis generation, grounded.** `research.propose_hypotheses` feeds the model real protocol source (function bodies + attack-path slices + Solodit checklist), and only accepts proposals that ground to a real `src/` function — hallucinated file/function citations are dropped. Cross-contract callers/callees are attached as evidence so findings span ≥2 contracts.
- **Adversarial verification.** For each lead, the reviewer is shown the affected function plus its cross-contract callers and rules `confirmed` (with an attack trace) or `rejected` (with counterevidence, e.g. an atomic factory/proxy `initialize`). On a real Lido/Mellow vault codebase this auto-rejected two front-running false positives with cited counterevidence.
- **Production scaffolding.** Observability (structlog + LangSmith with a safe preflight + `tool_ledger.jsonl`), tenacity retries with exponential backoff and a token-bucket rate limiter on every LLM call (`llm/resilience.py`), typed error hierarchy, a ~30-metric eval harness, a ground-truth **recall benchmark** (`sentinel benchmark`), ~170 unit+integration tests, and slimmed run artifacts (state.json ~18× smaller).
- **Solodit RAG**, dependency-tolerant (runs without Chroma; a fresh install enables the vector path), used as historical context only — never as proof of a target-repo bug.

## What I Cut

I kept RAG and Chroma optional so the agent runs in a minimal venv. I did not build a from-scratch Solidity parser — static facts come from regex/Slither extraction feeding a Protocol IR, which is good enough for call-graph and evidence grounding but misses some semantic precision. Validation artifacts are emitted as plans for most classes rather than always-compiling Foundry PoCs. The deterministic graph remains as a fallback rather than being deleted, because it guarantees a complete audit when the model stalls or the endpoint fails.

## What More Time Would Address

In priority order for real-world usefulness: (1) swap in a frontier model for the proposer/reviewer — quality and verdict consistency are model-bound today; (2) raise recall with iterative/budgeted proposing and broader vuln-class coverage (current proposer emits 3–6 hypotheses); (3) make PoCs executable — compile a failing `forge test` against the target and pass-after-fix; (4) sandbox the `forge`/`slither` subprocess in a container; (5) richer counterevidence gathering (deployment scripts, test setup, modifiers) for more consistent rejections. The recall benchmark added here is the gate that makes (1)–(2) measurable.

## Design Decision I Would Defend

**Composite `audit.*` tools + idempotent stages, instead of either a pure LLM ReAct loop or a fixed pipeline.** An engineer might reasonably have built a single ReAct agent that free-forms every tool call. I made each pipeline stage an idempotent node and exposed a self-healing composite tool per milestone, so the model genuinely *drives* (it selects and sequences the stages, and `research.propose_hypotheses`/the reviewer are real model decisions) while a guarded deterministic chain guarantees a complete, reproducible audit if the model stalls, repeats, or the remote endpoint drops a connection. This buys autonomy *and* reliability — which matters because an audit report that silently half-runs is worse than useless. The cost is that pipeline ordering is encoded in `_PIPELINE` rather than discovered by the model; I accept that trade for determinism and debuggability of a security tool.
