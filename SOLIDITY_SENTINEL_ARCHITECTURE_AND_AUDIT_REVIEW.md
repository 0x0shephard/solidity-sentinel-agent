# Solidity Sentinel Architecture and Audit Review

## Current Architecture

```text
CLI
  |
  v
LangGraph parent audit graph
  |
  +-- initialize_run
  |
  +-- maybe_sync_solodit_rag
  |     |
  |     +-- global Solodit cache
  |     |     data/rag/solodit_raw_cache.jsonl
  |     |     data/rag/solodit_normalized_findings.jsonl
  |     |     data/rag/chroma/
  |     |
  |     +-- stale-ok behavior
  |           use old cache if refresh fails
  |
  +-- inspect_repo
  |     |
  |     +-- list files
  |     +-- find Solidity contracts
  |     +-- basic text probes
  |
  +-- detect_framework
  |     |
  |     +-- Foundry detection
  |     +-- solc detection
  |     +-- forge availability
  |     +-- Slither availability
  |
  +-- run_static_analysis
  |     |
  |     +-- generic fact extraction
  |     |     functions
  |     |     function ranges
  |     |     access-control terms
  |     |     external calls
  |     |     token transfers
  |     |     storage writes
  |     |
  |     +-- pattern detectors
  |     |     tx.origin auth
  |     |     unguarded initializer
  |     |     oracle staleness
  |     |     unchecked ERC20 returns
  |     |     delegatecall
  |     |     unsafe OR guards
  |     |     external call before accounting
  |     |     strategy accounting trust
  |     |
  |     +-- Slither, if available
  |
  +-- build_targeted_rag_context
  |     |
  |     +-- build repo profile
  |     |     protocol domain
  |     |     contracts/functions
  |     |     role terms
  |     |     asset terms
  |     |     upgrade terms
  |     |     lifecycle terms
  |     |     invariant candidates
  |     |
  |     +-- build repo-specific RAG cache
  |           data/rag/repo_profiles/<repo-id>/profile.json
  |           data/rag/repo_profiles/<repo-id>/solodit_normalized_findings.jsonl
  |           data/rag/repo_profiles/<repo-id>/chroma/
  |
  +-- rank_hypotheses
  |     |
  |     +-- static detections become hypotheses
  |     +-- Slither findings become hypotheses
  |     +-- repo-profile invariant intents become manual-review hypotheses
  |
  +-- rag_retrieve_context
  |     |
  |     +-- Self-RAG subgraph per top hypothesis
  |           expand 3-5 queries
  |           retrieve targeted cache first
  |           fallback to global cache
  |           merge and dedupe
  |           grade retrieval quality
  |           repair weak retrieval once
  |           critique historical matches
  |           keep only safe-to-cite matches
  |
  +-- research_subgraph
  |     |
  |     +-- isolated scoped subagent
  |     +-- research tools only
  |     +-- receives hypothesis, source snippets, and RAG bundle
  |     +-- returns structured ResearchSubgraphResult
  |
  +-- summarize_context
  |
  +-- finish
        |
        +-- generate validation artifacts
        +-- compile/run validation artifacts when possible
        +-- write state.json
        +-- write report.json
        +-- write report.md
```

## Audit Flow

1. The user runs `sentinel audit --repo <repo> --objective <objective>`.
2. The parent graph creates a run directory under `runs/<run-id>/`.
3. The Solodit global RAG cache is synced or reused in stale-ok mode.
4. The repository is inspected for Solidity files, tests, framework metadata, and compiler version.
5. Static extraction collects local facts from source, test, and script files.
6. Static detectors produce structured `StaticDetection` objects when local evidence satisfies detector-specific rules.
7. A repo profile is built from contracts, functions, storage terms, lifecycle terms, role terms, asset terms, and upgrade terms.
8. A targeted Solodit context is built for the repo profile. It attempts focused Solodit fetches and also selects relevant findings from the global cache.
9. Hypotheses are ranked from static detections, analyzer output, and repo-profile invariant candidates.
10. Self-RAG runs for the top hypotheses and attaches only safe-to-cite historical context.
11. A scoped research subagent challenges each top hypothesis and returns a structured result.
12. Reporting separates confirmed/likely findings from manual-review and rejected hypotheses.
13. Final artifacts are written locally.

## Current Hawk High Review

Latest deterministic run:

```text
Run ID: 20260603-192310-463fd7
Repository: Test/2025-05-hawk-high
Tool calls: 39
Research subgraphs: 5
Hypotheses: 5
Findings/manual-review items: 5
Targeted RAG selected findings: 108
Repo profile domain: education_lifecycle
```

The targeted RAG upgrade improved recall shape: the agent now surfaces business-logic, upgradeability, storage-layout, and accounting review tracks instead of collapsing to one unchecked-ERC20 hypothesis.

However, the report is still not audit-grade for Hawk High. The confirmed finding is based on test-file `approve` calls, while the high-value benchmark findings are in `src/LevelOne.sol` and `src/LevelTwo.sol`.

Major reference findings still missed or not strongly grounded:

- Missing `cutOffScore` enforcement in `graduateAndUpgrade`.
- Missing division by `totalTeachers` in teacher payout math.
- UUPS upgrade flow calls `_authorizeUpgrade` but does not execute `upgradeTo` or `upgradeToAndCall`.
- Bursary accounting after graduation is incorrect or incomplete.
- Bursary funds can remain idle.
- LevelOne and LevelTwo storage layouts are inconsistent.
- Initialization and reinitialization risks need stronger upgradeability analysis.
- `reviewCount` is checked but never incremented.
- Session lifecycle checks are incomplete.
- Unbounded loops over teachers/students create gas and DoS risks.

## Issues

### 1. Production Source Evidence Is Too Weak

The agent currently allows `test/` and `script/` evidence to drive hypotheses and final findings. Tests and scripts are useful for understanding behavior, but final security findings should normally require dangerous local evidence from production contracts under `src/`.

Recommended change:

```text
source priority:
  1. src/
  2. contracts/
  3. libraries used by src/
  4. script/ as deployment context only
  5. test/ as behavioral context only
```

### 2. Business-Logic Detection Is Still Shallow

The repo profile creates useful review lanes, but it does not yet prove protocol-specific invariant violations. Hawk High is mostly a business-logic benchmark, not a classic exploit-pattern benchmark.

Needed detectors:

- unused critical config variable detector
- accounting percentage distribution detector
- UUPS upgrade execution detector
- storage layout diff detector
- state variable checked but never updated detector
- lifecycle guard detector
- stuck funds detector
- unbounded loop DoS detector

### 3. RAG Is Better, But Still Downstream Of Hypothesis Quality

Targeted Solodit context selected 108 relevant historical findings, but RAG cannot fix weak local hypothesis generation by itself. Historical findings should guide questions, not substitute for local evidence.

### 4. Slither and Build Failures Need Report-Level Visibility

If Foundry build or Slither fails, the final report should include a clear limitations section. Otherwise the report can look more complete than the analysis really was.

### 5. Validation Artifacts Are Too Generic

The current validation artifact generation still targets generic classes. Hawk High needs generated PoCs for concrete invariants:

- below-cutoff student still graduates
- three teachers cause overpayment/DoS
- implementation slot unchanged after `graduateAndUpgrade`
- `reviewCount` remains zero after reviews
- LevelTwo storage values are misread after upgrade

## Recommendations

### Immediate

1. Exclude `test/` and `script/` from confirmed findings unless explicitly requested.
2. Keep `test/` and `script/` as context for behavior and PoC generation.
3. Add a report warning when confirmed findings do not cite production source.
4. Add build/Slither failure summaries to `report.md`.
5. Add a Hawk High eval fixture with expected high/medium classes from the reference report.

### Next Implementation Layer

Add `static.detect_business_logic_invariants` with sub-checks:

```text
configured_but_not_enforced:
  set cutOffScore
  no comparison against studentScore during graduate/upgrade path

percentage_distribution_math:
  payPerTeacher = bursary * percentage / precision
  loop transfers payPerTeacher to every teacher
  no division by totalTeachers

upgrade_authorization_without_upgrade:
  UUPSUpgradeable imported/inherited
  _authorizeUpgrade called from public lifecycle function
  no upgradeTo/upgradeToAndCall in same path

storage_layout_mismatch:
  compare state variable order/types across upgrade implementations

checked_but_never_updated:
  reviewCount checked
  no reviewCount increment/write

lifecycle_missing_guard:
  sessionEnd set
  graduation/upgrade path does not require block.timestamp >= sessionEnd

stuck_funds:
  funds collected into bursary
  no complete withdrawal/distribution/reconciliation path

unbounded_loop_dos:
  loops over dynamic role/user arrays in privileged lifecycle functions
```

### Medium-Term

1. Add AST-backed extraction through `solc --ast-json` or Slither AST when build succeeds.
2. Add storage-layout extraction through Foundry/OpenZeppelin tooling.
3. Add invariant mining from variable/function names and comments.
4. Add a validation-test generator that uses hypothesis-specific templates.
5. Add separate scoring for:
   - source evidence quality
   - production-source coverage
   - hypothesis recall
   - finding recall
   - RAG usefulness
   - unsupported claim rate

## Quality Rating After Targeted RAG Upgrade

```text
Architecture:                 8/10
Tool registry/coherence:       8/10
RAG infrastructure:            8/10
Self-RAG flow:                 7/10
Subagent orchestration:        8/10
Evidence-grounded reporting:   5/10
Business-logic bug recall:     3/10
Hawk High audit usefulness:    4/10
```

The architecture is now strong enough to support serious improvements. The next bottleneck is not orchestration, RAG, or LangGraph structure. The bottleneck is local semantic understanding of protocol invariants and production-source evidence quality.

## Defensible Design Decision

The targeted Solodit layer remains additive and fail-soft instead of replacing the global RAG cache. This is the right tradeoff because targeted fetches depend on Solodit API filter behavior and repo-profile quality. A global cache gives stable fallback recall, while repo-specific caches improve relevance when profile extraction works.

The alternative would be to fetch only target-specific Solodit data per audit. That would be more fragile, slower, harder to reproduce, and vulnerable to bad profile queries. The current hybrid design is safer for production use.
