# Solidity Sentinel Agent

Solidity Sentinel is a production-shaped autonomous agent for Solidity repository triage. It combines a typed tool registry, a LangGraph audit pipeline, model-driven planning, Solodit-backed Self-RAG, scoped research subagents, Protocol IR, validation artifacts, LangSmith-compatible observability, and fixture/eval scoring.

The main command is:

```bash
sentinel audit --repo <repo> --objective "Find bugs" --real-llm
```

Every audit writes a reproducible run folder under `runs/<run_id>/` with a human report, structured state, tool ledger, RAG telemetry, protocol graph, proof packets, and validation artifacts.

## Repository Layout

```text
src/sentinel/
  cli.py                  CLI entrypoint
  graphs/parent.py        Main LangGraph audit pipeline and LLM planner spine
  graphs/research.py      Isolated per-hypothesis research subagent
  graphs/rag_subgraph.py  Self-RAG retrieval, repair, critique, and bundle graph
  tools/                  Typed tool registry implementations
  analysis/               Protocol IR, contest reasoning, gap hunters, invariants
  rag/                    Solodit sync, Chroma store, retrieval and ranking
  evals/                  Fixture and recall evaluation harness

runs/<run_id>/            Per-audit outputs
data/rag/                 Gitignored Solodit and Chroma cache
data/memory/              Gitignored advisory long-term memory
assets/                   Architecture diagram and submission assets
```

## Requirements

Recommended local tools:

- Python 3.12+
- Foundry, for `forge build` and generated validation artifacts
- Slither, optional but useful for deeper static analysis
- A real LLM provider: Hugging Face hosted inference/router or Ollama-compatible REST
- A Solodit API key for fresh historical-finding RAG
- Optional LangSmith API key for tracing

Check Solidity tooling:

```bash
forge --version
slither --version
```

If Slither is not installed, the agent still runs with partial static facts and records completeness gaps.

## Install

From the repository root:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/pip install -e .
.venv/bin/sentinel --help
```

If the virtual environment already exists:

```bash
source .venv/bin/activate
python -m pip install -e .
```

Verify Python dependencies:

```bash
.venv/bin/python - <<'PY'
from langgraph.graph import StateGraph
from langchain_ollama import ChatOllama
from langchain_huggingface import ChatHuggingFace
print("LangGraph/LangChain dependencies import successfully")
PY
```

## Configure Environment

Create a local `.env`:

```bash
cp .env.example .env
```

Never commit real API keys. If a key has ever been pasted into a chat or public place, regenerate it before use.

Load the environment before running:

```bash
set -a
source .env
set +a
```

## LLM Runtime

### Hosted Hugging Face

The documented real-audit default is hosted Hugging Face inference/router:

```env
SENTINEL_LLM_PROVIDER=huggingface
SENTINEL_MODEL=Qwen/Qwen2.5-Coder-32B-Instruct
HF_BASE_URL=https://router.huggingface.co/v1
HF_TOKEN=...
```

This keeps the larger model remote and avoids pulling a 32B model locally.

### Ollama-Compatible REST

Ollama can be local or cloud-hosted:

```env
SENTINEL_LLM_PROVIDER=ollama
SENTINEL_MODEL=gemma4:31b
OLLAMA_BASE_URL=https://ollama.com
OLLAMA_API_KEY=...
```

For local Ollama:

```env
SENTINEL_LLM_PROVIDER=ollama
SENTINEL_MODEL=qwen2.5-coder:7b
OLLAMA_BASE_URL=http://localhost:11434
```

You can override provider settings in the shell for a single run:

```bash
export SENTINEL_LLM_PROVIDER=ollama
export SENTINEL_MODEL=gemma4:31b
export OLLAMA_BASE_URL=https://ollama.com
```

## LangSmith Tracing

LangSmith is optional. When enabled and the key/project are valid, Sentinel traces planner calls, tool calls, graph transitions, subagent runs, RAG events, and retry/backoff events.

```env
LANGSMITH_TRACING=true
LANGSMITH_API_KEY=...
LANGSMITH_PROJECT=solidity-sentinel-agent
```

If tracing returns `403 Forbidden`, disable tracing for the run or verify the endpoint/project/account permissions:

```bash
export LANGSMITH_TRACING=false
export LANGCHAIN_TRACING_V2=false
export LANGCHAIN_TRACING=false
```

Local artifacts are always written even when LangSmith is disabled:

```text
tool_ledger.jsonl
state.json
report.json
report.md
retrieval_telemetry.jsonl
```

## Solodit RAG

Solodit RAG gives the agent historical context from prior findings. It is used as checklist and citation context, never as proof of a local bug.

Required `.env` settings:

```env
SOLODIT_API_URL=https://solodit.cyfrin.io/api/v1/solodit
SOLODIT_API_KEY=sk_new_key_here
SENTINEL_RAG_DIR=data/rag
SENTINEL_RAG_EMBED_MODEL=sentence-transformers/all-MiniLM-L6-v2
SENTINEL_RAG_FILTER_LANGUAGES=Solidity
SENTINEL_RAG_FILTER_IMPACTS=HIGH,MEDIUM
SENTINEL_RAG_QUALITY_SCORE=2
```

Sync historical findings:

```bash
.venv/bin/sentinel rag sync
```

Use strict mode when you want missing/invalid Solodit credentials to fail instead of falling back to stale cache:

```bash
.venv/bin/sentinel rag sync --strict
```

Expected successful output looks like:

```text
Status: ok
Findings: 1850
Pages: 19
Chroma: data/rag/chroma
```

The sync writes:

```text
data/rag/solodit_raw_cache.jsonl
data/rag/solodit_normalized_findings.jsonl
data/rag/sync_state.json
data/rag/index_metadata.json
data/rag/chroma/
```

Every Chroma index is fingerprinted with the embedding model, embedding dimension, corpus hash, canonical text version, chunking version, document count, and collection name. Retrieval refuses to use an incompatible index to avoid silent query/document embedding mismatch.

Rebuild indexes after changing embedding models:

```bash
.venv/bin/sentinel rag rebuild --scope global
.venv/bin/sentinel rag rebuild --scope repo --repo Test/2025-05-hawk-high
.venv/bin/sentinel rag rebuild --scope all --repo Test/2025-05-hawk-high
```

MiniLM is the default because it is fast and local-friendly. MPNet/BGE may improve retrieval quality, but they require more compute and an index rebuild. Use the eval harness before changing defaults:

```bash
.venv/bin/sentinel rag eval-embeddings --all
```

## Run A Full Audit

Load environment:

```bash
set -a
source .env
set +a
```

Optional: select Ollama cloud for this run:

```bash
export SENTINEL_LLM_PROVIDER=ollama
export SENTINEL_MODEL=gemma4:31b
export OLLAMA_BASE_URL=https://ollama.com
```

Optional: enable LangSmith if configured:

```bash
export LANGSMITH_TRACING=true
export LANGCHAIN_TRACING_V2=false
export LANGCHAIN_TRACING=false
```

Run an audit:

```bash
.venv/bin/sentinel audit \
  --repo Test/2025-07-orderbook \
  --objective "Find bugs in this Foundry smart contract repo. Use static detectors, protocol invariant mining, proof packets, Solodit RAG, Self-RAG, research subagent validation, and produce evidence-grounded findings." \
  --real-llm
```

Typical completion output:

```text
Run ID: 20260604-182315-32a6c8
Status: completed
Tool calls: 48
Current focus: done
State: runs/20260604-182315-32a6c8/state.json
Report: runs/20260604-182315-32a6c8/report.md
```

For a deterministic local smoke run without a real LLM:

```bash
.venv/bin/sentinel audit \
  --repo Test/2025-07-orderbook \
  --objective "Find bugs"
```

## Inspect A Run

Replace `<run_id>` with the printed run ID:

```bash
RUN=runs/<run_id>
sed -n '1,220p' "$RUN/report.md"
head -n 5 "$RUN/tool_ledger.jsonl"
sed -n '1,120p' "$RUN/state.json"
```

Important files:

```text
report.md                  Human-readable audit report
report.json                Structured report for evals and automation
state.json                 Slim final AuditState
tool_ledger.jsonl          Chronological tool-call ledger
retrieval_telemetry.jsonl  RAG queries, retrieval quality, safe-to-cite decisions
working_memory.json        Short-term audit memory
protocol_graph.json        Contracts, calls, asset flows, actors, attack-path slices
candidate_rank_trace.json  Why hypotheses were ranked/promoted/demoted
proof_packets.json         Proof obligations and validation status
artifacts/                 Slither output and generated validation plans/tests
```

## Replicate The Demo Walkthrough

1. Show the architecture memo:

```bash
open MEMO.md
```

2. List tools:

```bash
.venv/bin/sentinel tools list --json
```

3. Run or show a completed audit:

```bash
.venv/bin/sentinel audit \
  --repo Test/2025-07-orderbook \
  --objective "Find bugs" \
  --real-llm
```

4. Open the generated report and ledger:

```bash
RUN=runs/<run_id>
sed -n '1,220p' "$RUN/report.md"
head -n 20 "$RUN/tool_ledger.jsonl"
```

5. Walk through the core code:

```text
src/sentinel/graphs/parent.py        LLM planner spine and parent audit graph
src/sentinel/graphs/research.py      Isolated research subagent
src/sentinel/graphs/rag_subgraph.py  Self-RAG subgraph
src/sentinel/tools/registry.py       Tool registration
src/sentinel/tools/executor.py       Tool execution boundary
```

The speaking script is in:

```text
VIDEO_WALKTHROUGH_SCRIPT.md
```

## Evaluation

Run the full test suite:

```bash
.venv/bin/python -m pytest
```

Run fixture evals:

```bash
.venv/bin/sentinel eval --all
```

Run embedding retrieval evals:

```bash
.venv/bin/sentinel rag eval-embeddings --all
```

Run benchmark-style recall evaluation if benchmark fixtures are available:

```bash
.venv/bin/sentinel benchmark --help
```

## Troubleshooting

### `SOLODIT_API_KEY is not configured`

The agent can still use an existing stale cache if present. To force a live sync, set `SOLODIT_API_KEY` in `.env` and run:

```bash
.venv/bin/sentinel rag sync --strict
```

### Chroma or embedding mismatch

If you change `SENTINEL_RAG_EMBED_MODEL`, rebuild:

```bash
.venv/bin/sentinel rag rebuild --scope all --repo <repo>
```

### Foundry repo does not build

Install the target repo dependencies inside that repo:

```bash
cd Test/<repo>
forge install
forge build
```

Then return to the Sentinel repo root and run the audit again.

### LangSmith 403

Your key may be valid for reading but not for multipart trace ingestion, or the endpoint/project may not match the account. Disable tracing to continue:

```bash
export LANGSMITH_TRACING=false
export LANGCHAIN_TRACING_V2=false
export LANGCHAIN_TRACING=false
```

### Real LLM endpoint fails

Use another provider without changing code:

```bash
export SENTINEL_LLM_PROVIDER=ollama
export SENTINEL_MODEL=gemma4:31b
export OLLAMA_BASE_URL=https://ollama.com
```

or:

```bash
export SENTINEL_LLM_PROVIDER=huggingface
export SENTINEL_MODEL=Qwen/Qwen2.5-Coder-32B-Instruct
export HF_BASE_URL=https://router.huggingface.co/v1
```

## Security Notes

- Do not commit `.env`.
- Regenerate exposed Solodit, Hugging Face, Ollama, or LangSmith keys.
- Treat RAG matches as historical context only.
- Treat generated validation tests as untrusted until reviewed.
- Final findings should be grounded in local source evidence and either executable validation or a complete static proof.
