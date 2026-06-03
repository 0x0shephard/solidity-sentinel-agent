# Solidity Sentinel Agent

Solidity Sentinel is a LangGraph/LangChain agent for Solidity repository triage. It combines static Solidity evidence extraction, scoped research subagents, validation artifact generation, Solodit-backed historical-findings RAG, and report/eval outputs.

## Environment

Activate the local virtual environment:

```bash
source .venv/bin/activate
```

Verify dependencies:

```bash
python - <<'PY'
from langgraph.graph import StateGraph
from langchain_ollama import ChatOllama
from langchain_huggingface import ChatHuggingFace
print("LangGraph/LangChain dependencies import successfully")
PY
```

Verify local Solidity tools:

```bash
forge --version
env HOME=/private/tmp slither --version
ollama --version
```

## Default LLM Runtime

The documented real-LLM default is Hugging Face:

```env
SENTINEL_LLM_PROVIDER=huggingface
SENTINEL_MODEL=Qwen/Qwen2.5-Coder-7B-Instruct
HF_TOKEN=...
```

Ollama remains supported for local runs:

```env
SENTINEL_LLM_PROVIDER=ollama
SENTINEL_MODEL=qwen2.5-coder:7b
OLLAMA_BASE_URL=http://localhost:11434
```

## Solodit RAG

Regenerate any exposed Solodit API key before use. Store only the regenerated key in `.env`:

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
sentinel rag sync
```

The sync calls `POST /findings` with `X-Cyfrin-API-Key`, caches raw and normalized findings under `data/rag`, and builds a Chroma index when `chromadb` and `langchain-chroma` are installed. Audits use stale-ok sync: a stale cache can be used if live refresh fails.

## LangSmith

LangSmith is the primary tracing surface when enabled:

```env
LANGSMITH_TRACING=true
LANGSMITH_API_KEY=...
LANGSMITH_PROJECT=solidity-sentinel-agent
```

Local durable artifacts remain: `tool_ledger.jsonl`, `state.json`, `report.json`, `report.md`, eval summaries, and validation artifacts.

## Evaluation

Run tests and fixture evals:

```bash
.venv/bin/python -m pytest
.venv/bin/sentinel eval --all
```
