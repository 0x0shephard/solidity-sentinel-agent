# Solidity Sentinel Agent

Solidity Sentinel is being rebuilt as a real LangGraph/LangChain agent for Solidity repository triage.

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

The default target is Ollama:

```env
SENTINEL_LLM_PROVIDER=ollama
SENTINEL_MODEL=qwen2.5-coder:7b
OLLAMA_BASE_URL=http://localhost:11434
```

Ollama is installed locally, but the service must be running before real non-mock model calls work.

