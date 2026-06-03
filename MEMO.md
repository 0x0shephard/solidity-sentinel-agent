# Solidity Sentinel Memo

## What I Built

Solidity Sentinel is a LangGraph/LangChain audit agent for Solidity repository triage. It includes a coherent typed registry of 70+ tools across repo, build, static, research, dynamic, report, and memory namespaces; a parent audit graph; an isolated research subagent; deterministic fixture evals; report generation; validation-test artifacts; and a local tool ledger.

The latest upgrade adds Solodit-backed historical-findings RAG. The agent can sync findings from the Solodit API into a local `data/rag` cache, normalize them, build/query a Chroma vector store when the Chroma dependencies are installed, and hybrid-rank matches using semantic, keyword/tag, class/protocol, and quality/recency signals. RAG is used for planning and research, but historical findings are not treated as proof of target-repo vulnerability.

## What I Cut

I kept the RAG implementation dependency-tolerant so the existing virtualenv can still run without `chromadb` installed; a fresh install from `pyproject.toml` enables the intended Chroma path. I also did not fully remove the local tool ledger because it is valuable submission evidence and offline reproducibility, even though LangSmith is now the primary tracing target when enabled.

## What More Time Would Address

I would expand hard fixtures beyond access control, unchecked ERC20 returns, and toy reentrancy into oracle manipulation, governance, liquidation math, upgradeability, and multi-contract invariant bugs. I would also deepen the LLM planner into a budgeted loop that naturally replaces the deterministic mock path, and add CI/container scaffolding for one-command reviewer setup.

## Design Decision I Would Defend

I would defend keeping local reports, state, validation artifacts, and `tool_ledger.jsonl` alongside LangSmith. LangSmith is the right industry-standard trace surface for model/tool debugging, but a submission should still be inspectable offline without external account access. The ledger gives reviewers durable evidence of tool count, ordering, status, and composition.
