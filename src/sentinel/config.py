from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


LLMProviderName = Literal["mock", "ollama", "huggingface", "anthropic"]


class Settings(BaseModel):
    """Runtime configuration loaded from environment variables.

    The settings object is deliberately small in Phase 2. Later phases will
    consume these values in the LangChain provider factory and graph runner.
    """

    runs_dir: Path = Path("runs")
    llm_provider: LLMProviderName = "huggingface"
    model: str = "Qwen/Qwen2.5-Coder-32B-Instruct"
    ollama_base_url: str = "http://localhost:11434"
    ollama_api_key: str | None = None
    ollama_fallback_model: str = "qwen2.5-coder:7b"
    hf_token: str | None = None
    hf_base_url: str = "https://router.huggingface.co/v1"
    # Frontier model (Anthropic Claude) — the recommended provider for landing
    # crit/high findings. Uses adaptive thinking + effort (no temperature).
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-opus-4-8"
    anthropic_effort: str = "high"
    anthropic_thinking: bool = True
    anthropic_max_tokens: int = Field(default=16000, ge=1)
    max_tool_calls: int = Field(default=200, ge=1)
    # Cold `forge build`/`forge test` on a real protocol (full src + test tree) can
    # take minutes; 120s was timing out and surfacing as a blank build error.
    forge_command_timeout: int = Field(default=300, ge=1)
    # When a generated PoC test fails to compile, feed the solc error + real
    # target source back to the LLM to fix it, up to this many attempts. Default 1:
    # in practice the model repeats the same structural error on a 2nd pass, so a
    # retry mostly burns minutes for no gain (raise it if your model improves).
    poc_repair_max_attempts: int = Field(default=1, ge=0)
    planner_max_rounds: int = Field(default=14, ge=1)
    # Safety: the real-LLM planner may only directly select read/analysis tools;
    # write/network/install/cleanup tools are blocked unless explicitly approved.
    planner_allow_side_effects: bool = False
    # Dependency installs run untrusted postinstall scripts over the network; opt-in only.
    allow_installs: bool = False
    context_summary_interval: int = Field(default=6, ge=1)
    llm_max_retries: int = Field(default=3, ge=1)
    llm_backoff_base_seconds: float = Field(default=0.5, ge=0.0)
    llm_backoff_max_seconds: float = Field(default=8.0, ge=0.0)
    llm_max_calls_per_minute: int = Field(default=120, ge=1)
    persist_full_state: bool = False
    solodit_api_url: str = "https://solodit.cyfrin.io/api/v1/solodit"
    solodit_api_key: str | None = None
    rag_dir: Path = Path("data/rag")
    auditvault_dir: str | None = None
    rag_embed_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    rag_stale_after_hours: int = Field(default=24, ge=1)
    rag_default_page_size: int = Field(default=100, ge=1, le=100)
    rag_filter_languages: list[str] = Field(default_factory=lambda: ["Solidity"])
    rag_filter_impacts: list[str] = Field(default_factory=lambda: ["HIGH", "MEDIUM"])
    rag_quality_score: int = Field(default=2, ge=0, le=5)
    # The per-hypothesis self-RAG subgraph is ~7-10 tool calls each; it is pure
    # historical-context enrichment (research still deepens every hypothesis), so
    # cap it to the top-ranked hypotheses to avoid spending most of the audit's
    # calls on retrieval that often does not change findings.
    rag_max_hypotheses: int = Field(default=6, ge=1)
    rag_auto_rebuild: bool = False
    langsmith_tracing: bool = False
    langsmith_api_key: str | None = None
    langsmith_project: str = "solidity-sentinel-agent"


def get_settings() -> Settings:
    """Read settings from the process environment."""

    def split_csv(name: str, default: str) -> list[str]:
        return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]

    return Settings(
        runs_dir=Path(os.getenv("SENTINEL_RUNS_DIR", "runs")),
        llm_provider=os.getenv("SENTINEL_LLM_PROVIDER", "huggingface"),  # type: ignore[arg-type]
        model=os.getenv("SENTINEL_MODEL", "Qwen/Qwen2.5-Coder-32B-Instruct"),
        ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
        ollama_api_key=os.getenv("OLLAMA_API_KEY") or None,
        ollama_fallback_model=os.getenv("SENTINEL_OLLAMA_FALLBACK_MODEL", "qwen2.5-coder:7b"),
        hf_token=os.getenv("HF_TOKEN") or os.getenv("HUGGINGFACE_API_TOKEN"),
        hf_base_url=os.getenv("HF_BASE_URL", "https://router.huggingface.co/v1"),
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY") or None,
        anthropic_model=os.getenv("SENTINEL_ANTHROPIC_MODEL", "claude-opus-4-8"),
        anthropic_effort=os.getenv("SENTINEL_ANTHROPIC_EFFORT", "high"),
        anthropic_thinking=os.getenv("SENTINEL_ANTHROPIC_THINKING", "true").lower() in {"1", "true", "yes", "on"},
        anthropic_max_tokens=int(os.getenv("SENTINEL_ANTHROPIC_MAX_TOKENS", "16000")),
        max_tool_calls=int(os.getenv("SENTINEL_MAX_TOOL_CALLS", "200")),
        forge_command_timeout=int(os.getenv("SENTINEL_FORGE_COMMAND_TIMEOUT", "300")),
        poc_repair_max_attempts=int(os.getenv("SENTINEL_POC_REPAIR_MAX_ATTEMPTS", "1")),
        planner_max_rounds=int(os.getenv("SENTINEL_PLANNER_MAX_ROUNDS", "14")),
        planner_allow_side_effects=os.getenv("SENTINEL_PLANNER_ALLOW_SIDE_EFFECTS", "false").lower() in {"1", "true", "yes", "on"},
        allow_installs=os.getenv("SENTINEL_ALLOW_INSTALLS", "false").lower() in {"1", "true", "yes", "on"},
        context_summary_interval=int(os.getenv("SENTINEL_CONTEXT_SUMMARY_INTERVAL", "6")),
        llm_max_retries=int(os.getenv("SENTINEL_LLM_MAX_RETRIES", "3")),
        llm_backoff_base_seconds=float(os.getenv("SENTINEL_LLM_BACKOFF_BASE_SECONDS", "0.5")),
        llm_backoff_max_seconds=float(os.getenv("SENTINEL_LLM_BACKOFF_MAX_SECONDS", "8.0")),
        llm_max_calls_per_minute=int(os.getenv("SENTINEL_LLM_MAX_CALLS_PER_MINUTE", "120")),
        persist_full_state=os.getenv("SENTINEL_PERSIST_FULL_STATE", "false").lower() in {"1", "true", "yes", "on"},
        solodit_api_url=os.getenv("SOLODIT_API_URL", "https://solodit.cyfrin.io/api/v1/solodit"),
        solodit_api_key=os.getenv("SOLODIT_API_KEY") or None,
        rag_dir=Path(os.getenv("SENTINEL_RAG_DIR", "data/rag")),
        auditvault_dir=os.getenv("SENTINEL_AUDITVAULT_DIR") or None,
        rag_embed_model=os.getenv("SENTINEL_RAG_EMBED_MODEL", "sentence-transformers/all-MiniLM-L6-v2"),
        rag_stale_after_hours=int(os.getenv("SENTINEL_RAG_STALE_AFTER_HOURS", "24")),
        rag_default_page_size=int(os.getenv("SENTINEL_RAG_DEFAULT_PAGE_SIZE", "100")),
        rag_filter_languages=split_csv("SENTINEL_RAG_FILTER_LANGUAGES", "Solidity"),
        rag_filter_impacts=split_csv("SENTINEL_RAG_FILTER_IMPACTS", "HIGH,MEDIUM"),
        rag_quality_score=int(os.getenv("SENTINEL_RAG_QUALITY_SCORE", "2")),
        rag_max_hypotheses=int(os.getenv("SENTINEL_RAG_MAX_HYPOTHESES", "6")),
        rag_auto_rebuild=os.getenv("SENTINEL_RAG_AUTO_REBUILD", "false").lower() in {"1", "true", "yes", "on"},
        langsmith_tracing=os.getenv("LANGSMITH_TRACING", "false").lower() in {"1", "true", "yes", "on"},
        langsmith_api_key=os.getenv("LANGSMITH_API_KEY") or None,
        langsmith_project=os.getenv("LANGSMITH_PROJECT", "solidity-sentinel-agent"),
    )
