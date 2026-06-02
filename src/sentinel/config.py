from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


LLMProviderName = Literal["mock", "ollama", "huggingface"]


class Settings(BaseModel):
    """Runtime configuration loaded from environment variables.

    The settings object is deliberately small in Phase 2. Later phases will
    consume these values in the LangChain provider factory and graph runner.
    """

    runs_dir: Path = Path("runs")
    llm_provider: LLMProviderName = "ollama"
    model: str = "qwen2.5-coder:7b"
    ollama_base_url: str = "http://localhost:11434"
    hf_token: str | None = None
    hf_base_url: str = "https://router.huggingface.co/v1"
    max_tool_calls: int = Field(default=40, ge=1)
    context_summary_interval: int = Field(default=6, ge=1)


def get_settings() -> Settings:
    """Read settings from the process environment."""

    return Settings(
        runs_dir=Path(os.getenv("SENTINEL_RUNS_DIR", "runs")),
        llm_provider=os.getenv("SENTINEL_LLM_PROVIDER", "ollama"),  # type: ignore[arg-type]
        model=os.getenv("SENTINEL_MODEL", "qwen2.5-coder:7b"),
        ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
        hf_token=os.getenv("HF_TOKEN") or os.getenv("HUGGINGFACE_API_TOKEN"),
        hf_base_url=os.getenv("HF_BASE_URL", "https://router.huggingface.co/v1"),
        max_tool_calls=int(os.getenv("SENTINEL_MAX_TOOL_CALLS", "40")),
        context_summary_interval=int(os.getenv("SENTINEL_CONTEXT_SUMMARY_INTERVAL", "6")),
    )

