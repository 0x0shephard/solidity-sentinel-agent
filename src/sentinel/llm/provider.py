from __future__ import annotations

from sentinel.config import Settings, get_settings
from sentinel.errors import ConfigurationError
from sentinel.llm.base import BasePlanner, BaseResearchRefiner
from sentinel.llm.huggingface import HuggingFacePlanner, HuggingFaceResearchRefiner
from sentinel.llm.mock import MockPlanner, MockResearchRefiner
from sentinel.llm.ollama import OllamaPlanner, OllamaResearchRefiner


def get_planner(settings: Settings | None = None, mock: bool = False) -> BasePlanner:
    cfg = settings or get_settings()
    if mock or cfg.llm_provider == "mock":
        return MockPlanner()
    if cfg.llm_provider == "ollama":
        return OllamaPlanner(model=cfg.model, base_url=cfg.ollama_base_url, api_key=cfg.ollama_api_key)
    if cfg.llm_provider == "huggingface":
        if not cfg.hf_token:
            raise ConfigurationError("HF_TOKEN is required when SENTINEL_LLM_PROVIDER=huggingface")
        return HuggingFacePlanner(model=cfg.model, token=cfg.hf_token, base_url=cfg.hf_base_url)
    raise ConfigurationError(f"Unsupported LLM provider: {cfg.llm_provider}")


def get_research_refiner(settings: Settings | None = None, mock: bool = False) -> BaseResearchRefiner:
    cfg = settings or get_settings()
    if mock or cfg.llm_provider == "mock":
        return MockResearchRefiner()
    if cfg.llm_provider == "ollama":
        return OllamaResearchRefiner(model=cfg.model, base_url=cfg.ollama_base_url, api_key=cfg.ollama_api_key)
    if cfg.llm_provider == "huggingface":
        if not cfg.hf_token:
            raise ConfigurationError("HF_TOKEN is required when SENTINEL_LLM_PROVIDER=huggingface")
        return HuggingFaceResearchRefiner(model=cfg.model, token=cfg.hf_token, base_url=cfg.hf_base_url)
    raise ConfigurationError(f"Unsupported LLM provider: {cfg.llm_provider}")


def get_ollama_fallback_planner(settings: Settings | None = None) -> BasePlanner:
    cfg = settings or get_settings()
    return OllamaPlanner(model=cfg.ollama_fallback_model, base_url=cfg.ollama_base_url, api_key=cfg.ollama_api_key)


def get_ollama_fallback_refiner(settings: Settings | None = None) -> BaseResearchRefiner:
    cfg = settings or get_settings()
    return OllamaResearchRefiner(model=cfg.ollama_fallback_model, base_url=cfg.ollama_base_url, api_key=cfg.ollama_api_key)
