from __future__ import annotations

from sentinel.config import Settings, get_settings
from sentinel.errors import ConfigurationError
from sentinel.llm.base import BaseAdversarialReviewer, BaseHypothesisProposer, BasePlanner, BasePocRepairer, BaseResearchRefiner
from sentinel.llm.huggingface import (
    HuggingFaceAdversarialReviewer,
    HuggingFaceHypothesisProposer,
    HuggingFacePlanner,
    HuggingFacePocRepairer,
    HuggingFaceResearchRefiner,
)
from sentinel.llm.mock import (
    MockAdversarialReviewer,
    MockHypothesisProposer,
    MockPlanner,
    MockPocRepairer,
    MockResearchRefiner,
)
from sentinel.llm.ollama import (
    OllamaAdversarialReviewer,
    OllamaHypothesisProposer,
    OllamaPlanner,
    OllamaPocRepairer,
    OllamaResearchRefiner,
)


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
    if cfg.llm_provider == "anthropic":
        from sentinel.llm.anthropic_provider import AnthropicPlanner, _anthropic_kwargs

        return AnthropicPlanner(**_anthropic_kwargs(cfg))
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
    if cfg.llm_provider == "anthropic":
        from sentinel.llm.anthropic_provider import AnthropicResearchRefiner, _anthropic_kwargs

        return AnthropicResearchRefiner(**_anthropic_kwargs(cfg))
    raise ConfigurationError(f"Unsupported LLM provider: {cfg.llm_provider}")


def get_hypothesis_proposer(settings: Settings | None = None, mock: bool = False) -> BaseHypothesisProposer:
    cfg = settings or get_settings()
    if mock or cfg.llm_provider == "mock":
        return MockHypothesisProposer()
    if cfg.llm_provider == "ollama":
        return OllamaHypothesisProposer(model=cfg.model, base_url=cfg.ollama_base_url, api_key=cfg.ollama_api_key)
    if cfg.llm_provider == "huggingface":
        if not cfg.hf_token:
            raise ConfigurationError("HF_TOKEN is required when SENTINEL_LLM_PROVIDER=huggingface")
        return HuggingFaceHypothesisProposer(model=cfg.model, token=cfg.hf_token, base_url=cfg.hf_base_url)
    if cfg.llm_provider == "anthropic":
        from sentinel.llm.anthropic_provider import AnthropicHypothesisProposer, _anthropic_kwargs

        return AnthropicHypothesisProposer(**_anthropic_kwargs(cfg))
    raise ConfigurationError(f"Unsupported LLM provider: {cfg.llm_provider}")


def get_ollama_fallback_proposer(settings: Settings | None = None) -> BaseHypothesisProposer:
    cfg = settings or get_settings()
    return OllamaHypothesisProposer(model=cfg.ollama_fallback_model, base_url=cfg.ollama_base_url, api_key=cfg.ollama_api_key)


def get_adversarial_reviewer(settings: Settings | None = None, mock: bool = False) -> BaseAdversarialReviewer:
    cfg = settings or get_settings()
    if mock or cfg.llm_provider == "mock":
        return MockAdversarialReviewer()
    if cfg.llm_provider == "ollama":
        return OllamaAdversarialReviewer(model=cfg.model, base_url=cfg.ollama_base_url, api_key=cfg.ollama_api_key)
    if cfg.llm_provider == "huggingface":
        if not cfg.hf_token:
            raise ConfigurationError("HF_TOKEN is required when SENTINEL_LLM_PROVIDER=huggingface")
        return HuggingFaceAdversarialReviewer(model=cfg.model, token=cfg.hf_token, base_url=cfg.hf_base_url)
    if cfg.llm_provider == "anthropic":
        from sentinel.llm.anthropic_provider import AnthropicAdversarialReviewer, _anthropic_kwargs

        return AnthropicAdversarialReviewer(**_anthropic_kwargs(cfg))
    raise ConfigurationError(f"Unsupported LLM provider: {cfg.llm_provider}")


def get_ollama_fallback_reviewer(settings: Settings | None = None) -> BaseAdversarialReviewer:
    cfg = settings or get_settings()
    return OllamaAdversarialReviewer(model=cfg.ollama_fallback_model, base_url=cfg.ollama_base_url, api_key=cfg.ollama_api_key)


def get_ollama_fallback_planner(settings: Settings | None = None) -> BasePlanner:
    cfg = settings or get_settings()
    return OllamaPlanner(model=cfg.ollama_fallback_model, base_url=cfg.ollama_base_url, api_key=cfg.ollama_api_key)


def get_ollama_fallback_refiner(settings: Settings | None = None) -> BaseResearchRefiner:
    cfg = settings or get_settings()
    return OllamaResearchRefiner(model=cfg.ollama_fallback_model, base_url=cfg.ollama_base_url, api_key=cfg.ollama_api_key)


def get_poc_repairer(settings: Settings | None = None, mock: bool = False) -> BasePocRepairer:
    cfg = settings or get_settings()
    if mock or cfg.llm_provider == "mock":
        return MockPocRepairer()
    if cfg.llm_provider == "ollama":
        return OllamaPocRepairer(model=cfg.model, base_url=cfg.ollama_base_url, api_key=cfg.ollama_api_key)
    if cfg.llm_provider == "huggingface":
        if not cfg.hf_token:
            raise ConfigurationError("HF_TOKEN is required when SENTINEL_LLM_PROVIDER=huggingface")
        return HuggingFacePocRepairer(model=cfg.model, token=cfg.hf_token, base_url=cfg.hf_base_url)
    if cfg.llm_provider == "anthropic":
        from sentinel.llm.anthropic_provider import AnthropicPocRepairer, _anthropic_kwargs

        return AnthropicPocRepairer(**_anthropic_kwargs(cfg))
    raise ConfigurationError(f"Unsupported LLM provider: {cfg.llm_provider}")


def get_ollama_fallback_poc_repairer(settings: Settings | None = None) -> BasePocRepairer:
    cfg = settings or get_settings()
    return OllamaPocRepairer(model=cfg.ollama_fallback_model, base_url=cfg.ollama_base_url, api_key=cfg.ollama_api_key)
