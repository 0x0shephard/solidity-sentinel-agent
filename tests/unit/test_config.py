from sentinel.config import get_settings


def test_settings_read_huggingface_defaults(monkeypatch):
    monkeypatch.delenv("SENTINEL_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("SENTINEL_MODEL", raising=False)

    settings = get_settings()

    assert settings.llm_provider == "huggingface"
    assert settings.model == "Qwen/Qwen2.5-Coder-32B-Instruct"
    assert settings.ollama_base_url == "http://localhost:11434"
    assert settings.rag_embed_model == "sentence-transformers/all-MiniLM-L6-v2"


def test_settings_support_huggingface(monkeypatch):
    monkeypatch.setenv("SENTINEL_LLM_PROVIDER", "huggingface")
    monkeypatch.setenv("SENTINEL_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct")
    monkeypatch.setenv("HF_TOKEN", "test-token")

    settings = get_settings()

    assert settings.llm_provider == "huggingface"
    assert settings.model == "Qwen/Qwen2.5-Coder-7B-Instruct"
    assert settings.hf_token == "test-token"


def test_langsmith_tracing_requires_env_flag_and_key(monkeypatch):
    monkeypatch.setenv("LANGSMITH_TRACING", "true")
    monkeypatch.setenv("LANGSMITH_API_KEY", "test-key")

    settings = get_settings()

    assert settings.langsmith_tracing is True
    assert settings.langsmith_api_key == "test-key"
