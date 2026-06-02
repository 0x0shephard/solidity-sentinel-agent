from sentinel.config import get_settings


def test_settings_read_ollama_defaults(monkeypatch):
    monkeypatch.delenv("SENTINEL_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("SENTINEL_MODEL", raising=False)

    settings = get_settings()

    assert settings.llm_provider == "ollama"
    assert settings.model == "qwen2.5-coder:7b"
    assert settings.ollama_base_url == "http://localhost:11434"


def test_settings_support_huggingface(monkeypatch):
    monkeypatch.setenv("SENTINEL_LLM_PROVIDER", "huggingface")
    monkeypatch.setenv("SENTINEL_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct")
    monkeypatch.setenv("HF_TOKEN", "test-token")

    settings = get_settings()

    assert settings.llm_provider == "huggingface"
    assert settings.model == "Qwen/Qwen2.5-Coder-7B-Instruct"
    assert settings.hf_token == "test-token"

