import pytest

from sentinel.config import Settings
from sentinel.errors import ConfigurationError, NonRetryableExternalError
from sentinel.llm.base import ToolDecision, ToolPlan
from sentinel.llm.ollama import extract_json_object
from sentinel.llm.provider import get_planner, get_research_refiner


def test_extract_json_object_handles_fenced_json():
    text = '```json\n{"decisions": []}\n```'

    assert extract_json_object(text) == '{"decisions": []}'


def test_extract_json_object_rejects_non_json_text():
    with pytest.raises(NonRetryableExternalError):
        extract_json_object("not json")


def test_mock_provider_returns_empty_plan():
    planner = get_planner(Settings(llm_provider="mock"), mock=False)

    assert planner.plan("prompt", []).decisions == []


def test_mock_provider_returns_empty_research_refinement():
    refiner = get_research_refiner(Settings(llm_provider="mock"), mock=False)

    assert refiner.refine("prompt").recommended_tests == []


def test_huggingface_provider_requires_token():
    with pytest.raises(ConfigurationError):
        get_planner(Settings(llm_provider="huggingface", model="Qwen/Qwen2.5-Coder-7B-Instruct"), mock=False)


def test_huggingface_research_refiner_requires_token():
    with pytest.raises(ConfigurationError):
        get_research_refiner(Settings(llm_provider="huggingface", model="Qwen/Qwen2.5-Coder-7B-Instruct"), mock=False)


def test_tool_plan_schema():
    plan = ToolPlan(decisions=[ToolDecision(tool_name="repo.list_files", tool_input={"repo_path": "."}, rationale="inspect")])

    assert plan.decisions[0].tool_name == "repo.list_files"
