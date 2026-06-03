from __future__ import annotations

import json
import re

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama

from sentinel.errors import NonRetryableExternalError
from sentinel.llm.base import BasePlanner, BaseResearchRefiner, ToolPlan
from sentinel.schemas.research import ResearchRefinement


def extract_json_object(text: str) -> str:
    cleaned = text.strip()
    fenced = re.search(r"```(?:json)?\s*(.*?)```", cleaned, flags=re.DOTALL)
    if fenced:
        cleaned = fenced.group(1).strip()
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise NonRetryableExternalError(f"Model did not return a JSON object: {text[:300]}")
    return cleaned[start : end + 1]


class OllamaPlanner(BasePlanner):
    def __init__(self, model: str, base_url: str, llm: ChatOllama | None = None) -> None:
        self.llm = llm or ChatOllama(model=model, base_url=base_url, temperature=0.0, format="json")

    def plan(self, prompt: str, tools: list[dict]) -> ToolPlan:
        response = self.llm.invoke(
            [
                SystemMessage(
                    content=(
                        "You are Solidity Sentinel's planner. Return only JSON. "
                        "Use exactly this schema: "
                        '{"decisions":[{"tool_name":"repo.list_files","tool_input":{"repo_path":"..."},"rationale":"why"}]}. '
                        "Do not invent tool names."
                    )
                ),
                HumanMessage(content=prompt),
            ]
        )
        content = response.content if isinstance(response.content, str) else json.dumps(response.content)
        return ToolPlan.model_validate_json(extract_json_object(content))


class OllamaResearchRefiner(BaseResearchRefiner):
    def __init__(self, model: str, base_url: str, llm: ChatOllama | None = None) -> None:
        self.llm = llm or ChatOllama(model=model, base_url=base_url, temperature=0.0, format="json")

    def refine(self, prompt: str) -> ResearchRefinement:
        response = self.llm.invoke(
            [
                SystemMessage(
                    content=(
                        "You are Solidity Sentinel's research refiner. Return only JSON. "
                        "Use this schema: "
                        '{"likely_impact":"...",'
                        '"exploit_preconditions":["..."],'
                        '"recommended_tests":["..."],'
                        '"limitations":["..."],'
                        '"confidence_delta":0.0}. '
                        "Do not invent files, line numbers, or functions not present in the evidence."
                    )
                ),
                HumanMessage(content=prompt),
            ]
        )
        content = response.content if isinstance(response.content, str) else json.dumps(response.content)
        return ResearchRefinement.model_validate_json(extract_json_object(content))
