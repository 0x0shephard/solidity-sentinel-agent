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


def _ollama_client_kwargs(api_key: str | None) -> dict:
    if not api_key:
        return {}
    return {"headers": {"Authorization": f"Bearer {api_key}"}}


def coerce_research_refinement_payload(payload: dict) -> dict:
    coerced = dict(payload)
    for key in ("exploit_preconditions", "recommended_tests", "limitations"):
        value = coerced.get(key)
        if value is None:
            coerced[key] = []
        elif isinstance(value, str):
            coerced[key] = [value]
        elif isinstance(value, list):
            coerced[key] = [str(item) for item in value if item is not None]
        else:
            coerced[key] = [str(value)]
    if coerced.get("likely_impact") is not None:
        coerced["likely_impact"] = str(coerced["likely_impact"])
    try:
        delta = float(coerced.get("confidence_delta", 0.0))
    except (TypeError, ValueError):
        delta = 0.0
    coerced["confidence_delta"] = max(-0.2, min(0.2, delta))
    return coerced


def parse_research_refinement(content: str) -> ResearchRefinement:
    payload = json.loads(extract_json_object(content))
    if not isinstance(payload, dict):
        raise NonRetryableExternalError("Research refinement JSON must be an object.")
    return ResearchRefinement.model_validate(coerce_research_refinement_payload(payload))


class OllamaPlanner(BasePlanner):
    def __init__(self, model: str, base_url: str, api_key: str | None = None, llm: ChatOllama | None = None) -> None:
        self.llm = llm or ChatOllama(
            model=model,
            base_url=base_url,
            temperature=0.0,
            format="json",
            client_kwargs=_ollama_client_kwargs(api_key),
        )

    def plan(self, prompt: str, tools: list[dict]) -> ToolPlan:
        tool_catalog = json.dumps(tools, indent=2, default=str)[:120_000]
        response = self.llm.invoke(
            [
                SystemMessage(
                    content=(
                        "You are Solidity Sentinel's planner. Return only JSON. "
                        "Use exactly this schema: "
                        '{"decisions":[{"tool_name":"repo.list_files","tool_input":{"repo_path":"..."},"rationale":"why"}],"stop":false}. '
                        "Choose only from the provided tool catalog. Respect side effects, schemas, and chaining hints."
                    )
                ),
                HumanMessage(content=f"{prompt}\n\nTool catalog:\n{tool_catalog}"),
            ]
        )
        content = response.content if isinstance(response.content, str) else json.dumps(response.content)
        return ToolPlan.model_validate_json(extract_json_object(content))


class OllamaResearchRefiner(BaseResearchRefiner):
    def __init__(self, model: str, base_url: str, api_key: str | None = None, llm: ChatOllama | None = None) -> None:
        self.llm = llm or ChatOllama(
            model=model,
            base_url=base_url,
            temperature=0.0,
            format="json",
            client_kwargs=_ollama_client_kwargs(api_key),
        )

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
        return parse_research_refinement(content)
