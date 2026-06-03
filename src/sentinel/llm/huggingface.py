from __future__ import annotations

import json

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_huggingface import ChatHuggingFace, HuggingFaceEndpoint

from sentinel.llm.base import BasePlanner, BaseResearchRefiner, ToolPlan
from sentinel.llm.ollama import extract_json_object
from sentinel.schemas.research import ResearchRefinement


class HuggingFacePlanner(BasePlanner):
    def __init__(self, model: str, token: str, base_url: str | None = None, llm: ChatHuggingFace | None = None) -> None:
        endpoint = HuggingFaceEndpoint(
            model=model,
            huggingfacehub_api_token=token,
            endpoint_url=base_url,
            temperature=0.0,
            max_new_tokens=1024,
        )
        self.llm = llm or ChatHuggingFace(llm=endpoint, model_id=model, temperature=0.0)

    def plan(self, prompt: str, tools: list[dict]) -> ToolPlan:
        response = self.llm.invoke(
            [
                SystemMessage(
                    content=(
                        "You are Solidity Sentinel's planner. Return only JSON with key decisions. "
                        "Each decision must include tool_name, tool_input, and rationale. Do not invent tool names."
                    )
                ),
                HumanMessage(content=prompt),
            ]
        )
        content = response.content if isinstance(response.content, str) else json.dumps(response.content)
        return ToolPlan.model_validate_json(extract_json_object(content))


class HuggingFaceResearchRefiner(BaseResearchRefiner):
    def __init__(self, model: str, token: str, base_url: str | None = None, llm: ChatHuggingFace | None = None) -> None:
        endpoint = HuggingFaceEndpoint(
            model=model,
            huggingfacehub_api_token=token,
            endpoint_url=base_url,
            temperature=0.0,
            max_new_tokens=1024,
        )
        self.llm = llm or ChatHuggingFace(llm=endpoint, model_id=model, temperature=0.0)

    def refine(self, prompt: str) -> ResearchRefinement:
        response = self.llm.invoke(
            [
                SystemMessage(
                    content=(
                        "You refine Solidity audit hypotheses. Return only JSON with keys: "
                        "likely_impact, exploit_preconditions, recommended_tests, limitations, confidence_delta. "
                        "Do not invent files, line numbers, or functions outside the evidence."
                    )
                ),
                HumanMessage(content=prompt),
            ]
        )
        content = response.content if isinstance(response.content, str) else json.dumps(response.content)
        return ResearchRefinement.model_validate_json(extract_json_object(content))
