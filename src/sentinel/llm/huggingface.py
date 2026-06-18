from __future__ import annotations

import json

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_huggingface import ChatHuggingFace, HuggingFaceEndpoint

from sentinel.llm.base import (
    BaseAdversarialReviewer,
    BaseHypothesisProposer,
    BasePlanner,
    BasePocRepairer,
    BaseResearchRefiner,
    ToolPlan,
)
from sentinel.llm.ollama import (
    _POC_REPAIR_SYSTEM,
    _PROPOSER_SYSTEM,
    _REVIEWER_SYSTEM,
    extract_json_object,
    extract_solidity_code,
    parse_adversarial_verdict,
    parse_proposed_hypotheses,
    parse_research_refinement,
)
from sentinel.llm.resilience import invoke_chat
from sentinel.schemas.research import AdversarialVerdict, ProposedHypothesisBatch, ResearchRefinement


DEFAULT_HF_ROUTER_URL = "https://router.huggingface.co/v1"


def _endpoint_kwargs(model: str, base_url: str | None) -> dict:
    """Build HuggingFaceEndpoint kwargs without mixing model and endpoint_url.

    The LangChain HuggingFaceEndpoint class treats `endpoint_url` as a
    dedicated endpoint alternative to `model`, not as a generic base URL.
    Passing both raises a Pydantic validation error. The default HF router path
    works with `model`; a custom non-router URL is treated as a dedicated
    endpoint.
    """

    if base_url and base_url.rstrip("/") != DEFAULT_HF_ROUTER_URL.rstrip("/"):
        return {"endpoint_url": base_url}
    return {"model": model}


class HuggingFacePlanner(BasePlanner):
    def __init__(self, model: str, token: str, base_url: str | None = None, llm: ChatHuggingFace | None = None) -> None:
        endpoint = HuggingFaceEndpoint(
            **_endpoint_kwargs(model, base_url),
            huggingfacehub_api_token=token,
            temperature=0.0,
            max_new_tokens=1024,
        )
        self.llm = llm or ChatHuggingFace(llm=endpoint, model_id=model, temperature=0.0)

    def plan(self, prompt: str, tools: list[dict]) -> ToolPlan:
        tool_catalog = json.dumps(tools, indent=2, default=str)[:120_000]
        response = invoke_chat(self.llm, 
            [
                SystemMessage(
                    content=(
                        "You are Solidity Sentinel's planner. Return only JSON with key decisions. "
                        "Each decision must include tool_name, tool_input, and rationale; set stop=true only when no useful tool remains. "
                        "Choose only from the provided tool catalog and respect schemas, risks, side effects, and chaining hints."
                    )
                ),
                HumanMessage(content=f"{prompt}\n\nTool catalog:\n{tool_catalog}"),
            ]
        )
        content = response.content if isinstance(response.content, str) else json.dumps(response.content)
        return ToolPlan.model_validate_json(extract_json_object(content))


class HuggingFaceResearchRefiner(BaseResearchRefiner):
    def __init__(self, model: str, token: str, base_url: str | None = None, llm: ChatHuggingFace | None = None) -> None:
        endpoint = HuggingFaceEndpoint(
            **_endpoint_kwargs(model, base_url),
            huggingfacehub_api_token=token,
            temperature=0.0,
            max_new_tokens=1024,
        )
        self.llm = llm or ChatHuggingFace(llm=endpoint, model_id=model, temperature=0.0)

    def refine(self, prompt: str) -> ResearchRefinement:
        response = invoke_chat(self.llm, 
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
        return parse_research_refinement(content)


class HuggingFaceHypothesisProposer(BaseHypothesisProposer):
    def __init__(self, model: str, token: str, base_url: str | None = None, llm: ChatHuggingFace | None = None) -> None:
        endpoint = HuggingFaceEndpoint(
            **_endpoint_kwargs(model, base_url),
            huggingfacehub_api_token=token,
            temperature=0.0,
            max_new_tokens=1500,
        )
        self.llm = llm or ChatHuggingFace(llm=endpoint, model_id=model, temperature=0.0)

    def propose(self, prompt: str) -> ProposedHypothesisBatch:
        self.last_raw = ""
        response = invoke_chat(self.llm, 
            [SystemMessage(content=_PROPOSER_SYSTEM), HumanMessage(content=prompt)]
        )
        content = response.content if isinstance(response.content, str) else json.dumps(response.content)
        self.last_raw = content
        return parse_proposed_hypotheses(content)


class HuggingFaceAdversarialReviewer(BaseAdversarialReviewer):
    def __init__(self, model: str, token: str, base_url: str | None = None, llm: ChatHuggingFace | None = None) -> None:
        endpoint = HuggingFaceEndpoint(
            **_endpoint_kwargs(model, base_url),
            huggingfacehub_api_token=token,
            temperature=0.0,
            max_new_tokens=1024,
        )
        self.llm = llm or ChatHuggingFace(llm=endpoint, model_id=model, temperature=0.0)

    def review(self, prompt: str) -> AdversarialVerdict:
        response = invoke_chat(self.llm,
            [SystemMessage(content=_REVIEWER_SYSTEM), HumanMessage(content=prompt)]
        )
        content = response.content if isinstance(response.content, str) else json.dumps(response.content)
        return parse_adversarial_verdict(content)


class HuggingFacePocRepairer(BasePocRepairer):
    def __init__(self, model: str, token: str, base_url: str | None = None, llm: ChatHuggingFace | None = None) -> None:
        endpoint = HuggingFaceEndpoint(
            **_endpoint_kwargs(model, base_url),
            huggingfacehub_api_token=token,
            temperature=0.0,
            max_new_tokens=2000,
        )
        self.llm = llm or ChatHuggingFace(llm=endpoint, model_id=model, temperature=0.0)

    def repair(self, prompt: str) -> str:
        response = invoke_chat(self.llm, [SystemMessage(content=_POC_REPAIR_SYSTEM), HumanMessage(content=prompt)])
        content = response.content if isinstance(response.content, str) else json.dumps(response.content)
        return extract_solidity_code(content)
