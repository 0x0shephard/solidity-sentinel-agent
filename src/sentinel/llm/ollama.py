from __future__ import annotations

import json
import re

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama

from sentinel.errors import NonRetryableExternalError
from sentinel.llm.base import BaseAdversarialReviewer, BaseHypothesisProposer, BasePlanner, BaseResearchRefiner, ToolPlan
from sentinel.schemas.research import AdversarialVerdict, ProposedHypothesisBatch, ResearchRefinement


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


def _extract_json_value(text: str):
    cleaned = text.strip()
    fenced = re.search(r"```(?:json)?\s*(.*?)```", cleaned, flags=re.DOTALL)
    if fenced:
        cleaned = fenced.group(1).strip()
    for opener, closer in (("{", "}"), ("[", "]")):
        start = cleaned.find(opener)
        end = cleaned.rfind(closer)
        if start != -1 and end > start:
            try:
                return json.loads(cleaned[start : end + 1])
            except json.JSONDecodeError:
                continue
    raise NonRetryableExternalError(f"Model did not return JSON: {text[:300]}")


def coerce_proposed_hypothesis(payload: dict) -> dict | None:
    if not isinstance(payload, dict):
        return None
    affected_file = str(payload.get("affected_file") or payload.get("file") or "").strip()
    affected_function = str(payload.get("affected_function") or payload.get("function") or "").strip()
    title = str(payload.get("title") or "").strip()
    vulnerability_class = str(payload.get("vulnerability_class") or payload.get("class") or "manual_review").strip()
    if not affected_file or not affected_function or not title:
        return None
    preconditions = payload.get("exploit_preconditions") or payload.get("preconditions") or []
    if isinstance(preconditions, str):
        preconditions = [preconditions]
    preconditions = [str(item) for item in preconditions if item is not None][:8]
    try:
        confidence = float(payload.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5
    return {
        "title": title[:200],
        "vulnerability_class": vulnerability_class[:80],
        "affected_file": affected_file,
        "affected_function": affected_function,
        "affected_contract": (str(payload["affected_contract"]).strip() if payload.get("affected_contract") else None),
        "reasoning": str(payload.get("reasoning") or payload.get("explanation") or "")[:1500],
        "exploit_preconditions": preconditions,
        "confidence": max(0.0, min(1.0, confidence)),
    }


_HYP_LIST_KEYS = ("hypotheses", "findings", "vulnerabilities", "bugs", "issues", "results", "candidates")


def parse_proposed_hypotheses(content: str) -> ProposedHypothesisBatch:
    payload = _extract_json_value(content)
    raw_list: list = []
    if isinstance(payload, list):
        raw_list = payload
    elif isinstance(payload, dict):
        for key in _HYP_LIST_KEYS:
            value = payload.get(key)
            if isinstance(value, list):
                raw_list = value
                break
        else:
            # A single hypothesis object returned at top level.
            if any(payload.get(k) for k in ("affected_file", "file", "affected_function", "function")):
                raw_list = [payload]
    coerced = [item for item in (coerce_proposed_hypothesis(entry) for entry in raw_list) if item]
    return ProposedHypothesisBatch.model_validate({"hypotheses": coerced})


_PROPOSER_SYSTEM = (
    "You are Solidity Sentinel's hypothesis proposer, a senior smart-contract auditor. From the supplied "
    "protocol source code, attack-path slices, and historical checklist, propose the 3 to 6 most "
    "security-relevant, code-specific vulnerability hypotheses. Reason about access control, accounting and "
    "share/asset math, reentrancy and external-call ordering, oracle and report trust, initialization and "
    "upgrade safety, and rounding. "
    "Return ONLY JSON of the form "
    '{"hypotheses":[{"title":"...","vulnerability_class":"...","affected_file":"...",'
    '"affected_function":"...","affected_contract":"...","reasoning":"why this is exploitable and the attack",'
    '"exploit_preconditions":["..."],"confidence":0.0}]}. '
    "Every affected_file and affected_function MUST be copied verbatim from a '// file: ... | function: ...' "
    "header in the supplied source; never invent files, functions, or line numbers. It is fine to be "
    "uncertain — propose plausible candidates (they are validated downstream). Always return at least 3 "
    "hypotheses when source code is provided."
)


def coerce_adversarial_verdict(payload: dict) -> dict:
    coerced: dict = {}
    verdict = str(payload.get("verdict") or payload.get("status") or "needs_manual_review").strip().lower()
    aliases = {
        "confirm": "confirmed",
        "confirmed": "confirmed",
        "exploitable": "confirmed",
        "true_positive": "confirmed",
        "likely": "likely",
        "probable": "likely",
        "reject": "rejected",
        "rejected": "rejected",
        "mitigated": "rejected",
        "false_positive": "rejected",
        "not_exploitable": "rejected",
        "needs_manual_review": "needs_manual_review",
        "uncertain": "needs_manual_review",
        "unknown": "needs_manual_review",
    }
    coerced["verdict"] = aliases.get(verdict, "needs_manual_review")
    for key in ("attack_trace", "counterevidence"):
        value = payload.get(key)
        if value is None:
            coerced[key] = []
        elif isinstance(value, str):
            coerced[key] = [value]
        elif isinstance(value, list):
            coerced[key] = [str(item) for item in value if item is not None]
        else:
            coerced[key] = [str(value)]
    coerced["reasoning"] = str(payload.get("reasoning") or payload.get("explanation") or "")[:1500]
    try:
        delta = float(payload.get("confidence_delta", 0.0))
    except (TypeError, ValueError):
        delta = 0.0
    coerced["confidence_delta"] = max(-0.5, min(0.5, delta))
    return coerced


def parse_adversarial_verdict(content: str) -> AdversarialVerdict:
    payload = json.loads(extract_json_object(content))
    if not isinstance(payload, dict):
        raise NonRetryableExternalError("Adversarial verdict JSON must be an object.")
    return AdversarialVerdict.model_validate(coerce_adversarial_verdict(payload))


_REVIEWER_SYSTEM = (
    "You are Solidity Sentinel's adversarial reviewer, a senior auditor verifying a single vulnerability "
    "hypothesis. You are given the affected function and its cross-contract CALLERS. Decide whether the "
    "hypothesis is actually exploitable. "
    "If a caller (e.g. a factory or configurator) satisfies the dangerous precondition ATOMICALLY in the "
    "same transaction as deployment, the issue is mitigated -> verdict 'rejected' with the specific "
    "counterevidence (name the function/file). If an attacker can reach the function first or independently, "
    "verdict 'confirmed' with a concrete ordered attack_trace. If callers are insufficient to decide, verdict "
    "'needs_manual_review'. "
    "Return ONLY JSON: "
    '{"verdict":"confirmed|likely|rejected|needs_manual_review","attack_trace":["step 1","step 2"],'
    '"counterevidence":["mitigation found, with function/file"],"reasoning":"...","confidence_delta":0.0}. '
    "Base every claim only on the supplied code; never invent callers or guards."
)


class OllamaAdversarialReviewer(BaseAdversarialReviewer):
    def __init__(self, model: str, base_url: str, api_key: str | None = None, llm: ChatOllama | None = None) -> None:
        self.llm = llm or ChatOllama(
            model=model,
            base_url=base_url,
            temperature=0.0,
            format="json",
            client_kwargs=_ollama_client_kwargs(api_key),
        )

    def review(self, prompt: str) -> AdversarialVerdict:
        response = self.llm.invoke(
            [SystemMessage(content=_REVIEWER_SYSTEM), HumanMessage(content=prompt)]
        )
        content = response.content if isinstance(response.content, str) else json.dumps(response.content)
        return parse_adversarial_verdict(content)


class OllamaHypothesisProposer(BaseHypothesisProposer):
    def __init__(self, model: str, base_url: str, api_key: str | None = None, llm: ChatOllama | None = None) -> None:
        self.llm = llm or ChatOllama(
            model=model,
            base_url=base_url,
            temperature=0.0,
            format="json",
            client_kwargs=_ollama_client_kwargs(api_key),
        )

    def propose(self, prompt: str) -> ProposedHypothesisBatch:
        self.last_raw = ""
        response = self.llm.invoke(
            [SystemMessage(content=_PROPOSER_SYSTEM), HumanMessage(content=prompt)]
        )
        content = response.content if isinstance(response.content, str) else json.dumps(response.content)
        self.last_raw = content
        return parse_proposed_hypotheses(content)


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
