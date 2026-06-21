from __future__ import annotations

import json
import re

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import ChatOllama

from sentinel.errors import NonRetryableExternalError
from sentinel.llm.base import BaseAdversarialReviewer, BaseHypothesisProposer, BasePlanner, BasePocAuthor, BasePocRepairer, BaseResearchRefiner, ToolPlan
from sentinel.llm.resilience import invoke_chat
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


def extract_solidity_code(text: str) -> str:
    """Pull Solidity source from a model response.

    Prefers a fenced ```solidity block; otherwise falls back to the first text
    that looks like a Solidity file (has a pragma/contract). Returns "" when no
    plausible source is present so the caller treats it as "no repair".
    """
    if not text:
        return ""
    fenced = re.search(r"```(?:solidity|sol)?\s*(.*?)```", text, flags=re.DOTALL)
    candidate = fenced.group(1).strip() if fenced else text.strip()
    if "pragma solidity" in candidate or re.search(r"\bcontract\s+\w+", candidate):
        return candidate
    return ""


_POC_REPAIR_SYSTEM = (
    "You are Solidity Sentinel's PoC repair engine. You are given a Foundry test that FAILED to compile, the "
    "real source of the target contract(s), and the solc error output. Rewrite the test so it COMPILES against "
    "the real contract API and still expresses the same security check. Use only members, constructor "
    "signatures, and function signatures that actually exist in the supplied source — never invent methods. "
    "Keep the existing import paths and the contract name prefixed with 'Sentinel'. "
    "CRITICAL STRUCTURE: declare every contract, interface, and library at FILE SCOPE (top level). NEVER nest a "
    "contract/interface/library inside another contract or function — that is a syntax error (solc 9182). Put "
    "mock/helper contracts before or after the test contract, not inside it. "
    "Return ONLY the corrected Solidity file inside a single ```solidity code block, with no prose."
)


_POC_AUTHOR_SYSTEM = (
    "You are Solidity Sentinel's PoC author. Write a Foundry test that proves or refutes ONE vulnerability "
    "hypothesis. The protocol deploys its contracts through proxies/initializers, so you MUST inherit the "
    "protocol's existing test fixture (given to you) rather than constructing contracts from scratch: declare "
    "`contract Sentinel<Name> is <Fixture>` and call the fixture's setUp()/deploy helpers to obtain fully "
    "initialized instances. Then drive those instances to demonstrate the issue and assert the security "
    "invariant (use Foundry cheatcodes via the inherited Test/Vm). Use ONLY functions, state variables, and "
    "signatures that actually appear in the supplied fixture and target source — never invent members. Import "
    "the fixture from the given import path. Return ONLY the Solidity test in a single ```solidity code block."
)


class OllamaPocRepairer(BasePocRepairer):
    def __init__(self, model: str, base_url: str, api_key: str | None = None, llm: ChatOllama | None = None) -> None:
        self.llm = llm or ChatOllama(
            model=model,
            base_url=base_url,
            temperature=0.0,
            client_kwargs=_ollama_client_kwargs(api_key),
        )

    def repair(self, prompt: str) -> str:
        response = invoke_chat(self.llm, [SystemMessage(content=_POC_REPAIR_SYSTEM), HumanMessage(content=prompt)])
        content = response.content if isinstance(response.content, str) else json.dumps(response.content)
        return extract_solidity_code(content)


class OllamaPocAuthor(BasePocAuthor):
    def __init__(self, model: str, base_url: str, api_key: str | None = None, llm: ChatOllama | None = None) -> None:
        self.llm = llm or ChatOllama(
            model=model,
            base_url=base_url,
            temperature=0.0,
            client_kwargs=_ollama_client_kwargs(api_key),
        )

    def author(self, prompt: str) -> str:
        response = invoke_chat(self.llm, [SystemMessage(content=_POC_AUTHOR_SYSTEM), HumanMessage(content=prompt)])
        content = response.content if isinstance(response.content, str) else json.dumps(response.content)
        return extract_solidity_code(content)


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
    "CLASS-SCOPED MITIGATIONS: a guard, access modifier, nonReentrant, oracle gate, or atomic deployment only "
    "refutes hypotheses whose exploit depends on REACHING or ORDERING a call (access control, reentrancy, "
    "initialization/front-running). For accounting, fee, share/asset-math, and rounding hypotheses the defect "
    "is in the arithmetic itself — a nonReentrant modifier or access guard is NOT counterevidence; judge those "
    "purely on whether the math/accounting is wrong, and do NOT return 'rejected' citing a guard. "
    "DECISIVE MITIGATION RULE (access/reentrancy/init only): if ANY supplied caller is a factory/configurator/deployer (e.g. a function "
    "named create/deploy/configure/setup, or one that constructs a proxy via `new ...Proxy(... "
    "abi.encodeCall(IFactoryEntity.initialize, ...))`) and it invokes the affected function in the SAME "
    "transaction as deployment, then the dangerous precondition (e.g. an uninitialized one-time setter or "
    "initializer) is satisfied atomically and CANNOT be front-run. In that case you MUST return verdict "
    "'rejected' and cite that caller (function + file) as counterevidence. Apply this rule consistently: "
    "the same affected-function pattern wired by the same atomic caller is always 'rejected'. "
    "Only return 'confirmed' (with a concrete ordered attack_trace) when NO supplied caller closes the window "
    "and an attacker can reach the function first or independently. If callers are insufficient to decide, "
    "verdict 'needs_manual_review'. "
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
        response = invoke_chat(self.llm, 
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
        response = invoke_chat(self.llm, 
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
        response = invoke_chat(self.llm, 
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
        response = invoke_chat(self.llm, 
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
