from __future__ import annotations

from typing import Literal


EvidenceSourceType = Literal["production", "test", "script", "library", "dependency", "docs", "unknown"]
EvidenceRole = Literal["primary", "supporting", "behavioral_example", "deployment_context", "historical_context"]


def classify_source_path(path: str | None) -> EvidenceSourceType:
    """Classify local evidence paths so reports do not over-promote test/script clues."""

    if not path:
        return "unknown"
    normalized = str(path).replace("\\", "/").lower().lstrip("./")
    parts = [part for part in normalized.split("/") if part]
    if not parts:
        return "unknown"
    filename = parts[-1]
    if filename.endswith(".md") or filename.startswith("readme") or parts[0] in {"doc", "docs"}:
        return "docs"
    if any(part in {"node_modules", ".venv", "vendor"} for part in parts):
        return "dependency"
    if parts[0] in {"lib", "libs"}:
        return "library"
    if parts[0] in {"test", "tests"} or any(part in {"test", "tests", "mock", "mocks"} for part in parts):
        return "test"
    if parts[0] in {"script", "scripts"}:
        return "script"
    if parts[0] in {"src", "contracts"}:
        return "production"
    return "unknown"


def default_evidence_role(source_type: EvidenceSourceType) -> EvidenceRole:
    if source_type == "production":
        return "primary"
    if source_type == "test":
        return "behavioral_example"
    if source_type == "script":
        return "deployment_context"
    if source_type in {"docs", "library", "dependency"}:
        return "supporting"
    return "supporting"


def is_primary_production_path(path: str | None) -> bool:
    return classify_source_path(path) == "production"
