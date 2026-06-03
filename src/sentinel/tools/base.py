from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from sentinel.schemas.common import RiskLevel, SideEffect
from sentinel.state import AuditState


ToolFn = Callable[[BaseModel, AuditState], BaseModel | dict[str, Any]]


class RegisteredTool(BaseModel):
    """A typed capability that can be selected by an agent and run by executor."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    namespace: str
    name: str
    description: str
    input_model: type[BaseModel]
    output_model: type[BaseModel]
    fn: ToolFn
    risk_level: RiskLevel = RiskLevel.LOW
    side_effects: list[SideEffect] = Field(default_factory=lambda: [SideEffect.NONE])
    requires_network: bool = False
    examples: list[dict[str, Any]] = Field(default_factory=list)
    chaining_hints: list[str] = Field(default_factory=list)
    execution_kind: str = "deterministic"

    @property
    def full_name(self) -> str:
        return f"{self.namespace}.{self.name}"

    def public_dict(self) -> dict[str, Any]:
        """Return serializable metadata suitable for LLM tool selection."""

        return {
            "name": self.full_name,
            "namespace": self.namespace,
            "description": self.description,
            "input_schema": self.input_model.__name__,
            "input_json_schema": self.input_model.model_json_schema(),
            "output_schema": self.output_model.__name__,
            "output_json_schema": self.output_model.model_json_schema(),
            "risk_level": self.risk_level.value,
            "side_effects": [effect.value for effect in self.side_effects],
            "requires_network": self.requires_network,
            "examples": self.examples,
            "chaining_hints": self.chaining_hints,
            "execution_kind": self.execution_kind,
        }
