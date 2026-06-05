from __future__ import annotations

from sentinel.errors import UnknownToolError
from sentinel.tools.base import RegisteredTool


class ToolRegistry:
    """In-memory registry of all callable Sentinel tools."""

    def __init__(self) -> None:
        self._tools: dict[str, RegisteredTool] = {}

    def register(self, tool: RegisteredTool) -> None:
        if tool.full_name in self._tools:
            raise ValueError(f"Duplicate tool: {tool.full_name}")
        self._tools[tool.full_name] = tool

    def get(self, full_name: str) -> RegisteredTool:
        try:
            return self._tools[full_name]
        except KeyError as exc:
            raise UnknownToolError(f"Unknown tool: {full_name}") from exc

    def list(self) -> list[RegisteredTool]:
        return sorted(self._tools.values(), key=lambda tool: tool.full_name)

    def by_namespace(self, namespace: str) -> list[RegisteredTool]:
        return [tool for tool in self.list() if tool.namespace == namespace]

    def scoped(self, allowed_names: list[str]) -> "ToolRegistry":
        scoped = ToolRegistry()
        for name in allowed_names:
            scoped.register(self.get(name))
        return scoped

    def __len__(self) -> int:
        return len(self._tools)


def build_default_registry() -> ToolRegistry:
    from sentinel.tools import build, composite, dynamic, memory, repo, report, research, static

    registry = ToolRegistry()
    for module in [repo, build, static, research, dynamic, report, memory, composite]:
        module.register(registry)
    return registry
