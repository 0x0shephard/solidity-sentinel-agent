import pytest

from sentinel.errors import UnknownToolError
from sentinel.tools import build_default_registry
from sentinel.tools.registry import ToolRegistry


def test_default_registry_has_initial_tools_across_four_namespaces():
    registry = build_default_registry()
    namespaces = {tool.namespace for tool in registry.list()}

    assert len(registry) >= 12
    assert namespaces == {"repo", "build", "static", "research"}


def test_registry_lookup_and_namespace_filtering():
    registry = build_default_registry()

    assert registry.get("repo.list_files").full_name == "repo.list_files"
    assert all(tool.namespace == "repo" for tool in registry.by_namespace("repo"))


def test_registry_rejects_duplicate_tool():
    registry = ToolRegistry()
    tool = build_default_registry().get("repo.list_files")

    registry.register(tool)
    with pytest.raises(ValueError):
        registry.register(tool)


def test_registry_unknown_tool_raises_typed_error():
    with pytest.raises(UnknownToolError):
        build_default_registry().get("repo.nope")


def test_scoped_registry_contains_only_allowed_tools():
    scoped = build_default_registry().scoped(["repo.list_files", "research.rank_hypotheses"])

    assert [tool.full_name for tool in scoped.list()] == ["repo.list_files", "research.rank_hypotheses"]

