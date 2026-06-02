from sentinel.state import initial_audit_state
from sentinel.tools import build_default_registry
from sentinel.tools.executor import ToolExecutor


def test_phase_10_expected_tool_count_and_namespaces():
    registry = build_default_registry()
    by_namespace = {namespace: len(registry.by_namespace(namespace)) for namespace in ["repo", "build", "static", "research", "dynamic", "report", "memory"]}

    assert len(registry) >= 60
    assert by_namespace["repo"] >= 12
    assert by_namespace["build"] >= 10
    assert by_namespace["static"] >= 12
    assert by_namespace["dynamic"] >= 8
    assert by_namespace["report"] >= 7
    assert by_namespace["memory"] >= 6


def test_memory_tool_is_callable():
    state = initial_audit_state("run-1", ".", "Find bugs", "runs/run-1")
    output = ToolExecutor(build_default_registry()).execute("memory.summarize_context", {"note": "summarize"}, state)

    assert output.status == "ok"
    assert "compressed_context" in output.data


def test_report_tool_is_callable():
    state = initial_audit_state("run-1", ".", "Find bugs", "runs/run-1")
    output = ToolExecutor(build_default_registry()).execute("report.generate_json", {"data": {}}, state)

    assert output.status == "ok"
    assert output.data["run_id"] == "run-1"
