import pytest
from pydantic import ValidationError

from sentinel.schemas.common import PlanStep, ToolCallRecord, ToolStatus
from sentinel.schemas.report import Finding
from sentinel.schemas.research import VulnerabilityHypothesis


def test_plan_step_defaults_to_pending():
    step = PlanStep(id="inspect", description="Inspect repository")
    assert step.status == "pending"
    assert step.depends_on == []


def test_finding_confidence_is_bounded():
    with pytest.raises(ValidationError):
        Finding(
            id="f-1",
            title="bad confidence",
            severity="high",
            confidence=1.5,
            vulnerability_class="missing_access_control",
            summary="confidence must be between zero and one",
        )


def test_hypothesis_confidence_is_bounded():
    with pytest.raises(ValidationError):
        VulnerabilityHypothesis(
            id="h-1",
            title="bad confidence",
            vulnerability_class="reentrancy",
            evidence_summary="invalid score",
            confidence=-0.1,
        )


def test_tool_call_record_latency_and_retry_are_non_negative():
    with pytest.raises(ValidationError):
        ToolCallRecord(
            call_id="c-1",
            run_id="r-1",
            tool_name="repo.list_files",
            namespace="repo",
            input_hash="abc",
            status=ToolStatus.OK,
            started_at="2026-06-03T00:00:00Z",
            latency_ms=-1,
        )

