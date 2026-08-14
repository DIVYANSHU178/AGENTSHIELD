import pytest
from pydantic import ValidationError
from app.security.sandbox.contracts import (
    SandboxStatus,
    SandboxExecutionLimits,
    SandboxExecutionPolicy,
    SandboxExecutionResult,
)
from app.security.models.utils import utc_now

def test_sandbox_execution_limits_defaults_and_validation():
    limits = SandboxExecutionLimits()
    assert limits.timeout_seconds == 5.0
    assert limits.allow_network is False
    assert limits.allow_filesystem is False
    assert limits.environment_clean is True

    # Negative timeout rejected
    with pytest.raises(ValidationError):
        SandboxExecutionLimits(timeout_seconds=-1.0)

    # Zero timeout rejected
    with pytest.raises(ValidationError):
        SandboxExecutionLimits(timeout_seconds=0.0)

def test_sandbox_execution_policy_immutability():
    policy = SandboxExecutionPolicy(
        policy_id="test.policy",
        limits=SandboxExecutionLimits(timeout_seconds=2.5),
        isolation_level="logical_in_process",
    )
    assert policy.policy_id == "test.policy"
    assert policy.limits.timeout_seconds == 2.5

    # Frozen model prevents mutation
    with pytest.raises(ValidationError):
        policy.policy_id = "mutated.id"

def test_sandbox_execution_result_immutability():
    now = utc_now()
    res = SandboxExecutionResult(
        request_id="req-test-01",
        tool_name="calculator.compute",
        status=SandboxStatus.COMPLETED,
        executed=True,
        success=True,
        sandboxed=True,
        timed_out=False,
        started_at=now,
        completed_at=now,
        duration_ms=12.5,
        result={"val": 42},
    )

    assert res.status == SandboxStatus.COMPLETED
    assert res.executed is True
    assert res.success is True

    with pytest.raises(ValidationError):
        res.status = SandboxStatus.FAILED
