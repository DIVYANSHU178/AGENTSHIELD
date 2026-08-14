import pytest
from app.security.models import (
    ToolRequest,
    AgentIdentity,
    ToolCategory,
    ActionType,
    EventType,
)
from app.security.enforcement import SecurityEnforcementBoundary
from app.security.audit import SecurityAuditTrail
from app.security.sandbox.boundary import SandboxExecutionBoundary
from app.security.sandbox.contracts import (
    SandboxExecutionPolicy,
    SandboxExecutionLimits,
    SandboxStatus,
)

def test_fast_tool_completes_within_timeout():
    boundary = SecurityEnforcementBoundary()
    trail = SecurityAuditTrail()
    sandbox = SandboxExecutionBoundary(boundary=boundary, audit_trail=trail)

    req = ToolRequest(
        request_id="req-fast-01",
        agent=AgentIdentity(name="FastAgent"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="calculator",
        parameters={"op": "add", "a": 5, "b": 5},
    )
    enf_res = boundary.enforce(req)
    assert enf_res.authorized is True

    # 1.0s timeout policy
    policy = SandboxExecutionPolicy(
        policy_id="policy.fast",
        limits=SandboxExecutionLimits(timeout_seconds=1.0),
    )

    result = sandbox.execute(req, enf_res.authorization, policy=policy)
    assert result.status == SandboxStatus.COMPLETED
    assert result.executed is True
    assert result.success is True
    assert result.timed_out is False
    assert result.result["result"] == 10.0

def test_slow_tool_exceeding_timeout_is_contained_and_aborted():
    boundary = SecurityEnforcementBoundary()
    trail = SecurityAuditTrail()
    sandbox = SandboxExecutionBoundary(boundary=boundary, audit_trail=trail)

    # Slow tool requesting a 1.0s delay
    req = ToolRequest(
        request_id="req-slow-01",
        agent=AgentIdentity(name="SlowAgent"),
        tool_name="slow.tool",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="test",
        parameters={"delay": 1.0},
    )
    enf_res = boundary.enforce(req)
    assert enf_res.authorized is True

    # Configure a tight 0.1s timeout policy
    strict_policy = SandboxExecutionPolicy(
        policy_id="policy.strict.timeout",
        limits=SandboxExecutionLimits(timeout_seconds=0.1),
    )

    result = sandbox.execute(req, enf_res.authorization, policy=strict_policy)
    assert result.status == SandboxStatus.TIMED_OUT
    assert result.executed is True
    assert result.success is False
    assert result.timed_out is True
    assert "timed out" in result.error.lower()

    # Verify FAILED audit event was logged
    events = trail.get_events("req-slow-01")
    assert len(events) == 1
    assert events[0].event_type == EventType.FAILED
    assert events[0].details["failure_details"]["timed_out"] is True
