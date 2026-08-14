import pytest
from app.config.settings import settings
from app.security.models import (
    ToolRequest,
    AgentIdentity,
    ToolCategory,
    ActionType,
)
from app.security.enforcement import SecurityEnforcementBoundary
from app.security.sandbox.boundary import SandboxExecutionBoundary
from app.security.sandbox.contracts import SandboxStatus

def test_sandbox_string_transform_success():
    boundary = SecurityEnforcementBoundary()
    sandbox = SandboxExecutionBoundary(boundary=boundary)

    req = ToolRequest(
        request_id="req-str-sb",
        agent=AgentIdentity(name="TextAgent"),
        tool_name="string.transform",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="sandboxed text",
        parameters={"transform": "uppercase"},
    )
    enf_res = boundary.enforce(req)
    result = sandbox.execute(req, enf_res.authorization)

    assert result.status == SandboxStatus.COMPLETED
    assert result.result["output"] == "SANDBOXED TEXT"

def test_sandbox_health_check_success():
    boundary = SecurityEnforcementBoundary()
    sandbox = SandboxExecutionBoundary(boundary=boundary)

    req = ToolRequest(
        request_id="req-health-sb",
        agent=AgentIdentity(name="SysAgent"),
        tool_name="health.check",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.READ,
        target="engine",
    )
    enf_res = boundary.enforce(req)
    result = sandbox.execute(req, enf_res.authorization)

    assert result.status == SandboxStatus.COMPLETED
    assert result.result["status"] == "healthy"

def test_sandbox_unknown_tool_rejected():
    boundary = SecurityEnforcementBoundary()
    sandbox = SandboxExecutionBoundary(boundary=boundary)

    req = ToolRequest(
        request_id="req-unk-sb",
        agent=AgentIdentity(name="Agent"),
        tool_name="unregistered.arbitrary.tool",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="target",
    )
    enf_res = boundary.enforce(req)
    result = sandbox.execute(req, enf_res.authorization)

    assert result.status == SandboxStatus.DENIED
    assert result.executed is False
    assert "not registered" in result.error

def test_sandbox_unsupported_action_rejected():
    boundary = SecurityEnforcementBoundary()
    sandbox = SandboxExecutionBoundary(boundary=boundary)

    req = ToolRequest(
        request_id="req-unsupp-sb",
        agent=AgentIdentity(name="Agent"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.DELETE,
        target="calculator",
    )
    enf_res = boundary.enforce(req)
    result = sandbox.execute(req, enf_res.authorization)

    assert result.status == SandboxStatus.DENIED
    assert result.executed is False
    assert "not supported" in result.error

def test_sandbox_failing_handler_contained_without_crashing():
    boundary = SecurityEnforcementBoundary()
    sandbox = SandboxExecutionBoundary(boundary=boundary)

    req = ToolRequest(
        request_id="req-fail-sb",
        agent=AgentIdentity(name="FailAgent"),
        tool_name="failing.tool",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="test",
    )
    enf_res = boundary.enforce(req)
    result = sandbox.execute(req, enf_res.authorization)

    assert result.status == SandboxStatus.FAILED
    assert result.executed is True
    assert result.success is False
    assert "failed" in result.error.lower()

def test_sandbox_secret_non_leakage():
    boundary = SecurityEnforcementBoundary()
    sandbox = SandboxExecutionBoundary(boundary=boundary)

    req = ToolRequest(
        request_id="req-secret-check",
        agent=AgentIdentity(name="Agent"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="calculator",
        parameters={"op": "add", "a": 1, "b": 2},
    )
    enf_res = boundary.enforce(req)
    result = sandbox.execute(req, enf_res.authorization)

    secret = settings.get_authorization_secret()
    result_json = result.model_dump_json()

    assert secret not in result_json
