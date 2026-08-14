import pytest
from app.security.models import (
    ToolRequest,
    AgentIdentity,
    ToolCategory,
    ActionType,
)
from app.security.enforcement import SecurityEnforcementBoundary
from app.security.execution import SecureExecutionAdapter
from app.security.sandbox import SandboxExecutionBoundary, SandboxStatus

def test_secure_execution_adapter_category_mismatch_denied():
    boundary = SecurityEnforcementBoundary()
    adapter = SecureExecutionAdapter(boundary=boundary)

    # Request specifies NETWORK category for calculator.compute (which is registered as SYSTEM)
    mismatched_req = ToolRequest(
        request_id="req-cat-mismatch-01",
        agent=AgentIdentity(name="MismatchAgent"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.NETWORK,
        action=ActionType.EXECUTE,
        target="calculator",
        parameters={"op": "add", "a": 2, "b": 3},
    )

    enf_res = boundary.enforce(mismatched_req)
    assert enf_res.authorized is True

    result = adapter.execute(mismatched_req, enf_res.authorization)
    assert result.executed is False
    assert result.success is False
    assert result.result is None
    assert "category mismatch" in result.error.lower()

def test_sandbox_category_mismatch_denied():
    boundary = SecurityEnforcementBoundary()
    sandbox = SandboxExecutionBoundary(boundary=boundary)

    mismatched_req = ToolRequest(
        request_id="req-cat-mismatch-02",
        agent=AgentIdentity(name="MismatchAgent"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.EXECUTE,
        target="calculator",
        parameters={"op": "add", "a": 2, "b": 3},
    )

    enf_res = boundary.enforce(mismatched_req)
    assert enf_res.authorized is True

    result = sandbox.execute(mismatched_req, enf_res.authorization)
    assert result.status == SandboxStatus.DENIED
    assert result.executed is False
    assert result.success is False
    assert result.result is None
    assert "category mismatch" in result.error.lower()

@pytest.mark.parametrize(
    "tool_name,tool_category,action,params,expected_success",
    [
        ("calculator.compute", ToolCategory.SYSTEM, ActionType.EXECUTE, {"op": "add", "a": 5, "b": 5}, True),
        ("string.transform", ToolCategory.SYSTEM, ActionType.EXECUTE, {"transform": "uppercase", "text": "hello"}, True),
        ("health.check", ToolCategory.SYSTEM, ActionType.READ, {}, True),
        ("failing.tool", ToolCategory.SYSTEM, ActionType.EXECUTE, {}, False),
        ("slow.tool", ToolCategory.SYSTEM, ActionType.EXECUTE, {"delay": 0.05}, True),
    ],
)
def test_matching_category_tools_execute_as_expected(tool_name, tool_category, action, params, expected_success):
    boundary = SecurityEnforcementBoundary()
    sandbox = SandboxExecutionBoundary(boundary=boundary)

    req = ToolRequest(
        request_id=f"req-match-{tool_name.replace('.', '-')}",
        agent=AgentIdentity(name="MatchingAgent"),
        tool_name=tool_name,
        tool_category=tool_category,
        action=action,
        target="test_target",
        parameters=params,
    )

    enf_res = boundary.enforce(req)
    assert enf_res.authorized is True

    result = sandbox.execute(req, enf_res.authorization)
    assert result.executed is True
    assert result.success is expected_success
