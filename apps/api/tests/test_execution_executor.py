import pytest
from pydantic import ValidationError
from app.security.models import (
    ToolRequest,
    AgentIdentity,
    ToolCategory,
    ActionType,
)
from app.security.enforcement import SecurityEnforcementBoundary
from app.security.execution.executor import SecureExecutionAdapter
from app.security.execution.contracts import ExecutionResult

@pytest.fixture
def boundary():
    return SecurityEnforcementBoundary()

@pytest.fixture
def adapter(boundary):
    return SecureExecutionAdapter(boundary=boundary)

def test_execute_calculator_compute_success(adapter, boundary):
    req = ToolRequest(
        request_id="req-calc-001",
        agent=AgentIdentity(name="MathAgent"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="calculator",
        parameters={"op": "add", "a": 12.5, "b": 7.5},
    )

    enf_res = boundary.enforce(req)
    assert enf_res.authorized is True
    assert enf_res.authorization is not None

    result = adapter.execute(req, enf_res.authorization)

    assert isinstance(result, ExecutionResult)
    assert result.executed is True
    assert result.success is True
    assert result.request_id == "req-calc-001"
    assert result.tool_name == "calculator.compute"
    assert result.result["result"] == 20.0
    assert result.error is None
    assert result.authorization_id == enf_res.authorization.authorization_id

def test_execute_string_transform_success(adapter, boundary):
    req = ToolRequest(
        request_id="req-str-001",
        agent=AgentIdentity(name="TextAgent"),
        tool_name="string.transform",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="hello world",
        parameters={"transform": "uppercase"},
    )

    enf_res = boundary.enforce(req)
    assert enf_res.authorized is True

    result = adapter.execute(req, enf_res.authorization)
    assert result.executed is True
    assert result.success is True
    assert result.result["output"] == "HELLO WORLD"

def test_execute_health_check_success(adapter, boundary):
    req = ToolRequest(
        request_id="req-health-001",
        agent=AgentIdentity(name="SysAgent"),
        tool_name="health.check",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.READ,
        target="system.engine",
    )

    enf_res = boundary.enforce(req)
    assert enf_res.authorized is True

    result = adapter.execute(req, enf_res.authorization)
    assert result.executed is True
    assert result.success is True
    assert result.result["status"] == "healthy"

def test_execute_unknown_tool_denied(adapter, boundary):
    req = ToolRequest(
        request_id="req-unk-001",
        agent=AgentIdentity(name="Agent"),
        tool_name="unregistered.dangerous.tool",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="system",
    )

    enf_res = boundary.enforce(req)
    assert enf_res.authorized is True

    result = adapter.execute(req, enf_res.authorization)
    assert result.executed is False
    assert result.success is False
    assert "not registered" in result.error

def test_execute_unsupported_action_denied(adapter, boundary):
    req = ToolRequest(
        request_id="req-unsupp-001",
        agent=AgentIdentity(name="Agent"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.DELETE,  # Calculator does not support DELETE
        target="calculator",
    )

    enf_res = boundary.enforce(req)
    assert enf_res.authorized is True

    result = adapter.execute(req, enf_res.authorization)
    assert result.executed is False
    assert result.success is False
    assert "not supported" in result.error

def test_execute_failing_handler_returns_executed_true_success_false(adapter, boundary):
    req = ToolRequest(
        request_id="req-fail-001",
        agent=AgentIdentity(name="Agent"),
        tool_name="failing.tool",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="test",
    )

    enf_res = boundary.enforce(req)
    assert enf_res.authorized is True

    result = adapter.execute(req, enf_res.authorization)
    assert result.executed is True
    assert result.success is False
    assert "execution failed" in result.error.lower()

def test_execution_result_is_frozen_immutable(adapter, boundary):
    req = ToolRequest(
        request_id="req-immut-001",
        agent=AgentIdentity(name="Agent"),
        tool_name="health.check",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.READ,
        target="system.engine",
    )
    enf_res = boundary.enforce(req)
    result = adapter.execute(req, enf_res.authorization)

    with pytest.raises(ValidationError):
        result.executed = False
