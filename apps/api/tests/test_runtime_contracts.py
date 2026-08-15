import pytest
from pydantic import ValidationError
from app.security.models import (
    AgentIdentity,
    ToolCategory,
    ActionType,
    SecurityDecisionType,
)
from app.security.runtime import (
    RuntimeExecutionStatus,
    RuntimeExecutionContext,
    RuntimeExecutionRequest,
    RuntimeExecutionResult,
)
from app.security.models.utils import FrozenDict

def test_runtime_execution_request_construction_and_conversion():
    agent = AgentIdentity(name="OrchestratorAgent")
    context = RuntimeExecutionContext(environment="staging", session_id="sess-01", user_id="user-42")

    runtime_req = RuntimeExecutionRequest(
        request_id="req-orch-01",
        agent=agent,
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="calculator",
        parameters={"op": "multiply", "a": 6, "b": 7},
        destination=None,
        session_id="sess-01",
        context=context,
        metadata={"source": "api"},
    )

    assert runtime_req.request_id == "req-orch-01"
    assert runtime_req.tool_name == "calculator.compute"
    assert runtime_req.tool_category == ToolCategory.SYSTEM
    assert runtime_req.action == ActionType.EXECUTE
    assert runtime_req.parameters["op"] == "multiply"
    assert isinstance(runtime_req.parameters, FrozenDict)

    # Conversion to canonical ToolRequest
    tool_req = runtime_req.to_tool_request()
    assert tool_req.request_id == runtime_req.request_id
    assert tool_req.agent.agent_id == agent.agent_id
    assert tool_req.tool_name == "calculator.compute"
    assert tool_req.tool_category == ToolCategory.SYSTEM
    assert tool_req.action == ActionType.EXECUTE
    assert tool_req.target == "calculator"
    assert tool_req.parameters["a"] == 6
    assert tool_req.parameters["b"] == 7

def test_runtime_immutability():
    params = {"op": "add", "nested": {"val": 10}}
    meta = {"tag": "alpha"}

    req = RuntimeExecutionRequest(
        request_id="req-immut-orch",
        agent=AgentIdentity(name="Agent"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="calculator",
        parameters=params,
        metadata=meta,
    )

    # Caller dict mutation does not affect model
    params["nested"]["val"] = 999
    meta["tag"] = "tampered"
    assert req.parameters["nested"]["val"] == 10
    assert req.metadata["tag"] == "alpha"

    # Direct mutation raises TypeError
    with pytest.raises(TypeError):
        req.parameters["op"] = "sub"

    with pytest.raises(TypeError):
        req.parameters["nested"]["val"] = 50

    with pytest.raises(TypeError):
        req.metadata["tag"] = "beta"

def test_runtime_serialization_roundtrip():
    req = RuntimeExecutionRequest(
        request_id="req-ser-01",
        agent=AgentIdentity(name="Agent"),
        tool_name="string.transform",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="string",
        parameters={"transform": "uppercase", "text": "hello"},
    )

    json_str = req.model_dump_json()
    req_loaded = RuntimeExecutionRequest.model_validate_json(json_str)

    assert req_loaded.request_id == req.request_id
    assert req_loaded.tool_name == "string.transform"
    assert req_loaded.parameters["text"] == "hello"
    assert isinstance(req_loaded.parameters, FrozenDict)

def test_runtime_execution_result_validation():
    result = RuntimeExecutionResult(
        request_id="req-res-01",
        status=RuntimeExecutionStatus.COMPLETED,
        decision=SecurityDecisionType.ALLOW,
        authorized=True,
        executed=True,
        success=True,
        result=42.0,
        metadata={"exec_env": "sandbox"},
    )

    assert result.status == RuntimeExecutionStatus.COMPLETED
    assert result.authorized is True
    assert result.executed is True
    assert result.success is True
    assert result.result == 42.0
    assert isinstance(result.metadata, FrozenDict)

    # Reassignment blocked
    with pytest.raises(ValidationError):
        result.success = False
