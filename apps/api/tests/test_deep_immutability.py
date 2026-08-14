import copy
import pytest
from pydantic import ValidationError
from app.security.models import (
    ToolRequest,
    AgentIdentity,
    ToolCategory,
    ActionType,
    SecurityEvent,
    EventType,
    SecurityDecisionType,
)
from app.security.execution import ToolExecutionContract
from app.security.enforcement import ExecutionAuthorization, EnforcementResult
from app.security.execution.contracts import ExecutionResult
from app.security.sandbox.contracts import SandboxStatus, SandboxExecutionResult
from app.security.models.utils import FrozenDict

def test_tool_request_nested_immutability_and_defensive_copy():
    caller_params = {"op": "add", "a": 10, "nested": {"factor": 2}, "list": [1, 2]}
    caller_meta = {"env": "prod", "tags": {"team": "sec"}}

    req = ToolRequest(
        request_id="req-immut-01",
        agent=AgentIdentity(name="ImmutAgent"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="calculator",
        parameters=caller_params,
        metadata=caller_meta,
    )

    # 1. Modifying caller-owned dicts post-construction does not affect ToolRequest
    caller_params["a"] = 9999
    caller_params["nested"]["factor"] = 9999
    caller_params["list"].append(3)
    caller_meta["env"] = "tampered"

    assert req.parameters["a"] == 10
    assert req.parameters["nested"]["factor"] == 2
    assert req.parameters["list"] == (1, 2)
    assert req.metadata["env"] == "prod"

    # 2. Modifying ToolRequest fields directly raises TypeError
    with pytest.raises(TypeError):
        req.parameters["a"] = 50

    with pytest.raises(TypeError):
        req.parameters["nested"]["factor"] = 50

    with pytest.raises(TypeError):
        req.parameters["new_key"] = "bad"

    with pytest.raises(TypeError):
        req.parameters.pop("a")

    with pytest.raises(TypeError):
        req.parameters.clear()

    with pytest.raises(TypeError):
        req.parameters.update({"a": 100})

    with pytest.raises(TypeError):
        req.parameters.setdefault("b", 20)

    # 3. Outer model reassignment is blocked by frozen=True
    with pytest.raises(ValidationError):
        req.target = "tampered_target"

def test_security_event_nested_immutability():
    caller_details = {"outcome": "allowed", "nested": {"stage": "gateway"}}
    caller_meta = {"req": "123"}

    event = SecurityEvent(
        request_id="req-immut-02",
        event_type=EventType.ALLOWED,
        actor="security_gateway",
        details=caller_details,
        metadata=caller_meta,
    )

    # 1. Caller dict mutation does not affect SecurityEvent
    caller_details["outcome"] = "tampered"
    caller_details["nested"]["stage"] = "tampered"
    assert event.details["outcome"] == "allowed"
    assert event.details["nested"]["stage"] == "gateway"

    # 2. Modifying SecurityEvent details directly raises TypeError
    with pytest.raises(TypeError):
        event.details["outcome"] = "tampered"

    with pytest.raises(TypeError):
        event.details["nested"]["stage"] = "tampered"

    with pytest.raises(TypeError):
        event.details["tampered"] = True

    with pytest.raises(TypeError):
        event.details.pop("outcome")

    with pytest.raises(TypeError):
        event.details.clear()

    with pytest.raises(TypeError):
        event.details.update({"tampered": True})

def test_tool_execution_contract_supported_actions_immutability():
    def dummy_handler(r):
        return {}

    contract = ToolExecutionContract(
        tool_name="dummy.tool",
        tool_category=ToolCategory.SYSTEM,
        supported_actions={ActionType.EXECUTE, ActionType.READ},
        description="Dummy tool for test",
        handler=dummy_handler,
    )

    assert isinstance(contract.supported_actions, frozenset)
    assert ActionType.EXECUTE in contract.supported_actions

    # Attempting to mutate supported_actions raises AttributeError
    with pytest.raises(AttributeError):
        contract.supported_actions.add(ActionType.DELETE)

    with pytest.raises(AttributeError):
        contract.supported_actions.remove(ActionType.EXECUTE)

    with pytest.raises(AttributeError):
        contract.supported_actions.clear()

def test_models_json_roundtrips_preserved():
    req = ToolRequest(
        request_id="req-json-01",
        agent=AgentIdentity(name="Agent1"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="calculator",
        parameters={"op": "add", "a": 1, "nested": {"x": 10}},
    )

    json_data = req.model_dump_json()
    req_loaded = ToolRequest.model_validate_json(json_data)
    assert req_loaded.request_id == req.request_id
    assert req_loaded.parameters["nested"]["x"] == 10
    assert isinstance(req_loaded.parameters, FrozenDict)

    event = SecurityEvent(
        request_id="req-json-01",
        event_type=EventType.ALLOWED,
        actor="test_actor",
        details={"key": "val", "nested": {"score": 99}},
    )
    event_json = event.model_dump_json()
    event_loaded = SecurityEvent.model_validate_json(event_json)
    assert event_loaded.details["nested"]["score"] == 99
    assert isinstance(event_loaded.details, FrozenDict)
