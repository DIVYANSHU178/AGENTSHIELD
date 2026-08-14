from app.security.models import (
    ToolRequest,
    AgentIdentity,
    ToolCategory,
    ActionType,
)
from app.security.execution.executor import SecureExecutionAdapter

def test_execute_none_inputs_fail_closed():
    adapter = SecureExecutionAdapter()
    res1 = adapter.execute(None, None)
    assert res1.executed is False
    assert res1.success is False

    req = ToolRequest(
        request_id="req-valid-1",
        agent=AgentIdentity(name="Agent"),
        tool_name="health.check",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.READ,
        target="system",
    )
    res2 = adapter.execute(req, None)
    assert res2.executed is False
    assert res2.success is False

def test_execute_invalid_runtime_types_fail_closed():
    adapter = SecureExecutionAdapter()
    res = adapter.execute("invalid_string_request", "invalid_string_auth")
    assert res.executed is False
    assert res.success is False

def test_execute_dict_instead_of_model_fails_closed():
    adapter = SecureExecutionAdapter()
    res = adapter.execute({"request_id": "123"}, {"auth_id": "456"})
    assert res.executed is False
    assert res.success is False
