from app.security.models import (
    ToolRequest,
    AgentIdentity,
    ToolCategory,
    ActionType,
)
from app.security.sandbox.boundary import SandboxExecutionBoundary
from app.security.sandbox.contracts import SandboxStatus

def test_sandbox_none_inputs_fail_closed():
    sandbox = SandboxExecutionBoundary()
    res1 = sandbox.execute(None, None)
    assert res1.status == SandboxStatus.DENIED
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
    res2 = sandbox.execute(req, None)
    assert res2.status == SandboxStatus.DENIED
    assert res2.executed is False

def test_sandbox_invalid_runtime_types_fail_closed():
    sandbox = SandboxExecutionBoundary()
    res = sandbox.execute("invalid_string_request", "invalid_string_auth")
    assert res.status == SandboxStatus.DENIED
    assert res.executed is False
    assert res.success is False

def test_sandbox_dict_instead_of_model_fails_closed():
    sandbox = SandboxExecutionBoundary()
    res = sandbox.execute({"request_id": "123"}, {"auth_id": "456"})
    assert res.status == SandboxStatus.DENIED
    assert res.executed is False
