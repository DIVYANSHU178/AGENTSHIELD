from app.security.models import (
    ToolRequest,
    AgentIdentity,
    ToolCategory,
    ActionType,
)
from app.security.enforcement import SecurityEnforcementBoundary
from app.security.sandbox.boundary import SandboxExecutionBoundary
from app.security.sandbox.contracts import SandboxStatus

def test_repeated_sandbox_execution_determinism():
    boundary = SecurityEnforcementBoundary()
    sandbox = SandboxExecutionBoundary(boundary=boundary)

    req = ToolRequest(
        request_id="req-sb-determ",
        agent=AgentIdentity(name="MathAgent"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="calculator",
        parameters={"op": "pow", "a": 2, "b": 8},
    )

    enf_res = boundary.enforce(req)
    assert enf_res.authorized is True

    res1 = sandbox.execute(req, enf_res.authorization)
    res2 = sandbox.execute(req, enf_res.authorization)

    assert res1.status == res2.status == SandboxStatus.COMPLETED
    assert res1.executed == res2.executed == True
    assert res1.success == res2.success == True
    assert res1.result == res2.result == {"operation": "pow", "a": 2.0, "b": 8.0, "result": 256.0}
