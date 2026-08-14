from app.security.models import (
    ToolRequest,
    AgentIdentity,
    ToolCategory,
    ActionType,
)
from app.security.enforcement import SecurityEnforcementBoundary
from app.security.execution.executor import SecureExecutionAdapter

def test_repeated_execution_is_deterministic():
    boundary = SecurityEnforcementBoundary()
    adapter = SecureExecutionAdapter(boundary=boundary)

    req = ToolRequest(
        request_id="req-determ-001",
        agent=AgentIdentity(name="DetermAgent"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="calculator",
        parameters={"op": "add", "a": 50, "b": 25},
    )

    enf_res = boundary.enforce(req)
    assert enf_res.authorized is True

    res1 = adapter.execute(req, enf_res.authorization)
    res2 = adapter.execute(req, enf_res.authorization)

    assert res1.executed == res2.executed == True
    assert res1.success == res2.success == True
    assert res1.result == res2.result == {"operation": "add", "a": 50.0, "b": 25.0, "result": 75.0}
    assert res1.error == res2.error == None
