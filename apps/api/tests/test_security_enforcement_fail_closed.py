from unittest.mock import MagicMock
from app.security import (
    AgentIdentity,
    ToolRequest,
    ToolCategory,
    ActionType,
    SecurityEnforcementBoundary,
    SecurityDecisionType,
)

def test_enforcement_scenario_h_null_input():
    boundary = SecurityEnforcementBoundary()

    res = boundary.enforce(None)  # type: ignore

    assert res.authorized is False
    assert res.authorization is None
    assert res.decision == SecurityDecisionType.BLOCK
    assert "ToolRequest is None" in res.reason

def test_enforcement_scenario_i_internal_gateway_failure():
    mock_gateway = MagicMock()
    mock_gateway.evaluate.side_effect = RuntimeError("Simulated internal gateway crash")

    boundary = SecurityEnforcementBoundary(gateway=mock_gateway)
    agent = AgentIdentity(name="FailAgent")
    req = ToolRequest(
        request_id="req-crash",
        agent=agent,
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="sandbox/public/sample.txt",
    )

    res = boundary.enforce(req)

    assert res.authorized is False
    assert res.authorization is None
    assert res.decision == SecurityDecisionType.BLOCK
    assert "Internal gateway processing failure" in res.reason

def test_validate_authorization_null_inputs():
    boundary = SecurityEnforcementBoundary()
    assert boundary.validate_authorization(None, None) is False
