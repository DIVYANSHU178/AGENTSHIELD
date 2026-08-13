from unittest.mock import MagicMock
from app.security import (
    AgentIdentity,
    ToolRequest,
    ToolCategory,
    ActionType,
    SecurityDecisionGateway,
    SecurityDecisionType,
    Severity,
)

def test_gateway_fail_closed_none_request():
    gateway = SecurityDecisionGateway()
    result = gateway.evaluate(None)  # type: ignore

    assert result.decision.decision == SecurityDecisionType.BLOCK
    assert result.risk_assessment.severity == Severity.CRITICAL
    assert result.metadata["fail_closed_active"] is True
    assert "failing closed with BLOCK decision" in result.decision.reason

def test_gateway_fail_closed_internal_detector_exception():
    mock_registry = MagicMock()
    mock_registry.detect_all.side_effect = RuntimeError("Simulated detector error")

    gateway = SecurityDecisionGateway(detector_registry=mock_registry)
    agent = AgentIdentity(name="FailTestAgent")
    req = ToolRequest(
        request_id="req-fail-detector",
        agent=agent,
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="sandbox/public/sample.txt",
    )

    result = gateway.evaluate(req)

    assert result.decision.decision == SecurityDecisionType.BLOCK
    assert result.risk_assessment.risk_score == 100.0
    assert result.metadata["fail_closed_active"] is True
    assert "Security evaluation failed during internal stage processing" in result.decision.reason

def test_gateway_fail_closed_internal_risk_engine_exception():
    mock_risk_engine = MagicMock()
    mock_risk_engine.assess.side_effect = ValueError("Simulated risk engine error")

    gateway = SecurityDecisionGateway(risk_engine=mock_risk_engine)
    agent = AgentIdentity(name="FailTestAgent")
    req = ToolRequest(
        request_id="req-fail-risk",
        agent=agent,
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="sandbox/public/sample.txt",
    )

    result = gateway.evaluate(req)

    assert result.decision.decision == SecurityDecisionType.BLOCK
    assert result.decision.policy_id == "policy.gateway.fail_closed.block"
    assert result.metadata["fail_closed_active"] is True

def test_gateway_fail_closed_does_not_leak_raw_traceback_in_reason():
    mock_policy_engine = MagicMock()
    mock_policy_engine.evaluate_request.side_effect = KeyError("SECRET_INTERNAL_KEY_FAILURE")

    gateway = SecurityDecisionGateway(policy_engine=mock_policy_engine)
    agent = AgentIdentity(name="LeakTestAgent")
    req = ToolRequest(
        request_id="req-leak-test",
        agent=agent,
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="sandbox/public/sample.txt",
    )

    result = gateway.evaluate(req)

    assert result.decision.decision == SecurityDecisionType.BLOCK
    # Ensure raw exception name is sanitized in human reason
    assert "SECRET_INTERNAL_KEY_FAILURE" not in result.decision.reason
