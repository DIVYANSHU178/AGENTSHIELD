import pytest
from datetime import timedelta
from app.security.approval.policy import ApprovalPolicy, ApprovalPolicyEngine
from app.security.approval.errors import ApprovalPolicyViolationError
from app.security.gateway import SecurityEvaluationResult
from app.security.models import (
    ToolRequest,
    AgentIdentity,
    ToolCategory,
    ActionType,
    SecurityDecision,
    SecurityDecisionType,
    RiskAssessment,
    ThreatReport,
    Severity,
)
from app.security.models.utils import utc_now

def _create_mock_eval_result(decision_type: SecurityDecisionType) -> SecurityEvaluationResult:
    req_id = "req-pol-01"
    req = ToolRequest(
        request_id=req_id,
        agent=AgentIdentity(name="Agent"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="calculator",
    )
    decision = SecurityDecision(
        request_id=req_id,
        decision=decision_type,
        policy_id="test.policy",
        reason="Test evaluation reason",
    )
    risk_score = 50.0 if decision_type == SecurityDecisionType.REQUIRE_APPROVAL else (0.0 if decision_type == SecurityDecisionType.ALLOW else 100.0)
    severity = Severity.MEDIUM if decision_type == SecurityDecisionType.REQUIRE_APPROVAL else (Severity.INFO if decision_type == SecurityDecisionType.ALLOW else Severity.CRITICAL)
    risk = RiskAssessment(
        request_id=req_id,
        risk_score=risk_score,
        severity=severity,
        rationale="Risk rationale",
    )
    threat = ThreatReport(
        request_id=req_id,
        signals=[],
        overall_severity=risk.severity,
        summary="Threat report",
    )
    return SecurityEvaluationResult(
        request=req,
        threat_report=threat,
        risk_assessment=risk,
        decision=decision,
    )

def test_approval_policy_allows_only_require_approval():
    engine = ApprovalPolicyEngine()

    # REQUIRE_APPROVAL -> OK
    eval_approval = _create_mock_eval_result(SecurityDecisionType.REQUIRE_APPROVAL)
    engine.validate_can_create_approval(eval_approval)

    # ALLOW -> Policy Violation
    eval_allow = _create_mock_eval_result(SecurityDecisionType.ALLOW)
    with pytest.raises(ApprovalPolicyViolationError) as exc_info:
        engine.validate_can_create_approval(eval_allow)
    assert "REQUIRE_APPROVAL" in str(exc_info.value)

    # BLOCK -> Policy Violation
    eval_block = _create_mock_eval_result(SecurityDecisionType.BLOCK)
    with pytest.raises(ApprovalPolicyViolationError) as exc_info:
        engine.validate_can_create_approval(eval_block)
    assert "REQUIRE_APPROVAL" in str(exc_info.value)

def test_approval_policy_expiration_calculation():
    policy = ApprovalPolicy(default_ttl_seconds=1800.0, max_ttl_seconds=3600.0)
    engine = ApprovalPolicyEngine(policy=policy)
    base = utc_now()

    # Default TTL
    exp_default = engine.calculate_expiration(base)
    assert exp_default == base + timedelta(seconds=1800.0)

    # Custom valid TTL
    exp_custom = engine.calculate_expiration(base, ttl_seconds=600.0)
    assert exp_custom == base + timedelta(seconds=600.0)

    # TTL capped at max_ttl_seconds
    exp_capped = engine.calculate_expiration(base, ttl_seconds=999999.0)
    assert exp_capped == base + timedelta(seconds=3600.0)

    # TTL floored at 1.0s
    exp_floored = engine.calculate_expiration(base, ttl_seconds=-100.0)
    assert exp_floored == base + timedelta(seconds=1.0)
