import pytest
from pydantic import ValidationError
from app.security import (
    AgentIdentity,
    ToolRequest,
    ToolCategory,
    ActionType,
    RiskAssessment,
    Severity,
    SecurityDecision,
    SecurityDecisionType,
    PolicyContext,
    PolicyEngine,
    PolicyEngineError,
)

def make_context(req_id: str, score: float, sev: Severity) -> PolicyContext:
    agent = AgentIdentity(name="EngineTestAgent")
    req = ToolRequest(
        request_id=req_id,
        agent=agent,
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="sandbox/public/sample.txt",
    )
    risk = RiskAssessment(
        assessment_id="risk-assessment-999",
        request_id=req_id,
        risk_score=score,
        severity=sev,
    )
    return PolicyContext(request=req, risk_assessment=risk)

def test_engine_critical_block():
    engine = PolicyEngine()
    ctx = make_context("req-crit", 90.0, Severity.CRITICAL)
    dec = engine.evaluate(ctx)

    assert isinstance(dec, SecurityDecision)
    assert dec.request_id == "req-crit"
    assert dec.decision == SecurityDecisionType.BLOCK
    assert dec.risk_assessment_id == "risk-assessment-999"
    assert dec.policy_id == "policy.risk.critical.block"
    assert "CRITICAL" in dec.reason

def test_engine_very_high_block():
    engine = PolicyEngine()
    ctx = make_context("req-80", 80.0, Severity.HIGH)
    dec = engine.evaluate(ctx)

    assert dec.decision == SecurityDecisionType.BLOCK
    assert dec.policy_id == "policy.risk.very_high.block"
    assert "80.0" in dec.reason

def test_engine_high_approval():
    engine = PolicyEngine()
    ctx = make_context("req-60", 60.0, Severity.HIGH)
    dec = engine.evaluate(ctx)

    assert dec.decision == SecurityDecisionType.REQUIRE_APPROVAL
    assert dec.policy_id == "policy.risk.high.approval"

def test_engine_medium_approval():
    engine = PolicyEngine()
    ctx = make_context("req-30", 30.0, Severity.LOW)
    dec = engine.evaluate(ctx)

    assert dec.decision == SecurityDecisionType.REQUIRE_APPROVAL
    assert dec.policy_id == "policy.risk.medium.approval"

def test_engine_low_and_info_allow():
    engine = PolicyEngine()

    # 29.99 LOW -> ALLOW
    ctx_low = make_context("req-29", 29.99, Severity.LOW)
    dec_low = engine.evaluate(ctx_low)
    assert dec_low.decision == SecurityDecisionType.ALLOW
    assert dec_low.policy_id == "policy.default.allow"

    # 0.0 INFO -> ALLOW
    ctx_zero = make_context("req-0", 0.0, Severity.INFO)
    dec_zero = engine.evaluate(ctx_zero)
    assert dec_zero.decision == SecurityDecisionType.ALLOW
    assert dec_zero.policy_id == "policy.default.allow"

def test_engine_boundary_precedence():
    engine = PolicyEngine()
    # CRITICAL severity even if score is 0.0 must BLOCK
    ctx = make_context("req-crit-prec", 0.0, Severity.CRITICAL)
    dec = engine.evaluate(ctx)
    assert dec.decision == SecurityDecisionType.BLOCK
    assert dec.policy_id == "policy.risk.critical.block"

def test_engine_none_context_raises():
    engine = PolicyEngine()
    with pytest.raises(PolicyEngineError):
        engine.evaluate(None)  # type: ignore

def test_engine_determinism():
    engine = PolicyEngine()
    ctx = make_context("req-det", 65.0, Severity.HIGH)

    dec1 = engine.evaluate(ctx)
    dec2 = engine.evaluate(ctx)

    assert dec1.decision == dec2.decision
    assert dec1.policy_id == dec2.policy_id
    assert dec1.reason == dec2.reason
    assert dec1.request_id == dec2.request_id

def test_engine_decision_immutability():
    engine = PolicyEngine()
    ctx = make_context("req-freeze", 10.0, Severity.INFO)
    dec = engine.evaluate(ctx)

    with pytest.raises(ValidationError):
        dec.decision = SecurityDecisionType.BLOCK
