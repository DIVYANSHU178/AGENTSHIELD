from app.security import (
    AgentIdentity,
    ToolRequest,
    ToolCategory,
    ActionType,
    RiskAssessment,
    Severity,
    PolicyContext,
    SecurityDecisionType,
    CriticalRiskRule,
    VeryHighRiskRule,
    HighRiskRule,
    MediumRiskRule,
    DefaultAllowRule,
)

def make_context(score: float, sev: Severity) -> PolicyContext:
    agent = AgentIdentity(name="RuleAgent")
    req = ToolRequest(
        request_id="req-rule-test",
        agent=agent,
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="sandbox/public/sample.txt",
    )
    risk = RiskAssessment(
        request_id=req.request_id,
        risk_score=score,
        severity=sev,
    )
    return PolicyContext(request=req, risk_assessment=risk)

def test_critical_risk_rule():
    rule = CriticalRiskRule()
    assert rule.priority == 100
    assert rule.rule_id == "policy.risk.critical.block"

    ctx_crit = make_context(90.0, Severity.CRITICAL)
    res = rule.evaluate(ctx_crit)
    assert res is not None
    assert res[0] == SecurityDecisionType.BLOCK

    ctx_high = make_context(60.0, Severity.HIGH)
    assert rule.evaluate(ctx_high) is None

def test_very_high_risk_rule():
    rule = VeryHighRiskRule()
    assert rule.priority == 90

    ctx_80 = make_context(80.0, Severity.HIGH)
    res = rule.evaluate(ctx_80)
    assert res is not None
    assert res[0] == SecurityDecisionType.BLOCK

    ctx_79_99 = make_context(79.99, Severity.HIGH)
    assert rule.evaluate(ctx_79_99) is None

def test_high_risk_rule():
    rule = HighRiskRule()
    assert rule.priority == 70

    ctx_60 = make_context(60.0, Severity.HIGH)
    res = rule.evaluate(ctx_60)
    assert res is not None
    assert res[0] == SecurityDecisionType.REQUIRE_APPROVAL

    ctx_59_99 = make_context(59.99, Severity.MEDIUM)
    assert rule.evaluate(ctx_59_99) is None

def test_medium_risk_rule():
    rule = MediumRiskRule()
    assert rule.priority == 50

    ctx_30 = make_context(30.0, Severity.LOW)
    res = rule.evaluate(ctx_30)
    assert res is not None
    assert res[0] == SecurityDecisionType.REQUIRE_APPROVAL

    ctx_29_99 = make_context(29.99, Severity.LOW)
    assert rule.evaluate(ctx_29_99) is None

def test_default_allow_rule():
    rule = DefaultAllowRule()
    assert rule.priority == 0

    ctx_zero = make_context(0.0, Severity.INFO)
    res = rule.evaluate(ctx_zero)
    assert res is not None
    assert res[0] == SecurityDecisionType.ALLOW
