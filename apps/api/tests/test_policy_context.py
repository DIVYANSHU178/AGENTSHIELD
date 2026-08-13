import pytest
from pydantic import ValidationError
from app.security import (
    AgentIdentity,
    ToolRequest,
    ToolCategory,
    ActionType,
    RiskAssessment,
    ThreatReport,
    Severity,
    PolicyContext,
)

def make_req_and_risk(req_id: str = "req-100", risk_score: float = 0.0, severity: Severity = Severity.INFO):
    agent = AgentIdentity(name="TestAgent")
    req = ToolRequest(
        request_id=req_id,
        agent=agent,
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="sandbox/public/sample.txt",
    )
    risk = RiskAssessment(
        request_id=req_id,
        risk_score=risk_score,
        severity=severity,
    )
    return req, risk

def test_policy_context_valid():
    req, risk = make_req_and_risk()
    ctx = PolicyContext(request=req, risk_assessment=risk)
    assert ctx.request.request_id == "req-100"
    assert ctx.risk_assessment.risk_score == 0.0

def test_policy_context_mismatched_request_ids():
    agent = AgentIdentity(name="TestAgent")
    req = ToolRequest(
        request_id="req-100",
        agent=agent,
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="sandbox/public/sample.txt",
    )
    risk = RiskAssessment(
        request_id="req-mismatched",
        risk_score=50.0,
        severity=Severity.MEDIUM,
    )
    with pytest.raises(ValidationError):
        PolicyContext(request=req, risk_assessment=risk)

def test_policy_context_mismatched_threat_report_id():
    req, risk = make_req_and_risk()
    report = ThreatReport(request_id="req-mismatched-report", signals=[])
    with pytest.raises(ValidationError):
        PolicyContext(request=req, risk_assessment=risk, threat_report=report)

def test_policy_context_immutability():
    req, risk = make_req_and_risk()
    ctx = PolicyContext(request=req, risk_assessment=risk)
    with pytest.raises(ValidationError):
        ctx.request = req
