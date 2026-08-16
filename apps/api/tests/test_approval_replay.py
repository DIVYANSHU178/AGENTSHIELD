import pytest
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
from app.security.gateway import SecurityEvaluationResult
from app.security.approval.service import ApprovalService
from app.security.approval.contracts import ReviewerIdentity, ApprovalDecision
from app.security.approval.errors import InvalidApprovalStateTransitionError
from app.security.enforcement import SecurityEnforcementBoundary

def _make_eval(req_id: str) -> SecurityEvaluationResult:
    req = ToolRequest(
        request_id=req_id,
        agent=AgentIdentity(name="ReplayAgent"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="calculator",
    )
    return SecurityEvaluationResult(
        request=req,
        threat_report=ThreatReport(request_id=req_id, signals=[], overall_severity=Severity.MEDIUM, summary="Medium"),
        risk_assessment=RiskAssessment(request_id=req_id, risk_score=50.0, severity=Severity.MEDIUM, rationale="Risk"),
        decision=SecurityDecision(
            request_id=req_id,
            decision=SecurityDecisionType.REQUIRE_APPROVAL,
            policy_id="test.policy",
            reason="Requires approval",
        ),
    )

def test_double_approval_fails_deterministically():
    service = ApprovalService()
    eval_res = _make_eval("req-rep-01")
    app_req = service.create_approval(eval_res)

    reviewer = ReviewerIdentity(reviewer_id="rev-01")
    service.approve(app_req.approval_id, reviewer=reviewer, reason="First approval")

    # Second approval attempt must fail
    with pytest.raises(InvalidApprovalStateTransitionError):
        service.approve(app_req.approval_id, reviewer=reviewer, reason="Second approval attempt")

def test_double_rejection_fails_deterministically():
    service = ApprovalService()
    eval_res = _make_eval("req-rep-02")
    app_req = service.create_approval(eval_res)

    reviewer = ReviewerIdentity(reviewer_id="rev-02")
    service.reject(app_req.approval_id, reviewer=reviewer, reason="First rejection")

    # Second rejection attempt must fail
    with pytest.raises(InvalidApprovalStateTransitionError):
        service.reject(app_req.approval_id, reviewer=reviewer, reason="Second rejection attempt")

def test_approved_cannot_be_cancelled_or_rejected():
    service = ApprovalService()
    eval_res = _make_eval("req-rep-03")
    app_req = service.create_approval(eval_res)
    reviewer = ReviewerIdentity(reviewer_id="rev-03")
    service.approve(app_req.approval_id, reviewer=reviewer, reason="Approved")

    with pytest.raises(InvalidApprovalStateTransitionError):
        service.cancel(app_req.approval_id, reason="Cancel after approve")

    with pytest.raises(InvalidApprovalStateTransitionError):
        service.reject(app_req.approval_id, reviewer=reviewer, reason="Reject after approve")

def test_approval_replay_against_different_request_fails():
    service = ApprovalService()
    boundary = SecurityEnforcementBoundary()

    eval_res = _make_eval("req-rep-04")
    app_req = service.create_approval(eval_res)
    approved = service.approve(app_req.approval_id, reviewer=ReviewerIdentity(reviewer_id="rev-04"), reason="Ok")

    # Attempt to use approval against a different request ID
    diff_req = ToolRequest(
        request_id="req-rep-99-different",
        agent=AgentIdentity(name="ReplayAgent"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="calculator",
    )

    enf_res = boundary.authorize_approval(request=diff_req, approval=approved)
    assert enf_res.authorized is False
    assert "Request ID mismatch" in enf_res.reason
