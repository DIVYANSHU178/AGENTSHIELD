import pytest
from datetime import timedelta
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
from app.security.approval.contracts import ReviewerIdentity, ApprovalStatus
from app.security.approval.errors import ApprovalExpiredError, InvalidApprovalStateTransitionError
from app.security.approval.policy import ApprovalPolicy
from app.security.enforcement import SecurityEnforcementBoundary
from app.security.models.utils import utc_now

def _make_eval() -> SecurityEvaluationResult:
    req_id = "req-exp-01"
    req = ToolRequest(
        request_id=req_id,
        agent=AgentIdentity(name="ExpAgent"),
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

def test_expired_approval_cannot_be_approved():
    # TTL of 1 second
    service = ApprovalService(policy=ApprovalPolicy(default_ttl_seconds=1.0))
    eval_res = _make_eval()
    app_req = service.create_approval(eval_res, ttl_seconds=1.0)

    # Fast forward expiration check by modifying internal expires_at in test context
    past_time = utc_now() - timedelta(seconds=10)
    service._approvals[app_req.approval_id] = app_req.model_copy(update={"expires_at": past_time})

    reviewer = ReviewerIdentity(reviewer_id="rev-exp")
    with pytest.raises(ApprovalExpiredError):
        service.approve(app_req.approval_id, reviewer=reviewer, reason="Approve expired")

def test_expired_approval_cannot_be_authorized():
    service = ApprovalService()
    boundary = SecurityEnforcementBoundary()

    eval_res = _make_eval()
    app_req = service.create_approval(eval_res)
    reviewer = ReviewerIdentity(reviewer_id="rev-exp")
    approved = service.approve(app_req.approval_id, reviewer=reviewer, reason="Approved on time")

    # Manually expire the approved request
    expired_approved = approved.model_copy(update={"expires_at": utc_now() - timedelta(seconds=10)})

    enf_res = boundary.authorize_approval(request=eval_res.request, approval=expired_approved)
    assert enf_res.authorized is False
    assert enf_res.authorization is None
    assert "expired" in enf_res.reason.lower()

def test_expired_approval_cannot_be_resurrected():
    service = ApprovalService()
    eval_res = _make_eval()
    app_req = service.create_approval(eval_res)
    service.expire(app_req.approval_id)

    # Attempting to transition from EXPIRED to APPROVED
    reviewer = ReviewerIdentity(reviewer_id="rev-exp")
    with pytest.raises(InvalidApprovalStateTransitionError):
        service.approve(app_req.approval_id, reviewer=reviewer, reason="Resurrect")
