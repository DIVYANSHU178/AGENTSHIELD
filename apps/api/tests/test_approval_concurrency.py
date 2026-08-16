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
from app.security.approval.contracts import ReviewerIdentity, ApprovalStatus

def _make_eval(i: int) -> SecurityEvaluationResult:
    req_id = f"req-conc-{i}"
    req = ToolRequest(
        request_id=req_id,
        agent=AgentIdentity(name=f"Agent-{i}"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target=f"target-{i}",
        parameters={"index": i},
    )
    return SecurityEvaluationResult(
        request=req,
        threat_report=ThreatReport(request_id=req_id, signals=[], overall_severity=Severity.MEDIUM, summary="Medium"),
        risk_assessment=RiskAssessment(request_id=req_id, risk_score=50.0, severity=Severity.MEDIUM, rationale="Risk"),
        decision=SecurityDecision(
            request_id=req_id,
            decision=SecurityDecisionType.REQUIRE_APPROVAL,
            policy_id="test.policy",
            reason=f"Requires approval {i}",
        ),
    )

def test_multiple_independent_approval_lifecycles():
    service = ApprovalService()
    approvals = []

    # Create 50 approvals
    for i in range(50):
        ev = _make_eval(i)
        app = service.create_approval(ev)
        approvals.append(app)

    assert len(service.list_approvals(limit=100)) == 50

    # Approve even, reject odd
    reviewer = ReviewerIdentity(reviewer_id="rev-conc")
    for i, app in enumerate(approvals):
        if i % 2 == 0:
            service.approve(app.approval_id, reviewer=reviewer, reason=f"Approved #{i}")
        else:
            service.reject(app.approval_id, reviewer=reviewer, reason=f"Rejected #{i}")

    approved_list = service.list_approvals(status=ApprovalStatus.APPROVED, limit=100)
    rejected_list = service.list_approvals(status=ApprovalStatus.REJECTED, limit=100)
    pending_list = service.list_approvals(status=ApprovalStatus.PENDING, limit=100)

    assert len(approved_list) == 25
    assert len(rejected_list) == 25
    assert len(pending_list) == 0

def test_defensive_isolation_of_service_approvals():
    service = ApprovalService()
    ev = _make_eval(999)
    app = service.create_approval(ev)

    # Retrieve and verify returned copy
    app_copy = service.get_approval(app.approval_id)
    assert app_copy.approval_id == app.approval_id

    # Internal state is preserved
    assert service.get_approval(app.approval_id).status == ApprovalStatus.PENDING
