"""
Tests for AgentShield Phase 14 Approval Workflow RBAC and Reviewer Identity Propagation.
"""

import pytest
from app.security.approval.service import ApprovalService
from app.security.approval.contracts import (
    ApprovalStatus,
    ReviewerIdentity,
)
from app.security.identity.models import UserIdentity, Role, Permission
from app.security.identity.errors import AuthorizationDeniedError
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
from app.security.audit.trail import SecurityAuditTrail
from app.security.models.enums import EventType


@pytest.fixture
def approval_service():
    audit = SecurityAuditTrail()
    return ApprovalService(audit_trail=audit)


@pytest.fixture
def pending_approval(approval_service):
    req = ToolRequest(
        request_id="req-test-authz-app-01",
        agent=AgentIdentity(name="TestAgent"),
        tool_name="file.write",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.WRITE,
        target="/tmp/test.txt",
        parameters={"content": "hello"},
    )
    eval_res = SecurityEvaluationResult(
        request=req,
        threat_report=ThreatReport(request_id=req.request_id, signals=[], overall_severity=Severity.MEDIUM, summary="Review needed"),
        risk_assessment=RiskAssessment(request_id=req.request_id, risk_score=55.0, severity=Severity.MEDIUM, rationale="Medium risk"),
        decision=SecurityDecision(request_id=req.request_id, decision=SecurityDecisionType.REQUIRE_APPROVAL, policy_id="pol-1", reason="Approval needed"),
    )
    return approval_service.create_approval(eval_res, ttl_seconds=3600.0)


def test_authorized_reviewer_can_approve(approval_service, pending_approval):
    reviewer_user = UserIdentity(
        user_id="usr-alice",
        username="alice",
        display_name="Alice Security Lead",
        roles=(Role.SECURITY_REVIEWER,),
    )
    approved = approval_service.approve_with_identity(
        approval_id=pending_approval.approval_id,
        identity=reviewer_user,
        reason="Approved after manual review.",
    )
    assert approved.status == ApprovalStatus.APPROVED
    assert approved.resolution is not None
    assert approved.resolution.reviewer.reviewer_id == "usr-alice"
    assert approved.resolution.reviewer.reviewer_name == "Alice Security Lead"
    assert approved.resolution.reviewer.role == "SECURITY_REVIEWER"


def test_viewer_role_approve_denied_with_authorization_error(approval_service, pending_approval):
    viewer_user = UserIdentity(
        user_id="usr-carol",
        username="carol",
        display_name="Carol Viewer",
        roles=(Role.VIEWER,),
    )
    with pytest.raises(AuthorizationDeniedError):
        approval_service.approve_with_identity(
            approval_id=pending_approval.approval_id,
            identity=viewer_user,
            reason="Viewer attempting to approve",
        )

    # Legacy ReviewerIdentity with VIEWER role is also blocked
    viewer_rev = ReviewerIdentity(reviewer_id="usr-carol", reviewer_name="Carol", role="VIEWER")
    with pytest.raises(AuthorizationDeniedError):
        approval_service.approve(
            approval_id=pending_approval.approval_id,
            reviewer=viewer_rev,
            reason="Direct viewer review",
        )

    # Approval remains PENDING
    current = approval_service.get_approval(pending_approval.approval_id)
    assert current.status == ApprovalStatus.PENDING


def test_authorized_reviewer_can_reject(approval_service, pending_approval):
    reviewer_user = UserIdentity(
        user_id="usr-alice",
        username="alice",
        display_name="Alice Security Lead",
        roles=(Role.SECURITY_REVIEWER,),
    )
    rejected = approval_service.reject_with_identity(
        approval_id=pending_approval.approval_id,
        identity=reviewer_user,
        reason="Rejected due to policy violation.",
    )
    assert rejected.status == ApprovalStatus.REJECTED
    assert rejected.resolution.reviewer.reviewer_id == "usr-alice"


def test_viewer_role_reject_denied_with_authorization_error(approval_service, pending_approval):
    viewer_user = UserIdentity(
        user_id="usr-carol",
        username="carol",
        display_name="Carol Viewer",
        roles=(Role.VIEWER,),
    )
    with pytest.raises(AuthorizationDeniedError):
        approval_service.reject_with_identity(
            approval_id=pending_approval.approval_id,
            identity=viewer_user,
            reason="Viewer attempting to reject",
        )


def test_operator_can_cancel_approval(approval_service, pending_approval):
    operator_user = UserIdentity(
        user_id="usr-bob",
        username="bob",
        display_name="Bob Operator",
        roles=(Role.OPERATOR,),
    )
    cancelled = approval_service.cancel_with_identity(
        approval_id=pending_approval.approval_id,
        identity=operator_user,
        reason="Operation aborted by user",
    )
    assert cancelled.status == ApprovalStatus.CANCELLED


def test_viewer_cancel_denied_with_authorization_error(approval_service, pending_approval):
    viewer_user = UserIdentity(
        user_id="usr-carol",
        username="carol",
        display_name="Carol Viewer",
        roles=(Role.VIEWER,),
    )
    with pytest.raises(AuthorizationDeniedError):
        approval_service.cancel_with_identity(
            approval_id=pending_approval.approval_id,
            identity=viewer_user,
            reason="Viewer trying to cancel",
        )
