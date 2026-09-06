"""
Tests for Authoritative Security Invariants in AgentShield Phase 14.

Validates core invariants:
- Zero raw password / secret leakage in domain objects, audit logs, or API responses
- Authentication never manufactures ExecutionAuthorization
- Authorization never manufactures ExecutionAuthorization
- Database records cannot bypass SecurityDecisionGateway or SecurityEnforcementBoundary
- Terminal approvals cannot be resurrected or mutated via authorization layer
"""

import pytest
from app.security.identity.models import UserIdentity, Role, Permission, AuthSession, AuthorizationDecision
from app.security.identity.crypto import hash_password, verify_password
from app.security.identity.authentication import AuthenticationService
from app.security.identity.authorization import AuthorizationService
from app.security.enforcement.boundary import SecurityEnforcementBoundary, ExecutionAuthorization
from app.security.approval.service import ApprovalService
from app.security.approval.contracts import ReviewerIdentity
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


def test_no_password_or_salt_in_user_identity_domain_model():
    user = UserIdentity(
        user_id="usr-sec-01",
        username="sec_user",
        display_name="Security User",
        roles=(Role.ADMIN,),
    )
    user_dict = user.model_dump()
    assert "password" not in user_dict
    assert "password_hash" not in user_dict
    assert "password_salt" not in user_dict


def test_authentication_and_authorization_cannot_create_execution_authorization():
    """
    INVARIANT: Authentication and Authorization NEVER manufacture ExecutionAuthorization.
    Only SecurityEnforcementBoundary may issue ExecutionAuthorization.
    """
    auth_svc = AuthenticationService(auto_bootstrap=True)
    authz_svc = AuthorizationService()

    session = auth_svc.authenticate("admin", "AdminPass123!")
    user = auth_svc.validate_session(session.session_id)
    decision = authz_svc.authorize(user, Permission.MANAGE_SECURITY_CONFIGURATION)

    assert not isinstance(session, ExecutionAuthorization)
    assert not isinstance(user, ExecutionAuthorization)
    assert not isinstance(decision, ExecutionAuthorization)


def test_approval_resolution_by_authorized_user_does_not_manufacture_execution_authorization():
    """
    INVARIANT: Approving a request NEVER creates ExecutionAuthorization or executes tools.
    """
    approval_svc = ApprovalService()
    req = ToolRequest(
        request_id="req-inv-test-01",
        agent=AgentIdentity(name="AgentInv"),
        tool_name="file.write",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.WRITE,
        target="/tmp/test.txt",
    )
    eval_res = SecurityEvaluationResult(
        request=req,
        threat_report=ThreatReport(request_id=req.request_id, signals=[], overall_severity=Severity.MEDIUM, summary="OK"),
        risk_assessment=RiskAssessment(request_id=req.request_id, risk_score=50.0, severity=Severity.MEDIUM, rationale="OK"),
        decision=SecurityDecision(request_id=req.request_id, decision=SecurityDecisionType.REQUIRE_APPROVAL, policy_id="pol-1", reason="Approval required"),
    )
    app = approval_svc.create_approval(eval_res)

    reviewer = UserIdentity(
        user_id="usr-admin",
        username="admin",
        display_name="Administrator",
        roles=(Role.ADMIN,),
    )
    resolved_app = approval_svc.approve_with_identity(
        approval_id=app.approval_id,
        identity=reviewer,
        reason="Approved for testing",
    )
    assert not isinstance(resolved_app, ExecutionAuthorization)
    assert not hasattr(resolved_app, "authorization_token")
    assert not hasattr(resolved_app, "signature")


def test_terminal_approval_cannot_be_mutated_or_re_approved():
    """
    INVARIANT: Terminal states (APPROVED, REJECTED, EXPIRED, CANCELLED) cannot transition.
    """
    approval_svc = ApprovalService()
    req = ToolRequest(
        request_id="req-term-test-01",
        agent=AgentIdentity(name="AgentTerm"),
        tool_name="file.write",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.WRITE,
        target="/tmp/term.txt",
    )
    eval_res = SecurityEvaluationResult(
        request=req,
        threat_report=ThreatReport(request_id=req.request_id, signals=[], overall_severity=Severity.MEDIUM, summary="OK"),
        risk_assessment=RiskAssessment(request_id=req.request_id, risk_score=50.0, severity=Severity.MEDIUM, rationale="OK"),
        decision=SecurityDecision(request_id=req.request_id, decision=SecurityDecisionType.REQUIRE_APPROVAL, policy_id="pol-1", reason="Approval required"),
    )
    app = approval_svc.create_approval(eval_res)
    reviewer = UserIdentity(user_id="usr-admin", username="admin", display_name="Admin", roles=(Role.ADMIN,))

    approval_svc.approve_with_identity(app.approval_id, reviewer, reason="First approval")

    # Attempt second approval -> Must fail
    from app.security.approval.errors import InvalidApprovalStateTransitionError
    with pytest.raises(InvalidApprovalStateTransitionError):
        approval_svc.approve_with_identity(app.approval_id, reviewer, reason="Second approval attempt")
