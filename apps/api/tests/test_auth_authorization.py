"""
Tests for AgentShield Phase 14 Authorization Service and RBAC Policies.
"""

import pytest
from app.security.identity.authorization import AuthorizationService
from app.security.identity.models import UserIdentity, Role, Permission
from app.security.audit.trail import SecurityAuditTrail
from app.security.persistence.auth_audit_repository import AuthorizationAuditRepository
from app.security.models.enums import EventType


@pytest.fixture
def authz_service():
    audit = SecurityAuditTrail()
    auth_audit = AuthorizationAuditRepository()
    return AuthorizationService(audit_trail=audit, auth_audit_repository=auth_audit)


@pytest.fixture
def viewer_identity():
    return UserIdentity(
        user_id="usr-viewer-01",
        username="viewer",
        display_name="Viewer User",
        roles=(Role.VIEWER,),
    )


@pytest.fixture
def operator_identity():
    return UserIdentity(
        user_id="usr-ops-01",
        username="operator",
        display_name="Operator User",
        roles=(Role.OPERATOR,),
    )


@pytest.fixture
def reviewer_identity():
    return UserIdentity(
        user_id="usr-rev-01",
        username="reviewer",
        display_name="Security Reviewer",
        roles=(Role.SECURITY_REVIEWER,),
    )


@pytest.fixture
def admin_identity():
    return UserIdentity(
        user_id="usr-admin-01",
        username="admin",
        display_name="Admin User",
        roles=(Role.ADMIN,),
    )


def test_authorization_allow_for_authorized_permissions(authz_service, viewer_identity, reviewer_identity, admin_identity):
    # Viewer can view operations
    d1 = authz_service.authorize(viewer_identity, Permission.VIEW_OPERATIONS)
    assert d1.allowed is True
    assert d1.permission == Permission.VIEW_OPERATIONS

    # Reviewer can resolve approvals
    d2 = authz_service.authorize(reviewer_identity, Permission.RESOLVE_APPROVALS)
    assert d2.allowed is True

    # Admin can manage configuration and identities
    d3 = authz_service.authorize(admin_identity, Permission.MANAGE_SECURITY_CONFIGURATION)
    assert d3.allowed is True
    d4 = authz_service.authorize(admin_identity, Permission.MANAGE_IDENTITIES)
    assert d4.allowed is True


def test_authorization_deny_by_default_and_escalation_block(authz_service, viewer_identity, operator_identity):
    # Viewer cannot resolve approvals
    d1 = authz_service.authorize(viewer_identity, Permission.RESOLVE_APPROVALS)
    assert d1.allowed is False
    assert "denied" in d1.reason.lower()

    # Viewer cannot run scenario lab
    d2 = authz_service.authorize(viewer_identity, Permission.RUN_SCENARIO_LAB)
    assert d2.allowed is False

    # Operator cannot resolve approvals
    d3 = authz_service.authorize(operator_identity, Permission.RESOLVE_APPROVALS)
    assert d3.allowed is False

    # Operator cannot manage identities
    d4 = authz_service.authorize(operator_identity, Permission.MANAGE_IDENTITIES)
    assert d4.allowed is False


def test_authorization_denies_unauthenticated_caller(authz_service):
    d = authz_service.authorize(identity=None, permission=Permission.VIEW_OPERATIONS)
    assert d.allowed is False
    assert "unauthenticated" in d.reason.lower()


def test_authorization_denies_inactive_identity(authz_service):
    disabled_user = UserIdentity(
        user_id="usr-dis-01",
        username="disabled",
        display_name="Disabled User",
        roles=(Role.ADMIN,),
        is_active=False,
    )
    d = authz_service.authorize(disabled_user, Permission.VIEW_OPERATIONS)
    assert d.allowed is False
    assert "disabled" in d.reason.lower() or "inactive" in d.reason.lower()


def test_authorization_denies_unknown_permission(authz_service, admin_identity):
    d = authz_service.authorize(admin_identity, "INVALID_NON_EXISTENT_PERMISSION")
    assert d.allowed is False
    assert "unknown" in d.reason.lower()


def test_authorization_10x_determinism(authz_service, reviewer_identity, viewer_identity):
    """Prove authorization decisions produce 100% deterministic results across repeated evaluations."""
    results_allowed = []
    results_denied = []

    for _ in range(10):
        d_allow = authz_service.authorize(reviewer_identity, Permission.RESOLVE_APPROVALS)
        d_deny = authz_service.authorize(viewer_identity, Permission.RESOLVE_APPROVALS)
        results_allowed.append((d_allow.allowed, d_allow.permission))
        results_denied.append((d_deny.allowed, d_deny.permission))

    assert all(r == (True, Permission.RESOLVE_APPROVALS) for r in results_allowed)
    assert all(r == (False, Permission.RESOLVE_APPROVALS) for r in results_denied)


def test_authorization_records_audit_events(authz_service, viewer_identity):
    authz_service.authorize(viewer_identity, Permission.VIEW_OPERATIONS)
    authz_service.authorize(viewer_identity, Permission.RESOLVE_APPROVALS)

    events = authz_service.audit_trail.get_events()
    event_types = [e.event_type for e in events]
    assert EventType.AUTHORIZATION_ALLOWED in event_types
    assert EventType.AUTHORIZATION_DENIED in event_types
