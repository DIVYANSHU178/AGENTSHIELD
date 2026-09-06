"""
Tests for AgentShield Phase 14 Authentication Service and Session Management.
"""

import time
import pytest
from datetime import timedelta
from app.security.identity.authentication import AuthenticationService
from app.security.identity.models import Role, UserIdentity
from app.security.identity.errors import (
    InvalidCredentialsError,
    InactiveIdentityError,
    SessionExpiredError,
    SessionRevokedError,
)
from app.security.persistence.identity_repository import IdentityRepository
from app.security.persistence.session_repository import SessionRepository
from app.security.audit.trail import SecurityAuditTrail
from app.security.models.enums import EventType
from app.security.models.utils import utc_now



@pytest.fixture
def auth_service():
    audit = SecurityAuditTrail()
    ident_repo = IdentityRepository()
    sess_repo = SessionRepository()
    return AuthenticationService(
        identity_repository=ident_repo,
        session_repository=sess_repo,
        audit_trail=audit,
        auto_bootstrap=True,
    )


def test_authentication_with_valid_default_credentials(auth_service):
    session = auth_service.authenticate(username="admin", password="AdminPass123!")
    assert session is not None
    assert session.username == "admin"
    assert session.is_revoked is False
    assert session.is_valid() is True

    # Validate session token
    user = auth_service.validate_session(session.session_id)
    assert user is not None
    assert user.username == "admin"
    assert user.has_role(Role.ADMIN)


def test_authentication_with_invalid_password(auth_service):
    with pytest.raises(InvalidCredentialsError):
        auth_service.authenticate(username="admin", password="WrongPassword!")


def test_authentication_with_unknown_username(auth_service):
    with pytest.raises(InvalidCredentialsError):
        auth_service.authenticate(username="non_existent_user", password="Password123!")


def test_authentication_with_empty_or_malformed_credentials(auth_service):
    with pytest.raises(InvalidCredentialsError):
        auth_service.authenticate(username="", password="Password123!")

    with pytest.raises(InvalidCredentialsError):
        auth_service.authenticate(username="admin", password="")


def test_authentication_with_disabled_user_fails(auth_service):
    # Create and disable a user
    user = auth_service.create_user(
        username="temp_user",
        password="TempPassword123!",
        display_name="Temporary User",
        roles=(Role.VIEWER,),
    )
    auth_service.disable_user(user.user_id)

    with pytest.raises(InactiveIdentityError):
        auth_service.authenticate(username="temp_user", password="TempPassword123!")


def test_session_expiration_enforced(auth_service):
    # Create short TTL session (1 second)
    session = auth_service.authenticate(username="ops_user", password="OperatorPass123!", ttl_seconds=0.5)
    assert session.is_valid() is True

    # Validate immediately
    user = auth_service.validate_session(session.session_id)
    assert user is not None

    # Wait for expiration
    time.sleep(0.7)
    assert session.is_valid() is False
    expired_user = auth_service.validate_session(session.session_id)
    assert expired_user is None


def test_explicit_session_revocation_logout(auth_service):
    session = auth_service.authenticate(username="security_lead", password="ReviewerPass123!")
    token = session.session_id

    # Valid before revocation
    assert auth_service.validate_session(token) is not None

    # Explicit revocation
    revoked = auth_service.revoke_session(token, reason="User logout")
    assert revoked is True

    # Invalid after revocation
    assert auth_service.validate_session(token) is None

    # Revoked session retrieval reflects is_revoked = True
    stored_sess = auth_service.session_repository.get_session(token)
    assert stored_sess.is_revoked is True
    assert stored_sess.revocation_reason == "User logout"


def test_audit_events_recorded_during_auth_lifecycle(auth_service):
    # Successful login
    sess = auth_service.authenticate(username="viewer_user", password="ViewerPass123!")
    auth_service.revoke_session(sess.session_id)

    events = auth_service.audit_trail.get_events()
    event_types = [e.event_type for e in events]
    assert EventType.AUTHENTICATION_SUCCESS in event_types
    assert EventType.SESSION_CREATED in event_types
    assert EventType.SESSION_REVOKED in event_types
