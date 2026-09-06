"""
Tests for AgentShield Phase 14 Identity, Session, and Authorization Persistence across restarts.
"""

import os
import tempfile
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database.session import Base
from app.security.persistence.identity_repository import IdentityRepository
from app.security.persistence.session_repository import SessionRepository
from app.security.persistence.auth_audit_repository import AuthorizationAuditRepository
from app.security.identity.authentication import AuthenticationService
from app.security.identity.authorization import AuthorizationService
from app.security.identity.models import Role, Permission, UserIdentity


@pytest.fixture
def temp_db():
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_auth_persist.db")
    engine = create_engine(f"sqlite:///{db_path}", echo=False)
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    yield session_factory, engine, db_path
    engine.dispose()
    try:
        os.remove(db_path)
        os.rmdir(temp_dir)
    except Exception:
        pass


def test_identity_and_session_persistence_across_restart(temp_db):
    session_factory, engine, db_path = temp_db

    # 1. Process 1: Initialize service and create custom user and session
    ident_repo1 = IdentityRepository(session_factory=session_factory)
    sess_repo1 = SessionRepository(session_factory=session_factory)
    auth_svc1 = AuthenticationService(
        identity_repository=ident_repo1,
        session_repository=sess_repo1,
        auto_bootstrap=True,
    )

    custom_user = auth_svc1.create_user(
        username="durable_dev",
        password="DurablePassword123!",
        display_name="Durable Developer",
        roles=(Role.OPERATOR,),
        email="dev@durable.local",
    )
    sess1 = auth_svc1.authenticate("durable_dev", "DurablePassword123!")
    token = sess1.session_id

    # 2. Simulate complete process restart (new engine & repository instances connected to same SQLite DB)
    engine2 = create_engine(f"sqlite:///{db_path}", echo=False)
    session_factory2 = sessionmaker(bind=engine2, autoflush=False, autocommit=False)
    ident_repo2 = IdentityRepository(session_factory=session_factory2)
    sess_repo2 = SessionRepository(session_factory=session_factory2)
    auth_svc2 = AuthenticationService(
        identity_repository=ident_repo2,
        session_repository=sess_repo2,
        auto_bootstrap=False,
    )

    # Validate recovered user identity
    recovered_user = auth_svc2.validate_session(token)
    assert recovered_user is not None
    assert recovered_user.username == "durable_dev"
    assert recovered_user.roles == (Role.OPERATOR,)
    assert recovered_user.email == "dev@durable.local"

    # Revoke session in Process 2
    auth_svc2.revoke_session(token, reason="Process 2 logout")

    # 3. Simulate third restart: verify revoked state is durable
    ident_repo3 = IdentityRepository(session_factory=session_factory2)
    sess_repo3 = SessionRepository(session_factory=session_factory2)
    auth_svc3 = AuthenticationService(
        identity_repository=ident_repo3,
        session_repository=sess_repo3,
        auto_bootstrap=False,
    )
    assert auth_svc3.validate_session(token) is None
    durable_sess = sess_repo3.get_session(token)
    assert durable_sess.is_revoked is True
    assert durable_sess.revocation_reason == "Process 2 logout"


def test_authorization_audit_persistence(temp_db):
    session_factory, engine, db_path = temp_db
    auth_audit_repo = AuthorizationAuditRepository(session_factory=session_factory)
    authz_svc = AuthorizationService(auth_audit_repository=auth_audit_repo)

    user = UserIdentity(
        user_id="usr-test-aud",
        username="aud_user",
        display_name="Audit User",
        roles=(Role.SECURITY_REVIEWER,),
    )

    authz_svc.authorize(user, Permission.RESOLVE_APPROVALS)
    authz_svc.authorize(user, Permission.MANAGE_SECURITY_CONFIGURATION)

    # Query events from database
    events = auth_audit_repo.get_events(user_id="usr-test-aud")
    assert len(events) == 2
    decisions = [e["decision"] for e in events]
    assert "ALLOW" in decisions
    assert "DENY" in decisions
