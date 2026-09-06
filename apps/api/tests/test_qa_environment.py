"""
AgentShield — QA Environment & Reset Verification Tests

Validates:
1. QA reset affects exclusively the QA database.
2. The historical development database (agentshield.db) remains 100% untouched.
3. Strict safety guards refuse attempts to reset or target the dev database.
4. All 8 authoritative tables exist in the QA database.
5. Predictable test identities exist with correct Phase 14 roles:
   - VIEWER (viewer_user)
   - OPERATOR (ops_user)
   - SECURITY_REVIEWER (security_lead)
   - ADMIN (admin)
6. Authentication and login succeed for all four seeded identities.
7. The QA environment can be reset repeatedly and deterministically.
8. Dynamic environment selection switches to the QA target safely.
"""

import os
import sqlite3
from pathlib import Path
import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

from app.config import settings, Settings
from app.database.session import configure_database
from app.security.identity.models import Role
from app.security.identity.authentication import AuthenticationService
from app.security.identity.errors import InvalidCredentialsError
from app.security.persistence import (
    IdentityRepository,
    SessionRepository,
    AuditRepository,
)
from app.security.audit.trail import SecurityAuditTrail
from scripts.reset_qa_environment import (
    reset_qa_database,
    validate_qa_target,
    DevDatabaseProtectionError,
    REQUIRED_TABLES,
)


def get_db_snapshot(db_path: Path):
    """Capture row counts and file size of a SQLite database."""
    if not db_path.exists():
        return None, {}
    size = os.path.getsize(db_path)
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    counts = {}
    for t in tables:
        if not t.startswith("sqlite"):
            counts[t] = cur.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
    conn.close()
    return size, counts


def test_qa_reset_affects_only_qa_db_and_preserves_dev_db(tmp_path):
    """
    Verify that resetting the QA environment writes strictly to the QA target
    and leaves the historical development database completely untouched.
    """
    dev_path = settings.get_dev_database_path()
    dev_size_before, dev_counts_before = get_db_snapshot(dev_path)

    # Use an isolated test QA database path
    qa_file = tmp_path / "agentshield_qa_test.db"
    qa_url = f"sqlite:///{qa_file}"

    # Execute reset
    result = reset_qa_database(target_url=qa_url, force_qa=True)

    assert result["status"] == "ok"
    assert qa_file.exists()

    # Verify dev DB is 100% untouched
    dev_size_after, dev_counts_after = get_db_snapshot(dev_path)
    if dev_size_before is not None:
        assert dev_size_after == dev_size_before, "Dev database file size changed during QA reset!"
        assert dev_counts_after == dev_counts_before, "Dev database table counts changed during QA reset!"

    # Verify QA DB state
    qa_size, qa_counts = get_db_snapshot(qa_file)
    assert qa_counts.get("security_users") == 4
    assert qa_counts.get("security_sessions", 0) == 0
    assert qa_counts.get("security_audit_events", 0) == 0
    assert qa_counts.get("security_decisions", 0) == 0
    assert qa_counts.get("threat_activities", 0) == 0
    assert qa_counts.get("execution_activities", 0) == 0
    assert qa_counts.get("approval_requests", 0) == 0


def test_qa_reset_safety_refusal_on_dev_database():
    """
    Verify strict refusal when attempting to target the development database.
    """
    dev_path = settings.get_dev_database_path()
    dev_url = f"sqlite:///{dev_path}"

    # 1. Reset call targeting dev DB url must raise DevDatabaseProtectionError
    with pytest.raises(DevDatabaseProtectionError) as exc_info:
        reset_qa_database(target_url=dev_url, force_qa=True)
    assert "CRITICAL SAFETY VIOLATION" in str(exc_info.value)

    # 2. Path validation function direct test
    with pytest.raises(DevDatabaseProtectionError):
        validate_qa_target(target_path=dev_path, dev_path=dev_path, environment="qa")

    # 3. Filename matching agentshield.db
    fake_dev = Path("/tmp/agentshield.db")
    with pytest.raises(DevDatabaseProtectionError):
        validate_qa_target(target_path=fake_dev, dev_path=dev_path, environment="qa")

    # 4. Filename lacking 'qa' or 'test'
    fake_prod = Path("/tmp/other_database.db")
    with pytest.raises(DevDatabaseProtectionError):
        validate_qa_target(target_path=fake_prod, dev_path=dev_path, environment="qa")


def test_qa_tables_exist(tmp_path):
    """
    Verify all 8 Phase 13 & 14 tables are properly initialized in the QA database.
    """
    qa_file = tmp_path / "qa_tables_test.db"
    qa_url = f"sqlite:///{qa_file}"
    reset_qa_database(target_url=qa_url, force_qa=True)

    engine = create_engine(qa_url, connect_args={"check_same_thread": False})
    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())

    for req_table in REQUIRED_TABLES:
        assert req_table in table_names, f"Required table '{req_table}' missing from QA database"


def test_qa_four_test_identities_and_roles(tmp_path):
    """
    Verify the 4 predictable test identities are populated with exact Phase 14 roles.
    """
    qa_file = tmp_path / "qa_identities_test.db"
    qa_url = f"sqlite:///{qa_file}"
    result = reset_qa_database(target_url=qa_url, force_qa=True)

    users_by_name = {u["username"]: u for u in result["users"]}

    assert set(users_by_name.keys()) == {"viewer_user", "ops_user", "security_lead", "admin"}

    # VIEWER
    assert users_by_name["viewer_user"]["roles"] == ["VIEWER"]
    assert users_by_name["viewer_user"]["display_name"] == "Carol Viewer"

    # OPERATOR
    assert users_by_name["ops_user"]["roles"] == ["OPERATOR"]
    assert users_by_name["ops_user"]["display_name"] == "Bob Operator"

    # SECURITY_REVIEWER
    assert users_by_name["security_lead"]["roles"] == ["SECURITY_REVIEWER"]
    assert users_by_name["security_lead"]["display_name"] == "Alice Security Lead"

    # ADMIN
    assert users_by_name["admin"]["roles"] == ["ADMIN"]
    assert users_by_name["admin"]["display_name"] == "System Administrator"


def test_qa_login_works_for_all_seeded_identities(tmp_path):
    """
    Verify that authentication and active session issuance succeed
    for every seeded test identity on the QA database.
    """
    qa_file = tmp_path / "qa_auth_test.db"
    qa_url = f"sqlite:///{qa_file}"
    reset_qa_database(target_url=qa_url, force_qa=True)

    engine = create_engine(qa_url, connect_args={"check_same_thread": False})
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    ident_repo = IdentityRepository(session_factory=session_factory)
    sess_repo = SessionRepository(session_factory=session_factory)
    audit_repo = AuditRepository(session_factory=session_factory)
    audit_trail = SecurityAuditTrail(repository=audit_repo)

    auth_svc = AuthenticationService(
        identity_repository=ident_repo,
        session_repository=sess_repo,
        audit_trail=audit_trail,
        auto_bootstrap=False,
    )

    credentials = [
        ("viewer_user", "ViewerPass123!", Role.VIEWER),
        ("ops_user", "OperatorPass123!", Role.OPERATOR),
        ("security_lead", "ReviewerPass123!", Role.SECURITY_REVIEWER),
        ("admin", "AdminPass123!", Role.ADMIN),
    ]

    for uname, pwd, expected_role in credentials:
        session = auth_svc.authenticate(username=uname, password=pwd)
        assert session is not None
        assert session.is_valid() is True
        assert session.is_revoked is False
        assert session.username == uname

        resolved_user = auth_svc.validate_session(session.session_id)
        assert resolved_user is not None
        assert expected_role in resolved_user.roles

        # Negative test: invalid password fails closed
        with pytest.raises(InvalidCredentialsError):
            auth_svc.authenticate(username=uname, password="WrongPassword999!")


def test_qa_environment_can_be_reset_repeatedly(tmp_path):
    """
    Verify that the QA database can be safely reset multiple times,
    clearing any intermediate test artifacts and returning to a clean state.
    """
    qa_file = tmp_path / "qa_repeat_test.db"
    qa_url = f"sqlite:///{qa_file}"

    # First reset
    res1 = reset_qa_database(target_url=qa_url, force_qa=True)
    assert len(res1["users"]) == 4

    # Add extra data (simulate a teammate doing testing)
    engine = create_engine(qa_url, connect_args={"check_same_thread": False})
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    ident_repo = IdentityRepository(session_factory=session_factory)
    from app.security.identity.crypto import hash_password
    h, s = hash_password("TempPass123!")
    ident_repo.create_user(
        user_id="usr-temp-99",
        username="temp_tester",
        display_name="Temp Tester",
        password_hash=h,
        password_salt=s,
        roles=(Role.VIEWER,),
    )
    assert ident_repo.count_users() == 5

    # Second reset
    res2 = reset_qa_database(target_url=qa_url, force_qa=True)
    assert len(res2["users"]) == 4

    # Verify temp user was wiped and clean 4 accounts restored
    ident_repo2 = IdentityRepository(session_factory=session_factory)
    assert ident_repo2.count_users() == 4
    assert ident_repo2.get_user_by_username("temp_tester") is None
    assert ident_repo2.get_user_by_username("admin") is not None

    # Third reset
    res3 = reset_qa_database(target_url=qa_url, force_qa=True)
    assert len(res3["users"]) == 4


def test_qa_mode_settings_selection():
    """
    Verify Settings environment detection and database routing for QA mode.
    """
    # 1. Default settings -> Dev mode
    dev_settings = Settings()
    assert dev_settings.ENVIRONMENT == "development"
    assert "agentshield.db" in dev_settings.DATABASE_URL
    assert dev_settings.is_dev_mode() is True
    assert dev_settings.is_qa_mode() is False

    # 2. QA mode via ENVIRONMENT='qa'
    qa_settings = Settings(ENVIRONMENT="qa")
    assert qa_settings.ENVIRONMENT == "qa"
    assert "agentshield_qa.db" in qa_settings.DATABASE_URL
    assert qa_settings.is_qa_mode() is True
    assert qa_settings.is_dev_mode() is False

    # 3. QA mode via explicit QA database URL
    custom_qa_settings = Settings(DATABASE_URL="sqlite:///./my_team_qa.db")
    assert custom_qa_settings.is_qa_mode() is True
    assert custom_qa_settings.is_dev_mode() is False
