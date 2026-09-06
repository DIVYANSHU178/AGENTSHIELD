"""
Unit & Integration Tests for AgentShield Phase 15: Secrets & Configuration Hardening.

Validates:
1. Production mode fails closed when AGENTSHIELD_AUTHORIZATION_SECRET is missing
2. Production mode fails closed when AGENTSHIELD_AUTHORIZATION_SECRET is weak (< 32 chars)
3. Production mode succeeds with cryptographically strong secret (>= 32 chars)
4. Production mode fails closed when SECRET_KEY uses default placeholder or is weak
5. Production mode strictly rejects ALLOW_DEFAULT_CREDENTIALS=True
6. Production mode strictly rejects DEBUG=True
7. Development and QA environments permit safe, documented local fallbacks
8. get_sanitized_config() masks database credentials and exposes zero secrets
9. CORS origin regex is inactive in production by default to prevent LAN leaks
10. Database connection string credential masking (mask_connection_url)
11. Audit redaction strips database URLs with credentials and session tokens
12. Generic exception handler sanitizes errors in dev and blocks info disclosure in prod
13. Default credential seeding is strictly disabled in production
"""

import pytest
from unittest.mock import patch, MagicMock
from app.config.settings import Settings
from app.security.audit.redaction import sanitize_audit_payload, sanitize_string_value
from app.security.identity.authentication import AuthenticationService
from app.security.persistence.identity_repository import IdentityRepository
from fastapi import Request
from app.main import generic_exception_handler
import asyncio


def test_production_fails_when_authorization_secret_missing():
    """Verify production fails closed on Settings instantiation when AGENTSHIELD_AUTHORIZATION_SECRET is not set."""
    with pytest.raises(ValueError, match="AGENTSHIELD_AUTHORIZATION_SECRET environment variable must be explicitly set"):
        Settings(
            ENVIRONMENT="production",
            AGENTSHIELD_AUTHORIZATION_SECRET=None,
            SECRET_KEY="a" * 32,
        )


def test_production_fails_when_authorization_secret_too_short():
    """Verify production fails closed on Settings instantiation when AGENTSHIELD_AUTHORIZATION_SECRET has insufficient entropy (< 24 chars)."""
    with pytest.raises(ValueError, match="must be at least 24 characters long in production"):
        Settings(
            ENVIRONMENT="production",
            AGENTSHIELD_AUTHORIZATION_SECRET="short-secret-123",
            SECRET_KEY="a" * 32,
        )


def test_production_fails_when_secret_key_missing():
    """Verify production rejects empty SECRET_KEY on Settings instantiation."""
    with pytest.raises(ValueError, match="SECRET_KEY must be explicitly configured"):
        Settings(
            ENVIRONMENT="production",
            AGENTSHIELD_AUTHORIZATION_SECRET="a" * 32,
            SECRET_KEY="",
        )


def test_production_fails_when_secret_key_uses_default_or_weak():
    """Verify production rejects default placeholder or weak SECRET_KEY."""
    with pytest.raises(ValueError, match="SECRET_KEY must be explicitly configured and at least 24 characters"):
        Settings(
            ENVIRONMENT="production",
            AGENTSHIELD_AUTHORIZATION_SECRET="a" * 32,
            SECRET_KEY="agentshield-local-security-secret-key-change-in-prod",
        )

    with pytest.raises(ValueError, match="SECRET_KEY must be explicitly configured and at least 24 characters"):
        Settings(
            ENVIRONMENT="production",
            AGENTSHIELD_AUTHORIZATION_SECRET="a" * 32,
            SECRET_KEY="too_short_key",
        )


def test_production_rejects_allow_default_credentials():
    """Verify production configuration rejects ALLOW_DEFAULT_CREDENTIALS=True."""
    with pytest.raises(ValueError, match="ALLOW_DEFAULT_CREDENTIALS cannot be enabled in production"):
        Settings(
            ENVIRONMENT="production",
            AGENTSHIELD_AUTHORIZATION_SECRET="a" * 32,
            SECRET_KEY="b" * 32,
            ALLOW_DEFAULT_CREDENTIALS=True,
        )


def test_production_rejects_debug_mode():
    """Verify production configuration rejects DEBUG=True."""
    with pytest.raises(ValueError, match="DEBUG mode cannot be enabled in production"):
        Settings(
            ENVIRONMENT="production",
            AGENTSHIELD_AUTHORIZATION_SECRET="a" * 32,
            SECRET_KEY="b" * 32,
            DEBUG=True,
        )


def test_production_succeeds_with_strong_authorization_secret():
    """Verify production accepts high-entropy secret >= 24 characters."""
    strong_secret = "a_cryptographically_secure_random_key_64_bytes_entropy_for_agentshield"
    strong_key = "a_cryptographically_secure_random_secret_key_64_bytes_for_agentshield"
    cfg = Settings(
        ENVIRONMENT="production",
        AGENTSHIELD_AUTHORIZATION_SECRET=strong_secret,
        SECRET_KEY=strong_key,
        DATABASE_URL="sqlite:///./agentshield_prod.db",
    )
    assert cfg.get_authorization_secret() == strong_secret
    assert cfg.get_secret_key() == strong_key
    assert cfg.is_production() is True


def test_fastapi_lifespan_startup_fails_closed_when_production_auth_secret_missing():
    """Verify FastAPI application lifespan fails closed when AGENTSHIELD_AUTHORIZATION_SECRET is missing."""
    from fastapi.testclient import TestClient
    from app.main import app

    with patch("app.main.settings.ENVIRONMENT", "production"):
        with patch("app.main.settings.AGENTSHIELD_AUTHORIZATION_SECRET", None):
            with patch("app.main.settings.SECRET_KEY", "b" * 32):
                with pytest.raises(ValueError, match="AGENTSHIELD_AUTHORIZATION_SECRET environment variable must be explicitly set"):
                    with TestClient(app):
                        pass


def test_fastapi_lifespan_startup_fails_closed_when_production_secret_key_missing():
    """Verify FastAPI application lifespan fails closed when production SECRET_KEY uses placeholder or is missing."""
    from fastapi.testclient import TestClient
    from app.main import app

    with patch("app.main.settings.ENVIRONMENT", "production"):
        with patch("app.main.settings.AGENTSHIELD_AUTHORIZATION_SECRET", "a" * 32):
            with patch("app.main.settings.SECRET_KEY", "agentshield-local-security-secret-key-change-in-prod"):
                with pytest.raises(ValueError, match="SECRET_KEY must be explicitly configured"):
                    with TestClient(app):
                        pass


def test_enforcement_boundary_fails_closed_on_missing_production_secret():
    """Verify SecurityEnforcementBoundary raises ValueError instead of swallowing exception when secret missing in prod."""
    from app.security.enforcement.boundary import SecurityEnforcementBoundary
    from app.config.settings import settings

    with patch.object(settings, "ENVIRONMENT", "production"):
        with patch.object(settings, "AGENTSHIELD_AUTHORIZATION_SECRET", None):
            with pytest.raises(ValueError, match="AGENTSHIELD_AUTHORIZATION_SECRET"):
                SecurityEnforcementBoundary()


def test_error_messages_never_leak_attempted_secret_values():
    """Verify configuration validation error messages contain variable names but never attempted secret content."""
    attempted_weak_secret = "weak_short_key"
    with pytest.raises(ValueError) as excinfo:
        Settings(
            ENVIRONMENT="production",
            AGENTSHIELD_AUTHORIZATION_SECRET=attempted_weak_secret,
            SECRET_KEY="b" * 32,
        )
    err_msg = str(excinfo.value)
    assert attempted_weak_secret not in err_msg
    assert "AGENTSHIELD_AUTHORIZATION_SECRET" in err_msg


def test_dev_and_qa_allow_fallback_secrets():
    """Verify development and QA testing modes allow safe, documented local fallbacks."""
    dev_cfg = Settings(ENVIRONMENT="development", AGENTSHIELD_AUTHORIZATION_SECRET=None)
    assert dev_cfg.get_authorization_secret() == "agentshield-dev-local-hmac-secret-key-do-not-use-in-production"
    assert dev_cfg.get_secret_key() == "agentshield-local-security-secret-key-change-in-prod"

    qa_cfg = Settings(ENVIRONMENT="qa", AGENTSHIELD_AUTHORIZATION_SECRET=None)
    assert qa_cfg.get_authorization_secret() == "agentshield-dev-local-hmac-secret-key-do-not-use-in-production"


def test_sanitized_config_masks_secrets_and_connection_strings():
    """Verify get_sanitized_config() masks database credentials and exposes zero secrets."""
    db_with_creds = "postgresql://sec_user:super_secret_password@db.internal:5432/agentshield"
    auth_secret = "my_super_secret_auth_key_12345678901234567890"

    cfg = Settings(
        ENVIRONMENT="development",
        DATABASE_URL=db_with_creds,
        AGENTSHIELD_AUTHORIZATION_SECRET=auth_secret,
        SECRET_KEY="custom-development-secret-key-for-test",
    )

    sanitized = cfg.get_sanitized_config()

    # Raw secrets must NOT be in the sanitized dictionary
    assert auth_secret not in str(sanitized)
    assert "super_secret_password" not in str(sanitized)
    assert "custom-development-secret-key-for-test" not in str(sanitized)

    # Values must be safely masked or boolean-flagged
    assert sanitized["database_url"] == "postgresql://sec_user:****@db.internal:5432/agentshield"
    assert sanitized["authorization_secret_configured"] is True
    assert sanitized["secret_key_configured"] is True


def test_cors_origin_regex_inactive_in_production_by_default():
    """Verify the private LAN origin regex is inactive in production unless explicitly customized."""
    prod_cfg = Settings(
        ENVIRONMENT="production",
        AGENTSHIELD_AUTHORIZATION_SECRET="a" * 32,
        SECRET_KEY="b" * 32,
        DATABASE_URL="sqlite:///./agentshield_prod.db",
    )
    assert prod_cfg.get_cors_origin_regex() is None

    dev_cfg = Settings(ENVIRONMENT="development")
    assert dev_cfg.get_cors_origin_regex() is not None
    assert "192" in dev_cfg.get_cors_origin_regex()

    # Explicit custom origin regex in prod is respected
    custom_prod_cfg = Settings(
        ENVIRONMENT="production",
        AGENTSHIELD_AUTHORIZATION_SECRET="a" * 32,
        SECRET_KEY="b" * 32,
        DATABASE_URL="sqlite:///./agentshield_prod.db",
        CORS_ALLOW_ORIGIN_REGEX=r"^https://console\.agentshield\.internal$",
    )
    assert custom_prod_cfg.get_cors_origin_regex() == r"^https://console\.agentshield\.internal$"


def test_mask_connection_url_utility():
    """Verify Settings.mask_connection_url correctly redacts credentials."""
    assert Settings.mask_connection_url("sqlite:///./local.db") == "sqlite:///./local.db"
    assert (
        Settings.mask_connection_url("mysql://root:secretPass123@10.0.0.5:3306/db")
        == "mysql://root:****@10.0.0.5:3306/db"
    )
    assert (
        Settings.mask_connection_url("postgresql://user:pass@host.internal/prod")
        == "postgresql://user:****@host.internal/prod"
    )
    assert Settings.mask_connection_url("") == ""
    assert Settings.mask_connection_url(None) == ""


def test_audit_redaction_masks_db_credentials_and_session_tokens():
    """Verify audit redaction strips connection strings and session tokens."""
    payload = {
        "user_id": "usr-01",
        "connection_string": "postgresql://admin:superSecret@db:5432/app",
        "session_token": "token-1234567890abcdef",
        "details": {
            "endpoint": "postgres://reporter:pass999@analytics.internal/data",
            "safe_value": "hello_agentshield",
        },
    }

    sanitized = sanitize_audit_payload(payload)

    # Verify sensitive keys are masked
    assert sanitized["connection_string"] != "postgresql://admin:superSecret@db:5432/app"
    assert "superSecret" not in str(sanitized)
    assert "pass999" not in str(sanitized)
    assert sanitized["details"]["safe_value"] == "hello_agentshield"


def test_generic_exception_handler_sanitization():
    """Verify exception handler sanitizes error messages and hides them in production."""
    req = MagicMock(spec=Request)

    # Case A: Development mode with secret in error
    with patch.object(Settings, "is_dev_mode", return_value=True):
        secret = "agentshield-dev-local-hmac-secret-key-do-not-use-in-production"
        exc = RuntimeError(f"Connection failed using secret: {secret}")
        resp = asyncio.run(generic_exception_handler(req, exc))
        assert resp.status_code == 500
        body = resp.body.decode("utf-8")
        assert secret not in body
        assert "[REDACTED_SECRET_KEY]" in body

    # Case B: Production mode with internal trace/secret
    with patch.object(Settings, "is_dev_mode", return_value=False):
        exc = RuntimeError("Fatal: SQLite error at C:\\AgentShield\\Private\\secrets.db")
        resp = asyncio.run(generic_exception_handler(req, exc))
        assert resp.status_code == 500
        body = resp.body.decode("utf-8")
        assert "secrets.db" not in body
        assert "An unexpected error occurred." in body


def test_bootstrap_default_identities_disabled_in_production():
    """Verify default demo identities are NOT bootstrapped in production."""
    repo = IdentityRepository(session_factory=None)

    with patch.object(Settings, "is_production", return_value=True):
        auth_svc = AuthenticationService(
            identity_repository=repo,
            session_repository=None,
            audit_trail=None,
            auto_bootstrap=True,
        )
        assert repo.count_users() == 0, "Security Violation: Default credentials were created in production!"


def test_production_rejects_default_sqlite_db():
    """Verify production fails closed when attempting to use the default dev SQLite database."""
    with pytest.raises(ValueError, match="Production environment cannot use the default development SQLite database"):
        Settings(
            ENVIRONMENT="production",
            AGENTSHIELD_AUTHORIZATION_SECRET="a" * 32,
            SECRET_KEY="b" * 32,
            DATABASE_URL="sqlite:///./agentshield.db",
        )


def test_production_authentication_strictly_rejects_all_default_demo_accounts():
    """Verify production mode strictly rejects default demo accounts even if present in the database with valid passwords."""
    from app.security.identity.errors import InvalidCredentialsError
    from app.security.identity.crypto import hash_password
    from app.security.identity.models import Role

    repo = IdentityRepository(session_factory=None)
    # Seed the 4 demo users into repo to simulate pre-existing database
    demo_accounts = [
        ("admin", "AdminPass123!"),
        ("security_lead", "ReviewerPass123!"),
        ("ops_user", "OperatorPass123!"),
        ("viewer_user", "ViewerPass123!"),
    ]
    for uname, pwd in demo_accounts:
        pwd_hash, pwd_salt = hash_password(pwd)
        repo.create_user(
            user_id=f"usr-{uname}",
            username=uname,
            display_name=uname.title(),
            password_hash=pwd_hash,
            password_salt=pwd_salt,
            roles=(Role.OPERATOR,),
            is_active=True,
        )

    with patch.object(Settings, "is_production", return_value=True):
        auth_svc = AuthenticationService(
            identity_repository=repo,
            session_repository=None,
            audit_trail=None,
            auto_bootstrap=False,
        )
        for uname, pwd in demo_accounts:
            # Must reject even with correct password
            with pytest.raises(InvalidCredentialsError, match="Invalid username or password."):
                auth_svc.authenticate(uname, pwd)
            # Must reject with incorrect password
            with pytest.raises(InvalidCredentialsError, match="Invalid username or password."):
                auth_svc.authenticate(uname, "WrongPassword999!")


def test_production_authentication_allows_non_demo_users():
    """Verify non-demo enterprise identities authenticate successfully in production."""
    from app.security.identity.crypto import hash_password
    from app.security.identity.models import Role
    from app.security.persistence.session_repository import SessionRepository

    repo = IdentityRepository(session_factory=None)
    sess_repo = SessionRepository(session_factory=None)
    pwd_hash, pwd_salt = hash_password("ProdSecurePassword456!")
    repo.create_user(
        user_id="usr-secops",
        username="corp_secops_admin",
        display_name="Corporate SecOps Admin",
        password_hash=pwd_hash,
        password_salt=pwd_salt,
        roles=(Role.ADMIN,),
        is_active=True,
    )

    with patch.object(Settings, "is_production", return_value=True):
        auth_svc = AuthenticationService(
            identity_repository=repo,
            session_repository=sess_repo,
            audit_trail=None,
            auto_bootstrap=False,
        )
        session = auth_svc.authenticate("corp_secops_admin", "ProdSecurePassword456!")
        assert session is not None
        assert session.user_id == "usr-secops"


def test_production_demo_rejection_records_audit_and_never_leaks_secrets():
    """Verify demo account rejection in production emits an audit event with zero secret leakage."""
    from app.security.identity.errors import InvalidCredentialsError
    from app.security.audit.trail import SecurityAuditTrail

    audit_trail = SecurityAuditTrail(repository=None)
    repo = IdentityRepository(session_factory=None)

    with patch.object(Settings, "is_production", return_value=True):
        auth_svc = AuthenticationService(
            identity_repository=repo,
            session_repository=None,
            audit_trail=audit_trail,
            auto_bootstrap=False,
        )
        with pytest.raises(InvalidCredentialsError):
            auth_svc.authenticate("admin", "AdminPass123!")

    events = audit_trail.get_events()
    assert len(events) >= 1
    ev = events[-1]
    assert ev.event_type.value == "AUTHENTICATION_FAILURE"
    assert ev.details.get("username") == "admin"
    assert ev.details.get("reason") == "Default development demo account authentication is strictly prohibited in production."
    # Guarantee zero passwords or secret substrings are recorded
    assert "AdminPass123!" not in str(ev.details)
    assert "password" not in ev.details


def test_health_endpoint_exposes_environment():
    """Verify health endpoints return the configured environment."""
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "environment" in data

    resp_v1 = client.get("/api/v1/health")
    assert resp_v1.status_code == 200
    data_v1 = resp_v1.json()
    assert data_v1["status"] == "ok"
    assert "environment" in data_v1
