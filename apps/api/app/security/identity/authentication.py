"""
Authentication Service for AgentShield Phase 14.

Provides deterministic authentication, session lifecycle management, token revocation,
and identity provisioning with secure credential handling and zero plaintext secret leakage.
"""

import copy
from datetime import timedelta, datetime
from typing import Optional, Tuple, Dict, Any, List
from app.security.identity.models import UserIdentity, AuthSession, Role, Permission
from app.security.identity.crypto import hash_password, verify_password, generate_secure_token
from app.security.identity.errors import (
    AuthenticationError,
    InvalidCredentialsError,
    InactiveIdentityError,
    SessionExpiredError,
    SessionRevokedError,
    IdentityNotFoundError,
    IdentityAlreadyExistsError,
)
from app.security.persistence.identity_repository import IdentityRepository
from app.security.persistence.session_repository import SessionRepository
from app.security.audit.trail import SecurityAuditTrail
from app.security.audit.redaction import sanitize_audit_payload
from app.security.models.events import SecurityEvent
from app.security.models.enums import EventType
from app.config.settings import settings
from app.security.models.utils import generate_uuid, utc_now, ensure_utc



DEFAULT_DEMO_USERNAMES = frozenset({"admin", "security_lead", "ops_user", "viewer_user"})


class AuthenticationService:
    """
    Core service responsible for validating credentials, managing authenticated sessions,
    revoking tokens, and maintaining user identities.
    """

    def __init__(
        self,
        identity_repository: Optional[IdentityRepository] = None,
        session_repository: Optional[SessionRepository] = None,
        audit_trail: Optional[SecurityAuditTrail] = None,
        auto_bootstrap: bool = True,
    ) -> None:
        self._identity_repo = identity_repository or IdentityRepository()
        self._session_repo = session_repository or SessionRepository()
        self._audit_trail = audit_trail

        if auto_bootstrap:
            self._bootstrap_default_identities()

    @property
    def identity_repository(self) -> IdentityRepository:
        return self._identity_repo

    @property
    def session_repository(self) -> SessionRepository:
        return self._session_repo

    @property
    def audit_trail(self) -> Optional[SecurityAuditTrail]:
        return self._audit_trail

    def _bootstrap_default_identities(self) -> None:
        """
        Seed default identities deterministically if repository has no users.
        Strictly disabled in production environments.
        """
        if settings.is_production():
            return

        if self._identity_repo.count_users() == 0:
            defaults = [
                ("admin", "AdminPass123!", "System Administrator", (Role.ADMIN,), "admin@agentshield.local"),
                ("security_lead", "ReviewerPass123!", "Alice Security Lead", (Role.SECURITY_REVIEWER,), "reviewer@agentshield.local"),
                ("ops_user", "OperatorPass123!", "Bob Operator", (Role.OPERATOR,), "operator@agentshield.local"),
                ("viewer_user", "ViewerPass123!", "Carol Viewer", (Role.VIEWER,), "viewer@agentshield.local"),
            ]
            for uname, pwd, dname, roles, email in defaults:
                uid = f"usr-{uname}"
                pwd_hash, pwd_salt = hash_password(pwd)
                try:
                    self._identity_repo.create_user(
                        user_id=uid,
                        username=uname,
                        display_name=dname,
                        password_hash=pwd_hash,
                        password_salt=pwd_salt,
                        roles=roles,
                        email=email,
                        is_active=True,
                    )
                except IdentityAlreadyExistsError:
                    pass

    def authenticate(
        self,
        username: str,
        password: str,
        ttl_seconds: float = 86400.0,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuthSession:
        """
        Authenticate a user with username and password.
        Returns a new valid AuthSession upon success.
        Raises InvalidCredentialsError or InactiveIdentityError on failure.
        """
        if not username or not isinstance(username, str) or not username.strip():
            self._record_audit(
                event_type=EventType.AUTHENTICATION_FAILURE,
                request_id=correlation_id or "auth-failure",
                details={"reason": "Empty username provided"},
            )
            raise InvalidCredentialsError("Username is required.")

        if not password or not isinstance(password, str):
            self._record_audit(
                event_type=EventType.AUTHENTICATION_FAILURE,
                request_id=correlation_id or "auth-failure",
                details={"username": username.strip(), "reason": "Empty password provided"},
            )
            raise InvalidCredentialsError("Password is required.")

        uname_norm = username.strip().lower()

        # Reject default development demo accounts in production unconditionally (fail-closed)
        if settings.is_production() and uname_norm in DEFAULT_DEMO_USERNAMES:
            audit_details: Dict[str, Any] = {
                "username": uname_norm,
                "reason": "Default development demo account authentication is strictly prohibited in production.",
            }
            if metadata and "client_ip" in metadata:
                audit_details["client_ip"] = metadata["client_ip"]
            self._record_audit(
                event_type=EventType.AUTHENTICATION_FAILURE,
                request_id=correlation_id or f"auth-fail-demo-prohibited-{generate_uuid()[:8]}",
                details=audit_details,
            )
            raise InvalidCredentialsError("Invalid username or password.")

        user_lookup = self._identity_repo.get_user_by_username(uname_norm)

        if not user_lookup:
            self._record_audit(
                event_type=EventType.AUTHENTICATION_FAILURE,
                request_id=correlation_id or f"auth-fail-{generate_uuid()[:8]}",
                details={"username": uname_norm, "reason": "User not found"},
            )
            raise InvalidCredentialsError("Invalid username or password.")

        identity, pwd_hash, pwd_salt = user_lookup

        if not identity.is_active:
            self._record_audit(
                event_type=EventType.AUTHENTICATION_FAILURE,
                request_id=correlation_id or f"auth-fail-{identity.user_id}",
                details={"user_id": identity.user_id, "username": uname_norm, "reason": "User account is disabled"},
            )
            raise InactiveIdentityError(f"User account '{identity.username}' is disabled.")

        if not verify_password(password, pwd_hash, pwd_salt):
            self._record_audit(
                event_type=EventType.AUTHENTICATION_FAILURE,
                request_id=correlation_id or f"auth-fail-{identity.user_id}",
                details={"user_id": identity.user_id, "username": uname_norm, "reason": "Password mismatch"},
            )
            raise InvalidCredentialsError("Invalid username or password.")

        # Create session
        now = utc_now()
        expires_at = now + timedelta(seconds=ttl_seconds)
        token = generate_secure_token()

        session = self._session_repo.create_session(
            session_id=token,
            user_id=identity.user_id,
            username=identity.username,
            issued_at=now,
            expires_at=expires_at,
            metadata=copy.deepcopy(metadata or {}),
        )

        self._record_audit(
            event_type=EventType.AUTHENTICATION_SUCCESS,
            request_id=correlation_id or f"auth-ok-{identity.user_id}",
            details={
                "user_id": identity.user_id,
                "username": identity.username,
                "roles": [r.value for r in identity.roles],
            },
        )
        self._record_audit(
            event_type=EventType.SESSION_CREATED,
            request_id=correlation_id or f"sess-new-{identity.user_id}",
            details={
                "user_id": identity.user_id,
                "username": identity.username,
                "expires_at": expires_at.isoformat(),
            },
        )

        return session

    def validate_session(self, session_id: str) -> Optional[UserIdentity]:
        """
        Validate a session token. Returns UserIdentity if valid, or None if invalid/expired/revoked/disabled.
        """
        if not session_id or not isinstance(session_id, str):
            return None

        session = self._session_repo.get_session(session_id.strip())
        if not session or not session.is_valid():
            return None

        identity = self._identity_repo.get_user_by_id(session.user_id)
        if not identity or not identity.is_active:
            return None

        return identity

    def revoke_session(self, session_id: str, reason: str = "User logout") -> bool:
        """
        Revoke an active session token. Returns True if revoked successfully.
        """
        if not session_id or not isinstance(session_id, str):
            return False

        sess = self._session_repo.get_session(session_id.strip())
        if not sess:
            return False

        revoked = self._session_repo.revoke_session(session_id.strip(), reason=reason)
        if revoked:
            self._record_audit(
                event_type=EventType.SESSION_REVOKED,
                request_id=f"sess-rev-{sess.user_id}",
                details={
                    "user_id": sess.user_id,
                    "username": sess.username,
                    "reason": reason,
                },
            )
        return revoked

    def get_current_identity(self, session_id: str) -> Optional[UserIdentity]:
        """Convenience alias for validate_session."""
        return self.validate_session(session_id)

    def create_user(
        self,
        username: str,
        password: str,
        display_name: str,
        roles: Tuple[Role, ...],
        email: Optional[str] = None,
        is_active: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> UserIdentity:
        """Create and persist a new user identity with secure password hashing."""
        pwd_hash, pwd_salt = hash_password(password)
        uid = f"usr-{generate_uuid()[:12]}"
        return self._identity_repo.create_user(
            user_id=uid,
            username=username,
            display_name=display_name,
            password_hash=pwd_hash,
            password_salt=pwd_salt,
            roles=roles,
            email=email,
            is_active=is_active,
            metadata=metadata,
        )

    def disable_user(self, user_id: str) -> Optional[UserIdentity]:
        """Deactivate a user identity and log audit trail event."""
        updated = self._identity_repo.set_user_active(user_id, is_active=False)
        if updated:
            self._record_audit(
                event_type=EventType.IDENTITY_DISABLED,
                request_id=f"user-disable-{user_id}",
                details={"user_id": user_id, "username": updated.username},
            )
        return updated

    def assign_roles(self, user_id: str, roles: Tuple[Role, ...]) -> Optional[UserIdentity]:
        """Update roles for a user identity and log audit trail event."""
        updated = self._identity_repo.update_user_roles(user_id, roles)
        if updated:
            self._record_audit(
                event_type=EventType.ROLE_CHANGE,
                request_id=f"role-change-{user_id}",
                details={"user_id": user_id, "new_roles": [r.value for r in roles]},
            )
        return updated

    def list_identities(self, limit: int = 100) -> List[UserIdentity]:
        """Retrieve registered user identities."""
        return self._identity_repo.list_users(limit=limit)

    def _record_audit(self, event_type: EventType, request_id: str, details: Dict[str, Any]) -> None:
        if self._audit_trail is not None:
            try:
                ev = SecurityEvent(
                    event_id=generate_uuid(),
                    request_id=request_id,
                    event_type=event_type,
                    timestamp=utc_now(),
                    actor="authentication_service",
                    details=sanitize_audit_payload(details),
                    metadata={"stage": "authentication_service"},
                )
                self._audit_trail.record(ev)
            except Exception:
                pass


# Global singleton factory
_GLOBAL_AUTH_SERVICE: Optional[AuthenticationService] = None

def get_auth_service() -> AuthenticationService:
    """Retrieve or initialize the global persistent AuthenticationService instance."""
    global _GLOBAL_AUTH_SERVICE
    if _GLOBAL_AUTH_SERVICE is None:
        from app.database import init_db, SessionLocal
        from app.security.persistence import IdentityRepository, SessionRepository, AuditRepository
        init_db()
        ident_repo = IdentityRepository(session_factory=SessionLocal)
        sess_repo = SessionRepository(session_factory=SessionLocal)
        audit_repo = AuditRepository(session_factory=SessionLocal)
        audit_trail = SecurityAuditTrail(repository=audit_repo)
        _GLOBAL_AUTH_SERVICE = AuthenticationService(
            identity_repository=ident_repo,
            session_repository=sess_repo,
            audit_trail=audit_trail,
            auto_bootstrap=True,
        )
    return _GLOBAL_AUTH_SERVICE

def set_auth_service(service: Optional[AuthenticationService]) -> None:
    """Explicitly set or reset the global AuthenticationService instance."""
    global _GLOBAL_AUTH_SERVICE
    _GLOBAL_AUTH_SERVICE = service
