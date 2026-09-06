"""
Authorization Service for AgentShield Phase 14.

Provides deterministic Role-Based Access Control (RBAC), explicit permission matching,
deny-by-default evaluation, and immutable audit logging.
"""

from datetime import datetime
from typing import Optional, Union, Dict, Any, List
from app.security.identity.models import (
    UserIdentity,
    Role,
    Permission,
    ROLE_PERMISSIONS,
    AuthorizationDecision,
)
from app.security.identity.errors import AuthorizationDeniedError
from app.security.persistence.auth_audit_repository import AuthorizationAuditRepository
from app.security.audit.trail import SecurityAuditTrail
from app.security.audit.redaction import sanitize_audit_payload
from app.security.models.events import SecurityEvent
from app.security.models.enums import EventType
from app.security.models.utils import generate_uuid, utc_now



class AuthorizationService:
    """
    Dedicated authorization service enforcing explicit, deny-by-default RBAC policies.
    """

    def __init__(
        self,
        audit_trail: Optional[SecurityAuditTrail] = None,
        auth_audit_repository: Optional[AuthorizationAuditRepository] = None,
    ) -> None:
        self._audit_trail = audit_trail
        self._auth_audit_repo = auth_audit_repository or AuthorizationAuditRepository()

    @property
    def audit_trail(self) -> Optional[SecurityAuditTrail]:
        return self._audit_trail

    @property
    def auth_audit_repository(self) -> AuthorizationAuditRepository:
        return self._auth_audit_repo

    def authorize(
        self,
        identity: Optional[UserIdentity],
        permission: Union[Permission, str],
        resource: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> AuthorizationDecision:
        """
        Evaluate whether an identity possesses the requested permission.
        Enforces Deny-By-Default:
        - None identity -> DENY
        - Inactive identity -> DENY
        - Unknown permission / role -> DENY
        - Unmatched permission -> DENY
        - Matched active permission -> ALLOW
        """
        now = utc_now()
        decision_id = generate_uuid()

        # 1. Parse and validate permission
        target_perm: Optional[Permission] = None
        if isinstance(permission, Permission):
            target_perm = permission
        elif isinstance(permission, str):
            try:
                target_perm = Permission(permission.upper())
            except ValueError:
                target_perm = None

        if target_perm is None:
            decision = AuthorizationDecision(
                decision_id=decision_id,
                user_id=identity.user_id if identity else None,
                username=identity.username if identity else None,
                permission=Permission.VIEW_OPERATIONS,  # fallback placeholder for invalid perm
                resource=resource,
                allowed=False,
                reason=f"Unknown or malformed permission: '{permission}'.",
                timestamp=now,
            )
            self._record_decision(decision, correlation_id)
            return decision

        # 2. Check unauthenticated caller
        if identity is None:
            decision = AuthorizationDecision(
                decision_id=decision_id,
                user_id=None,
                username=None,
                permission=target_perm,
                resource=resource,
                allowed=False,
                reason="Unauthenticated caller: identity context is missing.",
                timestamp=now,
            )
            self._record_decision(decision, correlation_id)
            return decision

        # 3. Check disabled/inactive identity
        if not identity.is_active:
            decision = AuthorizationDecision(
                decision_id=decision_id,
                user_id=identity.user_id,
                username=identity.username,
                permission=target_perm,
                resource=resource,
                allowed=False,
                reason=f"Identity '{identity.username}' is disabled/inactive.",
                timestamp=now,
            )
            self._record_decision(decision, correlation_id)
            return decision

        # 4. Check explicit RBAC permission matching
        if identity.has_permission(target_perm):
            user_roles = [r.value for r in identity.roles]
            decision = AuthorizationDecision(
                decision_id=decision_id,
                user_id=identity.user_id,
                username=identity.username,
                permission=target_perm,
                resource=resource,
                allowed=True,
                reason=f"Permission '{target_perm.value}' granted to roles {user_roles}.",
                timestamp=now,
            )
            self._record_decision(decision, correlation_id)
            return decision

        # 5. Deny by default
        user_roles = [r.value for r in identity.roles]
        decision = AuthorizationDecision(
            decision_id=decision_id,
            user_id=identity.user_id,
            username=identity.username,
            permission=target_perm,
            resource=resource,
            allowed=False,
            reason=f"Permission '{target_perm.value}' denied: roles {user_roles} lack required capability.",
            timestamp=now,
        )
        self._record_decision(decision, correlation_id)
        return decision

    def check_permission(
        self,
        identity: Optional[UserIdentity],
        permission: Union[Permission, str],
        resource: Optional[str] = None,
    ) -> bool:
        """Convenience boolean check for permission possession."""
        decision = self.authorize(identity=identity, permission=permission, resource=resource)
        return decision.allowed

    def _record_decision(self, decision: AuthorizationDecision, correlation_id: Optional[str] = None) -> None:
        event_type = EventType.AUTHORIZATION_ALLOWED if decision.allowed else EventType.AUTHORIZATION_DENIED

        # 1. Record to persistent authorization audit repo
        self._auth_audit_repo.record_event(
            event_type=event_type.value,
            decision="ALLOW" if decision.allowed else "DENY",
            user_id=decision.user_id,
            username=decision.username,
            permission=decision.permission.value if decision.permission else None,
            resource=decision.resource,
            reason=decision.reason,
            correlation_id=correlation_id,
            timestamp=decision.timestamp,
        )

        # 2. Record to security audit trail if attached
        if self._audit_trail is not None:
            try:
                ev = SecurityEvent(
                    event_id=generate_uuid(),
                    request_id=correlation_id or decision.decision_id,
                    event_type=event_type,
                    timestamp=decision.timestamp,
                    actor="authorization_service",
                    details=sanitize_audit_payload({
                        "decision_id": decision.decision_id,
                        "user_id": decision.user_id,
                        "username": decision.username,
                        "permission": decision.permission.value if decision.permission else None,
                        "resource": decision.resource,
                        "allowed": decision.allowed,
                        "reason": decision.reason,
                    }),
                    metadata={"stage": "authorization_service"},
                )
                self._audit_trail.record(ev)
            except Exception:
                pass


# Global singleton factory
_GLOBAL_AUTHORIZATION_SERVICE: Optional[AuthorizationService] = None

def get_authorization_service() -> AuthorizationService:
    """Retrieve or initialize the global persistent AuthorizationService instance."""
    global _GLOBAL_AUTHORIZATION_SERVICE
    if _GLOBAL_AUTHORIZATION_SERVICE is None:
        from app.database import init_db, SessionLocal
        from app.security.persistence import AuthorizationAuditRepository, AuditRepository
        init_db()
        auth_audit_repo = AuthorizationAuditRepository(session_factory=SessionLocal)
        audit_repo = AuditRepository(session_factory=SessionLocal)
        audit_trail = SecurityAuditTrail(repository=audit_repo)
        _GLOBAL_AUTHORIZATION_SERVICE = AuthorizationService(
            audit_trail=audit_trail,
            auth_audit_repository=auth_audit_repo,
        )
    return _GLOBAL_AUTHORIZATION_SERVICE

def set_authorization_service(service: Optional[AuthorizationService]) -> None:
    """Explicitly set or reset the global AuthorizationService instance."""
    global _GLOBAL_AUTHORIZATION_SERVICE
    _GLOBAL_AUTHORIZATION_SERVICE = service
