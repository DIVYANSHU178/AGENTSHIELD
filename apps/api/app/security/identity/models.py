"""
Authoritative Identity and RBAC Models for AgentShield Phase 14.

Defines immutable Pydantic V2 representations for:
- System roles (VIEWER, OPERATOR, SECURITY_REVIEWER, ADMIN)
- Explicit permissions (Deny by default)
- User identity objects (immutable, no raw credentials)
- Authentication session / token objects
- Authorization decisions
"""

from enum import Enum
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple, Set, FrozenSet
from pydantic import BaseModel, ConfigDict, Field, field_validator
from app.security.models.utils import generate_uuid, utc_now, ensure_utc, deep_freeze, FrozenDict


class Role(str, Enum):
    """Authoritative system roles with explicit hierarchical capabilities."""
    VIEWER = "VIEWER"
    OPERATOR = "OPERATOR"
    SECURITY_REVIEWER = "SECURITY_REVIEWER"
    ADMIN = "ADMIN"


class Permission(str, Enum):
    """Explicit, granular permissions across AgentShield operational capabilities."""
    VIEW_OPERATIONS = "VIEW_OPERATIONS"
    VIEW_THREATS = "VIEW_THREATS"
    VIEW_DECISIONS = "VIEW_DECISIONS"
    VIEW_AUDIT = "VIEW_AUDIT"
    VIEW_APPROVALS = "VIEW_APPROVALS"
    RESOLVE_APPROVALS = "RESOLVE_APPROVALS"
    CANCEL_APPROVAL = "CANCEL_APPROVAL"
    RUN_SCENARIO_LAB = "RUN_SCENARIO_LAB"
    MANAGE_IDENTITIES = "MANAGE_IDENTITIES"
    MANAGE_ROLES = "MANAGE_ROLES"
    MANAGE_SECURITY_CONFIGURATION = "MANAGE_SECURITY_CONFIGURATION"
    MANAGE_TOOLS = "MANAGE_TOOLS"
    MANAGE_POLICIES = "MANAGE_POLICIES"


# Authoritative, explicit Role-to-Permission mapping (Deny by Default)
ROLE_PERMISSIONS: Dict[Role, FrozenSet[Permission]] = {
    Role.VIEWER: frozenset({
        Permission.VIEW_OPERATIONS,
        Permission.VIEW_THREATS,
        Permission.VIEW_DECISIONS,
        Permission.VIEW_AUDIT,
        Permission.VIEW_APPROVALS,
    }),
    Role.OPERATOR: frozenset({
        Permission.VIEW_OPERATIONS,
        Permission.VIEW_THREATS,
        Permission.VIEW_DECISIONS,
        Permission.VIEW_AUDIT,
        Permission.VIEW_APPROVALS,
        Permission.CANCEL_APPROVAL,
        Permission.RUN_SCENARIO_LAB,
    }),
    Role.SECURITY_REVIEWER: frozenset({
        Permission.VIEW_OPERATIONS,
        Permission.VIEW_THREATS,
        Permission.VIEW_DECISIONS,
        Permission.VIEW_AUDIT,
        Permission.VIEW_APPROVALS,
        Permission.RESOLVE_APPROVALS,
        Permission.CANCEL_APPROVAL,
        Permission.RUN_SCENARIO_LAB,
    }),
    Role.ADMIN: frozenset({
        Permission.VIEW_OPERATIONS,
        Permission.VIEW_THREATS,
        Permission.VIEW_DECISIONS,
        Permission.VIEW_AUDIT,
        Permission.VIEW_APPROVALS,
        Permission.RESOLVE_APPROVALS,
        Permission.CANCEL_APPROVAL,
        Permission.RUN_SCENARIO_LAB,
        Permission.MANAGE_IDENTITIES,
        Permission.MANAGE_ROLES,
        Permission.MANAGE_SECURITY_CONFIGURATION,
        Permission.MANAGE_TOOLS,
        Permission.MANAGE_POLICIES,
    }),
}


class UserIdentity(BaseModel):
    """
    Immutable representation of an authenticated user/operator identity.
    Contains zero raw credentials or plaintext secrets.
    """
    model_config = ConfigDict(frozen=True)

    user_id: str = Field(..., description="Unique immutable user identifier")
    username: str = Field(..., description="Unique login username")
    email: Optional[str] = Field(default=None, description="Optional verified email address")
    display_name: str = Field(..., description="Human-readable display name")
    roles: Tuple[Role, ...] = Field(default_factory=tuple, description="Assigned RBAC roles")
    is_active: bool = Field(default=True, description="Whether identity is active or disabled")
    created_at: datetime = Field(default_factory=utc_now, description="UTC creation timestamp")
    updated_at: datetime = Field(default_factory=utc_now, description="UTC last update timestamp")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary safe identity metadata")

    @field_validator("user_id", "username", "display_name", mode="before")
    @classmethod
    def validate_non_empty_str(cls, value: Any, info) -> str:
        if value is None or not isinstance(value, str) or not value.strip():
            raise ValueError(f"Field '{info.field_name}' must be a non-empty string.")
        return value.strip()

    @field_validator("roles", mode="before")
    @classmethod
    def normalize_roles(cls, value: Any) -> Tuple[Role, ...]:
        if value is None:
            return ()
        if isinstance(value, (list, set, tuple)):
            res = []
            for r in value:
                if isinstance(r, str):
                    try:
                        res.append(Role(r.upper()))
                    except ValueError:
                        raise ValueError(f"Unknown role '{r}'")
                elif isinstance(r, Role):
                    res.append(r)
                else:
                    raise ValueError(f"Invalid role item type: {type(r)}")
            return tuple(res)
        raise ValueError("Roles must be a collection of Role enums or valid strings.")

    @field_validator("metadata", mode="after")
    @classmethod
    def freeze_metadata(cls, value: Any) -> Any:
        if value is None:
            return FrozenDict()
        return deep_freeze(value)

    @field_validator("created_at", "updated_at", mode="before")
    @classmethod
    def validate_utc(cls, value: Any) -> datetime:
        if isinstance(value, datetime):
            return ensure_utc(value)
        return value

    def has_role(self, role: Role) -> bool:
        return role in self.roles

    def has_permission(self, permission: Permission) -> bool:
        if not self.is_active:
            return False
        for role in self.roles:
            perms = ROLE_PERMISSIONS.get(role, frozenset())
            if permission in perms:
                return True
        return False

    @property
    def permissions(self) -> Set[Permission]:
        if not self.is_active:
            return set()
        res: Set[Permission] = set()
        for role in self.roles:
            res.update(ROLE_PERMISSIONS.get(role, frozenset()))
        return res


class AuthSession(BaseModel):
    """
    Immutable representation of an active or revoked authentication session / token.
    """
    model_config = ConfigDict(frozen=True)

    session_id: str = Field(..., description="Unique session/token identifier")
    user_id: str = Field(..., description="Associated user ID")
    username: str = Field(..., description="Associated username")
    issued_at: datetime = Field(default_factory=utc_now, description="UTC issuance timestamp")
    expires_at: datetime = Field(..., description="UTC expiration timestamp")
    is_revoked: bool = Field(default=False, description="Whether session has been revoked/logged out")
    revoked_at: Optional[datetime] = Field(default=None, description="UTC revocation timestamp if revoked")
    revocation_reason: Optional[str] = Field(default=None, description="Reason for session revocation")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary session metadata")

    @field_validator("session_id", "user_id", "username", mode="before")
    @classmethod
    def validate_non_empty(cls, value: Any, info) -> str:
        if value is None or not isinstance(value, str) or not value.strip():
            raise ValueError(f"Field '{info.field_name}' must be a non-empty string.")
        return value.strip()

    @field_validator("issued_at", "expires_at", "revoked_at", mode="before")
    @classmethod
    def validate_utc(cls, value: Any) -> Any:
        if isinstance(value, datetime):
            return ensure_utc(value)
        return value

    @field_validator("metadata", mode="after")
    @classmethod
    def freeze_metadata(cls, value: Any) -> Any:
        if value is None:
            return FrozenDict()
        return deep_freeze(value)

    def is_valid(self, now: Optional[datetime] = None) -> bool:
        if self.is_revoked:
            return False
        current_time = ensure_utc(now) if now else utc_now()
        return current_time < self.expires_at


class AuthorizationDecision(BaseModel):
    """
    Immutable authorization decision rendered by AuthorizationService.
    Explicit allow/deny determination.
    """
    model_config = ConfigDict(frozen=True)

    decision_id: str = Field(default_factory=generate_uuid, description="Unique authorization decision ID")
    user_id: Optional[str] = Field(default=None, description="Requesting user ID")
    username: Optional[str] = Field(default=None, description="Requesting username")
    permission: Permission = Field(..., description="Requested permission")
    resource: Optional[str] = Field(default=None, description="Target resource identifier or scope")
    allowed: bool = Field(..., description="Whether action is explicitly permitted")
    reason: str = Field(..., description="Explicit rationale for allow or deny")
    timestamp: datetime = Field(default_factory=utc_now, description="UTC decision timestamp")

    @field_validator("timestamp", mode="before")
    @classmethod
    def validate_utc(cls, value: Any) -> datetime:
        if isinstance(value, datetime):
            return ensure_utc(value)
        return value
