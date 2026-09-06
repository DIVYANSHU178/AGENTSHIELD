"""
Identity, Authentication & Authorization Package for AgentShield Phase 14.
"""

from app.security.identity.models import (
    Role,
    Permission,
    ROLE_PERMISSIONS,
    UserIdentity,
    AuthSession,
    AuthorizationDecision,
)
from app.security.identity.crypto import (
    hash_password,
    verify_password,
    generate_secure_token,
)
from app.security.identity.errors import (
    IdentitySecurityError,
    AuthenticationError,
    InvalidCredentialsError,
    InactiveIdentityError,
    SessionExpiredError,
    SessionRevokedError,
    AuthorizationDeniedError,
    IdentityNotFoundError,
    IdentityAlreadyExistsError,
)
from app.security.identity.authentication import (
    AuthenticationService,
    get_auth_service,
)
from app.security.identity.authorization import (
    AuthorizationService,
    get_authorization_service,
)

__all__ = [
    "Role",
    "Permission",
    "ROLE_PERMISSIONS",
    "UserIdentity",
    "AuthSession",
    "AuthorizationDecision",
    "hash_password",
    "verify_password",
    "generate_secure_token",
    "IdentitySecurityError",
    "AuthenticationError",
    "InvalidCredentialsError",
    "InactiveIdentityError",
    "SessionExpiredError",
    "SessionRevokedError",
    "AuthorizationDeniedError",
    "IdentityNotFoundError",
    "IdentityAlreadyExistsError",
    "AuthenticationService",
    "get_auth_service",
    "AuthorizationService",
    "get_authorization_service",
]
