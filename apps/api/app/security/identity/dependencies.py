"""
FastAPI Authentication and Authorization Dependencies for AgentShield Phase 14.
"""

from typing import Optional, Callable
from fastapi import Request, Header, Depends, HTTPException, status
from app.config import settings
from app.security.identity.models import UserIdentity, Permission
from app.security.identity.authentication import AuthenticationService, get_auth_service
from app.security.identity.authorization import AuthorizationService, get_authorization_service
from app.security.identity.errors import (
    AuthenticationError,
    InvalidCredentialsError,
    InactiveIdentityError,
    SessionExpiredError,
    SessionRevokedError,
    AuthorizationDeniedError,
)


def get_current_token(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_session_id: Optional[str] = Header(default=None, alias="X-Session-ID"),
) -> Optional[str]:
    """
    Extract authentication session token from Authorization: Bearer <token>,
    X-Session-ID header, or session_id cookie.
    """
    if authorization and authorization.strip():
        parts = authorization.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()
        if len(parts) == 1:
            return parts[0].strip()

    if x_session_id and x_session_id.strip():
        return x_session_id.strip()

    cookie_token = request.cookies.get("session_id")
    if cookie_token and cookie_token.strip():
        return cookie_token.strip()

    return None


def get_current_user(
    token: Optional[str] = Depends(get_current_token),
    auth_service: AuthenticationService = Depends(get_auth_service),
) -> UserIdentity:
    """
    Strict dependency requiring a valid, active, non-revoked, non-expired authentication session.
    Raises HTTP 401 Unauthorized if missing, revoked, or expired.
    """
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    identity = auth_service.validate_session(token)
    if not identity:
        # Determine if session exists but is revoked or expired
        session = auth_service.session_repository.get_session(token)
        if session:
            if session.is_revoked:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Session has been revoked: {session.revocation_reason or 'Logged out'}.",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            if not session.is_valid():
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication session has expired.",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            # Check user status
            user = auth_service.identity_repository.get_user_by_id(session.user_id)
            if user and not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"User identity '{user.username}' is disabled/inactive.",
                    headers={"WWW-Authenticate": "Bearer"},
                )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication session token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return identity


def get_current_user_optional(
    token: Optional[str] = Depends(get_current_token),
    auth_service: AuthenticationService = Depends(get_auth_service),
) -> Optional[UserIdentity]:
    """
    Optional dependency: returns UserIdentity if valid token provided;
    Raises 401 if an invalid/revoked/expired token is explicitly supplied;
    Returns None if no token was provided at all.
    """
    if not token:
        return None

    identity = auth_service.validate_session(token)
    if not identity:
        session = auth_service.session_repository.get_session(token)
        if session:
            if session.is_revoked:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Session has been revoked: {session.revocation_reason or 'Logged out'}.",
                )
            if not session.is_valid():
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication session has expired.",
                )
            user = auth_service.identity_repository.get_user_by_id(session.user_id)
            if user and not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"User identity '{user.username}' is disabled/inactive.",
                )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication session token.",
        )

    return identity


def require_permission(permission: Permission) -> Callable:
    """
    Dependency factory that validates whether the caller has the required RBAC permission.
    If authenticated identity is present: checks authorization and raises 403 Forbidden if lacking capability.
    If no token is present: in dev/test environments permits legacy test execution; in production raises 401.
    """
    def _permission_guard(
        user: Optional[UserIdentity] = Depends(get_current_user_optional),
        authorization_service: AuthorizationService = Depends(get_authorization_service),
    ) -> Optional[UserIdentity]:
        if user is not None:
            decision = authorization_service.authorize(user, permission)
            if not decision.allowed:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=decision.reason,
                )
            return user

        # Unauthenticated request: check environment
        env = (settings.ENVIRONMENT or "").strip().lower()
        if env not in ("development", "test", "testing", "dev", "local"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Authentication required for permission '{permission.value}'.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return None

    return _permission_guard
