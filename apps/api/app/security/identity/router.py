"""
Authentication, Authorization & Identity Management REST API Router for AgentShield Phase 14.
"""

from typing import List, Optional, Any
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Header
from pydantic import BaseModel, Field, field_validator
from app.security.identity.models import (
    Role,
    Permission,
    UserIdentity,
    AuthSession,
    AuthorizationDecision,
)
from app.security.identity.authentication import AuthenticationService, get_auth_service
from app.security.identity.authorization import AuthorizationService, get_authorization_service
from app.security.identity.dependencies import (
    get_current_token,
    get_current_user,
    get_current_user_optional,
    require_permission,
)
from app.security.identity.errors import (
    AuthenticationError,
    InvalidCredentialsError,
    InactiveIdentityError,
    SessionExpiredError,
    SessionRevokedError,
    IdentityNotFoundError,
    IdentityAlreadyExistsError,
)

auth_router = APIRouter(prefix="/auth", tags=["authentication-and-identity"])


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, description="Username or login identifier")
    password: str = Field(..., min_length=1, description="Plaintext login password")
    ttl_seconds: float = Field(default=86400.0, ge=60.0, le=604800.0, description="Session TTL in seconds")


class LoginResponse(BaseModel):
    session_id: str = Field(..., description="Active session / bearer token")
    user_id: str = Field(..., description="Authenticated user ID")
    username: str = Field(..., description="Authenticated username")
    display_name: str = Field(..., description="User display name")
    roles: List[str] = Field(..., description="Assigned RBAC roles")
    issued_at: datetime = Field(..., description="UTC issuance timestamp")
    expires_at: datetime = Field(..., description="UTC expiration timestamp")


class LogoutResponse(BaseModel):
    message: str
    revoked: bool


class AuthorizeCheckRequest(BaseModel):
    permission: str = Field(..., description="Target permission name to evaluate")
    resource: Optional[str] = Field(default=None, description="Optional target resource scope")


class CreateIdentityRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=128)
    password: str = Field(..., min_length=6, max_length=128)
    display_name: str = Field(..., min_length=1, max_length=128)
    roles: List[Role] = Field(default_factory=lambda: [Role.VIEWER])
    email: Optional[str] = Field(default=None, max_length=256)
    is_active: bool = Field(default=True)


class UpdateRolesRequest(BaseModel):
    roles: List[Role] = Field(..., min_length=1, description="New list of assigned roles")


@auth_router.post("/login", response_model=LoginResponse)
def login(
    body: LoginRequest,
    auth_service: AuthenticationService = Depends(get_auth_service),
) -> LoginResponse:
    """
    Authenticate user credentials and issue an active session token.
    """
    try:
        session = auth_service.authenticate(
            username=body.username,
            password=body.password,
            ttl_seconds=body.ttl_seconds,
        )
        user = auth_service.validate_session(session.session_id)
        if not user:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Session initialization failed.")

        return LoginResponse(
            session_id=session.session_id,
            user_id=user.user_id,
            username=user.username,
            display_name=user.display_name,
            roles=[r.value for r in user.roles],
            issued_at=session.issued_at,
            expires_at=session.expires_at,
        )
    except InactiveIdentityError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except InvalidCredentialsError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))
    except AuthenticationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))


@auth_router.post("/logout", response_model=LogoutResponse)
def logout(
    token: Optional[str] = Depends(get_current_token),
    auth_service: AuthenticationService = Depends(get_auth_service),
) -> LogoutResponse:
    """
    Explicitly revoke the current authentication session token.
    """
    if not token:
        return LogoutResponse(message="No active session provided", revoked=False)

    revoked = auth_service.revoke_session(token, reason="User logout via API")
    return LogoutResponse(
        message="Session revoked successfully." if revoked else "Session was already inactive or not found.",
        revoked=revoked,
    )


@auth_router.get("/me", response_model=UserIdentity)
def get_current_identity_profile(
    user: UserIdentity = Depends(get_current_user),
) -> UserIdentity:
    """
    Retrieve identity details and roles for the currently authenticated caller.
    """
    return user


@auth_router.post("/authorize", response_model=AuthorizationDecision)
def check_authorization(
    body: AuthorizeCheckRequest,
    user: UserIdentity = Depends(get_current_user),
    authorization_service: AuthorizationService = Depends(get_authorization_service),
) -> AuthorizationDecision:
    """
    Evaluate whether the authenticated caller possesses a specific permission.
    """
    return authorization_service.authorize(
        identity=user,
        permission=body.permission,
        resource=body.resource,
    )


@auth_router.get("/identities", response_model=List[UserIdentity], dependencies=[Depends(require_permission(Permission.MANAGE_IDENTITIES))])
def list_identities(
    limit: int = 100,
    auth_service: AuthenticationService = Depends(get_auth_service),
) -> List[UserIdentity]:
    """
    List registered identities (requires MANAGE_IDENTITIES permission).
    """
    return auth_service.list_identities(limit=limit)


@auth_router.post("/identities", response_model=UserIdentity, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_permission(Permission.MANAGE_IDENTITIES))])
def create_identity(
    body: CreateIdentityRequest,
    auth_service: AuthenticationService = Depends(get_auth_service),
) -> UserIdentity:
    """
    Create a new user identity (requires MANAGE_IDENTITIES permission).
    """
    try:
        return auth_service.create_user(
            username=body.username,
            password=body.password,
            display_name=body.display_name,
            roles=tuple(body.roles),
            email=body.email,
            is_active=body.is_active,
        )
    except IdentityAlreadyExistsError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@auth_router.post("/identities/{user_id}/disable", response_model=UserIdentity, dependencies=[Depends(require_permission(Permission.MANAGE_IDENTITIES))])
def disable_identity(
    user_id: str,
    auth_service: AuthenticationService = Depends(get_auth_service),
) -> UserIdentity:
    """
    Disable an existing user identity (requires MANAGE_IDENTITIES permission).
    """
    updated = auth_service.disable_user(user_id)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User '{user_id}' not found.")
    return updated


@auth_router.post("/identities/{user_id}/roles", response_model=UserIdentity, dependencies=[Depends(require_permission(Permission.MANAGE_ROLES))])
def update_identity_roles(
    user_id: str,
    body: UpdateRolesRequest,
    auth_service: AuthenticationService = Depends(get_auth_service),
) -> UserIdentity:
    """
    Update assigned RBAC roles for a user identity (requires MANAGE_ROLES permission).
    """
    try:
        updated = auth_service.assign_roles(user_id, tuple(body.roles))
        if not updated:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User '{user_id}' not found.")
        return updated
    except IdentityNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
