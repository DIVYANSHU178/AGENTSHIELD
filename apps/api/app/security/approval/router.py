from typing import Optional, List, Any, Dict
from fastapi import APIRouter, HTTPException, Query, Path, status, Depends
from pydantic import BaseModel, Field, field_validator
from app.security.approval.contracts import (
    ApprovalRequest,
    ApprovalStatus,
    ReviewerIdentity,
)
from app.security.approval.service import get_approval_service
from app.security.approval.errors import (
    ApprovalNotFoundError,
    ApprovalExpiredError,
    InvalidApprovalStateTransitionError,
    ApprovalPolicyViolationError,
    ApprovalTamperingError,
)
from app.security.identity.models import UserIdentity, Permission
from app.security.identity.errors import AuthorizationDeniedError
from app.security.identity.dependencies import get_current_user_optional, require_permission


approval_router = APIRouter(prefix="/security/approvals", tags=["approvals"])

class ReviewActionRequest(BaseModel):
    reviewer_id: str = Field(..., min_length=1, max_length=64, description="Reviewer identifier")
    reviewer_name: Optional[str] = Field(default=None, max_length=128, description="Reviewer human-readable name")
    role: Optional[str] = Field(default="security_reviewer", max_length=64, description="Reviewer role")
    reason: str = Field(..., min_length=1, max_length=1000, description="Explicit review justification")

    @field_validator("reviewer_id", mode="before")
    @classmethod
    def validate_reviewer_id(cls, value: Any, info) -> Any:
        if value is None:
            raise ValueError(f"Field '{info.field_name}' cannot be None.")
        if not isinstance(value, str):
            raise ValueError(f"Field '{info.field_name}' must be a string, got {type(value).__name__}.")
        stripped = value.strip()
        if not stripped:
            raise ValueError(f"Field '{info.field_name}' must not be empty or whitespace-only.")
        if len(stripped) > 64:
            raise ValueError(f"Field '{info.field_name}' exceeds maximum length of 64 characters.")
        return stripped

    @field_validator("reason", mode="before")
    @classmethod
    def validate_reason(cls, value: Any, info) -> Any:
        if value is None:
            raise ValueError(f"Field '{info.field_name}' cannot be None.")
        if not isinstance(value, str):
            raise ValueError(f"Field '{info.field_name}' must be a string, got {type(value).__name__}.")
        stripped = value.strip()
        if not stripped:
            raise ValueError(f"Field '{info.field_name}' must not be empty or whitespace-only.")
        if len(stripped) > 1000:
            raise ValueError(f"Field '{info.field_name}' exceeds maximum length of 1000 characters.")
        return stripped

    @field_validator("reviewer_name", "role", mode="before")
    @classmethod
    def validate_optional_str(cls, value: Any, info) -> Any:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError(f"Field '{info.field_name}' must be a string if provided, got {type(value).__name__}.")
        stripped = value.strip()
        if stripped and len(stripped) > (128 if info.field_name == "reviewer_name" else 64):
            raise ValueError(f"Field '{info.field_name}' exceeds maximum allowed length.")
        return stripped or None

class CancelActionRequest(BaseModel):
    reason: str = Field(default="Cancelled by requester", min_length=1, max_length=1000, description="Reason for cancellation")

    @field_validator("reason", mode="before")
    @classmethod
    def validate_reason(cls, value: Any, info) -> Any:
        if value is None:
            return "Cancelled by requester"
        if not isinstance(value, str):
            raise ValueError(f"Field '{info.field_name}' must be a string, got {type(value).__name__}.")
        stripped = value.strip()
        if not stripped:
            return "Cancelled by requester"
        if len(stripped) > 1000:
            raise ValueError(f"Field '{info.field_name}' exceeds maximum length of 1000 characters.")
        return stripped

@approval_router.get("", response_model=List[ApprovalRequest], dependencies=[Depends(require_permission(Permission.VIEW_APPROVALS))])
def list_approvals(
    status: Optional[ApprovalStatus] = Query(default=None, description="Filter by approval status"),
    limit: int = Query(default=50, ge=1, le=200, description="Max items to return"),
) -> List[ApprovalRequest]:
    """List all approval requests with optional status filtering."""
    service = get_approval_service()
    return service.list_approvals(status=status, limit=limit)

@approval_router.get("/{approval_id}", response_model=ApprovalRequest, dependencies=[Depends(require_permission(Permission.VIEW_APPROVALS))])
def get_approval(
    approval_id: str = Path(..., min_length=8, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$"),
) -> ApprovalRequest:
    """Retrieve details for a specific approval request."""
    service = get_approval_service()
    try:
        return service.get_approval(approval_id)
    except ApprovalNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))

@approval_router.post("/{approval_id}/approve", response_model=ApprovalRequest)
def approve_request(
    approval_id: str = Path(..., min_length=8, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$"),
    body: ReviewActionRequest = ...,
    current_user: Optional[UserIdentity] = Depends(require_permission(Permission.RESOLVE_APPROVALS)),
) -> ApprovalRequest:
    """Approve a pending approval request."""
    if current_user is not None and not current_user.has_permission(Permission.RESOLVE_APPROVALS):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Identity '{current_user.username}' is not authorized to resolve approvals.",
        )

    service = get_approval_service()
    reviewer = ReviewerIdentity(
        reviewer_id=current_user.user_id if current_user else body.reviewer_id,
        reviewer_name=current_user.display_name if current_user else body.reviewer_name,
        role=current_user.roles[0].value if (current_user and current_user.roles) else body.role,
    )
    try:
        return service.approve(
            approval_id=approval_id,
            reviewer=reviewer,
            reason=body.reason,
        )
    except AuthorizationDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ApprovalNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except (ApprovalExpiredError, InvalidApprovalStateTransitionError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

@approval_router.post("/{approval_id}/reject", response_model=ApprovalRequest)
def reject_request(
    approval_id: str = Path(..., min_length=8, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$"),
    body: ReviewActionRequest = ...,
    current_user: Optional[UserIdentity] = Depends(require_permission(Permission.RESOLVE_APPROVALS)),
) -> ApprovalRequest:
    """Reject a pending approval request."""
    if current_user is not None and not current_user.has_permission(Permission.RESOLVE_APPROVALS):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Identity '{current_user.username}' is not authorized to resolve approvals.",
        )

    service = get_approval_service()
    reviewer = ReviewerIdentity(
        reviewer_id=current_user.user_id if current_user else body.reviewer_id,
        reviewer_name=current_user.display_name if current_user else body.reviewer_name,
        role=current_user.roles[0].value if (current_user and current_user.roles) else body.role,
    )
    try:
        return service.reject(
            approval_id=approval_id,
            reviewer=reviewer,
            reason=body.reason,
        )
    except AuthorizationDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ApprovalNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except (ApprovalExpiredError, InvalidApprovalStateTransitionError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

@approval_router.post("/{approval_id}/cancel", response_model=ApprovalRequest)
def cancel_request(
    approval_id: str = Path(..., min_length=8, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$"),
    body: CancelActionRequest = ...,
    current_user: Optional[UserIdentity] = Depends(require_permission(Permission.CANCEL_APPROVAL)),
) -> ApprovalRequest:
    """Cancel a pending approval request."""
    if current_user is not None and not current_user.has_permission(Permission.CANCEL_APPROVAL):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Identity '{current_user.username}' is not authorized to cancel approvals.",
        )

    service = get_approval_service()
    try:
        return service.cancel(approval_id=approval_id, reason=body.reason)
    except AuthorizationDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ApprovalNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except InvalidApprovalStateTransitionError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
