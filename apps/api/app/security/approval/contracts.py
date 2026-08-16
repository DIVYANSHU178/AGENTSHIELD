from enum import Enum
from datetime import datetime
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, ConfigDict, Field, field_validator
from app.security.models import (
    AgentIdentity,
    ToolCategory,
    ActionType,
    Severity,
    SecurityDecisionType,
)
from app.security.models.utils import generate_uuid, utc_now, ensure_utc, deep_freeze, FrozenDict

class ApprovalStatus(str, Enum):
    """Lifecycle states for an approval request."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"

class ApprovalDecision(str, Enum):
    """Reviewer decision on an approval request."""
    APPROVE = "APPROVE"
    REJECT = "REJECT"

class ReviewerIdentity(BaseModel):
    """Identity of the reviewer or operator acting on an approval."""
    model_config = ConfigDict(frozen=True)

    reviewer_id: str = Field(..., description="Unique reviewer identifier")
    reviewer_name: Optional[str] = Field(default=None, description="Human-readable reviewer name")
    role: Optional[str] = Field(default="security_reviewer", description="Reviewer role or designation")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional reviewer metadata")

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
        return stripped

    @field_validator("metadata", mode="after")
    @classmethod
    def freeze_metadata(cls, value: Any) -> Any:
        if value is None:
            return FrozenDict()
        return deep_freeze(value)

class ApprovalResolution(BaseModel):
    """Cryptographic/auditable record of an approval review decision."""
    model_config = ConfigDict(frozen=True)

    resolution_id: str = Field(default_factory=generate_uuid, description="Unique resolution identifier")
    approval_id: str = Field(..., description="Target approval request ID")
    request_id: str = Field(..., description="Target tool execution request ID")
    reviewer: ReviewerIdentity = Field(..., description="Reviewer identity")
    decision: ApprovalDecision = Field(..., description="Reviewer decision")
    reason: str = Field(..., min_length=1, description="Explicit justification for approval or rejection")
    resolved_at: datetime = Field(default_factory=utc_now, description="Timestamp of resolution")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Resolution metadata")

    @field_validator("metadata", mode="after")
    @classmethod
    def freeze_metadata(cls, value: Any) -> Any:
        if value is None:
            return FrozenDict()
        return deep_freeze(value)

    @field_validator("resolved_at", mode="before")
    @classmethod
    def validate_utc_timestamp(cls, value: Any) -> Any:
        if isinstance(value, datetime):
            return ensure_utc(value)
        return value

class ApprovalRequest(BaseModel):
    """
    Immutable representation of an approval request bound to a specific evaluated ToolRequest.
    
    INVARIANTS:
    - Strictly bound to original request via request_id, agent_id, and request_fingerprint.
    - Altering target, parameters, tool, action, category, or destination invalidates approval.
    - Deeply immutable once instantiated.
    """
    model_config = ConfigDict(frozen=True)

    approval_id: str = Field(default_factory=generate_uuid, description="Unique approval request ID")
    request_id: str = Field(..., description="Bound ToolRequest request_id")
    agent: AgentIdentity = Field(..., description="Bound agent identity")
    tool_name: str = Field(..., description="Bound tool name")
    tool_category: ToolCategory = Field(..., description="Bound tool category")
    action: ActionType = Field(..., description="Bound action type")
    target: str = Field(..., description="Bound target resource or identifier")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Bound tool parameters")
    destination: Optional[str] = Field(default=None, description="Bound network/destination endpoint")
    request_fingerprint: str = Field(..., description="Deterministic SHA-256 fingerprint of bound request")
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Calculated risk score at evaluation")
    severity: Severity = Field(..., description="Calculated risk severity")
    decision: SecurityDecisionType = Field(default=SecurityDecisionType.REQUIRE_APPROVAL, description="Originating security decision")
    created_at: datetime = Field(default_factory=utc_now, description="Timestamp when approval request was created")
    expires_at: datetime = Field(..., description="Expiration timestamp for approval request")
    status: ApprovalStatus = Field(default=ApprovalStatus.PENDING, description="Current approval lifecycle state")
    resolution: Optional[ApprovalResolution] = Field(default=None, description="Resolution record if reviewed")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Approval request metadata")

    @field_validator("parameters", "metadata", mode="after")
    @classmethod
    def freeze_dicts(cls, value: Any) -> Any:
        if value is None:
            return FrozenDict()
        return deep_freeze(value)

    @field_validator("created_at", "expires_at", mode="before")
    @classmethod
    def validate_utc_timestamps(cls, value: Any) -> Any:
        if isinstance(value, datetime):
            return ensure_utc(value)
        return value

    def is_expired(self, current_time: Optional[datetime] = None) -> bool:
        """Check if approval request has passed its expiration time."""
        now = ensure_utc(current_time or utc_now())
        return now > self.expires_at

    def can_resolve(self) -> bool:
        """Check if approval is in PENDING state and not expired."""
        return self.status == ApprovalStatus.PENDING and not self.is_expired()
