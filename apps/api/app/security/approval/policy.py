from datetime import datetime, timedelta
from typing import Optional, Any, Dict
from pydantic import BaseModel, ConfigDict, Field, field_validator
from app.security.models import SecurityDecisionType
from app.security.gateway import SecurityEvaluationResult
from app.security.approval.errors import ApprovalPolicyViolationError
from app.security.models.utils import utc_now, ensure_utc, deep_freeze, FrozenDict

class ApprovalPolicy(BaseModel):
    """Configuration policy governing approval request creation, TTL, and review requirements."""
    model_config = ConfigDict(frozen=True)

    policy_id: str = Field(default="approval.policy.default", description="Unique approval policy ID")
    default_ttl_seconds: float = Field(default=3600.0, ge=1.0, description="Default time-to-live in seconds (1 hour)")
    max_ttl_seconds: float = Field(default=86400.0, ge=1.0, description="Maximum permitted TTL in seconds (24 hours)")
    allow_cancellation: bool = Field(default=True, description="Whether requester can cancel a pending approval")
    require_reviewer_reason: bool = Field(default=True, description="Whether reviewer must supply a non-empty reason")
    auto_expire_on_read: bool = Field(default=True, description="Whether service dynamically expires past-due items on access")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional policy metadata")

    @field_validator("metadata", mode="after")
    @classmethod
    def freeze_metadata(cls, value: Any) -> Any:
        if value is None:
            return FrozenDict()
        return deep_freeze(value)

class ApprovalPolicyEngine:
    """
    Evaluates policy rules for the creation and lifetime of approval requests.
    Enforces that approvals can strictly ONLY be created for REQUIRE_APPROVAL decisions.
    """

    def __init__(self, policy: Optional[ApprovalPolicy] = None) -> None:
        self._policy = policy or ApprovalPolicy()

    @property
    def policy(self) -> ApprovalPolicy:
        return self._policy

    def validate_can_create_approval(self, eval_result: SecurityEvaluationResult) -> None:
        """
        Verify that a SecurityEvaluationResult qualifies for approval workflow creation.
        ALLOW and BLOCK decisions must NEVER create approval requests.
        """
        if eval_result is None or eval_result.decision is None:
            raise ApprovalPolicyViolationError("Cannot create approval for null or malformed SecurityEvaluationResult.")

        decision = eval_result.decision.decision
        if decision != SecurityDecisionType.REQUIRE_APPROVAL:
            raise ApprovalPolicyViolationError(
                f"Approval requests can ONLY be created for REQUIRE_APPROVAL decisions; "
                f"cannot create approval for '{decision.value}' decision."
            )

    def calculate_expiration(
        self,
        created_at: datetime,
        ttl_seconds: Optional[float] = None,
    ) -> datetime:
        """Calculate UTC expiration timestamp bounded by policy maximums."""
        base_time = ensure_utc(created_at)
        ttl = ttl_seconds if ttl_seconds is not None else self._policy.default_ttl_seconds
        ttl = max(1.0, min(ttl, self._policy.max_ttl_seconds))
        return base_time + timedelta(seconds=ttl)
