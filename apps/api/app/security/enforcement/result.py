from datetime import datetime
from typing import Dict, Any, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from app.security.models import SecurityDecisionType
from app.security.models.utils import utc_now, ensure_utc, deep_freeze, FrozenDict
from app.security.enforcement.authorization import ExecutionAuthorization

class EnforcementResult(BaseModel):
    """
    Serializable, immutable result model produced by SecurityEnforcementBoundary.
    Exposes explicit authorization status (authorized=True/False) and optional ExecutionAuthorization credential.
    
    INVARIANTS ENFORCED:
    - BLOCK decision -> authorized MUST be False, authorization MUST be None.
    - REQUIRE_APPROVAL decision -> authorized MUST be False, authorization MUST be None.
    - ALLOW decision -> authorized MAY be True if valid ExecutionAuthorization is provided.
    """
    model_config = ConfigDict(frozen=True)

    request_id: str = Field(..., description="Correlated ToolRequest identifier")
    correlation_id: str = Field(..., description="Correlation identifier matching input security context")
    decision: SecurityDecisionType = Field(..., description="Authoritative SecurityDecisionType from Phase 5 gateway")
    authorized: bool = Field(..., description="Explicit boolean indicator: True if execution authorization granted, False otherwise")
    authorization: Optional[ExecutionAuthorization] = Field(default=None, description="ExecutionAuthorization capability token if authorized=True")
    reason: str = Field(..., description="Human-readable justification of enforcement determination")
    evaluated_at: datetime = Field(default_factory=utc_now, description="Timezone-aware UTC timestamp of enforcement evaluation")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary enforcement metadata")

    @model_validator(mode="after")
    def validate_enforcement_invariants(self) -> "EnforcementResult":
        if self.decision != SecurityDecisionType.ALLOW:
            if self.authorized:
                raise ValueError(f"EnforcementResult invariant violation: Decision '{self.decision.value}' CANNOT be authorized=True.")
            if self.authorization is not None:
                raise ValueError(f"EnforcementResult invariant violation: Decision '{self.decision.value}' CANNOT contain an authorization object.")

        if self.authorized:
            if self.authorization is None:
                raise ValueError("EnforcementResult invariant violation: authorized=True requires a non-null ExecutionAuthorization object.")
            if self.authorization.decision != SecurityDecisionType.ALLOW:
                raise ValueError(f"EnforcementResult invariant violation: ExecutionAuthorization has invalid decision '{self.authorization.decision.value}'.")
            if self.authorization.request_id != self.request_id:
                raise ValueError("EnforcementResult invariant violation: ExecutionAuthorization request_id mismatch.")

        return self

    @field_validator("request_id", "correlation_id", "reason", mode="before")
    @classmethod
    def validate_non_empty_str(cls, value: Any, info) -> Any:
        if isinstance(value, str) and not value.strip():
            raise ValueError(f"Field '{info.field_name}' must not be an empty string")
        return value

    @field_validator("metadata", mode="after")
    @classmethod
    def freeze_metadata(cls, value: Any) -> Any:
        if value is None:
            return FrozenDict()
        return deep_freeze(value)

    @field_validator("evaluated_at", mode="before")
    @classmethod
    def validate_utc_timestamp(cls, value: Any) -> Any:
        if isinstance(value, datetime):
            return ensure_utc(value)
        return value
