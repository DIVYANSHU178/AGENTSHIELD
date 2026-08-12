from datetime import datetime
from typing import Dict, Any, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator
from app.security.models.enums import SecurityDecisionType
from app.security.models.utils import generate_uuid, utc_now, ensure_utc

class SecurityDecision(BaseModel):
    """
    Final security decision rendered by AgentShield policy boundary for a ToolRequest.
    Immutable representation configured with Pydantic V2 frozen=True.
    """
    model_config = ConfigDict(frozen=True)

    decision_id: str = Field(default_factory=generate_uuid, description="Unique decision identifier")
    request_id: str = Field(..., description="Correlated ToolRequest identifier")
    decision: SecurityDecisionType = Field(..., description="Action determination (ALLOW, BLOCK, REQUIRE_APPROVAL)")
    risk_assessment_id: Optional[str] = Field(default=None, description="Optional correlated RiskAssessment identifier")
    reason: str = Field(..., description="Human-readable justification for the decision")
    decided_at: datetime = Field(default_factory=utc_now, description="Timezone-aware UTC timestamp of decision")
    policy_id: Optional[str] = Field(default=None, description="Optional governing policy identifier")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary decision metadata")

    @field_validator("decision_id", "request_id", "reason", mode="before")
    @classmethod
    def validate_non_empty_str(cls, value: Any, info) -> Any:
        if isinstance(value, str) and not value.strip():
            raise ValueError(f"Field '{info.field_name}' must not be an empty string")
        return value

    @field_validator("decided_at", mode="before")
    @classmethod
    def validate_utc_timestamp(cls, value: Any) -> Any:
        if isinstance(value, datetime):
            return ensure_utc(value)
        return value
