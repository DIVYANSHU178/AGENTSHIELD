from datetime import datetime
from typing import Dict, Any, List
from pydantic import BaseModel, ConfigDict, Field, field_validator
from app.security.models.enums import Severity
from app.security.models.utils import generate_uuid, utc_now, ensure_utc

class RiskAssessment(BaseModel):
    """
    Evaluated risk assessment for a ToolRequest based on detected signals.
    Immutable representation configured with Pydantic V2 frozen=True.
    """
    model_config = ConfigDict(frozen=True)

    assessment_id: str = Field(default_factory=generate_uuid, description="Unique assessment identifier")
    request_id: str = Field(..., description="Correlated ToolRequest identifier")
    risk_score: float = Field(..., description="Calculated numeric risk score bounded between 0.0 and 100.0")
    severity: Severity = Field(..., description="Assigned risk severity level")
    contributing_signals: List[str] = Field(default_factory=list, description="IDs of signals contributing to risk score")
    rationale: str = Field(default="", description="Explanatory text for the calculated score")
    assessed_at: datetime = Field(default_factory=utc_now, description="Timezone-aware UTC timestamp of assessment")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary assessment metadata")

    @field_validator("risk_score")
    @classmethod
    def validate_risk_score_range(cls, value: float) -> float:
        if not (0.0 <= value <= 100.0):
            raise ValueError(f"Risk score must be bounded between 0.0 and 100.0 inclusive, got {value}")
        return value

    @field_validator("assessment_id", "request_id", mode="before")
    @classmethod
    def validate_non_empty_str(cls, value: Any, info) -> Any:
        if isinstance(value, str) and not value.strip():
            raise ValueError(f"Field '{info.field_name}' must not be an empty string")
        return value

    @field_validator("assessed_at", mode="before")
    @classmethod
    def validate_utc_timestamp(cls, value: Any) -> Any:
        if isinstance(value, datetime):
            return ensure_utc(value)
        return value
