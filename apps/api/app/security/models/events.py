from datetime import datetime
from typing import Dict, Any
from pydantic import BaseModel, ConfigDict, Field, field_validator
from app.security.models.enums import EventType
from app.security.models.utils import generate_uuid, utc_now, ensure_utc

class SecurityEvent(BaseModel):
    """
    Audit log record capturing lifecycle activity within the security boundary.
    Immutable representation configured with Pydantic V2 frozen=True.
    """
    model_config = ConfigDict(frozen=True)

    event_id: str = Field(default_factory=generate_uuid, description="Unique audit event identifier")
    request_id: str = Field(..., description="Correlated ToolRequest identifier")
    event_type: EventType = Field(..., description="Type of event recorded in lifecycle")
    timestamp: datetime = Field(default_factory=utc_now, description="Timezone-aware UTC timestamp of event")
    actor: str = Field(..., description="System component or entity generating event (e.g. security_engine)")
    details: Dict[str, Any] = Field(default_factory=dict, description="Structured event detail payload")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary event metadata")

    @field_validator("event_id", "request_id", "actor", mode="before")
    @classmethod
    def validate_non_empty_str(cls, value: Any, info) -> Any:
        if isinstance(value, str) and not value.strip():
            raise ValueError(f"Field '{info.field_name}' must not be an empty string")
        return value

    @field_validator("timestamp", mode="before")
    @classmethod
    def validate_utc_timestamp(cls, value: Any) -> Any:
        if isinstance(value, datetime):
            return ensure_utc(value)
        return value
