from datetime import datetime
from typing import Dict, Any, List
from pydantic import BaseModel, ConfigDict, Field, field_validator
from app.security.models.enums import ThreatType, Severity
from app.security.models.utils import generate_uuid, utc_now, ensure_utc, deep_freeze, FrozenDict

class ThreatSignal(BaseModel):
    """
    Represents an individual security signal detected during input/tool inspection.
    Deeply immutable representation configured with Pydantic V2 frozen=True.
    """
    model_config = ConfigDict(frozen=True)

    signal_id: str = Field(default_factory=generate_uuid, description="Unique signal identifier")
    threat_type: ThreatType = Field(..., description="Classification of detected threat")
    severity: Severity = Field(..., description="Assigned severity level")
    title: str = Field(..., description="Short summary title of the threat signal")
    description: str = Field(..., description="Detailed description of findings")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Structured evidence payload")
    confidence: float = Field(..., description="Confidence score normalized between 0.0 and 1.0")
    source: str = Field(default="detector", description="Identifier of the producing detector/component")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary signal metadata")

    @field_validator("confidence")
    @classmethod
    def validate_confidence_range(cls, value: float) -> float:
        if not (0.0 <= value <= 1.0):
            raise ValueError(f"Confidence score must be normalized between 0.0 and 1.0 inclusive, got {value}")
        return value

    @field_validator("signal_id", "title", mode="before")
    @classmethod
    def validate_non_empty_str(cls, value: Any, info) -> Any:
        if isinstance(value, str) and not value.strip():
            raise ValueError(f"Field '{info.field_name}' must not be an empty string")
        return value

    @field_validator("evidence", "metadata", mode="after")
    @classmethod
    def freeze_dict(cls, value: Any) -> Any:
        if value is None:
            return FrozenDict()
        return deep_freeze(value)


class ThreatReport(BaseModel):
    """
    Aggregated threat detection findings produced for a specific ToolRequest.
    Deeply immutable representation configured with Pydantic V2 frozen=True.
    """
    model_config = ConfigDict(frozen=True)

    report_id: str = Field(default_factory=generate_uuid, description="Unique report identifier")
    request_id: str = Field(..., description="Correlated ToolRequest identifier")
    signals: List[ThreatSignal] = Field(default_factory=list, description="List of detected threat signals")
    overall_severity: Severity = Field(default=Severity.INFO, description="Overall evaluated threat severity")
    summary: str = Field(default="", description="High-level narrative summary")
    analyzed_at: datetime = Field(default_factory=utc_now, description="Timezone-aware UTC timestamp of analysis")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary report metadata")

    @field_validator("report_id", "request_id", mode="before")
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

    @field_validator("analyzed_at", mode="before")
    @classmethod
    def validate_utc_timestamp(cls, value: Any) -> Any:
        if isinstance(value, datetime):
            return ensure_utc(value)
        return value
