from datetime import datetime
from typing import Dict, Any
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from app.security.models import (
    ToolRequest,
    ThreatReport,
    RiskAssessment,
    SecurityDecision,
)
from app.security.models.utils import utc_now, ensure_utc

class SecurityEvaluationResult(BaseModel):
    """
    Unified, serializable result produced by SecurityDecisionGateway.
    Encapsulates all evaluation artifacts generated during security pipeline execution:
    ToolRequest -> ThreatReport -> RiskAssessment -> SecurityDecision
    Immutable representation configured with Pydantic V2 frozen=True.
    """
    model_config = ConfigDict(frozen=True)

    request: ToolRequest = Field(..., description="The input ToolRequest evaluated")
    threat_report: ThreatReport = Field(..., description="Aggregated ThreatReport from Phase 2 threat detection")
    risk_assessment: RiskAssessment = Field(..., description="Calculated RiskAssessment from Phase 3 Risk Engine")
    decision: SecurityDecision = Field(..., description="Authoritative SecurityDecision from Phase 4 Policy Engine")
    evaluated_at: datetime = Field(default_factory=utc_now, description="Timezone-aware UTC timestamp of gateway evaluation")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Gateway execution metadata")

    @model_validator(mode="after")
    def validate_correlation_ids(self) -> "SecurityEvaluationResult":
        req_id = self.request.request_id
        if self.threat_report.request_id != req_id:
            raise ValueError(
                f"Correlation mismatch: ThreatReport request_id ('{self.threat_report.request_id}') "
                f"!= ToolRequest request_id ('{req_id}')."
            )
        if self.risk_assessment.request_id != req_id:
            raise ValueError(
                f"Correlation mismatch: RiskAssessment request_id ('{self.risk_assessment.request_id}') "
                f"!= ToolRequest request_id ('{req_id}')."
            )
        if self.decision.request_id != req_id:
            raise ValueError(
                f"Correlation mismatch: SecurityDecision request_id ('{self.decision.request_id}') "
                f"!= ToolRequest request_id ('{req_id}')."
            )
        return self

    @field_validator("evaluated_at", mode="before")
    @classmethod
    def validate_utc_timestamp(cls, value: Any) -> Any:
        if isinstance(value, datetime):
            return ensure_utc(value)
        return value
