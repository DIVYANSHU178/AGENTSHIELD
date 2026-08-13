from typing import Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator
from app.security.models import ToolRequest, ThreatReport, RiskAssessment

class PolicyContext(BaseModel):
    """
    Immutable security context required for PolicyEngine evaluation.
    Encapsulates the ToolRequest, RiskAssessment, and optional ThreatReport.
    Configured with Pydantic V2 frozen=True to guarantee immutability.
    """
    model_config = ConfigDict(frozen=True)

    request: ToolRequest = Field(..., description="Target ToolRequest being evaluated")
    risk_assessment: RiskAssessment = Field(..., description="Calculated RiskAssessment from RiskEngine")
    threat_report: Optional[ThreatReport] = Field(default=None, description="Optional aggregated ThreatReport")

    @model_validator(mode="after")
    def validate_correlation_and_presence(self) -> "PolicyContext":
        if self.request is None:
            raise ValueError("PolicyContext requires a non-null ToolRequest.")
        if self.risk_assessment is None:
            raise ValueError("PolicyContext requires a non-null RiskAssessment.")

        req_id = self.request.request_id
        if self.risk_assessment.request_id != req_id:
            raise ValueError(
                f"Correlation mismatch: RiskAssessment request_id ('{self.risk_assessment.request_id}') "
                f"does not match ToolRequest request_id ('{req_id}')."
            )

        if self.threat_report is not None and self.threat_report.request_id != req_id:
            raise ValueError(
                f"Correlation mismatch: ThreatReport request_id ('{self.threat_report.request_id}') "
                f"does not match ToolRequest request_id ('{req_id}')."
            )

        return self
