from enum import Enum
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from app.security.models import (
    SecurityDecisionType,
    Severity,
    AgentIdentity,
    ToolCategory,
    ActionType,
)
from app.security.runtime.contracts import RuntimeExecutionStatus
from app.security.approval.contracts import ApprovalStatus
from app.security.models.utils import generate_uuid, deep_freeze, FrozenDict



class ScenarioCategory(str, Enum):
    """Categorization for security scenario and attack laboratory test cases."""
    BASELINE = "BASELINE"
    APPROVAL_LIFECYCLE = "APPROVAL_LIFECYCLE"
    ANTI_TAMPER = "ANTI_TAMPER"
    FAILURE_ABUSE = "FAILURE_ABUSE"

class ScenarioDefinition(BaseModel):
    """
    Immutable metadata definition of an authoritative laboratory scenario.
    """
    model_config = ConfigDict(frozen=True)

    scenario_id: str = Field(..., description="Unique scenario identifier (e.g. ALLOW_CLEAN)")
    name: str = Field(..., description="Human-readable scenario title")
    description: str = Field(..., description="Operational explanation of what this scenario tests")
    category: ScenarioCategory = Field(..., description="Laboratory test classification")
    expected_decision: SecurityDecisionType = Field(..., description="Expected Policy Engine security decision")
    expected_status: RuntimeExecutionStatus = Field(..., description="Expected Runtime Execution lifecycle status")
    expected_executed: bool = Field(..., description="Whether tool handler execution is expected")
    requires_approval: bool = Field(default=False, description="Whether this scenario triggers an approval workflow")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Static scenario metadata")

    @field_validator("metadata", mode="after")
    @classmethod
    def freeze_metadata(cls, value: Any) -> Any:
        if value is None:
            return FrozenDict()
        return deep_freeze(value)

class ScenarioRunRequest(BaseModel):
    """Request payload to execute a specific laboratory scenario."""
    scenario_id: str = Field(..., description="Scenario identifier to execute")
    request_id: Optional[str] = Field(default=None, description="Optional custom correlation request ID")

    @field_validator("scenario_id", "request_id", mode="before")
    @classmethod
    def validate_non_empty_str(cls, value: Any, info) -> Any:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError(f"Field '{info.field_name}' must be a string.")
        stripped = value.strip()
        if not stripped and info.field_name == "scenario_id":
            raise ValueError("Field 'scenario_id' must not be empty or whitespace-only.")
        return stripped or None

class ScenarioResult(BaseModel):
    """
    Structured outcome of a Scenario Laboratory run.
    Distinguishes expected vs actual behavior with strict secret redaction.
    """
    model_config = ConfigDict(frozen=True)

    scenario_id: str = Field(..., description="Executed scenario ID")
    scenario_name: str = Field(..., description="Human-readable scenario name")
    category: ScenarioCategory = Field(..., description="Scenario classification")
    request_id: str = Field(..., description="Correlated request ID")
    
    # Expected vs Actual Policy Decision
    expected_decision: SecurityDecisionType = Field(..., description="Expected security decision")
    actual_decision: SecurityDecisionType = Field(..., description="Actual observed security decision")
    
    # Expected vs Actual Runtime Lifecycle Status
    expected_status: RuntimeExecutionStatus = Field(..., description="Expected execution status")
    actual_status: RuntimeExecutionStatus = Field(..., description="Actual observed execution status")
    
    # Expected vs Actual Tool Execution Flag
    expected_executed: bool = Field(..., description="Expected tool execution flag")
    actual_executed: bool = Field(..., description="Actual observed tool execution flag")
    
    # Approval lifecycle tracking
    expected_approval_status: Optional[ApprovalStatus] = Field(default=None, description="Expected approval state if applicable")
    actual_approval_status: Optional[ApprovalStatus] = Field(default=None, description="Actual observed approval state if applicable")
    approval_id: Optional[str] = Field(default=None, description="Generated approval ID if created")
    
    # Overall Verification Outcome
    passed: bool = Field(..., description="Whether actual outcomes match all authoritative expectations")
    message: str = Field(..., description="Explanation of verification outcome or mismatch details")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Safe, sanitized result details")

    @field_validator("metadata", mode="after")
    @classmethod
    def sanitize_and_freeze_metadata(cls, value: Any) -> Any:
        if value is None:
            return FrozenDict()
        from app.security.audit.redaction import sanitize_audit_payload
        sanitized = sanitize_audit_payload(value)
        return deep_freeze(sanitized)

    @model_validator(mode="after")
    def validate_passed_invariants(self) -> "ScenarioResult":
        """Ensure that passed=True is structurally impossible if expected and actual authoritative fields mismatch."""
        if self.passed:
            if self.expected_decision != self.actual_decision:
                raise ValueError(
                    f"ScenarioResult cannot have passed=True when expected_decision ({self.expected_decision}) "
                    f"!= actual_decision ({self.actual_decision})."
                )
            if self.expected_status != self.actual_status:
                raise ValueError(
                    f"ScenarioResult cannot have passed=True when expected_status ({self.expected_status}) "
                    f"!= actual_status ({self.actual_status})."
                )
            if self.expected_executed != self.actual_executed:
                raise ValueError(
                    f"ScenarioResult cannot have passed=True when expected_executed ({self.expected_executed}) "
                    f"!= actual_executed ({self.actual_executed})."
                )
            if self.expected_approval_status is not None and self.actual_approval_status != self.expected_approval_status:
                raise ValueError(
                    f"ScenarioResult cannot have passed=True when expected_approval_status ({self.expected_approval_status}) "
                    f"!= actual_approval_status ({self.actual_approval_status})."
                )
        return self
