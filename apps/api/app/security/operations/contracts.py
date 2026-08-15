from datetime import datetime
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator
from app.security.models import (
    ToolCategory,
    ActionType,
    ThreatType,
    Severity,
    SecurityDecisionType,
    EventType,
    SecurityEvent,
)
from app.security.runtime.contracts import RuntimeExecutionStatus
from app.security.models.utils import utc_now, ensure_utc, deep_freeze, FrozenDict

class ComponentStatus(str, Enum):
    """Component health operational status."""
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"

class ComponentHealth(BaseModel):
    """Health inspection record for an individual AgentShield security component."""
    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="Component identifier/name")
    status: ComponentStatus = Field(..., description="Operational status")
    details: str = Field(..., description="Status summary or diagnostic message")
    checked_at: datetime = Field(default_factory=utc_now, description="Timestamp of health check")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Component-specific health metadata")

    @field_validator("name", "details", mode="before")
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

    @field_validator("checked_at", mode="before")
    @classmethod
    def validate_utc_timestamp(cls, value: Any) -> Any:
        if isinstance(value, datetime):
            return ensure_utc(value)
        return value

class OverallSystemHealth(BaseModel):
    """Aggregated operational health for the entire AgentShield security pipeline."""
    model_config = ConfigDict(frozen=True)

    status: ComponentStatus = Field(..., description="Overall system operational status")
    components: List[ComponentHealth] = Field(default_factory=list, description="Health records for individual components")
    checked_at: datetime = Field(default_factory=utc_now, description="Timestamp of system health check")
    version: str = Field(default="0.1.0", description="AgentShield security engine version")
    summary: Optional[str] = Field(default=None, description="Human-readable health summary")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="System health metadata")

    @field_validator("metadata", mode="after")
    @classmethod
    def freeze_metadata(cls, value: Any) -> Any:
        if value is None:
            return FrozenDict()
        return deep_freeze(value)

    @field_validator("checked_at", mode="before")
    @classmethod
    def validate_utc_timestamp(cls, value: Any) -> Any:
        if isinstance(value, datetime):
            return ensure_utc(value)
        return value

class SecurityMetrics(BaseModel):
    """Deterministic operational metrics derived from in-memory security runtime and audit state."""
    model_config = ConfigDict(frozen=True)

    total_requests: int = Field(default=0, ge=0, description="Total tool requests evaluated")
    allowed: int = Field(default=0, ge=0, description="Total ALLOW decisions rendered")
    require_approval: int = Field(default=0, ge=0, description="Total REQUIRE_APPROVAL decisions rendered")
    blocked: int = Field(default=0, ge=0, description="Total BLOCK decisions rendered")
    authorized: int = Field(default=0, ge=0, description="Total authorization capability credentials issued")
    denied_execution: int = Field(default=0, ge=0, description="Total requests denied execution")
    successful_execution: int = Field(default=0, ge=0, description="Total sandbox executions completed successfully")
    failed_execution: int = Field(default=0, ge=0, description="Total sandbox executions failed")
    timed_out_execution: int = Field(default=0, ge=0, description="Total sandbox executions timed out")
    detected_threats: int = Field(default=0, ge=0, description="Total threat signals detected")
    critical_risk_requests: int = Field(default=0, ge=0, description="Total requests with CRITICAL risk")
    high_risk_requests: int = Field(default=0, ge=0, description="Total requests with HIGH risk")
    medium_risk_requests: int = Field(default=0, ge=0, description="Total requests with MEDIUM risk")
    audit_events: int = Field(default=0, ge=0, description="Total audit events recorded in audit trail")
    runtime_requests: int = Field(default=0, ge=0, description="Total runtime orchestration requests processed")
    runtime_failures: int = Field(default=0, ge=0, description="Total runtime orchestration failures")
    calculated_at: datetime = Field(default_factory=utc_now, description="Timestamp when metrics were computed")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metrics metadata")

    @field_validator("metadata", mode="after")
    @classmethod
    def freeze_metadata(cls, value: Any) -> Any:
        if value is None:
            return FrozenDict()
        return deep_freeze(value)

    @field_validator("calculated_at", mode="before")
    @classmethod
    def validate_utc_timestamp(cls, value: Any) -> Any:
        if isinstance(value, datetime):
            return ensure_utc(value)
        return value

class ThreatActivityItem(BaseModel):
    """Safe, redacted threat signal item for the Security Operations Console."""
    model_config = ConfigDict(frozen=True)

    threat_id: str = Field(..., description="Unique threat signal identifier")
    threat_type: ThreatType = Field(..., description="Categorized threat type")
    severity: Severity = Field(..., description="Threat severity level")
    detector: str = Field(..., description="Detector module name or source")
    request_id: str = Field(..., description="Correlated ToolRequest identifier")
    title: str = Field(..., description="Safe human-readable title")
    description: str = Field(..., description="Safe human-readable description")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score 0.0 to 1.0")
    timestamp: datetime = Field(default_factory=utc_now, description="Timestamp of threat detection")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Safe redacted threat metadata")

    @field_validator("threat_id", "detector", "request_id", "title", mode="before")
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

    @field_validator("timestamp", mode="before")
    @classmethod
    def validate_utc_timestamp(cls, value: Any) -> Any:
        if isinstance(value, datetime):
            return ensure_utc(value)
        return value

class SecurityDecisionItem(BaseModel):
    """Safe security policy decision item for the Security Operations Console."""
    model_config = ConfigDict(frozen=True)

    decision_id: str = Field(..., description="Unique security decision identifier")
    request_id: str = Field(..., description="Correlated ToolRequest identifier")
    decision: SecurityDecisionType = Field(..., description="Rendered security decision")
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Risk engine numerical score")
    severity: Severity = Field(..., description="Calculated risk severity")
    policy_id: Optional[str] = Field(default=None, description="Matched governing policy ID")
    reason: str = Field(..., description="Human-readable decision explanation")
    threat_count: int = Field(default=0, ge=0, description="Number of contributing threat signals")
    timestamp: datetime = Field(default_factory=utc_now, description="Timestamp of policy decision")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Safe decision metadata")

    @field_validator("decision_id", "request_id", "reason", mode="before")
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

    @field_validator("timestamp", mode="before")
    @classmethod
    def validate_utc_timestamp(cls, value: Any) -> Any:
        if isinstance(value, datetime):
            return ensure_utc(value)
        return value

class ExecutionActivityItem(BaseModel):
    """Safe execution outcome item for the Security Operations Console."""
    model_config = ConfigDict(frozen=True)

    execution_id: str = Field(..., description="Unique execution outcome identifier")
    request_id: str = Field(..., description="Correlated ToolRequest identifier")
    tool_name: str = Field(..., description="Name of executed/targeted tool")
    tool_category: ToolCategory = Field(..., description="Category of executed tool")
    action: ActionType = Field(..., description="Action requested on tool")
    status: RuntimeExecutionStatus = Field(..., description="Execution status")
    success: bool = Field(..., description="Whether execution was successful")
    duration_ms: float = Field(default=0.0, ge=0.0, description="Execution duration in milliseconds")
    error: Optional[str] = Field(default=None, description="Safe error message if execution failed")
    timestamp: datetime = Field(default_factory=utc_now, description="Timestamp of execution")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Safe execution metadata")

    @field_validator("execution_id", "request_id", "tool_name", mode="before")
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

    @field_validator("timestamp", mode="before")
    @classmethod
    def validate_utc_timestamp(cls, value: Any) -> Any:
        if isinstance(value, datetime):
            return ensure_utc(value)
        return value

class OperationsOverview(BaseModel):
    """Unified operational snapshot for the Security Operations Console dashboard."""
    model_config = ConfigDict(frozen=True)

    overall_health: OverallSystemHealth = Field(..., description="System and component health status")
    metrics: SecurityMetrics = Field(..., description="Real-time security metrics")
    recent_threats: List[ThreatActivityItem] = Field(default_factory=list, description="Recent detected threats")
    recent_decisions: List[SecurityDecisionItem] = Field(default_factory=list, description="Recent security decisions")
    recent_executions: List[ExecutionActivityItem] = Field(default_factory=list, description="Recent tool execution outcomes")
    generated_at: datetime = Field(default_factory=utc_now, description="Timestamp when overview was constructed")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Overview metadata")

    @field_validator("metadata", mode="after")
    @classmethod
    def freeze_metadata(cls, value: Any) -> Any:
        if value is None:
            return FrozenDict()
        return deep_freeze(value)

    @field_validator("generated_at", mode="before")
    @classmethod
    def validate_utc_timestamp(cls, value: Any) -> Any:
        if isinstance(value, datetime):
            return ensure_utc(value)
        return value

class OperationsControlAction(str, Enum):
    """Permitted read-only operational control actions for Phase 10."""
    READ_STATUS = "READ_STATUS"
    READ_HEALTH = "READ_HEALTH"
    READ_METRICS = "READ_METRICS"
    READ_THREATS = "READ_THREATS"
    READ_DECISIONS = "READ_DECISIONS"
    READ_EXECUTIONS = "READ_EXECUTIONS"
    READ_AUDIT = "READ_AUDIT"

class OperationsControlRequest(BaseModel):
    """Safe operational control query request."""
    model_config = ConfigDict(frozen=True)

    action: OperationsControlAction = Field(..., description="Requested operational control action")
    target: Optional[str] = Field(default=None, description="Optional target identifier (e.g. request_id)")
    limit: Optional[int] = Field(default=50, ge=1, le=200, description="Maximum items to return")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Query parameters")

    @field_validator("parameters", mode="after")
    @classmethod
    def freeze_parameters(cls, value: Any) -> Any:
        if value is None:
            return FrozenDict()
        return deep_freeze(value)

class OperationsControlResponse(BaseModel):
    """Safe operational control query response."""
    model_config = ConfigDict(frozen=True)

    action: OperationsControlAction = Field(..., description="Executed operational control action")
    success: bool = Field(..., description="Whether query was successful")
    data: Any = Field(default=None, description="Returned operational payload")
    executed_at: datetime = Field(default_factory=utc_now, description="Timestamp of execution")
    message: str = Field(default="Operation completed successfully", description="Status message")
