from enum import Enum
from datetime import datetime
from typing import Dict, Any, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator
from app.security.models import (
    ToolRequest,
    AgentIdentity,
    ToolCategory,
    ActionType,
    SecurityDecisionType,
)
from app.security.gateway.result import SecurityEvaluationResult
from app.security.enforcement.result import EnforcementResult
from app.security.sandbox.contracts import SandboxExecutionResult
from app.security.models.utils import generate_uuid, utc_now, ensure_utc, deep_freeze, FrozenDict

class RuntimeExecutionStatus(str, Enum):
    """Lifecycle status for an agent runtime execution request."""
    SUBMITTED = "SUBMITTED"
    AUTHORIZED = "AUTHORIZED"
    DENIED = "DENIED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"

class RuntimeExecutionContext(BaseModel):
    """
    Optional runtime execution context accompanying an agent action.
    Configured with Pydantic V2 frozen=True and deep immutability.
    """
    model_config = ConfigDict(frozen=True)

    environment: str = Field(default="production", description="Execution environment (e.g. production, staging)")
    session_id: Optional[str] = Field(default=None, description="Correlated runtime session ID")
    user_id: Optional[str] = Field(default=None, description="Originating human user identifier")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary context metadata")

    @field_validator("metadata", mode="after")
    @classmethod
    def freeze_metadata(cls, value: Any) -> Any:
        if value is None:
            return FrozenDict()
        return deep_freeze(value)

class RuntimeExecutionRequest(BaseModel):
    """
    Canonical request representation received by the Agent Runtime Integration layer.
    Configured with Pydantic V2 frozen=True and deep immutability.
    """
    model_config = ConfigDict(frozen=True)

    request_id: str = Field(default_factory=generate_uuid, description="Unique runtime request identifier")
    agent: AgentIdentity = Field(..., description="Agent identity requesting the action")
    tool_name: str = Field(..., description="Target tool name to execute")
    tool_category: ToolCategory = Field(..., description="Category classification of the target tool")
    action: ActionType = Field(..., description="Type of operation requested")
    target: str = Field(..., description="Target resource being acted upon")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Structured tool argument parameters")
    destination: Optional[str] = Field(default=None, description="Optional destination endpoint or path")
    session_id: Optional[str] = Field(default=None, description="Optional session correlation identifier")
    context: Optional[RuntimeExecutionContext] = Field(default=None, description="Runtime execution context")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary JSON-compatible metadata")

    @field_validator("request_id", "tool_name", "target", mode="before")
    @classmethod
    def validate_non_empty_str(cls, value: Any, info) -> Any:
        if isinstance(value, str) and not value.strip():
            raise ValueError(f"Field '{info.field_name}' must not be an empty string")
        return value

    @field_validator("parameters", "metadata", mode="after")
    @classmethod
    def freeze_nested_dict(cls, value: Any) -> Any:
        if value is None:
            return FrozenDict()
        return deep_freeze(value)

    def to_tool_request(self) -> ToolRequest:
        """
        Convert to canonical ToolRequest preserving exact correlation identifiers,
        agent identity, tool name, category, action, target, and parameters.
        """
        return ToolRequest(
            request_id=self.request_id,
            agent=self.agent,
            tool_name=self.tool_name,
            tool_category=self.tool_category,
            action=self.action,
            target=self.target,
            parameters=self.parameters,
            destination=self.destination,
            session_id=self.session_id,
            metadata=self.metadata,
        )

class RuntimeExecutionResult(BaseModel):
    """
    Authoritative, immutable outcome model returned by AgentRuntimeOrchestrator.
    
    INVARIANTS:
    - executed=False, success=False when security decision is BLOCK or REQUIRE_APPROVAL (status=DENIED).
    - executed=True, success=True when sandbox execution completes normally (status=COMPLETED).
    - executed=True, success=False when sandbox execution times out (status=TIMED_OUT).
    - executed=True, success=False when an authorized handler raises an exception (status=FAILED).
    """
    model_config = ConfigDict(frozen=True)

    request_id: str = Field(..., description="Correlated request identifier")
    status: RuntimeExecutionStatus = Field(..., description="Authoritative runtime execution status")
    decision: Optional[SecurityDecisionType] = Field(default=None, description="Phase 4/5 security decision")
    authorized: bool = Field(default=False, description="True if Phase 6 granted execution authorization")
    executed: bool = Field(default=False, description="True if sandbox tool handler was invoked")
    success: bool = Field(default=False, description="True if tool handler executed successfully")
    authorization_id: Optional[str] = Field(default=None, description="ExecutionAuthorization credential ID if authorized")
    evaluation: Optional[SecurityEvaluationResult] = Field(default=None, description="Gateway security evaluation artifacts")
    enforcement: Optional[EnforcementResult] = Field(default=None, description="Enforcement boundary outcome")
    sandbox_result: Optional[SandboxExecutionResult] = Field(default=None, description="Sandbox containment execution outcome")
    result: Optional[Any] = Field(default=None, description="Output returned by the tool handler on success")
    error: Optional[str] = Field(default=None, description="Error or denial reason if execution did not succeed")
    started_at: datetime = Field(default_factory=utc_now, description="Timezone-aware UTC start timestamp")
    completed_at: datetime = Field(default_factory=utc_now, description="Timezone-aware UTC completion timestamp")
    duration_ms: float = Field(default=0.0, description="Total orchestration duration in milliseconds")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary runtime orchestration metadata")

    @field_validator("request_id", mode="before")
    @classmethod
    def validate_non_empty_str(cls, value: Any, info) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Field '{info.field_name}' must not be empty.")
        return value.strip()

    @field_validator("metadata", mode="after")
    @classmethod
    def freeze_metadata(cls, value: Any) -> Any:
        if value is None:
            return FrozenDict()
        return deep_freeze(value)

    @field_validator("started_at", "completed_at", mode="before")
    @classmethod
    def validate_utc_timestamp(cls, value: Any) -> datetime:
        if isinstance(value, datetime):
            return ensure_utc(value)
        return value
