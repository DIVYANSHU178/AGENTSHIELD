import copy
import math
from enum import Enum
from datetime import datetime
from typing import Dict, Any, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator
from app.security.models import ToolRequest
from app.security.enforcement import ExecutionAuthorization
from app.security.models.utils import utc_now, ensure_utc, deep_freeze, FrozenDict

class SandboxStatus(str, Enum):
    """Execution status returned by the sandbox execution boundary."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    TIMED_OUT = "TIMED_OUT"
    DENIED = "DENIED"
    FAILED = "FAILED"

class SandboxExecutionLimits(BaseModel):
    """
    Strongly typed execution limits for sandboxed execution.
    Configured with Pydantic V2 frozen=True.

    CONTRACT CONSTRAINTS:
    - timeout_seconds: strictly positive finite float between 0.01s (min) and 300.0s (max).
    - rejects NaN, Infinity, non-numeric, 0, negative values, and out-of-bound floats.
    """
    model_config = ConfigDict(frozen=True)

    timeout_seconds: float = Field(default=5.0, ge=0.01, le=300.0, description="Maximum allowed execution duration in seconds")
    max_memory_mb: Optional[int] = Field(default=None, ge=1, le=4096, description="Memory ceiling limit in megabytes")
    allow_network: bool = Field(default=False, description="Strict network restriction flag")
    allow_filesystem: bool = Field(default=False, description="Strict filesystem access restriction flag")
    environment_clean: bool = Field(default=True, description="Strict secret and environment variable isolation flag")

    @field_validator("timeout_seconds", mode="before")
    @classmethod
    def validate_timeout_finite(cls, value: Any) -> float:
        if value is None:
            raise ValueError("timeout_seconds cannot be None.")
        try:
            val_float = float(value)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"timeout_seconds must be a valid numeric float: {value}") from exc

        if math.isnan(val_float) or math.isinf(val_float):
            raise ValueError("timeout_seconds cannot be NaN or Infinity.")
        if val_float <= 0:
            raise ValueError("timeout_seconds must be strictly positive.")
        return val_float

class SandboxExecutionPolicy(BaseModel):
    """
    Policy specification governing sandbox containment and resource limits.
    """
    model_config = ConfigDict(frozen=True)

    policy_id: str = Field(default="sandbox.default", description="Unique sandbox policy identifier")
    limits: SandboxExecutionLimits = Field(default_factory=SandboxExecutionLimits, description="Configured resource and execution limits")
    isolation_level: str = Field(default="logical_in_process", description="Containment boundary level (e.g. logical_in_process)")
    description: str = Field(default="Default deterministic sandbox execution policy", description="Policy narrative description")

    @field_validator("policy_id", mode="before")
    @classmethod
    def validate_policy_id(cls, value: Any) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("policy_id must not be empty.")
        return value.strip()

class SandboxExecutionRequest(BaseModel):
    """
    Immutable request payload passed to SandboxExecutionBoundary.
    """
    model_config = ConfigDict(frozen=True)

    request: ToolRequest = Field(..., description="Correlated ToolRequest")
    authorization: ExecutionAuthorization = Field(..., description="Phase 6 HMAC-signed ExecutionAuthorization token")
    policy: SandboxExecutionPolicy = Field(default_factory=SandboxExecutionPolicy, description="Active sandbox policy")

class SandboxExecutionResult(BaseModel):
    """
    Immutable, serializable outcome model produced by SandboxExecutionBoundary.

    INVARIANTS ENFORCED:
    - executed=False when authorization is invalid, category mismatches, or is denied (status=DENIED).
    - executed=True, success=True when execution completes within limits (status=COMPLETED).
    - executed=True, success=False, timed_out=True when execution exceeds timeout limit (status=TIMED_OUT).
    - executed=True, success=False when an authorized handler throws an exception (status=FAILED).
    """
    model_config = ConfigDict(frozen=True)

    request_id: str = Field(..., description="Correlated ToolRequest identifier")
    tool_name: str = Field(..., description="Executed tool name")
    status: SandboxStatus = Field(..., description="Authoritative sandbox outcome status")
    executed: bool = Field(..., description="True if handler execution was actually attempted")
    success: bool = Field(..., description="True if handler completed successfully within limits")
    sandboxed: bool = Field(default=True, description="True indicating execution was governed by Sandbox boundary")
    timed_out: bool = Field(default=False, description="True if execution was aborted due to timeout")
    authorization_id: Optional[str] = Field(default=None, description="ExecutionAuthorization credential ID if authorized")
    started_at: datetime = Field(default_factory=utc_now, description="Timezone-aware UTC timestamp of execution start")
    completed_at: datetime = Field(default_factory=utc_now, description="Timezone-aware UTC timestamp of execution completion")
    duration_ms: float = Field(default=0.0, description="Total execution duration in milliseconds")
    result: Optional[Any] = Field(default=None, description="Output returned by the tool handler on success")
    error: Optional[str] = Field(default=None, description="Error message if execution failed, timed out, or was denied")
    sandbox_policy_id: str = Field(default="sandbox.default", description="ID of sandbox policy applied")
    containment_metadata: Dict[str, Any] = Field(default_factory=dict, description="Safe containment and operational metadata")

    @field_validator("request_id", "tool_name", mode="before")
    @classmethod
    def validate_non_empty_str(cls, value: Any, info) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Field '{info.field_name}' must not be empty.")
        return value.strip()

    @field_validator("containment_metadata", mode="after")
    @classmethod
    def freeze_containment_metadata(cls, value: Any) -> Any:
        if value is None:
            return FrozenDict()
        return deep_freeze(value)

    @field_validator("started_at", "completed_at", mode="before")
    @classmethod
    def validate_utc_timestamp(cls, value: Any) -> datetime:
        if isinstance(value, datetime):
            return ensure_utc(value)
        return value
