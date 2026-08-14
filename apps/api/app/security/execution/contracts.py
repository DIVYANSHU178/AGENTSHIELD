import copy
from datetime import datetime
from typing import Dict, Any, Optional, Set, Callable, FrozenSet, Iterable
from pydantic import BaseModel, ConfigDict, Field, field_validator
from app.security.models import ToolCategory, ActionType, ToolRequest
from app.security.models.utils import utc_now, ensure_utc, deep_freeze, FrozenDict

class ToolExecutionContract(BaseModel):
    """
    Strongly typed contract for an explicitly registered, safe demonstration tool handler.
    Deeply immutable representation configured with Pydantic V2 frozen=True and frozenset actions.
    """
    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    tool_name: str = Field(..., description="Unique registered tool identifier (e.g. calculator.compute)")
    tool_category: ToolCategory = Field(..., description="Security classification category")
    supported_actions: frozenset[ActionType] = Field(..., description="Immutable set of allowed ActionTypes for this tool")
    description: str = Field(default="", description="Human-readable tool description")
    handler: Callable[[ToolRequest], Any] = Field(..., description="Deterministic Python callable handler")

    @field_validator("tool_name", mode="before")
    @classmethod
    def validate_non_empty_name(cls, value: Any) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("tool_name must not be empty.")
        return value.strip()

    @field_validator("supported_actions", mode="before")
    @classmethod
    def validate_actions(cls, value: Any) -> frozenset[ActionType]:
        if not value:
            raise ValueError("supported_actions must contain at least one ActionType.")
        if isinstance(value, (set, frozenset, list, tuple)):
            return frozenset(value)
        return frozenset(value)

    @field_validator("handler")
    @classmethod
    def validate_handler_callable(cls, value: Any) -> Callable[[ToolRequest], Any]:
        if not callable(value):
            raise ValueError("Tool handler must be a callable function.")
        return value


class ExecutionResult(BaseModel):
    """
    Serializable, immutable execution outcome model produced by SecureExecutionAdapter.

    INVARIANTS ENFORCED:
    - executed=False when authorization is invalid, missing, or verification fails.
    - executed=True, success=True when an authorized handler executes successfully.
    - executed=True, success=False when an authorized handler raises an exception.
    """
    model_config = ConfigDict(frozen=True)

    request_id: str = Field(..., description="Correlated ToolRequest identifier")
    tool_name: str = Field(..., description="Target tool name")
    executed: bool = Field(..., description="True if the registered tool handler was actually invoked")
    success: bool = Field(..., description="True if the tool handler completed without error")
    authorization_id: Optional[str] = Field(default=None, description="ExecutionAuthorization credential ID if authorized")
    started_at: datetime = Field(default_factory=utc_now, description="Timezone-aware UTC timestamp of execution start")
    completed_at: datetime = Field(default_factory=utc_now, description="Timezone-aware UTC timestamp of execution completion")
    result: Optional[Any] = Field(default=None, description="Output returned by the tool handler on success")
    error: Optional[str] = Field(default=None, description="Error message if execution failed or authorization was denied")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary execution metadata")

    @field_validator("request_id", "tool_name", mode="before")
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
