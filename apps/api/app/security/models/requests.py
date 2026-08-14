from datetime import datetime
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, ConfigDict, Field, field_validator
from app.security.models.enums import ToolCategory, ActionType
from app.security.models.agent import AgentIdentity
from app.security.models.utils import generate_uuid, utc_now, ensure_utc, deep_freeze, FrozenDict

class ToolRequest(BaseModel):
    """
    Canonical representation of a tool execution request initiated by an AI Agent.
    Every tool request must pass through AgentShield before execution.
    Deeply immutable representation configured with Pydantic V2 frozen=True and deep_freeze.
    """
    model_config = ConfigDict(frozen=True)

    request_id: str = Field(default_factory=generate_uuid, description="Unique identifier for this tool request")
    agent: AgentIdentity = Field(..., description="Agent Identity metadata")
    tool_name: str = Field(..., description="Logical name of the tool requested (e.g. filesystem.read)")
    tool_category: ToolCategory = Field(..., description="Category classification of the target tool")
    action: ActionType = Field(..., description="Type of operation requested")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Structured tool argument parameters")
    target: str = Field(..., description="Target resource being acted upon")
    destination: Optional[str] = Field(default=None, description="Optional destination endpoint or path")
    timestamp: datetime = Field(default_factory=utc_now, description="Timezone-aware UTC request timestamp")
    session_id: Optional[str] = Field(default=None, description="Optional session correlation identifier")
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

    @field_validator("timestamp", mode="before")
    @classmethod
    def validate_utc_timestamp(cls, value: Any) -> Any:
        if isinstance(value, datetime):
            return ensure_utc(value)
        return value


class SecurityContext(BaseModel):
    """
    Contextual security metadata available to AgentShield during inspection.
    Deeply immutable representation configured with Pydantic V2 frozen=True.
    """
    model_config = ConfigDict(frozen=True)

    session_id: str = Field(..., description="Active session identifier")
    user_id: Optional[str] = Field(default=None, description="Associated user identifier")
    agent_id: str = Field(..., description="Target agent identifier")
    environment: str = Field(default="development", description="Runtime execution environment")
    trust_level: str = Field(default="standard", description="Assigned security trust level")
    previous_decisions: List[str] = Field(default_factory=list, description="Historical security decisions in session")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary JSON-compatible security metadata")

    @field_validator("session_id", "agent_id", mode="before")
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
