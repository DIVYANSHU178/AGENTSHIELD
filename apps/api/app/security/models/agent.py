from typing import Dict, Any, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator
from app.security.models.utils import generate_uuid

class AgentIdentity(BaseModel):
    """
    Represents the identity of an AI agent making a tool execution request.
    Immutable representation configured with Pydantic V2 frozen=True.
    """
    model_config = ConfigDict(frozen=True)

    agent_id: str = Field(default_factory=generate_uuid, description="Unique identifier for the agent instance")
    name: str = Field(..., description="Human-readable logical name of the agent")
    version: str = Field(default="1.0.0", description="Agent release/definition version")
    provider: str = Field(default="internal", description="Agent execution runtime provider framework")
    session_id: Optional[str] = Field(default=None, description="Optional active session identifier")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary JSON-compatible agent metadata")

    @field_validator("agent_id", "name", mode="before")
    @classmethod
    def validate_non_empty_str(cls, value: Any, info) -> Any:
        if isinstance(value, str) and not value.strip():
            raise ValueError(f"Field '{info.field_name}' must not be an empty string")
        return value
