"""
Agent-Gateway Communication Protocol (AGCP v1).
Defines standard envelope, headers, and serialization formats for autonomous AI agent interactions.
"""

from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from app.agent.models import AgentActionRequest, AgentActionResponse

PROTOCOL_VERSION = "v1"
HEADER_AGENT_KEY = "X-Agent-Key"
HEADER_CORRELATION_ID = "X-Correlation-ID"
HEADER_IDEMPOTENCY_KEY = "X-Idempotency-Key"


class AGCPEnvelope(BaseModel):
    """
    Standard protocol envelope wrapping agent action payloads.
    """
    protocol_version: str = Field(default=PROTOCOL_VERSION)
    request: AgentActionRequest
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AGCPResponseEnvelope(BaseModel):
    """
    Standard protocol envelope wrapping gateway action responses.
    """
    protocol_version: str = Field(default=PROTOCOL_VERSION)
    response: AgentActionResponse
    metadata: Dict[str, Any] = Field(default_factory=dict)
