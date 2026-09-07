"""
Authoritative Data Models for AgentShield Agent Runtime & Gateway Ingestion (AGCP v1).
"""

from enum import Enum
from datetime import datetime
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator
from app.security.models.utils import utc_now, ensure_utc


class AgentStatus(str, Enum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


class ActionType(str, Enum):
    TOOL_CALL = "tool_call"
    MESSAGE = "message"
    QUERY = "query"
    SHELL = "shell"
    NETWORK = "network"
    FILE = "file"


class GatewayDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class ExecutionStatus(str, Enum):
    EXECUTED = "EXECUTED"
    BLOCKED = "BLOCKED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    FAILED = "FAILED"


class AgentRegistration(BaseModel):
    """
    Immutable representation of an autonomous AI agent registered with AgentShield.
    """
    model_config = ConfigDict(frozen=True)

    agent_id: str = Field(..., min_length=2, max_length=128, description="Unique agent identifier")
    name: str = Field(..., min_length=1, max_length=128, description="Display name of the agent")
    description: str = Field(default="", max_length=512, description="Agent operational description")
    capabilities: List[str] = Field(default_factory=list, description="Declared operational capabilities")
    scopes: List[str] = Field(default_factory=lambda: ["tools:execute"], description="Declared operational scopes")
    assigned_roles: List[str] = Field(default_factory=lambda: ["AGENT"], description="RBAC roles granted to agent")
    max_budget_per_hour: float = Field(default=100.0, ge=0.0, description="Rate limit / operational cost ceiling")
    allowed_tools: List[str] = Field(default_factory=list, description="Explicit allowlist of permitted tool names")
    status: AgentStatus = Field(default=AgentStatus.ACTIVE, description="Current lifecycle status")
    api_key_hash: Optional[str] = Field(default=None, description="Hashed API key credential")
    created_at: datetime = Field(default_factory=utc_now, description="UTC creation timestamp")
    updated_at: datetime = Field(default_factory=utc_now, description="UTC last update timestamp")


class AgentActionRequest(BaseModel):
    """
    Standardized payload for autonomous agent actions submitted to the security gateway.
    """
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    agent_id: str = Field(default="agent_default", min_length=1, max_length=128, description="Originating agent identifier")
    action_type: ActionType = Field(default=ActionType.TOOL_CALL, description="Classification of action")
    target: str = Field(default="", max_length=512, description="Tool name, endpoint, destination, or target")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Action arguments and inputs")
    context: Dict[str, Any] = Field(default_factory=dict, description="Session, user, parent task, or reasoning trace")
    idempotency_key: Optional[str] = Field(default=None, max_length=128, description="Idempotent execution key")

    @classmethod
    def model_validate(cls, obj: Any, *args, **kwargs):
        if isinstance(obj, dict):
            obj = dict(obj)
            if "tool_name" in obj and not obj.get("target"):
                obj["target"] = obj["tool_name"]
            elif "target" in obj and "tool_name" not in obj:
                obj["tool_name"] = obj["target"]
        return super().model_validate(obj, *args, **kwargs)

    def __init__(self, **data: Any):
        if "tool_name" in data and not data.get("target"):
            data["target"] = data["tool_name"]
        super().__init__(**data)

    @property
    def tool_name(self) -> str:
        return self.target


class AgentActionResponse(BaseModel):
    """
    Authoritative response from the AgentShield Security Gateway.
    """
    model_config = ConfigDict(frozen=True)

    action_id: str = Field(default_factory=lambda: f"act_{uuid.uuid4().hex[:12]}", description="Unique action tracking UUID")
    agent_id: str = Field(default="agent_unknown", description="Target agent identifier")
    decision: GatewayDecision = Field(..., description="Enforcement decision (ALLOW, DENY, REQUIRE_APPROVAL)")
    execution_status: ExecutionStatus = Field(default=ExecutionStatus.PENDING_APPROVAL, description="Execution status")
    result: Optional[Any] = Field(default=None, description="Tool execution outcome (if executed)")
    error: Optional[str] = Field(default=None, description="Security denial or runtime failure reason")
    reason: Optional[str] = Field(default=None, description="Friendly policy reason or error explanation")
    approval_id: Optional[str] = Field(default=None, description="Approval request ID if status is PENDING_APPROVAL")
    decision_details: Dict[str, Any] = Field(default_factory=dict, description="Policy and threat scan metadata")
    threat_report: Dict[str, Any] = Field(default_factory=lambda: {"threat_detected": False, "signals": []}, description="Threat report metadata")
    execution: Optional[Dict[str, Any]] = Field(default=None, description="Tool execution outcome envelope")
    audit_id: Optional[str] = Field(default=None, description="Security audit log event ID")
    duration_ms: float = Field(default=0.0, description="Processing duration in milliseconds")

    def __init__(self, **data: Any):
        if "reason" not in data and "error" in data:
            data["reason"] = data["error"]
        elif "error" not in data and "reason" in data:
            data["error"] = data["reason"]

        dec = data.get("decision")
        if dec == GatewayDecision.ALLOW or dec == "ALLOW":
            exec_status = data.get("execution_status")
            status_str = exec_status.value if hasattr(exec_status, "value") else (exec_status or "COMPLETED")
            if status_str in ("EXECUTED", "COMPLETED"):
                status_str = "COMPLETED"
            data["execution"] = {"status": status_str, "result": data.get("result")}
        else:
            data["execution"] = None

        super().__init__(**data)
