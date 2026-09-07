"""
Production Gateway Action Ingestion REST API Router for AgentShield (Stage 4, 11, 12).
Provides /api/v1/gateway/actions and management APIs for Agents, Tools, and Policies.
"""

from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Header, Request, Response, Path, Query
from pydantic import BaseModel, Field

from app.agent.models import (
    AgentActionRequest,
    AgentActionResponse,
    AgentRegistration,
    AgentStatus,
    GatewayDecision,
    ExecutionStatus,
)
from app.agent.service import AgentGatewayService, get_agent_gateway_service
from app.agent.registry import AgentRegistry, get_agent_registry
from app.security.execution.tool_registry_service import ToolRegistryRepository, get_tool_registry_repository
from app.security.policies.policy_repository import PolicyRepository, get_policy_repository
from app.security.identity.dependencies import get_current_user, get_current_user_optional, require_permission
from app.security.identity.models import UserIdentity, Permission

gateway_router = APIRouter(tags=["gateway-and-governance"])


# -----------------------------------------------------------------------------
# Stage 4: Production Action Ingestion Endpoint
# -----------------------------------------------------------------------------

@gateway_router.post(
    "/gateway/actions",
    response_model=AgentActionResponse,
    responses={
        200: {"description": "Action evaluated by security gateway (ALLOW, DENY, or REQUIRE_APPROVAL)."},
        401: {"description": "Missing or invalid agent API key."},
        403: {"description": "Agent is suspended or revoked."},
    },
)
@gateway_router.post(
    "/agent/action",
    response_model=AgentActionResponse,
    include_in_schema=False,
)
def ingest_agent_action(
    request: AgentActionRequest,
    raw_request: Request,
    response: Response,
    x_agent_key: Optional[str] = Header(default=None, alias="X-Agent-Key"),
    authorization: Optional[str] = Header(default=None),
    gateway_service: AgentGatewayService = Depends(get_agent_gateway_service),
    agent_registry: AgentRegistry = Depends(get_agent_registry),
) -> AgentActionResponse:
    """
    Authoritative ingestion endpoint for autonomous AI agent actions.
    Performs full identity verification, input threat scanning, policy engine evaluation,
    and isolated tool execution.
    """
    # Extract agent key from header or bearer token
    agent_key = x_agent_key
    if not agent_key and authorization and authorization.lower().startswith("bearer "):
        agent_key = authorization.split(" ", 1)[1].strip()

    if not agent_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing agent API key. Provide X-Agent-Key or Authorization Bearer header.",
        )

    # Validate agent identity
    agent = agent_registry.get_by_api_key(agent_key)
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or inactive agent API key.",
        )

    if agent.status == AgentStatus.SUSPENDED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Agent '{agent.agent_id}' is currently suspended.",
        )
    if agent.status == AgentStatus.REVOKED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Agent '{agent.agent_id}' is currently revoked.",
        )

    # Set correlation ID
    corr_id = raw_request.headers.get("X-Correlation-ID")
    if corr_id:
        response.headers["X-Correlation-ID"] = corr_id

    # Ensure originating agent_id matches authenticated agent
    req = request.model_copy(update={"agent_id": agent.agent_id})

    action_response = gateway_service.handle_action(req, agent_key=agent_key)
    response.status_code = status.HTTP_200_OK
    return action_response


# -----------------------------------------------------------------------------
# Stage 11: Tool Registry Management Endpoints
# -----------------------------------------------------------------------------

class ToolRegistrationRequest(BaseModel):
    tool_id: str = Field(..., min_length=2, max_length=64)
    name: str = Field(..., min_length=2, max_length=128)
    category: str = Field(..., min_length=2, max_length=64)
    description: str = Field(..., min_length=2, max_length=512)
    risk_classification: str = Field(default="MEDIUM")
    handler_type: str = Field(default="isolated_process")
    is_enabled: bool = Field(default=True)
    allowed_environments: List[str] = Field(default_factory=lambda: ["development", "staging", "production"])
    parameters_schema: Dict[str, Any] = Field(default_factory=dict)


@gateway_router.get("/tools", response_model=List[Dict[str, Any]])
def list_tools(
    is_enabled: Optional[bool] = Query(default=None),
    tool_repo: ToolRegistryRepository = Depends(get_tool_registry_repository),
    current_user: UserIdentity = Depends(require_permission(Permission.VIEW_OPERATIONS, allow_unauthenticated_in_dev=False)),
) -> List[Dict[str, Any]]:
    """List all authorized tools in the security catalog."""
    return tool_repo.list_tools(is_enabled=is_enabled)


@gateway_router.get("/tools/{tool_id}", response_model=Dict[str, Any])
def get_tool(
    tool_id: str = Path(...),
    tool_repo: ToolRegistryRepository = Depends(get_tool_registry_repository),
    current_user: UserIdentity = Depends(require_permission(Permission.VIEW_OPERATIONS, allow_unauthenticated_in_dev=False)),
) -> Dict[str, Any]:
    """Retrieve details for a specific registered tool."""
    tool = tool_repo.get_tool(tool_id)
    if not tool:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Tool '{tool_id}' not found.")
    return tool


@gateway_router.post("/tools", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
def register_tool(
    body: ToolRegistrationRequest,
    tool_repo: ToolRegistryRepository = Depends(get_tool_registry_repository),
    current_user: UserIdentity = Depends(require_permission(Permission.MANAGE_TOOLS, allow_unauthenticated_in_dev=False)),
) -> Dict[str, Any]:
    """Register a new tool contract in the catalog."""
    return tool_repo.register_tool(
        tool_id=body.tool_id,
        name=body.name,
        category=body.category,
        description=body.description,
        risk_classification=body.risk_classification,
        handler_type=body.handler_type,
        is_enabled=body.is_enabled,
        allowed_environments=body.allowed_environments,
        parameters_schema=body.parameters_schema,
    )


@gateway_router.delete("/tools/{tool_id}")
def delete_tool(
    tool_id: str = Path(...),
    tool_repo: ToolRegistryRepository = Depends(get_tool_registry_repository),
    current_user: UserIdentity = Depends(require_permission(Permission.MANAGE_TOOLS, allow_unauthenticated_in_dev=False)),
) -> Dict[str, Any]:
    """Soft-disable a tool by marking it disabled."""
    success = tool_repo.delete_tool(tool_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Tool '{tool_id}' not found.")
    return {"message": f"Tool '{tool_id}' disabled successfully.", "tool_id": tool_id}


# -----------------------------------------------------------------------------
# Stage 12: Policy Management Endpoints
# -----------------------------------------------------------------------------

class PolicyCreateRequest(BaseModel):
    policy_id: str = Field(..., min_length=2, max_length=64)
    name: str = Field(..., min_length=2, max_length=128)
    description: str = Field(..., min_length=2, max_length=512)
    rule_type: str = Field(..., min_length=2, max_length=64)
    priority: int = Field(default=50, ge=0, le=100)
    conditions: Dict[str, Any] = Field(default_factory=dict)
    action: str = Field(default="REQUIRE_APPROVAL")
    is_enabled: bool = Field(default=True)


@gateway_router.get("/policies", response_model=List[Dict[str, Any]])
def list_policies(
    is_enabled: Optional[bool] = Query(default=None),
    policy_repo: PolicyRepository = Depends(get_policy_repository),
    current_user: UserIdentity = Depends(require_permission(Permission.VIEW_OPERATIONS, allow_unauthenticated_in_dev=False)),
) -> List[Dict[str, Any]]:
    """List all security policies ordered by priority descending."""
    return policy_repo.list_policies(is_enabled=is_enabled)


@gateway_router.get("/policies/{policy_id}", response_model=Dict[str, Any])
def get_policy(
    policy_id: str = Path(...),
    policy_repo: PolicyRepository = Depends(get_policy_repository),
    current_user: UserIdentity = Depends(require_permission(Permission.VIEW_OPERATIONS, allow_unauthenticated_in_dev=False)),
) -> Dict[str, Any]:
    """Retrieve details for a specific security policy."""
    policy = policy_repo.get_policy(policy_id)
    if not policy:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Policy '{policy_id}' not found.")
    return policy


@gateway_router.post("/policies", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
def create_policy(
    body: PolicyCreateRequest,
    policy_repo: PolicyRepository = Depends(get_policy_repository),
    current_user: UserIdentity = Depends(require_permission(Permission.MANAGE_POLICIES, allow_unauthenticated_in_dev=False)),
) -> Dict[str, Any]:
    """Create a new security policy definition."""
    return policy_repo.create_policy(
        policy_id=body.policy_id,
        name=body.name,
        description=body.description,
        rule_type=body.rule_type,
        priority=body.priority,
        conditions=body.conditions,
        action=body.action,
        is_enabled=body.is_enabled,
    )


@gateway_router.delete("/policies/{policy_id}")
def delete_policy(
    policy_id: str = Path(...),
    policy_repo: PolicyRepository = Depends(get_policy_repository),
    current_user: UserIdentity = Depends(require_permission(Permission.MANAGE_POLICIES, allow_unauthenticated_in_dev=False)),
) -> Dict[str, Any]:
    """Disable a security policy."""
    success = policy_repo.delete_policy(policy_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Policy '{policy_id}' not found.")
    return {"message": f"Policy '{policy_id}' disabled successfully.", "policy_id": policy_id}


# -----------------------------------------------------------------------------
# Agent Management Endpoints
# -----------------------------------------------------------------------------

class AgentCreateRequest(BaseModel):
    agent_id: Optional[str] = Field(default=None, max_length=64)
    name: str = Field(..., min_length=2, max_length=128)
    description: str = Field(default="", max_length=512)
    capabilities: List[str] = Field(default_factory=list)
    scopes: List[str] = Field(default_factory=lambda: ["tools:execute"])
    allowed_tools: List[str] = Field(default_factory=list)
    max_budget_per_hour: float = Field(default=100.0, ge=0.0)
    api_key: Optional[str] = Field(default=None)


@gateway_router.get("/agents", response_model=List[AgentRegistration])
def list_agents(
    status_filter: Optional[AgentStatus] = Query(default=None, alias="status"),
    agent_registry: AgentRegistry = Depends(get_agent_registry),
    current_user: UserIdentity = Depends(require_permission(Permission.VIEW_OPERATIONS, allow_unauthenticated_in_dev=False)),
) -> List[AgentRegistration]:
    """List registered autonomous agents (Admin/Operator only)."""
    return agent_registry.list_agents(status=status_filter)


@gateway_router.get("/agents/{agent_id}", response_model=AgentRegistration)
def get_agent(
    agent_id: str = Path(...),
    agent_registry: AgentRegistry = Depends(get_agent_registry),
    current_user: UserIdentity = Depends(require_permission(Permission.VIEW_OPERATIONS, allow_unauthenticated_in_dev=False)),
) -> AgentRegistration:
    """Retrieve details for a specific registered agent."""
    agent = agent_registry.get(agent_id)
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Agent '{agent_id}' not found.")
    return agent


@gateway_router.post("/agents", response_model=Dict[str, Any], status_code=status.HTTP_200_OK)
def register_agent(
    body: AgentCreateRequest,
    agent_registry: AgentRegistry = Depends(get_agent_registry),
    current_user: UserIdentity = Depends(require_permission(Permission.MANAGE_IDENTITIES, allow_unauthenticated_in_dev=False)),
) -> Dict[str, Any]:
    """Register a new autonomous agent and return assigned API key."""
    import uuid as _uuid
    agent_id = body.agent_id or f"agent_{_uuid.uuid4().hex[:10]}"
    scopes = body.scopes or ["tools:execute"]
    agent = AgentRegistration(
        agent_id=agent_id,
        name=body.name,
        description=body.description,
        capabilities=body.capabilities or scopes,
        scopes=scopes,
        allowed_tools=body.allowed_tools,
        max_budget_per_hour=body.max_budget_per_hour,
        status=AgentStatus.ACTIVE,
    )
    reg_agent, plain_key = agent_registry.register(agent, api_key=body.api_key)
    return {
        "agent_id": reg_agent.agent_id,
        "name": reg_agent.name,
        "api_key": plain_key,
        "agent": reg_agent.model_dump(),
        "message": "Store this API key securely. It will not be shown again in plaintext.",
    }


@gateway_router.put("/agents/{agent_id}/status")
def update_agent_status(
    agent_id: str = Path(...),
    new_status: AgentStatus = Query(...),
    agent_registry: AgentRegistry = Depends(get_agent_registry),
    current_user: UserIdentity = Depends(require_permission(Permission.MANAGE_IDENTITIES, allow_unauthenticated_in_dev=False)),
) -> Dict[str, Any]:
    """Update agent lifecycle status (ACTIVE, SUSPENDED, REVOKED)."""
    updated = agent_registry.update_status(agent_id, new_status)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Agent '{agent_id}' not found.")
    return {"message": f"Agent '{agent_id}' status updated to {new_status.value}.", "agent": updated.model_dump()}
