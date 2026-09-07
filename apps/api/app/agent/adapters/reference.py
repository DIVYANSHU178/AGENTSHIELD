"""
Reference Agent Adapter for AgentShield.
Demonstrates the full autonomous agent loop submitting actions to the Security Gateway.
"""

from typing import Dict, Any, Optional
from app.agent.models import AgentActionRequest, AgentActionResponse, ActionType
from app.agent.adapters.base import BaseAgentAdapter
from app.agent.service import AgentGatewayService, get_agent_gateway_service


class ReferenceAgentAdapter(BaseAgentAdapter):
    """
    Standard reference adapter connecting an autonomous agent to AgentGatewayService.
    """

    def __init__(
        self,
        agent_id: str = "reference-autonomous-agent",
        agent_key: Optional[str] = "agk_reference_agent_secret_key",
        gateway_service: Optional[AgentGatewayService] = None,
    ) -> None:
        self._agent_id = agent_id
        self._agent_key = agent_key
        self._gateway = gateway_service or get_agent_gateway_service()

    @property
    def agent_id(self) -> str:
        return self._agent_id

    def submit_action(
        self,
        action_type: str,
        target: str,
        parameters: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentActionResponse:
        """Submit action directly to the security gateway pipeline."""
        act_type = ActionType(action_type) if action_type in [e.value for e in ActionType] else ActionType.TOOL_CALL
        req = AgentActionRequest(
            agent_id=self._agent_id,
            action_type=act_type,
            target=target,
            parameters=parameters,
            context=context or {},
        )
        return self._gateway.handle_action(req, agent_key=self._agent_key)
