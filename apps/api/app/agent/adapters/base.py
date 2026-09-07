"""
Base Agent Adapter Interface for AgentShield.
Defines contracts for connecting external agent loops (LangChain, CrewAI, AutoGen, custom)
to the AgentShield Security Gateway.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from app.agent.models import AgentActionRequest, AgentActionResponse


class BaseAgentAdapter(ABC):
    """
    Abstract adapter interface for autonomous agents.
    """

    @property
    @abstractmethod
    def agent_id(self) -> str:
        """Registered agent identifier."""
        pass

    @abstractmethod
    def submit_action(
        self,
        action_type: str,
        target: str,
        parameters: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentActionResponse:
        """Submit an intended action to the security gateway."""
        pass
