"""
Base contract and result models for real, isolated tool handlers in AgentShield.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from app.security.models import ToolCategory, ActionType


class BaseTool(ABC):
    """
    Abstract contract for executable tool implementations.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique tool identifier (e.g. 'calculator')."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of tool capabilities."""
        pass

    @property
    @abstractmethod
    def category(self) -> ToolCategory:
        """Security classification category."""
        pass

    @abstractmethod
    def execute(self, parameters: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute tool operation within containment boundaries.
        Returns dictionary containing output data.
        """
        pass
