from abc import ABC, abstractmethod
from typing import Optional, Tuple
from app.security.models import SecurityDecisionType
from app.security.policies.context import PolicyContext

class PolicyRule(ABC):
    """
    Abstract base class for all deterministic policy rules.
    A policy rule evaluates a PolicyContext and determines whether a policy condition matches.

    CRITICAL CONTRACT RULES:
    - Policy rules MUST be pure, deterministic, and side-effect free.
    - Policy rules MUST NOT execute tools, shell commands, or network calls.
    """

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique stable identifier for the policy rule (e.g. 'policy.risk.critical.block')."""
        pass

    @property
    @abstractmethod
    def priority(self) -> int:
        """Numeric priority for deterministic evaluation order (higher priority evaluated first)."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable explanation of the rule's policy objective."""
        pass

    @abstractmethod
    def evaluate(self, context: PolicyContext) -> Optional[Tuple[SecurityDecisionType, str]]:
        """
        Evaluate the rule against the provided PolicyContext.
        Returns a tuple of (SecurityDecisionType, human_readable_reason) if matched,
        or None if the rule condition is not met.
        """
        pass
