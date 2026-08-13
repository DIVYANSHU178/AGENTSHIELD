from typing import List, Dict
from app.security.policies.base import PolicyRule

class PolicyRegistry:
    """
    Deterministic registry for managing policy rules ordered explicitly by priority descending.
    """

    def __init__(self) -> None:
        self._rules: Dict[str, PolicyRule] = {}

    def register(self, rule: PolicyRule) -> None:
        """
        Register a policy rule.
        Raises ValueError if a rule with the same rule_id is already registered.
        """
        if rule.rule_id in self._rules:
            raise ValueError(f"Policy rule with rule_id '{rule.rule_id}' is already registered.")
        self._rules[rule.rule_id] = rule

    def unregister(self, rule_id: str) -> None:
        """Unregister a policy rule by its rule_id."""
        self._rules.pop(rule_id, None)

    def get_rules(self) -> List[PolicyRule]:
        """Return registered rules sorted strictly by priority descending."""
        return sorted(self._rules.values(), key=lambda r: r.priority, reverse=True)


def create_default_policy_registry() -> PolicyRegistry:
    """
    Factory function creating a PolicyRegistry populated with default AgentShield Phase 4 policy rules.
    Precedence: CRITICAL BLOCK (100) > VERY HIGH BLOCK (90) > HIGH APPROVAL (70) > MEDIUM APPROVAL (50) > DEFAULT ALLOW (0).
    """
    from app.security.policies.rules import (
        CriticalRiskRule,
        VeryHighRiskRule,
        HighRiskRule,
        MediumRiskRule,
        DefaultAllowRule,
    )

    registry = PolicyRegistry()
    registry.register(CriticalRiskRule())
    registry.register(VeryHighRiskRule())
    registry.register(HighRiskRule())
    registry.register(MediumRiskRule())
    registry.register(DefaultAllowRule())
    return registry
