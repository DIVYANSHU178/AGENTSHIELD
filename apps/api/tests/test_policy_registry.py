import pytest
from app.security import (
    PolicyRegistry,
    CriticalRiskRule,
    VeryHighRiskRule,
    HighRiskRule,
    MediumRiskRule,
    DefaultAllowRule,
    create_default_policy_registry,
)

def test_registry_ordering():
    registry = PolicyRegistry()
    r_allow = DefaultAllowRule()
    r_crit = CriticalRiskRule()
    r_high = HighRiskRule()

    # Register out of order
    registry.register(r_allow)
    registry.register(r_crit)
    registry.register(r_high)

    rules = registry.get_rules()
    priorities = [r.priority for r in rules]
    assert priorities == [100, 70, 0]
    assert rules[0].rule_id == "policy.risk.critical.block"

def test_registry_duplicate_rule_id_rejected():
    registry = PolicyRegistry()
    r1 = CriticalRiskRule()
    r2 = CriticalRiskRule()

    registry.register(r1)
    with pytest.raises(ValueError):
        registry.register(r2)

def test_create_default_policy_registry():
    registry = create_default_policy_registry()
    rules = registry.get_rules()
    assert len(rules) == 5
    priorities = [r.priority for r in rules]
    assert priorities == [100, 90, 70, 50, 0]
