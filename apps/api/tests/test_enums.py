import pytest
from app.security import (
    ToolCategory,
    ActionType,
    ThreatType,
    Severity,
    SecurityDecisionType,
    EventType,
)

def test_enum_values():
    assert ToolCategory.FILESYSTEM == "FILESYSTEM"
    assert ActionType.READ == "READ"
    assert ThreatType.PROMPT_INJECTION == "PROMPT_INJECTION"
    assert Severity.HIGH == "HIGH"
    assert SecurityDecisionType.ALLOW == "ALLOW"
    assert SecurityDecisionType.BLOCK == "BLOCK"
    assert SecurityDecisionType.REQUIRE_APPROVAL == "REQUIRE_APPROVAL"
    assert EventType.REQUESTED == "REQUESTED"

def test_invalid_enum_instantiation():
    with pytest.raises(ValueError):
        ToolCategory("INVALID_CATEGORY")
