import pytest
from app.security.models import SecurityDecisionType
from app.security.runtime.contracts import RuntimeExecutionStatus
from app.security.laboratory.contracts import (
    ScenarioCategory,
    ScenarioDefinition,
)
from app.security.laboratory.registry import (
    ScenarioRegistry,
    create_default_scenario_registry,
    get_scenario_registry,
)
from app.security.laboratory.errors import UnknownScenarioError

EXPECTED_20_SCENARIOS = [
    "ALLOW_CLEAN",
    "REQUIRE_APPROVAL_PROMPT_INJECTION",
    "REQUIRE_APPROVAL_CREDENTIAL_ACCESS",
    "BLOCK_EXFILTRATION",
    "APPROVED_EXECUTION",
    "APPROVAL_REJECT",
    "APPROVAL_CANCEL",
    "APPROVAL_EXPIRE",
    "TAMPER_REQUEST_ID",
    "TAMPER_AGENT",
    "TAMPER_TARGET",
    "TAMPER_PARAMETERS",
    "TAMPER_TOOL",
    "TAMPER_CATEGORY",
    "TAMPER_ACTION",
    "TAMPER_DESTINATION",
    "UNKNOWN_APPROVAL",
    "DOUBLE_APPROVAL",
    "DOUBLE_REJECTION",
    "TERMINAL_NON_RESURRECTION",
]

def test_registry_contains_all_20_scenarios():
    registry = create_default_scenario_registry()
    assert len(registry) == 20
    for sid in EXPECTED_20_SCENARIOS:
        assert registry.has(sid), f"Scenario '{sid}' missing from registry"
        defn = registry.get(sid)
        assert defn.scenario_id == sid

def test_registry_category_filtering():
    registry = create_default_scenario_registry()
    baseline = registry.list_scenarios(category=ScenarioCategory.BASELINE)
    assert len(baseline) == 4

    approval_lf = registry.list_scenarios(category=ScenarioCategory.APPROVAL_LIFECYCLE)
    assert len(approval_lf) == 4

    anti_tamper = registry.list_scenarios(category=ScenarioCategory.ANTI_TAMPER)
    assert len(anti_tamper) == 8

    failure_abuse = registry.list_scenarios(category=ScenarioCategory.FAILURE_ABUSE)
    assert len(failure_abuse) == 4

def test_registry_unknown_scenario_raises():
    registry = create_default_scenario_registry()
    with pytest.raises(UnknownScenarioError):
        registry.get("TOTALLY_UNKNOWN_SCENARIO")

    with pytest.raises(UnknownScenarioError):
        registry.get("")

    with pytest.raises(UnknownScenarioError):
        registry.get(None)

def test_registry_duplicate_registration_rejected():
    registry = ScenarioRegistry()
    d = ScenarioDefinition(
        scenario_id="TEST_DUP",
        name="Dup",
        description="Desc",
        category=ScenarioCategory.BASELINE,
        expected_decision=SecurityDecisionType.ALLOW,
        expected_status=RuntimeExecutionStatus.COMPLETED,
        expected_executed=True,
    )
    registry.register(d)
    assert len(registry) == 1

    with pytest.raises(ValueError, match="already registered"):
        registry.register(d)

def test_registry_singleton_accessor():
    r1 = get_scenario_registry()
    r2 = get_scenario_registry()
    assert r1 is r2
    assert len(r1) == 20
