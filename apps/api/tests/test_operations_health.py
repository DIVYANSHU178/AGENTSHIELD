from unittest.mock import MagicMock
import pytest
from app.security.operations.health import SecurityHealthChecker
from app.security.operations.contracts import ComponentStatus, ComponentHealth, OverallSystemHealth
from app.security.gateway import SecurityDecisionGateway
from app.security.enforcement import SecurityEnforcementBoundary
from app.security.sandbox import SandboxExecutionBoundary
from app.security.execution import (
    SecureExecutionAdapter,
    ToolExecutionRegistry,
    ToolExecutionContract,
    create_default_execution_registry,
)
from app.security.runtime import AgentRuntimeOrchestrator
from app.security.audit import SecurityAuditTrail
from app.security.models import ToolCategory, ActionType

EXPECTED_COMPONENT_NAMES = [
    "SecurityDecisionGateway",
    "SecurityEnforcementBoundary",
    "SandboxExecutionBoundary",
    "SecureExecutionAdapter",
    "ToolExecutionRegistry",
    "AgentRuntimeOrchestrator",
    "SecurityAuditTrail",
]

def test_health_checker_individual_components():
    checker = SecurityHealthChecker()

    gw_health = checker.check_gateway()
    assert gw_health.name == "SecurityDecisionGateway"
    assert gw_health.status == ComponentStatus.HEALTHY

    enf_health = checker.check_enforcement_boundary()
    assert enf_health.name == "SecurityEnforcementBoundary"
    assert enf_health.status == ComponentStatus.HEALTHY

    sb_health = checker.check_sandbox_boundary()
    assert sb_health.name == "SandboxExecutionBoundary"
    assert sb_health.status == ComponentStatus.HEALTHY

    adapter_health = checker.check_execution_adapter()
    assert adapter_health.name == "SecureExecutionAdapter"
    assert adapter_health.status == ComponentStatus.HEALTHY

    reg_health = checker.check_execution_registry()
    assert reg_health.name == "ToolExecutionRegistry"
    assert reg_health.status == ComponentStatus.HEALTHY
    assert reg_health.metadata.get("registered_tools_count") == 5

    orch_health = checker.check_runtime_orchestrator()
    assert orch_health.name == "AgentRuntimeOrchestrator"
    assert orch_health.status == ComponentStatus.HEALTHY

    audit_health = checker.check_audit_trail()
    assert audit_health.name == "SecurityAuditTrail"
    assert audit_health.status == ComponentStatus.HEALTHY

def test_health_checker_check_all_aggregated_7_components():
    gateway = SecurityDecisionGateway()
    boundary = SecurityEnforcementBoundary(gateway=gateway)
    sandbox = SandboxExecutionBoundary(boundary=boundary)
    registry = create_default_execution_registry()
    adapter = SecureExecutionAdapter(registry=registry)
    audit_trail = SecurityAuditTrail()
    orchestrator = AgentRuntimeOrchestrator(
        gateway=gateway,
        boundary=boundary,
        sandbox=sandbox,
        audit_trail=audit_trail,
    )

    checker = SecurityHealthChecker(
        gateway=gateway,
        boundary=boundary,
        sandbox=sandbox,
        adapter=adapter,
        registry=registry,
        orchestrator=orchestrator,
        audit_trail=audit_trail,
    )

    sys_health: OverallSystemHealth = checker.check_all()

    assert sys_health.status == ComponentStatus.HEALTHY
    assert len(sys_health.components) == 7
    
    component_names = [c.name for c in sys_health.components]
    assert component_names == EXPECTED_COMPONENT_NAMES
    assert set(component_names) == set(EXPECTED_COMPONENT_NAMES)

    for comp in sys_health.components:
        assert comp.status == ComponentStatus.HEALTHY
        assert comp.checked_at is not None

def test_health_checker_custom_injected_registry():
    custom_reg = ToolExecutionRegistry()
    custom_reg.register(
        ToolExecutionContract(
            tool_name="custom.ping",
            tool_category=ToolCategory.SYSTEM,
            supported_actions={ActionType.EXECUTE},
            handler=lambda params: {"ping": "pong"},
        )
    )
    custom_reg.register(
        ToolExecutionContract(
            tool_name="custom.echo",
            tool_category=ToolCategory.SYSTEM,
            supported_actions={ActionType.EXECUTE},
            handler=lambda params: {"echo": params},
        )
    )

    checker = SecurityHealthChecker(registry=custom_reg)
    reg_health = checker.check_execution_registry()

    assert reg_health.name == "ToolExecutionRegistry"
    assert reg_health.status == ComponentStatus.HEALTHY
    assert reg_health.metadata.get("registered_tools_count") == 2
    assert "custom.ping" in reg_health.metadata.get("tools", [])
    assert "custom.echo" in reg_health.metadata.get("tools", [])

def test_health_checker_empty_registry():
    empty_reg = ToolExecutionRegistry()
    checker = SecurityHealthChecker(registry=empty_reg)
    reg_health = checker.check_execution_registry()

    assert reg_health.name == "ToolExecutionRegistry"
    assert reg_health.status == ComponentStatus.HEALTHY
    assert reg_health.metadata.get("registered_tools_count") == 0
    assert list(reg_health.metadata.get("tools", [])) == []

def test_health_checker_registry_inspection_never_executes_handlers():
    spy_handler = MagicMock(return_value={"executed": True})
    spy_reg = ToolExecutionRegistry()
    spy_reg.register(
        ToolExecutionContract(
            tool_name="sensitive.tool",
            tool_category=ToolCategory.SYSTEM,
            supported_actions={ActionType.EXECUTE},
            handler=spy_handler,
        )
    )

    checker = SecurityHealthChecker(registry=spy_reg)
    for _ in range(5):
        reg_health = checker.check_execution_registry()
        assert reg_health.status == ComponentStatus.HEALTHY
        all_health = checker.check_all()
        assert all_health.status == ComponentStatus.HEALTHY

    spy_handler.assert_not_called()

def test_health_checker_corrupt_or_invalid_registry_fails_safely():
    # Pass non-registry object
    checker_bad_type = SecurityHealthChecker(registry="invalid_registry_string")  # type: ignore
    reg_health = checker_bad_type.check_execution_registry()
    assert reg_health.name == "ToolExecutionRegistry"
    assert reg_health.status in (ComponentStatus.FAILED, ComponentStatus.DEGRADED)

    all_health = checker_bad_type.check_all()
    assert all_health.status in (ComponentStatus.FAILED, ComponentStatus.DEGRADED)

def test_health_checker_determinism_10x():
    checker = SecurityHealthChecker()
    first_check = checker.check_all()

    for _ in range(10):
        current_check = checker.check_all()
        assert current_check.status == first_check.status
        assert len(current_check.components) == 7
        assert [c.name for c in current_check.components] == EXPECTED_COMPONENT_NAMES
        for i in range(7):
            assert current_check.components[i].name == first_check.components[i].name
            assert current_check.components[i].status == first_check.components[i].status

def test_health_snapshot_immutability_and_json_roundtrip():
    checker = SecurityHealthChecker()
    health = checker.check_all()

    # Mutation assertion
    with pytest.raises(Exception):
        health.status = ComponentStatus.FAILED  # type: ignore

    with pytest.raises(Exception):
        health.components[0].status = ComponentStatus.FAILED  # type: ignore

    # JSON roundtrip assertion
    json_str = health.model_dump_json()
    reconstituted = OverallSystemHealth.model_validate_json(json_str)

    assert reconstituted.status == health.status
    assert len(reconstituted.components) == 7
    assert [c.name for c in reconstituted.components] == EXPECTED_COMPONENT_NAMES

def test_health_check_does_not_mutate_registry():
    registry = create_default_execution_registry()
    tools_before = [c.tool_name for c in registry.list_tools()]
    count_before = len(registry)

    checker = SecurityHealthChecker(registry=registry)
    checker.check_execution_registry()
    checker.check_all()

    tools_after = [c.tool_name for c in registry.list_tools()]
    count_after = len(registry)

    assert tools_before == tools_after
    assert count_before == count_after
