import pytest
from app.security.models import (
    ToolCategory,
    ActionType,
    ThreatType,
    Severity,
    SecurityDecisionType,
)
from app.security.runtime.contracts import RuntimeExecutionStatus
from app.security.operations.contracts import (
    ComponentStatus,
    ComponentHealth,
    OverallSystemHealth,
    SecurityMetrics,
    ThreatActivityItem,
    SecurityDecisionItem,
    ExecutionActivityItem,
    OperationsOverview,
    OperationsControlAction,
    OperationsControlRequest,
    OperationsControlResponse,
)
from app.security.models.utils import utc_now, FrozenDict

def test_component_health_contract_and_immutability():
    ch = ComponentHealth(
        name="Gateway",
        status=ComponentStatus.HEALTHY,
        details="Gateway operational",
        metadata={"key": "value", "nested": {"a": 1}},
    )

    assert ch.name == "Gateway"
    assert ch.status == ComponentStatus.HEALTHY
    assert isinstance(ch.metadata, FrozenDict)

    with pytest.raises(TypeError):
        ch.metadata["key"] = "tampered"

    with pytest.raises(TypeError):
        ch.metadata["nested"]["a"] = 2

def test_overall_system_health_contract():
    ch1 = ComponentHealth(name="Gateway", status=ComponentStatus.HEALTHY, details="OK")
    ch2 = ComponentHealth(name="Sandbox", status=ComponentStatus.HEALTHY, details="OK")

    sys_health = OverallSystemHealth(
        status=ComponentStatus.HEALTHY,
        components=[ch1, ch2],
        version="0.1.0",
        metadata={"cluster": "primary"},
    )

    assert sys_health.status == ComponentStatus.HEALTHY
    assert len(sys_health.components) == 2
    assert isinstance(sys_health.metadata, FrozenDict)

def test_security_metrics_contract():
    metrics = SecurityMetrics(
        total_requests=10,
        allowed=7,
        require_approval=2,
        blocked=1,
        authorized=7,
        successful_execution=6,
        failed_execution=1,
        detected_threats=3,
        critical_risk_requests=1,
        metadata={"source": "in_memory"},
    )

    assert metrics.total_requests == 10
    assert metrics.allowed == 7
    assert metrics.blocked == 1
    assert isinstance(metrics.metadata, FrozenDict)

def test_threat_decision_execution_items_contracts():
    t_item = ThreatActivityItem(
        threat_id="t-01",
        threat_type=ThreatType.PROMPT_INJECTION,
        severity=Severity.HIGH,
        detector="PromptInjectionDetector",
        request_id="req-01",
        title="Prompt Injection",
        description="Detected prompt injection payload",
        confidence=0.95,
        metadata={"evidence": {"matched": "ignore instructions"}},
    )
    assert t_item.threat_type == ThreatType.PROMPT_INJECTION
    assert isinstance(t_item.metadata, FrozenDict)

    d_item = SecurityDecisionItem(
        decision_id="dec-01",
        request_id="req-01",
        decision=SecurityDecisionType.REQUIRE_APPROVAL,
        risk_score=75.0,
        severity=Severity.HIGH,
        policy_id="policy.prompt.require_approval",
        reason="Prompt injection requires operator approval",
        threat_count=1,
    )
    assert d_item.decision == SecurityDecisionType.REQUIRE_APPROVAL

    e_item = ExecutionActivityItem(
        execution_id="exec-01",
        request_id="req-01",
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        status=RuntimeExecutionStatus.DENIED,
        success=False,
        duration_ms=1.5,
        error="Denied by policy",
    )
    assert e_item.status == RuntimeExecutionStatus.DENIED

def test_operations_overview_serialization_roundtrip():
    sys_health = OverallSystemHealth(
        status=ComponentStatus.HEALTHY,
        components=[ComponentHealth(name="GW", status=ComponentStatus.HEALTHY, details="OK")],
    )
    metrics = SecurityMetrics(total_requests=1)

    overview = OperationsOverview(
        overall_health=sys_health,
        metrics=metrics,
        recent_threats=[],
        recent_decisions=[],
        recent_executions=[],
    )

    json_str = overview.model_dump_json()
    loaded = OperationsOverview.model_validate_json(json_str)

    assert loaded.overall_health.status == ComponentStatus.HEALTHY
    assert loaded.metrics.total_requests == 1
    assert isinstance(loaded.metadata, FrozenDict)

def test_operations_control_contracts():
    req = OperationsControlRequest(
        action=OperationsControlAction.READ_STATUS,
        parameters={"filter": "active"},
    )
    assert req.action == OperationsControlAction.READ_STATUS
    assert isinstance(req.parameters, FrozenDict)

    res = OperationsControlResponse(
        action=OperationsControlAction.READ_STATUS,
        success=True,
        data={"status": "HEALTHY"},
    )
    assert res.success is True
