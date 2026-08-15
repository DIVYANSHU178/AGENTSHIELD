import pytest
from app.security.operations.contracts import (
    OperationsControlAction,
    OperationsControlRequest,
)
from app.security.operations.service import SecurityOperationsService

def test_operations_control_read_actions_allowed():
    service = SecurityOperationsService()

    # 1. READ_STATUS
    res_status = service.execute_control(OperationsControlRequest(action=OperationsControlAction.READ_STATUS))
    assert res_status.success is True

    # 2. READ_HEALTH
    res_health = service.execute_control(OperationsControlRequest(action=OperationsControlAction.READ_HEALTH))
    assert res_health.success is True

    # 3. READ_METRICS
    res_metrics = service.execute_control(OperationsControlRequest(action=OperationsControlAction.READ_METRICS))
    assert res_metrics.success is True

    # 4. READ_THREATS
    res_threats = service.execute_control(OperationsControlRequest(action=OperationsControlAction.READ_THREATS))
    assert res_threats.success is True

    # 5. READ_DECISIONS
    res_dec = service.execute_control(OperationsControlRequest(action=OperationsControlAction.READ_DECISIONS))
    assert res_dec.success is True

    # 6. READ_EXECUTIONS
    res_exec = service.execute_control(OperationsControlRequest(action=OperationsControlAction.READ_EXECUTIONS))
    assert res_exec.success is True

    # 7. READ_AUDIT
    res_audit = service.execute_control(OperationsControlRequest(action=OperationsControlAction.READ_AUDIT))
    assert res_audit.success is True

def test_operations_control_mutating_actions_forbidden():
    # Attempting to construct OperationsControlRequest with forbidden actions fails schema validation
    with pytest.raises(ValueError):
        OperationsControlRequest(action="APPROVE_REQUEST")  # type: ignore

    with pytest.raises(ValueError):
        OperationsControlRequest(action="EXECUTE_TOOL")  # type: ignore

    with pytest.raises(ValueError):
        OperationsControlRequest(action="OVERRIDE_POLICY")  # type: ignore

    with pytest.raises(ValueError):
        OperationsControlRequest(action="DELETE_AUDIT")  # type: ignore
