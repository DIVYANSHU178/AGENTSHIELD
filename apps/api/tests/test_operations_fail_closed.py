import pytest
from app.security.operations.service import SecurityOperationsService
from app.security.operations.contracts import (
    ComponentHealth,
    ComponentStatus,
    OperationsControlRequest,
)

def test_operations_service_fail_closed_on_none_inputs():
    service = SecurityOperationsService()

    # None evaluation recording does not crash or corrupt
    service.record_evaluation(None)
    assert service.get_metrics().total_requests == 0

    # None runtime result recording does not crash
    service.record_runtime_execution(None)
    assert service.get_metrics().runtime_requests == 0

    # None control request fails safely
    with pytest.raises(ValueError):
        service.execute_control(None)  # type: ignore

@pytest.mark.parametrize(
    "invalid_input",
    [
        "",
        "   ",
        None,
    ],
)
def test_component_health_rejects_empty_strings(invalid_input):
    with pytest.raises(ValueError):
        ComponentHealth(
            name=invalid_input,
            status=ComponentStatus.HEALTHY,
            details="Valid details",
        )

    with pytest.raises(ValueError):
        ComponentHealth(
            name="ValidName",
            status=ComponentStatus.HEALTHY,
            details=invalid_input,
        )
