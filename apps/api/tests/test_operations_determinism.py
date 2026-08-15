from app.security.models import (
    ToolRequest,
    AgentIdentity,
    ToolCategory,
    ActionType,
)
from app.security.gateway import SecurityDecisionGateway
from app.security.operations.service import SecurityOperationsService

def test_operations_service_repeated_reads_are_deterministic():
    gateway = SecurityDecisionGateway()
    service = SecurityOperationsService()

    req = ToolRequest(
        request_id="req-det-op-01",
        agent=AgentIdentity(name="Agent"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="calculator",
        parameters={"op": "add", "a": 10, "b": 20},
    )
    service.record_evaluation(gateway.evaluate(req))

    # Perform 10 repeated reads of overview and metrics
    overviews = [service.get_overview() for _ in range(10)]
    metrics_list = [service.get_metrics() for _ in range(10)]

    first_overview = overviews[0]
    first_metrics = metrics_list[0]

    for ov in overviews[1:]:
        assert ov.overall_health.status == first_overview.overall_health.status
        assert ov.metrics.total_requests == first_overview.metrics.total_requests
        assert ov.metrics.allowed == first_overview.metrics.allowed
        assert len(ov.recent_decisions) == len(first_overview.recent_decisions)

    for m in metrics_list[1:]:
        assert m.total_requests == first_metrics.total_requests
        assert m.allowed == first_metrics.allowed
        assert m.blocked == first_metrics.blocked
        assert m.require_approval == first_metrics.require_approval
