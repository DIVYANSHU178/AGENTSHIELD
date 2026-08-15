from fastapi.testclient import TestClient
from app.main import app
from app.security.operations.service import SecurityOperationsService, set_operations_service
from app.security.models import (
    ToolRequest,
    AgentIdentity,
    ToolCategory,
    ActionType,
)
from app.security.gateway import SecurityDecisionGateway

client = TestClient(app)

def setup_function():
    # Fresh operations service before each test
    service = SecurityOperationsService()
    set_operations_service(service)

def test_api_operations_health_endpoint():
    response = client.get("/api/v1/security/operations/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert len(data["components"]) >= 6

def test_api_operations_overview_endpoint():
    response = client.get("/api/v1/security/operations/overview")
    assert response.status_code == 200
    data = response.json()
    assert "overall_health" in data
    assert "metrics" in data
    assert "recent_threats" in data
    assert "recent_decisions" in data
    assert "recent_executions" in data

def test_api_operations_metrics_endpoint():
    response = client.get("/api/v1/security/operations/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "total_requests" in data
    assert "allowed" in data
    assert "blocked" in data

def test_api_operations_threats_and_decisions_endpoints():
    # Populate a sample evaluation
    service = SecurityOperationsService()
    set_operations_service(service)
    gateway = SecurityDecisionGateway()

    req = ToolRequest(
        request_id="req-api-thr",
        agent=AgentIdentity(name="Agent"),
        tool_name="file.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target=".env",
    )
    service.record_evaluation(gateway.evaluate(req))

    # GET /threats
    res_thr = client.get("/api/v1/security/operations/threats")
    assert res_thr.status_code == 200
    threats = res_thr.json()
    assert len(threats) >= 1
    assert threats[0]["request_id"] == "req-api-thr"

    # GET /decisions
    res_dec = client.get("/api/v1/security/operations/decisions")
    assert res_dec.status_code == 200
    decisions = res_dec.json()
    assert len(decisions) >= 1
    assert decisions[0]["request_id"] == "req-api-thr"

def test_api_operations_control_endpoint():
    # Valid READ_STATUS
    res_valid = client.post(
        "/api/v1/security/operations/control",
        json={"action": "READ_STATUS", "limit": 10},
    )
    assert res_valid.status_code == 200
    assert res_valid.json()["success"] is True

    # Invalid Action (e.g. attempting to approve)
    res_invalid = client.post(
        "/api/v1/security/operations/control",
        json={"action": "APPROVE_REQUEST"},
    )
    assert res_invalid.status_code in (400, 422)
