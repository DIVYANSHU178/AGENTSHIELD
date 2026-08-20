import uuid
from fastapi.testclient import TestClient
from app.main import app
from app.security.models import SecurityDecisionType
from app.security.approval.service import get_approval_service
from app.security.operations.service import get_operations_service

def test_api_list_scenarios():
    client = TestClient(app)
    resp = client.get("/api/v1/dev/laboratory/scenarios")
    assert resp.status_code == 200
    scenarios = resp.json()
    assert len(scenarios) == 20

    # Filter by category
    resp_filtered = client.get("/api/v1/dev/laboratory/scenarios?category=ANTI_TAMPER")
    assert resp_filtered.status_code == 200
    anti_tamper = resp_filtered.json()
    assert len(anti_tamper) == 8

def test_api_run_all_20_scenarios_live():
    client = TestClient(app)
    list_resp = client.get("/api/v1/dev/laboratory/scenarios")
    scenarios = list_resp.json()
    run_prefix = uuid.uuid4().hex[:8]

    for s in scenarios:
        sid = s["scenario_id"]
        run_resp = client.post(
            "/api/v1/dev/laboratory/run",
            json={"scenario_id": sid, "request_id": f"api-test-{run_prefix}-{sid.lower()}"},
        )
        assert run_resp.status_code == 200, f"Scenario '{sid}' failed: {run_resp.text}"
        data = run_resp.json()
        assert data["passed"] is True, f"Scenario '{sid}' assertion failed: {data['message']}"

def test_api_operations_and_approval_synchronization():
    client = TestClient(app)
    req_id = f"sync-test-prompt-{uuid.uuid4().hex[:8]}"
    run_resp = client.post(
        "/api/v1/dev/laboratory/run",
        json={"scenario_id": "REQUIRE_APPROVAL_PROMPT_INJECTION", "request_id": req_id},
    )
    assert run_resp.status_code == 200
    data = run_resp.json()
    app_id = data["approval_id"]
    assert app_id is not None

    # Check that approval service has this approval
    app_svc = get_approval_service()
    approval = app_svc.get_approval(app_id)
    assert approval.request_id == req_id
    assert approval.status.value == "PENDING"

    # Check that operations service recorded the decision
    ops = get_operations_service()
    decisions = ops.get_decisions(limit=10)
    assert any(d.request_id == req_id for d in decisions)

