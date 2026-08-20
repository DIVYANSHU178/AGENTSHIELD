import uuid
from unittest.mock import patch
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings
from app.security.models import EventType
from app.security.operations.service import get_operations_service

def test_laboratory_endpoints_production_lockout():
    client = TestClient(app)
    with patch.object(settings, "ENVIRONMENT", "production"):
        # GET /scenarios must return 403
        r1 = client.get("/api/v1/dev/laboratory/scenarios")
        assert r1.status_code == 403

        # POST /run must return 403
        r2 = client.post("/api/v1/dev/laboratory/run", json={"scenario_id": "ALLOW_CLEAN"})
        assert r2.status_code == 403

def test_laboratory_secret_redaction_in_api_response():
    client = TestClient(app)
    resp = client.post("/api/v1/dev/laboratory/run", json={"scenario_id": "BLOCK_EXFILTRATION"})
    assert resp.status_code == 200
    text = resp.text
    assert "sk-proj" not in text
    assert "api_key" not in text

def test_laboratory_audit_trail_events_generated():
    client = TestClient(app)
    req_id = f"lab-audit-verify-{uuid.uuid4().hex[:8]}"
    resp = client.post(
        "/api/v1/dev/laboratory/run",
        json={"scenario_id": "ALLOW_CLEAN", "request_id": req_id},
    )
    assert resp.status_code == 200

    ops = get_operations_service()
    events = ops.audit_trail.get_events(request_id=req_id)
    event_types = [e.event_type for e in events]
    assert EventType.REQUESTED in event_types
    assert EventType.ANALYZED in event_types
    assert EventType.ALLOWED in event_types
    assert EventType.EXECUTED in event_types

def test_laboratory_malformed_api_inputs_return_422_or_404():
    client = TestClient(app)

    # Unknown scenario ID -> 404
    r1 = client.post("/api/v1/dev/laboratory/run", json={"scenario_id": "NON_EXISTENT"})
    assert r1.status_code == 404

    # Empty scenario ID -> 422
    r2 = client.post("/api/v1/dev/laboratory/run", json={"scenario_id": ""})
    assert r2.status_code == 422

    # Whitespace-only scenario ID -> 422
    r3 = client.post("/api/v1/dev/laboratory/run", json={"scenario_id": "   "})
    assert r3.status_code == 422

    # Missing scenario_id field -> 422
    r4 = client.post("/api/v1/dev/laboratory/run", json={"request_id": "req-1"})
    assert r4.status_code == 422
