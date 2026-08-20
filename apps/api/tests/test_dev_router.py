import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
from app.main import app
from app.config import settings
from app.security.models import (
    SecurityDecisionType,
    EventType,
)
from app.security.runtime.contracts import RuntimeExecutionStatus
from app.security.operations.service import get_operations_service
from app.security.approval.service import get_approval_service

def test_dev_endpoint_allow_scenario():
    from app.security.models.utils import generate_uuid
    req_id = f"custom-allow-req-{generate_uuid()[:8]}"
    client = TestClient(app)
    resp = client.post(
        "/api/v1/dev/test-requests",
        json={"scenario": "ALLOW", "request_id": req_id},
    )
    assert resp.status_code == 200
    data = resp.json()

    # Invariants
    assert data["scenario"] == "ALLOW"
    assert data["request_id"] == req_id
    assert data["decision"] == "ALLOW"
    assert data["status"] == "COMPLETED"
    assert data["authorized"] is True
    assert data["executed"] is True
    assert data["success"] is True
    assert data["approval_id"] is None
    assert data["result"] is not None
    assert data["result"]["result"] == 30.0
    assert data["error"] is None

    # Check that console operations synchronized
    ops = get_operations_service()
    decisions = ops.get_decisions(limit=10)
    assert any(d.request_id == req_id and d.decision == SecurityDecisionType.ALLOW for d in decisions)

def test_dev_endpoint_require_approval_scenario():
    from app.security.models.utils import generate_uuid
    req_id = f"custom-approval-req-{generate_uuid()[:8]}"
    client = TestClient(app)
    resp = client.post(
        "/api/v1/dev/test-requests",
        json={"scenario": "REQUIRE_APPROVAL", "request_id": req_id},
    )
    assert resp.status_code == 200
    data = resp.json()

    # Invariants
    assert data["scenario"] == "REQUIRE_APPROVAL"
    assert data["request_id"] == req_id
    assert data["decision"] == "REQUIRE_APPROVAL"
    assert data["status"] == "DENIED"
    assert data["authorized"] is False
    assert data["executed"] is False
    assert data["success"] is False
    assert data["approval_id"] is not None
    assert data["result"] is None
    assert "REQUIRE_APPROVAL" in data["error"]

    # Verify approval was created in PENDING state
    approval_svc = get_approval_service()
    approval = approval_svc.get_approval(data["approval_id"])
    assert approval.status.value == "PENDING"
    assert approval.request_id == req_id

def test_dev_endpoint_block_scenario_and_secret_redaction():
    from app.security.models.utils import generate_uuid
    req_id = f"custom-block-req-{generate_uuid()[:8]}"
    client = TestClient(app)
    resp = client.post(
        "/api/v1/dev/test-requests",
        json={"scenario": "BLOCK", "request_id": req_id},
    )
    assert resp.status_code == 200
    data = resp.json()

    # Invariants
    assert data["scenario"] == "BLOCK"
    assert data["request_id"] == req_id
    assert data["decision"] == "BLOCK"
    assert data["status"] == "DENIED"
    assert data["authorized"] is False
    assert data["executed"] is False
    assert data["success"] is False
    assert data["approval_id"] is None
    assert data["result"] is None
    assert "BLOCK" in data["error"]

    # Strict non-leakage check: raw secret MUST NOT appear anywhere in response text or JSON
    raw_secret = "sk-proj-TEST-SECRET-DO-NOT-LEAK"
    assert raw_secret not in resp.text
    assert "api_key" not in resp.text

def test_dev_endpoint_optional_request_id():
    client = TestClient(app)
    resp = client.post(
        "/api/v1/dev/test-requests",
        json={"scenario": "ALLOW"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["request_id"].startswith("dev-allow-")

def test_dev_endpoint_malformed_requests_produce_422():
    client = TestClient(app)

    # 1. Unknown scenario
    resp1 = client.post(
        "/api/v1/dev/test-requests",
        json={"scenario": "UNKNOWN_SCENARIO"},
    )
    assert resp1.status_code == 422

    # 2. Missing scenario
    resp2 = client.post(
        "/api/v1/dev/test-requests",
        json={"request_id": "req-missing-scenario"},
    )
    assert resp2.status_code == 422

    # 3. Malformed JSON body
    resp3 = client.post(
        "/api/v1/dev/test-requests",
        content="not-a-valid-json",
        headers={"Content-Type": "application/json"},
    )
    assert resp3.status_code == 422

    # 4. Null scenario
    resp4 = client.post(
        "/api/v1/dev/test-requests",
        json={"scenario": None},
    )
    assert resp4.status_code == 422

def test_dev_endpoint_disabled_in_production_mode():
    client = TestClient(app)
    with patch.object(settings, "ENVIRONMENT", "production"):
        resp = client.post(
            "/api/v1/dev/test-requests",
            json={"scenario": "ALLOW"},
        )
        assert resp.status_code in (403, 404)
        assert "Development endpoints are disabled" in resp.text or resp.status_code == 404

def test_dev_endpoint_does_not_bypass_pipeline():
    """Verify that requests pass genuinely through Gateway -> Enforcement -> Sandbox -> Audit."""
    from app.security.models.utils import generate_uuid
    client = TestClient(app)
    req_id = f"pipeline-audit-check-{generate_uuid()}"
    resp = client.post(
        "/api/v1/dev/test-requests",
        json={"scenario": "ALLOW", "request_id": req_id},
    )
    assert resp.status_code == 200

    ops = get_operations_service()
    events = ops.audit_trail.get_events(request_id=req_id)
    event_types = [e.event_type for e in events]
    assert event_types == [
        EventType.REQUESTED,
        EventType.ANALYZED,
        EventType.ALLOWED,
        EventType.EXECUTED,
    ]
