import pytest
from datetime import timedelta
from app.security.approval.contracts import (
    ApprovalStatus,
    ApprovalDecision,
    ReviewerIdentity,
    ApprovalResolution,
    ApprovalRequest,
)
from app.security.models import AgentIdentity, ToolCategory, ActionType, Severity, SecurityDecisionType
from app.security.models.utils import utc_now, generate_uuid

def test_reviewer_identity_and_resolution_immutability():
    reviewer = ReviewerIdentity(
        reviewer_id="rev-001",
        reviewer_name="Alice Security",
        role="sec_lead",
        metadata={"clearance": "level_3"},
    )
    assert reviewer.reviewer_id == "rev-001"
    assert reviewer.metadata["clearance"] == "level_3"

    with pytest.raises(Exception):
        reviewer.reviewer_id = "rev-002"  # type: ignore

    with pytest.raises(TypeError):
        reviewer.metadata["tamper"] = True

    resolution = ApprovalResolution(
        approval_id="app-123",
        request_id="req-123",
        reviewer=reviewer,
        decision=ApprovalDecision.APPROVE,
        reason="Verified legitimate administrative prompt update.",
        metadata={"ticket": "SEC-999"},
    )
    assert resolution.decision == ApprovalDecision.APPROVE
    assert resolution.resolved_at is not None

    with pytest.raises(TypeError):
        resolution.metadata["tamper"] = True

def test_reviewer_identity_validation_matrix():
    # Valid reviewer ID
    rev = ReviewerIdentity(reviewer_id="sec-admin-01")
    assert rev.reviewer_id == "sec-admin-01"

    # Stripped whitespace
    rev_ws = ReviewerIdentity(reviewer_id="   sec-admin-02   ")
    assert rev_ws.reviewer_id == "sec-admin-02"

    # Rejection of None
    with pytest.raises(Exception):
        ReviewerIdentity(reviewer_id=None)  # type: ignore

    # Rejection of empty string
    with pytest.raises(Exception):
        ReviewerIdentity(reviewer_id="")

    # Rejection of whitespace-only string
    with pytest.raises(Exception):
        ReviewerIdentity(reviewer_id="   ")

    # Rejection of non-string
    with pytest.raises(Exception):
        ReviewerIdentity(reviewer_id=12345)  # type: ignore

    with pytest.raises(Exception):
        ReviewerIdentity(reviewer_id=["admin"])  # type: ignore

    with pytest.raises(Exception):
        ReviewerIdentity(reviewer_id={"id": "admin"})  # type: ignore


def test_approval_request_deep_immutability():
    agent = AgentIdentity(name="AgentA")
    created = utc_now()
    expires = created + timedelta(hours=1)

    app_req = ApprovalRequest(
        approval_id="app-test-01",
        request_id="req-test-01",
        agent=agent,
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="calculator",
        parameters={"op": "add", "a": 10, "b": 20},
        destination=None,
        request_fingerprint="abc123sha256fingerprint",
        risk_score=55.0,
        severity=Severity.MEDIUM,
        created_at=created,
        expires_at=expires,
        status=ApprovalStatus.PENDING,
        metadata={"environment": "production"},
    )

    # Immutability checks
    with pytest.raises(Exception):
        app_req.status = ApprovalStatus.APPROVED  # type: ignore

    with pytest.raises(TypeError):
        app_req.parameters["a"] = 999

    with pytest.raises(TypeError):
        app_req.metadata["injected"] = True

def test_approval_request_expiration_helpers():
    created = utc_now()
    expires = created + timedelta(seconds=2)

    app_req = ApprovalRequest(
        approval_id="app-test-02",
        request_id="req-test-02",
        agent=AgentIdentity(name="AgentB"),
        tool_name="file.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="conf.json",
        parameters={},
        request_fingerprint="fp123",
        risk_score=60.0,
        severity=Severity.HIGH,
        created_at=created,
        expires_at=expires,
    )

    assert not app_req.is_expired(current_time=created + timedelta(seconds=1))
    assert app_req.is_expired(current_time=created + timedelta(seconds=3))
    assert app_req.can_resolve()

def test_approval_request_json_roundtrip():
    agent = AgentIdentity(name="AgentC")
    created = utc_now()
    expires = created + timedelta(hours=2)

    original = ApprovalRequest(
        approval_id=generate_uuid(),
        request_id="req-json-01",
        agent=agent,
        tool_name="string.transform",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="text",
        parameters={"transform": "uppercase", "text": "hello"},
        request_fingerprint="sha256_mock_fingerprint",
        risk_score=50.0,
        severity=Severity.MEDIUM,
        created_at=created,
        expires_at=expires,
        status=ApprovalStatus.PENDING,
        metadata={"tag": "demo"},
    )

    json_str = original.model_dump_json()
    reconstituted = ApprovalRequest.model_validate_json(json_str)

    assert reconstituted.approval_id == original.approval_id
    assert reconstituted.request_id == original.request_id
    assert reconstituted.request_fingerprint == original.request_fingerprint
    assert reconstituted.parameters == original.parameters
    assert reconstituted.status == original.status
    assert reconstituted.risk_score == original.risk_score
