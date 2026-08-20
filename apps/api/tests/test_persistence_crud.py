"""
Phase 13 Persistence CRUD and Domain Repository Unit Tests.

Tests table initialization, CRUD operations, filtering, ordering, and redactions
for AuditRepository, DecisionRepository, ThreatRepository, ExecutionRepository, and ApprovalRepository.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database.base import Base
from app.database.session import init_db
from app.security.models import (
    ToolCategory,
    ActionType,
    ThreatType,
    Severity,
    SecurityDecisionType,
    EventType,
    AgentIdentity,
    SecurityEvent,
)
from app.security.models.utils import generate_uuid, utc_now
from app.security.operations.contracts import (
    SecurityDecisionItem,
    ThreatActivityItem,
    ExecutionActivityItem,
)
from app.security.runtime.contracts import RuntimeExecutionStatus
from app.security.approval.contracts import (
    ApprovalRequest,
    ApprovalResolution,
    ApprovalStatus,
    ApprovalDecision,
    ReviewerIdentity,
)
from app.security.approval.errors import (
    ApprovalNotFoundError,
    InvalidApprovalStateTransitionError,
)
from app.security.persistence import (
    AuditRepository,
    DecisionRepository,
    ThreatRepository,
    ExecutionRepository,
    ApprovalRepository,
)


@pytest.fixture
def test_session_factory(tmp_path):
    db_file = tmp_path / "persistence_test.db"
    db_url = f"sqlite:///{db_file}"
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    init_db(target_engine=engine)
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)


def test_audit_repository_crud_and_chronology(test_session_factory):
    repo = AuditRepository(session_factory=test_session_factory)

    ev1 = SecurityEvent(
        event_id="evt-001",
        request_id="req-100",
        event_type=EventType.REQUESTED,
        timestamp=utc_now(),
        actor="client",
        details={"prompt": "Test secret sk-proj-abcdef1234567890", "api_key": "my-secret-key"},
        metadata={"stage": "ingress"},
    )
    ev2 = SecurityEvent(
        event_id="evt-002",
        request_id="req-100",
        event_type=EventType.ANALYZED,
        timestamp=utc_now(),
        actor="detector",
        details={"score": 0.0},
        metadata={"stage": "analysis"},
    )
    ev3 = SecurityEvent(
        event_id="evt-003",
        request_id="req-100",
        event_type=EventType.ALLOWED,
        timestamp=utc_now(),
        actor="gateway",
        details={"decision": "ALLOW"},
        metadata={"stage": "gateway"},
    )

    repo.save(ev1)
    repo.save(ev2)
    repo.save(ev3)

    # Count
    assert repo.count() == 3
    assert repo.count(request_id="req-100") == 3
    assert repo.count(request_id="req-nonexistent") == 0

    # Get by event_id
    fetched = repo.get_by_event_id("evt-001")
    assert fetched is not None
    assert fetched.event_id == "evt-001"
    assert fetched.event_type == EventType.REQUESTED
    # Secret must be redacted
    assert "sk-proj" not in str(fetched.details)
    assert "[REDACTED_TOKEN]" in str(fetched.details)

    # Ordering preservation
    events = repo.get_events(request_id="req-100")
    assert len(events) == 3
    assert [e.event_type for e in events] == [EventType.REQUESTED, EventType.ANALYZED, EventType.ALLOWED]

    # Idempotent replay safety (no duplicate created)
    repo.save(ev1)
    assert repo.count() == 3


def test_decision_repository_crud(test_session_factory):
    repo = DecisionRepository(session_factory=test_session_factory)

    d1 = SecurityDecisionItem(
        decision_id="dec-1",
        request_id="req-1",
        decision=SecurityDecisionType.ALLOW,
        risk_score=0.0,
        severity=Severity.INFO,
        policy_id="policy.default.allow",
        reason="Clean request allowed.",
        threat_count=0,
        timestamp=utc_now(),
        metadata={"secret_key": "sk-proj-do-not-leak"},
    )
    d2 = SecurityDecisionItem(
        decision_id="dec-2",
        request_id="req-2",
        decision=SecurityDecisionType.BLOCK,
        risk_score=100.0,
        severity=Severity.CRITICAL,
        policy_id="policy.risk.critical.block",
        reason="Malicious request blocked.",
        threat_count=2,
        timestamp=utc_now(),
    )

    repo.save(d1)
    repo.save(d2)

    assert repo.count() == 2
    assert repo.count(decision=SecurityDecisionType.ALLOW) == 1
    assert repo.count(decision=SecurityDecisionType.BLOCK) == 1
    assert repo.count(severity=Severity.CRITICAL) == 1

    fetched_d1 = repo.get_by_id("dec-1")
    assert fetched_d1 is not None
    assert fetched_d1.decision == SecurityDecisionType.ALLOW
    # Redacted in metadata
    assert "sk-proj" not in str(fetched_d1.metadata)

    listed = repo.list_decisions(limit=10)
    assert len(listed) == 2
    assert listed[0].decision_id == "dec-2"  # Newest first


def test_threat_repository_crud(test_session_factory):
    repo = ThreatRepository(session_factory=test_session_factory)

    t1 = ThreatActivityItem(
        threat_id="thr-1",
        threat_type=ThreatType.PROMPT_INJECTION,
        severity=Severity.HIGH,
        detector="prompt_injection_detector",
        request_id="req-1",
        title="Prompt Injection Attack",
        description="Override system instruction attempted",
        confidence=0.92,
        timestamp=utc_now(),
        metadata={"evidence": "ignore previous instructions"},
    )
    t2 = ThreatActivityItem(
        threat_id="thr-2",
        threat_type=ThreatType.CREDENTIAL_ACCESS,
        severity=Severity.CRITICAL,
        detector="credential_detector",
        request_id="req-2",
        title="Credential Access Attempt",
        description="Reading private key",
        confidence=0.98,
        timestamp=utc_now(),
        metadata={"token": "sk-proj-secret-token"},
    )

    repo.save(t1)
    repo.save(t2)

    assert repo.count() == 2
    assert repo.count(severity=Severity.CRITICAL) == 1
    assert repo.count(severity=Severity.HIGH) == 1

    critical_threats = repo.list_threats(severity=Severity.CRITICAL)
    assert len(critical_threats) == 1
    assert critical_threats[0].threat_id == "thr-2"
    assert "sk-proj" not in str(critical_threats[0].metadata)


def test_execution_repository_crud(test_session_factory):
    repo = ExecutionRepository(session_factory=test_session_factory)

    ex1 = ExecutionActivityItem(
        execution_id="exec-1",
        request_id="req-1",
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        status=RuntimeExecutionStatus.COMPLETED,
        success=True,
        duration_ms=5.4,
        timestamp=utc_now(),
        metadata={"authorized": True, "executed": True},
    )
    ex2 = ExecutionActivityItem(
        execution_id="exec-2",
        request_id="req-2",
        tool_name="network.upload",
        tool_category=ToolCategory.NETWORK,
        action=ActionType.UPLOAD,
        status=RuntimeExecutionStatus.DENIED,
        success=False,
        duration_ms=1.1,
        error="Security policy blocked execution",
        timestamp=utc_now(),
        metadata={"authorized": False, "executed": False},
    )

    repo.save(ex1)
    repo.save(ex2)

    assert repo.count() == 2
    assert repo.count(status=RuntimeExecutionStatus.COMPLETED) == 1
    assert repo.count(status=RuntimeExecutionStatus.DENIED) == 1
    assert repo.count(success=True) == 1

    fetched = repo.get_by_id("exec-1")
    assert fetched is not None
    assert fetched.success is True
    assert fetched.tool_name == "calculator.compute"


def test_approval_repository_crud_and_state_machine(test_session_factory):
    repo = ApprovalRepository(session_factory=test_session_factory)

    agent = AgentIdentity(agent_id="ag-01", name="DevAgent")
    app = ApprovalRequest(
        approval_id="app-101",
        request_id="req-101",
        agent=agent,
        tool_name="database.drop",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="users_table",
        parameters={"force": True, "api_key": "sk-proj-test-secret"},
        request_fingerprint="sha256_mock_fingerprint_101",
        risk_score=65.0,
        severity=Severity.HIGH,
        decision=SecurityDecisionType.REQUIRE_APPROVAL,
        created_at=utc_now(),
        expires_at=utc_now(),
        status=ApprovalStatus.PENDING,
    )

    repo.save(app)

    # Initial state
    stored = repo.get_by_id("app-101")
    assert stored is not None
    assert stored.status == ApprovalStatus.PENDING
    assert stored.request_id == "req-101"
    assert "sk-proj" not in str(stored.parameters)

    # Get by request_id
    by_req = repo.get_by_request_id("req-101")
    assert by_req is not None
    assert by_req.approval_id == "app-101"

    # Transition PENDING -> APPROVED
    reviewer = ReviewerIdentity(reviewer_id="rev-01", reviewer_name="Admin", role="security_lead")
    resolution = ApprovalResolution(
        resolution_id="res-001",
        approval_id="app-101",
        request_id="req-101",
        reviewer=reviewer,
        decision=ApprovalDecision.APPROVE,
        reason="Approved after manual inspection.",
        resolved_at=utc_now(),
    )

    approved = repo.update_status("app-101", ApprovalStatus.APPROVED, resolution=resolution)
    assert approved.status == ApprovalStatus.APPROVED
    assert approved.resolution is not None
    assert approved.resolution.reviewer.reviewer_name == "Admin"

    # Attempt illegal transition from terminal state APPROVED -> REJECTED
    with pytest.raises(InvalidApprovalStateTransitionError):
        repo.update_status("app-101", ApprovalStatus.REJECTED)

    # Unknown approval lookup
    assert repo.get_by_id("unknown-id") is None
    with pytest.raises(ApprovalNotFoundError):
        repo.update_status("unknown-id", ApprovalStatus.APPROVED)
