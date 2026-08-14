import pytest
from datetime import timezone
from app.security.models import (
    ToolRequest,
    AgentIdentity,
    ToolCategory,
    ActionType,
    ThreatReport,
    ThreatSignal,
    ThreatType,
    Severity,
    RiskAssessment,
    SecurityDecision,
    SecurityDecisionType,
    EventType,
    SecurityEvent,
)
from app.security.enforcement.result import EnforcementResult
from app.security.enforcement.authorization import ExecutionAuthorization
from app.security.audit.factory import SecurityEventFactory

@pytest.fixture
def sample_request():
    return ToolRequest(
        request_id="req-factory-001",
        agent=AgentIdentity(agent_id="ag-001", name="TestAgent"),
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="sandbox/public/sample.txt",
        parameters={"mode": "readonly"},
    )

@pytest.fixture
def sample_threat_report(sample_request):
    return ThreatReport(
        request_id=sample_request.request_id,
        signals=[],
        overall_severity=Severity.INFO,
        summary="No threats detected",
    )

@pytest.fixture
def sample_risk_assessment(sample_request):
    return RiskAssessment(
        assessment_id="risk-001",
        request_id=sample_request.request_id,
        risk_score=0.0,
        severity=Severity.INFO,
        contributing_signals=[],
        rationale="Clean request",
    )

def test_create_requested_event(sample_request):
    event = SecurityEventFactory.create_requested_event(sample_request)

    assert isinstance(event, SecurityEvent)
    assert event.event_type == EventType.REQUESTED
    assert event.request_id == sample_request.request_id
    assert event.actor == "TestAgent"
    assert event.timestamp.tzinfo == timezone.utc
    assert event.details["tool_name"] == "filesystem.read"
    assert event.details["tool_category"] == "FILESYSTEM"
    assert event.details["action"] == "READ"
    assert event.details["has_parameters"] is True
    assert "mode" in event.details["parameter_keys"]

def test_create_analyzed_event(sample_request, sample_threat_report, sample_risk_assessment):
    event = SecurityEventFactory.create_analyzed_event(
        request=sample_request,
        threat_report=sample_threat_report,
        risk_assessment=sample_risk_assessment,
    )

    assert event.event_type == EventType.ANALYZED
    assert event.request_id == sample_request.request_id
    assert event.actor == "security_analyzer"
    assert event.timestamp.tzinfo == timezone.utc
    assert event.details["risk_score"] == 0.0
    assert event.details["risk_severity"] == "INFO"
    assert event.details["threat_count"] == 0

def test_create_decision_event_allow(sample_request, sample_risk_assessment):
    decision = SecurityDecision(
        decision_id="dec-001",
        request_id=sample_request.request_id,
        decision=SecurityDecisionType.ALLOW,
        risk_assessment_id=sample_risk_assessment.assessment_id,
        reason="Low risk allowed",
        policy_id="policy.default.allow",
    )

    event = SecurityEventFactory.create_decision_event(
        request=sample_request,
        decision=decision,
        risk_assessment=sample_risk_assessment,
    )

    assert event.event_type == EventType.ALLOWED
    assert event.request_id == sample_request.request_id
    assert event.details["decision"] == "ALLOW"
    assert event.details["policy_id"] == "policy.default.allow"

def test_create_decision_event_require_approval(sample_request, sample_risk_assessment):
    decision = SecurityDecision(
        decision_id="dec-002",
        request_id=sample_request.request_id,
        decision=SecurityDecisionType.REQUIRE_APPROVAL,
        risk_assessment_id=sample_risk_assessment.assessment_id,
        reason="Medium risk requires review",
        policy_id="policy.medium.approval",
    )

    event = SecurityEventFactory.create_decision_event(
        request=sample_request,
        decision=decision,
        risk_assessment=sample_risk_assessment,
    )

    assert event.event_type == EventType.APPROVAL_REQUIRED
    assert event.request_id == sample_request.request_id
    assert event.details["decision"] == "REQUIRE_APPROVAL"

def test_create_decision_event_blocked(sample_request, sample_risk_assessment):
    decision = SecurityDecision(
        decision_id="dec-003",
        request_id=sample_request.request_id,
        decision=SecurityDecisionType.BLOCK,
        risk_assessment_id=sample_risk_assessment.assessment_id,
        reason="Critical threat blocked",
        policy_id="policy.critical.block",
    )

    event = SecurityEventFactory.create_decision_event(
        request=sample_request,
        decision=decision,
        risk_assessment=sample_risk_assessment,
    )

    assert event.event_type == EventType.BLOCKED
    assert event.request_id == sample_request.request_id
    assert event.details["decision"] == "BLOCK"

def test_create_enforcement_event():
    res = EnforcementResult(
        request_id="req-enf-123",
        correlation_id="req-enf-123",
        decision=SecurityDecisionType.BLOCK,
        authorized=False,
        authorization=None,
        reason="Blocked by boundary",
    )

    event = SecurityEventFactory.create_enforcement_event(res)
    assert event.event_type == EventType.BLOCKED
    assert event.request_id == "req-enf-123"
    assert event.details["authorized"] is False
    assert event.details["decision"] == "BLOCK"

def test_create_executed_event_metadata_only():
    event = SecurityEventFactory.create_executed_event(
        request_id="req-exec-001",
        actor="external_runtime",
        outcome_metadata={"output_bytes": 1024, "status": "success"},
    )

    assert event.event_type == EventType.EXECUTED
    assert event.request_id == "req-exec-001"
    assert event.actor == "external_runtime"
    assert event.details["output_bytes"] == 1024

def test_create_failed_event_metadata_only():
    event = SecurityEventFactory.create_failed_event(
        request_id="req-fail-001",
        actor="external_runtime",
        error_message="Runtime execution crashed",
    )

    assert event.event_type == EventType.FAILED
    assert event.request_id == "req-fail-001"
    assert event.details["error"] == "Runtime execution crashed"
