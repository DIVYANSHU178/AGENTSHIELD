import json
import pytest
from pydantic import ValidationError
from app.security.models import (
    SecurityEvent,
    EventType,
)
from app.security.audit.trail import SecurityAuditTrail
from app.security.audit.errors import InvalidSecurityEventError
from app.security.models.utils import generate_uuid, utc_now

def make_event(req_id: str, ev_type: EventType, actor: str = "test_actor") -> SecurityEvent:
    return SecurityEvent(
        event_id=generate_uuid(),
        request_id=req_id,
        event_type=ev_type,
        timestamp=utc_now(),
        actor=actor,
        details={"status": "ok"},
        metadata={"seq": 1},
    )

def test_audit_trail_record_and_get_events():
    trail = SecurityAuditTrail()
    assert len(trail) == 0

    e1 = make_event("req-101", EventType.REQUESTED)
    e2 = make_event("req-101", EventType.ANALYZED)
    e3 = make_event("req-101", EventType.ALLOWED)
    e4 = make_event("req-102", EventType.REQUESTED)

    trail.record(e1)
    trail.record(e2)
    trail.record(e3)
    trail.record(e4)

    assert len(trail) == 4
    assert trail.count() == 4
    assert trail.count("req-101") == 3
    assert trail.count("req-102") == 1

    # Filter by request_id
    req101_events = trail.get_events("req-101")
    assert len(req101_events) == 3
    assert req101_events[0].event_type == EventType.REQUESTED
    assert req101_events[1].event_type == EventType.ANALYZED
    assert req101_events[2].event_type == EventType.ALLOWED

def test_audit_trail_event_ordering_preservation():
    trail = SecurityAuditTrail()

    events = [
        make_event("req-order", EventType.REQUESTED),
        make_event("req-order", EventType.ANALYZED),
        make_event("req-order", EventType.APPROVAL_REQUIRED),
    ]

    trail.record_all(events)

    seq = trail.get_event_sequence("req-order")
    assert seq == [EventType.REQUESTED, EventType.ANALYZED, EventType.APPROVAL_REQUIRED]

def test_audit_trail_defensive_copying_immutability():
    """
    CRITICAL: Mutating collections returned by get_events() MUST NOT mutate internal audit state.
    """
    trail = SecurityAuditTrail()
    e1 = make_event("req-defensive", EventType.REQUESTED)
    e2 = make_event("req-defensive", EventType.ANALYZED)

    trail.record(e1)
    trail.record(e2)

    # 1. Mutate returned list
    retrieved = trail.get_events("req-defensive")
    assert len(retrieved) == 2
    retrieved.clear()  # Caller clears their list

    # Internal trail MUST still contain both events!
    assert len(trail.get_events("req-defensive")) == 2
    assert len(trail) == 2

    # 2. Mutate returned list via pop/append
    retrieved_all = trail.get_events()
    retrieved_all.pop()
    retrieved_all.append(make_event("req-fake", EventType.BLOCKED))

    assert len(trail.get_events()) == 2
    assert trail.get_events()[0].request_id == "req-defensive"

def test_security_event_model_frozen_immutability():
    """SecurityEvent itself is frozen=True and cannot be mutated."""
    event = make_event("req-immutable", EventType.REQUESTED)
    with pytest.raises(ValidationError):
        event.actor = "malicious_actor"

def test_audit_trail_rejects_invalid_malformed_events():
    trail = SecurityAuditTrail()

    # None event
    with pytest.raises(InvalidSecurityEventError):
        trail.record(None)  # type: ignore

    # Non-SecurityEvent object
    with pytest.raises(InvalidSecurityEventError):
        trail.record({"request_id": "req-123", "event_type": "REQUESTED"})  # type: ignore

    # None in record_all
    with pytest.raises(InvalidSecurityEventError):
        trail.record_all(None)  # type: ignore

def test_security_event_serialization_roundtrip():
    event = make_event("req-serde-123", EventType.ALLOWED, actor="enforcement_boundary")
    
    json_str = event.model_dump_json()
    assert isinstance(json_str, str)

    restored = SecurityEvent.model_validate_json(json_str)
    assert restored.event_id == event.event_id
    assert restored.request_id == event.request_id
    assert restored.event_type == event.event_type
    assert restored.actor == event.actor
    assert restored.timestamp == event.timestamp
    assert restored.details == event.details
    assert restored.metadata == event.metadata
