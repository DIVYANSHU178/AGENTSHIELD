import pytest
from app.security.models import SecurityEvent, EventType
from app.security.audit import SecurityAuditTrail

def test_audit_trail_deep_defensive_isolation():
    trail = SecurityAuditTrail()

    caller_details = {"status": "ok", "nested": {"stage": "eval", "signals": [1, 2]}}
    caller_meta = {"env": "prod"}

    event = SecurityEvent(
        request_id="req-audit-iso-01",
        event_type=EventType.ALLOWED,
        actor="gateway",
        details=caller_details,
        metadata=caller_meta,
    )

    trail.record(event)

    # 1. Mutating caller objects post-record does not alter stored audit event
    caller_details["status"] = "tampered"
    caller_details["nested"]["stage"] = "tampered"
    caller_meta["env"] = "tampered"

    stored_events = trail.get_events("req-audit-iso-01")
    assert len(stored_events) == 1
    assert stored_events[0].details["status"] == "ok"
    assert stored_events[0].details["nested"]["stage"] == "eval"
    assert stored_events[0].metadata["env"] == "prod"

    # 2. Mutating returned event list collection does not alter internal trail
    returned_list = trail.get_events()
    returned_list.clear()
    assert len(trail.get_events()) == 1

    # 3. Direct mutation attempts on returned event details raise TypeError
    event_from_trail = trail.get_events()[0]
    with pytest.raises(TypeError):
        event_from_trail.details["tampered"] = True

    with pytest.raises(TypeError):
        event_from_trail.details["nested"]["tampered"] = True

    with pytest.raises(TypeError):
        event_from_trail.metadata["tampered"] = True

    # 4. Internal stored event remains 100% clean and untampered
    fresh_events = trail.get_events("req-audit-iso-01")
    assert "tampered" not in fresh_events[0].details
    assert "tampered" not in fresh_events[0].details["nested"]
    assert "tampered" not in fresh_events[0].metadata
    assert fresh_events[0].details["status"] == "ok"
    assert fresh_events[0].details["nested"]["stage"] == "eval"

def test_audit_gateway_lifecycle_defensive_isolation():
    trail = SecurityAuditTrail()

    ev1 = SecurityEvent(request_id="req-life-01", event_type=EventType.REQUESTED, actor="agent", details={"step": 1})
    ev2 = SecurityEvent(request_id="req-life-01", event_type=EventType.ANALYZED, actor="engine", details={"step": 2})
    ev3 = SecurityEvent(request_id="req-life-01", event_type=EventType.ALLOWED, actor="gateway", details={"step": 3})

    trail.record_all([ev1, ev2, ev3])

    lifecycle_events = trail.get_gateway_lifecycle_events("req-life-01")
    assert len(lifecycle_events) == 3

    # Mutating returned list
    lifecycle_events.pop()
    assert len(trail.get_gateway_lifecycle_events("req-life-01")) == 3

    # Mutating details is blocked
    with pytest.raises(TypeError):
        lifecycle_events[0].details["step"] = 999

    assert trail.get_gateway_lifecycle_events("req-life-01")[0].details["step"] == 1
