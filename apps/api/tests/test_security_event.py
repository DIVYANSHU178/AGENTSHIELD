from app.security import SecurityEvent, EventType

def test_security_event_creation():
    evt = SecurityEvent(
        request_id="req-001",
        event_type=EventType.BLOCKED,
        actor="policy_engine",
        details={"matched_policy": "block_sensitive_paths"}
    )
    assert evt.request_id == "req-001"
    assert evt.event_type == EventType.BLOCKED
    assert evt.actor == "policy_engine"
    assert evt.timestamp.tzinfo is not None
