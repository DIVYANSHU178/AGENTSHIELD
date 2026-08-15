from app.security.models import (
    ToolRequest,
    AgentIdentity,
    ToolCategory,
    ActionType,
    EventType,
)
from app.security.runtime import (
    AgentRuntimeOrchestrator,
    RuntimeExecutionRequest,
)
from app.security.operations.service import SecurityOperationsService
from app.security.audit import SecurityAuditTrail

def test_operations_audit_event_retrieval_and_redaction():
    audit_trail = SecurityAuditTrail()
    service = SecurityOperationsService(audit_trail=audit_trail)
    orchestrator = AgentRuntimeOrchestrator(audit_trail=audit_trail, operations_service=service)

    # 1. Clean ALLOW request -> 4 events
    req_allow = RuntimeExecutionRequest(
        request_id="req-aud-allow-01",
        agent=AgentIdentity(name="Agent"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="calculator",
        parameters={"op": "add", "a": 10, "b": 20},
    )
    orchestrator.orchestrate(req_allow)

    events_allow = service.get_audit_events(request_id="req-aud-allow-01")
    assert len(events_allow) == 4

    types_allow = [e.event_type for e in events_allow]
    assert EventType.EXECUTED in types_allow
    assert EventType.ALLOWED in types_allow
    assert EventType.ANALYZED in types_allow
    assert EventType.REQUESTED in types_allow

    # 2. Secret Redaction on BLOCK request -> 3 events
    req_block = RuntimeExecutionRequest(
        request_id="req-aud-block-01",
        agent=AgentIdentity(name="Agent"),
        tool_name="file.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target=".env",
        parameters={"secret_key": "sk-proj-supersecretkey123456789"},
    )
    orchestrator.orchestrate(req_block)

    events_block = service.get_audit_events(request_id="req-aud-block-01")
    assert len(events_block) == 3

    types_block = [e.event_type for e in events_block]
    assert EventType.BLOCKED in types_block
    assert EventType.ANALYZED in types_block
    assert EventType.REQUESTED in types_block

    # Redaction check
    for ev in events_block:
        details_str = str(ev.details)
        assert "sk-proj-supersecretkey123456789" not in details_str
