from typing import List, Optional
from app.security.models import SecurityEvent, EventType
from app.security.gateway.result import SecurityEvaluationResult
from app.security.enforcement.result import EnforcementResult
from app.security.audit.trail import SecurityAuditTrail, TERMINAL_DECISION_EVENT_TYPES
from app.security.audit.factory import SecurityEventFactory
from app.security.audit.errors import AuditRecordingError

def record_gateway_lifecycle(
    audit_trail: SecurityAuditTrail,
    eval_result: SecurityEvaluationResult,
) -> List[SecurityEvent]:
    """
    Record the authoritative 3-stage security gateway lifecycle events:
    1. REQUESTED
    2. ANALYZED
    3. ALLOWED | APPROVAL_REQUIRED | BLOCKED
    
    IDEMPOTENCY INVARIANT:
    If the complete canonical gateway lifecycle has already been recorded for this request_id,
    returns the existing lifecycle events without appending duplicates.
    
    Fail-safe: If audit recording encounters an error, raises AuditRecordingError
    without altering the evaluation result or granting unauthorized permissions.
    """
    if audit_trail is None:
        raise AuditRecordingError("SecurityAuditTrail is required.")
    if eval_result is None or eval_result.request is None:
        raise AuditRecordingError("SecurityEvaluationResult is required.")

    try:
        req_id = eval_result.request.request_id

        # Idempotency check: if the canonical 3-event lifecycle is already present, return existing events
        if audit_trail.has_gateway_lifecycle(req_id):
            return audit_trail.get_gateway_lifecycle_events(req_id)

        events: List[SecurityEvent] = []

        # 1. Ingress REQUESTED event
        req_event = SecurityEventFactory.create_requested_event(
            request=eval_result.request,
            actor=eval_result.request.agent.name or eval_result.request.agent.agent_id,
        )
        events.append(req_event)

        # 2. Security Analysis ANALYZED event
        analyzed_event = SecurityEventFactory.create_analyzed_event(
            request=eval_result.request,
            threat_report=eval_result.threat_report,
            risk_assessment=eval_result.risk_assessment,
        )
        events.append(analyzed_event)

        # 3. Policy Decision event (Terminal event for evaluation lifecycle)
        decision_event = SecurityEventFactory.create_decision_event(
            request=eval_result.request,
            decision=eval_result.decision,
            risk_assessment=eval_result.risk_assessment,
        )
        events.append(decision_event)

        audit_trail.record_all(events)
        return events

    except Exception as e:
        raise AuditRecordingError(f"Failed to record gateway lifecycle events: {str(e)}") from e

def record_enforcement_lifecycle(
    audit_trail: SecurityAuditTrail,
    enforcement_result: EnforcementResult,
) -> Optional[SecurityEvent]:
    """
    Record an enforcement boundary outcome event if not already recorded.
    If a terminal decision event (ALLOWED, APPROVAL_REQUIRED, BLOCKED) has already
    been recorded for this request_id by the gateway evaluation, skips recording
    a duplicate event to maintain exactly one terminal event per evaluation lifecycle.
    """
    if audit_trail is None:
        raise AuditRecordingError("SecurityAuditTrail is required.")
    if enforcement_result is None:
        raise AuditRecordingError("EnforcementResult is required.")

    try:
        # Check if terminal decision event is already recorded for this request
        if audit_trail.has_terminal_event(enforcement_result.request_id):
            # Terminal decision already recorded; return the existing terminal event
            existing_events = [
                e for e in audit_trail.get_events(enforcement_result.request_id)
                if e.event_type in TERMINAL_DECISION_EVENT_TYPES
            ]
            return existing_events[-1] if existing_events else None

        # Standalone enforcement recording (when gateway lifecycle was not pre-recorded)
        event = SecurityEventFactory.create_enforcement_event(enforcement_result)
        audit_trail.record(event)
        return event
    except Exception as e:
        raise AuditRecordingError(f"Failed to record enforcement event: {str(e)}") from e
