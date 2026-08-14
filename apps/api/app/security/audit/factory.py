from typing import Optional, Dict, Any
from app.security.models import (
    ToolRequest,
    ThreatReport,
    RiskAssessment,
    SecurityDecision,
    SecurityDecisionType,
    SecurityEvent,
    EventType,
)
from app.security.enforcement.result import EnforcementResult
from app.security.audit.redaction import sanitize_audit_payload, sanitize_string_value
from app.security.models.utils import generate_uuid, utc_now

class SecurityEventFactory:
    """
    Deterministic builder and factory for creating canonical SecurityEvent instances
    across the complete AgentShield security boundary lifecycle.
    """

    @staticmethod
    def create_requested_event(
        request: ToolRequest,
        actor: Optional[str] = None,
    ) -> SecurityEvent:
        """Construct a canonical REQUESTED security audit event."""
        if request is None:
            raise ValueError("ToolRequest is required to create a REQUESTED audit event.")

        actor_name = actor or request.agent.name or request.agent.agent_id
        details = {
            "tool_name": request.tool_name,
            "tool_category": request.tool_category.value,
            "action": request.action.value,
            "target": sanitize_string_value(request.target),
            "destination": sanitize_string_value(request.destination) if request.destination else None,
            "has_parameters": bool(request.parameters),
            "parameter_keys": sorted(list(request.parameters.keys())) if request.parameters else [],
        }

        return SecurityEvent(
            event_id=generate_uuid(),
            request_id=request.request_id,
            event_type=EventType.REQUESTED,
            timestamp=utc_now(),
            actor=actor_name,
            details=sanitize_audit_payload(details),
            metadata={"stage": "ingress"},
        )

    @staticmethod
    def create_analyzed_event(
        request: ToolRequest,
        threat_report: ThreatReport,
        risk_assessment: RiskAssessment,
        actor: str = "security_analyzer",
    ) -> SecurityEvent:
        """Construct a canonical ANALYZED security audit event."""
        if request is None:
            raise ValueError("ToolRequest is required to create an ANALYZED audit event.")
        if threat_report is None or risk_assessment is None:
            raise ValueError("ThreatReport and RiskAssessment are required to create an ANALYZED audit event.")

        details = {
            "threat_count": len(threat_report.signals),
            "highest_threat_severity": threat_report.overall_severity.value,
            "risk_score": risk_assessment.risk_score,
            "risk_severity": risk_assessment.severity.value,
            "contributing_signals_count": len(risk_assessment.contributing_signals),
            "detectors_triggered": sorted(list(set(s.source for s in threat_report.signals))),
        }

        return SecurityEvent(
            event_id=generate_uuid(),
            request_id=request.request_id,
            event_type=EventType.ANALYZED,
            timestamp=utc_now(),
            actor=actor,
            details=sanitize_audit_payload(details),
            metadata={"stage": "analysis"},
        )

    @staticmethod
    def create_decision_event(
        request: ToolRequest,
        decision: SecurityDecision,
        risk_assessment: RiskAssessment,
        actor: str = "policy_engine",
    ) -> SecurityEvent:
        """Construct a canonical decision security audit event (ALLOWED, APPROVAL_REQUIRED, or BLOCKED)."""
        if request is None:
            raise ValueError("ToolRequest is required to create a decision audit event.")
        if decision is None or risk_assessment is None:
            raise ValueError("SecurityDecision and RiskAssessment are required to create a decision audit event.")

        decision_type = decision.decision
        if decision_type == SecurityDecisionType.ALLOW:
            event_type = EventType.ALLOWED
        elif decision_type == SecurityDecisionType.BLOCK:
            event_type = EventType.BLOCKED
        elif decision_type == SecurityDecisionType.REQUIRE_APPROVAL:
            event_type = EventType.APPROVAL_REQUIRED
        else:
            event_type = EventType.BLOCKED

        details = {
            "decision": decision_type.value,
            "policy_id": decision.policy_id,
            "risk_score": risk_assessment.risk_score,
            "risk_severity": risk_assessment.severity.value,
            "reason": sanitize_string_value(decision.reason),
            "risk_assessment_id": decision.risk_assessment_id,
        }

        return SecurityEvent(
            event_id=generate_uuid(),
            request_id=request.request_id,
            event_type=event_type,
            timestamp=utc_now(),
            actor=actor,
            details=sanitize_audit_payload(details),
            metadata={"stage": "policy_decision"},
        )

    @staticmethod
    def create_enforcement_event(
        result: EnforcementResult,
        actor: str = "enforcement_boundary",
    ) -> SecurityEvent:
        """Construct a canonical enforcement outcome audit event."""
        if result is None:
            raise ValueError("EnforcementResult is required to create an enforcement audit event.")

        decision_type = result.decision
        if decision_type == SecurityDecisionType.ALLOW:
            event_type = EventType.ALLOWED
        elif decision_type == SecurityDecisionType.BLOCK:
            event_type = EventType.BLOCKED
        elif decision_type == SecurityDecisionType.REQUIRE_APPROVAL:
            event_type = EventType.APPROVAL_REQUIRED
        else:
            event_type = EventType.BLOCKED

        details = {
            "authorized": result.authorized,
            "decision": result.decision.value,
            "reason": sanitize_string_value(result.reason),
            "has_authorization": result.authorization is not None,
            "authorization_id": result.authorization.authorization_id if result.authorization else None,
        }

        return SecurityEvent(
            event_id=generate_uuid(),
            request_id=result.request_id,
            event_type=event_type,
            timestamp=utc_now(),
            actor=actor,
            details=sanitize_audit_payload(details),
            metadata={"stage": "enforcement"},
        )

    @staticmethod
    def create_executed_event(
        request_id: str,
        actor: str = "execution_layer",
        outcome_metadata: Optional[Dict[str, Any]] = None,
    ) -> SecurityEvent:
        """
        Construct a canonical EXECUTED security audit event representing an externally supplied outcome.
        NOTE: This factory method strictly records metadata and does NOT perform any tool execution.
        """
        if not request_id or not request_id.strip():
            raise ValueError("request_id must not be empty.")

        details = sanitize_audit_payload(outcome_metadata or {"executed": True})

        return SecurityEvent(
            event_id=generate_uuid(),
            request_id=request_id.strip(),
            event_type=EventType.EXECUTED,
            timestamp=utc_now(),
            actor=actor,
            details=details,
            metadata={"stage": "execution_outcome"},
        )

    @staticmethod
    def create_failed_event(
        request_id: str,
        actor: str = "execution_layer",
        error_message: str = "Execution failed",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SecurityEvent:
        """
        Construct a canonical FAILED security audit event representing an externally supplied failure.
        NOTE: This factory method strictly records metadata and does NOT perform any tool execution.
        """
        if not request_id or not request_id.strip():
            raise ValueError("request_id must not be empty.")

        details = {
            "error": sanitize_string_value(error_message),
            "failure_details": sanitize_audit_payload(metadata or {}),
        }

        return SecurityEvent(
            event_id=generate_uuid(),
            request_id=request_id.strip(),
            event_type=EventType.FAILED,
            timestamp=utc_now(),
            actor=actor,
            details=details,
            metadata={"stage": "execution_failure"},
        )
