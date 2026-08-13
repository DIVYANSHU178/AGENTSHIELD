from typing import Optional
from app.security.models import (
    ToolRequest,
    ThreatReport,
    RiskAssessment,
    SecurityDecision,
    SecurityDecisionType,
    Severity,
    AgentIdentity,
    ToolCategory,
    ActionType,
)
from app.security.detectors import (
    DetectorRegistry,
    create_default_registry,
    build_threat_report,
)
from app.security.risk import RiskEngine
from app.security.policies import PolicyEngine
from app.security.gateway.result import SecurityEvaluationResult
from app.security.models.utils import generate_uuid, utc_now

class SecurityDecisionGateway:
    """
    Authoritative Gateway for AgentShield Security Pipeline.
    Orchestrates:
    ToolRequest -> Threat Detection -> ThreatReport -> Risk Assessment -> Policy Evaluation -> SecurityDecision

    CRITICAL CONTRACT RULES:
    - Must be deterministic, local, explainable, serializable, and fail-closed.
    - Must NOT execute tools, shell commands, network calls, browser automation, or LLMs.
    - Preserves correlation_id (request_id) across all security pipeline artifacts.
    - Fails closed to BLOCK decision on unexpected internal stage failures or invalid input.
    """

    def __init__(
        self,
        detector_registry: Optional[DetectorRegistry] = None,
        risk_engine: Optional[RiskEngine] = None,
        policy_engine: Optional[PolicyEngine] = None,
    ) -> None:
        self._detector_registry = detector_registry or create_default_registry()
        self._risk_engine = risk_engine or RiskEngine()
        self._policy_engine = policy_engine or PolicyEngine()

    @property
    def detector_registry(self) -> DetectorRegistry:
        return self._detector_registry

    @property
    def risk_engine(self) -> RiskEngine:
        return self._risk_engine

    @property
    def policy_engine(self) -> PolicyEngine:
        return self._policy_engine

    def evaluate(self, request: ToolRequest) -> SecurityEvaluationResult:
        """
        Evaluate a ToolRequest through the complete AgentShield security pipeline.
        Returns unified SecurityEvaluationResult.
        Fails closed to BLOCK decision if request is None or an internal processing stage fails.
        """
        if request is None:
            return self._fail_closed(
                request=None,
                reason="ToolRequest cannot be None; failing closed with BLOCK decision.",
            )

        try:
            # Stage 1: Threat Detection (Phase 2)
            signals = self._detector_registry.detect_all(request)

            # Stage 2: Threat Report Construction (Phase 2)
            threat_report = build_threat_report(request.request_id, signals)

            # Stage 3: Risk Assessment (Phase 3)
            risk_assessment = self._risk_engine.assess(request, threat_report)

            # Stage 4: Policy Evaluation (Phase 4)
            decision = self._policy_engine.evaluate_request(request, risk_assessment, threat_report)

            return SecurityEvaluationResult(
                request=request,
                threat_report=threat_report,
                risk_assessment=risk_assessment,
                decision=decision,
                evaluated_at=utc_now(),
                metadata={
                    "gateway_version": "1.0",
                    "fail_closed_active": False,
                },
            )

        except Exception as exc:
            # FAIL-CLOSED SECURITY: Any internal stage exception returns a safe BLOCK decision
            return self._fail_closed(
                request=request,
                reason="Security evaluation failed during internal stage processing; failing closed with BLOCK decision for safety.",
                error_detail=str(exc),
            )

    def _fail_closed(
        self,
        request: Optional[ToolRequest],
        reason: str,
        error_detail: Optional[str] = None,
    ) -> SecurityEvaluationResult:
        """Construct a safe fail-closed BLOCK SecurityEvaluationResult."""
        req_id = request.request_id if request is not None else generate_uuid()

        if request is None:
            request = ToolRequest(
                request_id=req_id,
                agent=AgentIdentity(agent_id="agent-fail-closed", name="FailClosedAgent"),
                tool_name="system.unknown",
                tool_category=ToolCategory.SYSTEM,
                action=ActionType.EXECUTE,
                target="unknown",
            )

        fallback_report = ThreatReport(
            request_id=req_id,
            signals=[],
            highest_severity=Severity.CRITICAL,
            summary="Fail-closed fallback: Internal security pipeline error occurred.",
        )

        fallback_risk = RiskAssessment(
            assessment_id=generate_uuid(),
            request_id=req_id,
            risk_score=100.0,
            severity=Severity.CRITICAL,
            contributing_signals=[],
            rationale="Fail-closed fallback: Maximum risk assigned due to internal evaluation exception.",
            metadata={"fail_closed": True},
        )

        fallback_decision = SecurityDecision(
            decision_id=generate_uuid(),
            request_id=req_id,
            decision=SecurityDecisionType.BLOCK,
            risk_assessment_id=fallback_risk.assessment_id,
            reason=reason,
            policy_id="policy.gateway.fail_closed.block",
            metadata={
                "fail_closed": True,
                "error_summary": "Security pipeline evaluation error handled safely.",
            },
        )

        return SecurityEvaluationResult(
            request=request,
            threat_report=fallback_report,
            risk_assessment=fallback_risk,
            decision=fallback_decision,
            evaluated_at=utc_now(),
            metadata={
                "gateway_version": "1.0",
                "fail_closed_active": True,
            },
        )
