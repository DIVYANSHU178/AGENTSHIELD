from typing import Optional
from app.security.models import (
    ToolRequest,
    ThreatReport,
    RiskAssessment,
    SecurityDecision,
    SecurityDecisionType,
)
from app.security.policies.context import PolicyContext
from app.security.policies.registry import PolicyRegistry, create_default_policy_registry

class PolicyEngineError(Exception):
    """Domain exception raised when PolicyEngine encounters invalid policy context or evaluation failures."""
    pass

class PolicyEngine:
    """
    Deterministic Policy Engine for AgentShield.
    Evaluates PolicyContext against prioritized PolicyRules to render an authoritative SecurityDecision
    (ALLOW, REQUIRE_APPROVAL, BLOCK).

    CRITICAL CONTRACT RULES:
    - Must be deterministic, local, explainable, and side-effect free.
    - Must NOT execute tools, shell commands, or network calls.
    - Must NOT call LLMs or external APIs.
    - Must NOT perform tool execution or filesystem modifications.
    """

    def __init__(self, registry: Optional[PolicyRegistry] = None) -> None:
        self._registry = registry or create_default_policy_registry()

    @property
    def registry(self) -> PolicyRegistry:
        return self._registry

    def evaluate(self, context: PolicyContext) -> SecurityDecision:
        """
        Evaluate a PolicyContext against registered rules in priority order.
        Returns an immutable canonical SecurityDecision.
        Raises PolicyEngineError if context is invalid.
        """
        if context is None:
            raise PolicyEngineError("PolicyEngine evaluation requires a non-null PolicyContext.")

        rules = self._registry.get_rules()

        for rule in rules:
            match_result = rule.evaluate(context)
            if match_result is not None:
                decision_type, reason = match_result
                signal_count = len(context.threat_report.signals) if context.threat_report else 0

                return SecurityDecision(
                    request_id=context.request.request_id,
                    decision=decision_type,
                    risk_assessment_id=context.risk_assessment.assessment_id,
                    reason=reason,
                    policy_id=rule.rule_id,
                    metadata={
                        "matched_rule": rule.rule_id,
                        "rule_priority": rule.priority,
                        "risk_score": context.risk_assessment.risk_score,
                        "severity": context.risk_assessment.severity.value,
                        "signal_count": signal_count,
                    },
                )

        raise PolicyEngineError(
            f"Policy evaluation incomplete: No matching rule (including default allow) triggered for request '{context.request.request_id}'."
        )

    def evaluate_request(
        self,
        request: ToolRequest,
        risk_assessment: RiskAssessment,
        threat_report: Optional[ThreatReport] = None,
    ) -> SecurityDecision:
        """
        Convenience wrapper constructing PolicyContext and evaluating it against PolicyEngine rules.
        """
        try:
            context = PolicyContext(
                request=request,
                risk_assessment=risk_assessment,
                threat_report=threat_report,
            )
        except Exception as exc:
            raise PolicyEngineError(f"Failed to create valid PolicyContext: {str(exc)}") from exc

        return self.evaluate(context)
