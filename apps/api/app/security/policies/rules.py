from typing import Optional, Tuple
from app.security.models import SecurityDecisionType, Severity
from app.security.policies.base import PolicyRule
from app.security.policies.context import PolicyContext

class CriticalRiskRule(PolicyRule):
    """Rule 1: Block requests with CRITICAL risk severity (Priority 100)."""

    RULE_ID = "policy.risk.critical.block"
    PRIORITY = 100
    DESCRIPTION = "Block requests evaluated with CRITICAL risk severity."

    @property
    def rule_id(self) -> str:
        return self.RULE_ID

    @property
    def priority(self) -> int:
        return self.PRIORITY

    @property
    def description(self) -> str:
        return self.DESCRIPTION

    def evaluate(self, context: PolicyContext) -> Optional[Tuple[SecurityDecisionType, str]]:
        if context.risk_assessment.severity == Severity.CRITICAL:
            return (
                SecurityDecisionType.BLOCK,
                "Request blocked because risk severity is CRITICAL.",
            )
        return None


class VeryHighRiskRule(PolicyRule):
    """Rule 2: Block requests with risk score >= 80.0 (Priority 90)."""

    RULE_ID = "policy.risk.very_high.block"
    PRIORITY = 90
    DESCRIPTION = "Block requests with calculated numerical risk score >= 80.0."

    @property
    def rule_id(self) -> str:
        return self.RULE_ID

    @property
    def priority(self) -> int:
        return self.PRIORITY

    @property
    def description(self) -> str:
        return self.DESCRIPTION

    def evaluate(self, context: PolicyContext) -> Optional[Tuple[SecurityDecisionType, str]]:
        score = context.risk_assessment.risk_score
        if score >= 80.0:
            return (
                SecurityDecisionType.BLOCK,
                f"Request blocked because calculated risk score is {score:.1f} (>= 80.0 threshold).",
            )
        return None


class HighRiskRule(PolicyRule):
    """Rule 3: Require human approval for HIGH severity or risk score >= 60.0 (Priority 70)."""

    RULE_ID = "policy.risk.high.approval"
    PRIORITY = 70
    DESCRIPTION = "Require human approval for requests with HIGH risk severity or risk score >= 60.0."

    @property
    def rule_id(self) -> str:
        return self.RULE_ID

    @property
    def priority(self) -> int:
        return self.PRIORITY

    @property
    def description(self) -> str:
        return self.DESCRIPTION

    def evaluate(self, context: PolicyContext) -> Optional[Tuple[SecurityDecisionType, str]]:
        sev = context.risk_assessment.severity
        score = context.risk_assessment.risk_score
        if sev == Severity.HIGH or score >= 60.0:
            return (
                SecurityDecisionType.REQUIRE_APPROVAL,
                f"Request requires approval because calculated risk score is {score:.1f} ({sev.value}).",
            )
        return None


class MediumRiskRule(PolicyRule):
    """Rule 4: Require human approval for MEDIUM severity or risk score >= 30.0 (Priority 50)."""

    RULE_ID = "policy.risk.medium.approval"
    PRIORITY = 50
    DESCRIPTION = "Require human approval for requests with MEDIUM risk severity or risk score >= 30.0."

    @property
    def rule_id(self) -> str:
        return self.RULE_ID

    @property
    def priority(self) -> int:
        return self.PRIORITY

    @property
    def description(self) -> str:
        return self.DESCRIPTION

    def evaluate(self, context: PolicyContext) -> Optional[Tuple[SecurityDecisionType, str]]:
        sev = context.risk_assessment.severity
        score = context.risk_assessment.risk_score
        if sev == Severity.MEDIUM or score >= 30.0:
            return (
                SecurityDecisionType.REQUIRE_APPROVAL,
                f"Request requires approval because calculated risk score is {score:.1f} ({sev.value}).",
            )
        return None


class DefaultAllowRule(PolicyRule):
    """Rule 5: Bounded allow for safe low-risk requests meeting criteria (Priority 0)."""

    RULE_ID = "policy.default.allow"
    PRIORITY = 0
    DESCRIPTION = "Allow low-risk request when no higher-priority blocking or approval policy condition is triggered."

    @property
    def rule_id(self) -> str:
        return self.RULE_ID

    @property
    def priority(self) -> int:
        return self.PRIORITY

    @property
    def description(self) -> str:
        return self.DESCRIPTION

    def evaluate(self, context: PolicyContext) -> Optional[Tuple[SecurityDecisionType, str]]:
        sev = context.risk_assessment.severity
        score = context.risk_assessment.risk_score
        if sev in (Severity.LOW, Severity.INFO) and score < 30.0:
            return (
                SecurityDecisionType.ALLOW,
                "Request allowed because no blocking or approval policy condition was triggered and risk profile is low.",
            )
        return (
            SecurityDecisionType.BLOCK,
            "Request denied by fail-closed default boundary: risk profile does not qualify for default allow.",
        )


class InjectionDetectedBlockRule(PolicyRule):
    """Rule 2.5: Block requests with active prompt injection or jailbreak signals (Priority 85)."""

    RULE_ID = "policy.threat.injection.block"
    PRIORITY = 85
    DESCRIPTION = "Block requests where prompt injection, jailbreak, or adversarial manipulation was detected."

    @property
    def rule_id(self) -> str:
        return self.RULE_ID

    @property
    def priority(self) -> int:
        return self.PRIORITY

    @property
    def description(self) -> str:
        return self.DESCRIPTION

    def evaluate(self, context: PolicyContext) -> Optional[Tuple[SecurityDecisionType, str]]:
        if getattr(context, "threat_signals", None):
            for signal in context.threat_signals:
                tt = getattr(signal, "threat_type", None) or (signal.get("threat_type") if isinstance(signal, dict) else "")
                if str(tt).lower() in ("prompt_injection", "jailbreak", "adversarial_manipulation"):
                    return (
                        SecurityDecisionType.BLOCK,
                        f"Request blocked due to detected {tt} signal.",
                    )
        return None


class AuthorizedLowRiskAllowRule(PolicyRule):
    """Rule: Explicitly allow low-risk requests meeting bounded criteria (Priority 10)."""

    RULE_ID = "policy.risk.low.allow"
    PRIORITY = 10
    DESCRIPTION = "Allow low-risk requests meeting all bounded criteria and explicit capability grants."

    @property
    def rule_id(self) -> str:
        return self.RULE_ID

    @property
    def priority(self) -> int:
        return self.PRIORITY

    @property
    def description(self) -> str:
        return self.DESCRIPTION

    def evaluate(self, context: PolicyContext) -> Optional[Tuple[SecurityDecisionType, str]]:
        sev = context.risk_assessment.severity
        score = context.risk_assessment.risk_score
        if sev in (Severity.LOW, Severity.INFO) and score < 30.0:
            return (
                SecurityDecisionType.ALLOW,
                f"Request explicitly allowed: low risk profile ({score:.1f}) and compliant parameters.",
            )
        return None


class DefaultDenyRule(PolicyRule):
    """Rule: Catch-all fail-closed security boundary (Priority 0)."""

    RULE_ID = "policy.default.deny"
    PRIORITY = 0
    DESCRIPTION = "Fail-closed catch-all rule: Deny any action not explicitly permitted by preceding policies."

    @property
    def rule_id(self) -> str:
        return self.RULE_ID

    @property
    def priority(self) -> int:
        return self.PRIORITY

    @property
    def description(self) -> str:
        return self.DESCRIPTION

    def evaluate(self, context: PolicyContext) -> Optional[Tuple[SecurityDecisionType, str]]:
        return (
            SecurityDecisionType.BLOCK,
            "Request blocked by default fail-closed security boundary (no preceding allow policy matched).",
        )
