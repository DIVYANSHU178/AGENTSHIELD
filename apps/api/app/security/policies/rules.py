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
    """Rule 5: Allow request when no higher-priority rule matches (Priority 0)."""

    RULE_ID = "policy.default.allow"
    PRIORITY = 0
    DESCRIPTION = "Allow request when no higher-priority blocking or approval policy condition is triggered."

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
            SecurityDecisionType.ALLOW,
            "Request allowed because no blocking or approval policy condition was triggered.",
        )
