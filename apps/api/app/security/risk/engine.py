from typing import Optional, List
from app.security.models import (
    ToolRequest,
    ThreatReport,
    SecurityContext,
    RiskAssessment,
    Severity,
)
from app.security.risk.scoring import (
    calculate_signal_contribution,
    aggregate_signal_contributions,
    classify_risk_severity,
    build_risk_rationale,
)

class RiskEngineError(Exception):
    """Domain exception raised when RiskEngine fails to perform risk assessment."""
    pass

class RiskEngine:
    """
    Deterministic Risk Engine for AgentShield.
    Evaluates ThreatReport findings to compute a numerical risk assessment (0.0 to 100.0)
    and overall risk severity classification.
    
    CRITICAL CONTRACT RULES:
    - Must be stateless, deterministic, explainable, and side-effect free.
    - Must NOT generate SecurityDecision objects or ALLOW/BLOCK policies.
    - Must NOT execute tools, shell commands, or network calls.
    """

    SCORING_VERSION = "1.0"
    AGGREGATION_METHOD = "bounded_probability_union"

    def assess(
        self,
        request: ToolRequest,
        threat_report: ThreatReport,
        context: Optional[SecurityContext] = None,
    ) -> RiskAssessment:
        """
        Perform risk assessment for the given ToolRequest and ThreatReport.
        Returns a canonical RiskAssessment domain object.
        Raises RiskEngineError if input parameters are invalid.
        """
        if request is None:
            raise RiskEngineError("Invalid input: ToolRequest cannot be None.")
        if threat_report is None:
            raise RiskEngineError("Invalid input: ThreatReport cannot be None.")

        signals = threat_report.signals or []

        # 1. Empty signals case
        if not signals:
            return RiskAssessment(
                request_id=request.request_id,
                risk_score=0.0,
                severity=Severity.INFO,
                contributing_signals=[],
                rationale="No threat signals were detected; risk score is 0.0.",
                metadata={
                    "scoring_version": self.SCORING_VERSION,
                    "aggregation": self.AGGREGATION_METHOD,
                    "signal_count": 0,
                },
            )

        # 2. Calculate contributions for each detected ThreatSignal
        contributions: List[float] = []
        contributing_signal_ids: List[str] = []

        for sig in signals:
            contrib = calculate_signal_contribution(sig)
            contributions.append(contrib)
            contributing_signal_ids.append(sig.signal_id)

        # 3. Aggregate combined risk score
        risk_score = aggregate_signal_contributions(contributions)

        # 4. Classify risk severity level
        risk_severity = classify_risk_severity(risk_score)

        # 5. Build human-readable rationale
        rationale = build_risk_rationale(risk_score, risk_severity, signals)

        return RiskAssessment(
            request_id=request.request_id,
            risk_score=risk_score,
            severity=risk_severity,
            contributing_signals=contributing_signal_ids,
            rationale=rationale,
            metadata={
                "scoring_version": self.SCORING_VERSION,
                "aggregation": self.AGGREGATION_METHOD,
                "signal_count": len(signals),
            },
        )
