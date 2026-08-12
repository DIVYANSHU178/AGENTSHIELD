import math
from typing import List, Tuple, Dict
from app.security.models import ThreatSignal, ThreatType, Severity

# Base severity weights
BASE_SEVERITY_WEIGHTS: Dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 15.0,
    Severity.MEDIUM: 35.0,
    Severity.HIGH: 60.0,
    Severity.CRITICAL: 90.0,
}

# Threat-type relative risk multipliers
THREAT_TYPE_MULTIPLIERS: Dict[ThreatType, float] = {
    ThreatType.PROMPT_INJECTION: 1.00,
    ThreatType.CREDENTIAL_ACCESS: 1.20,
    ThreatType.SENSITIVE_DATA_ACCESS: 1.00,
    ThreatType.DATA_EXFILTRATION: 1.35,
    ThreatType.DANGEROUS_ACTION: 1.20,
    ThreatType.MALICIOUS_DESTINATION: 1.20,
    ThreatType.PRIVILEGE_ESCALATION: 1.30,
    ThreatType.SUSPICIOUS_BEHAVIOR: 0.80,
    ThreatType.UNKNOWN: 0.70,
}

def calculate_signal_contribution(signal: ThreatSignal) -> float:
    """
    Calculate the effective risk contribution of an individual ThreatSignal.
    Formula: base_weight * confidence * threat_type_multiplier
    Clamped strictly between 0.0 and 100.0.
    """
    base_weight = BASE_SEVERITY_WEIGHTS.get(signal.severity, 0.0)
    confidence = max(0.0, min(1.0, signal.confidence))
    multiplier = THREAT_TYPE_MULTIPLIERS.get(signal.threat_type, 1.00)

    contribution = base_weight * confidence * multiplier
    return max(0.0, min(100.0, contribution))

def aggregate_signal_contributions(contributions: List[float]) -> float:
    """
    Combine multiple signal risk contributions using a deterministic bounded probability union formula.
    Formula: 100 * (1 - product(1 - contribution_i / 100))
    Ensures diminishing returns while remaining strictly bounded in [0.0, 100.0].
    """
    if not contributions:
        return 0.0

    product_term = 1.0
    for contrib in contributions:
        c_clamped = max(0.0, min(100.0, contrib))
        product_term *= (1.0 - (c_clamped / 100.0))

    combined = 100.0 * (1.0 - product_term)
    # Round to 2 decimal places and clamp
    rounded = round(combined, 2)
    return max(0.0, min(100.0, rounded))

def classify_risk_severity(risk_score: float) -> Severity:
    """
    Classify a numerical risk score into an overall Risk Severity level based on deterministic thresholds:
    0.0  - 14.99 -> INFO
    15.0 - 34.99 -> LOW
    35.0 - 59.99 -> MEDIUM
    60.0 - 84.99 -> HIGH
    85.0 - 100.0 -> CRITICAL
    """
    if risk_score < 15.0:
        return Severity.INFO
    elif risk_score < 35.0:
        return Severity.LOW
    elif risk_score < 60.0:
        return Severity.MEDIUM
    elif risk_score < 85.0:
        return Severity.HIGH
    else:
        return Severity.CRITICAL

def build_risk_rationale(
    risk_score: float,
    severity: Severity,
    signals: List[ThreatSignal],
) -> str:
    """
    Generate a human-readable, deterministic explanation of the calculated risk assessment.
    """
    if not signals:
        return "No threat signals were detected; risk score is 0.0."

    counts: Dict[Severity, int] = {}
    threat_types: set = set()
    for sig in signals:
        counts[sig.severity] = counts.get(sig.severity, 0) + 1
        threat_types.add(sig.threat_type.value)

    sev_summary_parts = []
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        if counts.get(sev, 0) > 0:
            sev_summary_parts.append(f"{counts[sev]} {sev.value}")

    sev_str = ", ".join(sev_summary_parts)
    types_str = ", ".join(sorted(threat_types))

    return (
        f"Risk score {risk_score:.1f} ({severity.value}) derived from {len(signals)} threat signal(s) "
        f"[{sev_str}] covering categories [{types_str}]. "
        f"Contributions were aggregated using deterministic bounded probability union."
    )
