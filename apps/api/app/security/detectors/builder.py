from typing import List
from app.security.models import ThreatReport, ThreatSignal, Severity

SEVERITY_HIERARCHY = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

def select_highest_severity(signals: List[ThreatSignal]) -> Severity:
    """Deterministically select the highest severity among detected signals."""
    if not signals:
        return Severity.INFO
    return max(signals, key=lambda s: SEVERITY_HIERARCHY.get(s.severity, 0)).severity

def generate_report_summary(signals: List[ThreatSignal]) -> str:
    """Generate a deterministic human-readable narrative summary for detected signals."""
    if not signals:
        return "No threats detected."

    counts = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 0,
        Severity.MEDIUM: 0,
        Severity.LOW: 0,
        Severity.INFO: 0,
    }

    for sig in signals:
        counts[sig.severity] = counts.get(sig.severity, 0) + 1

    summary_parts = []
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        cnt = counts[sev]
        if cnt > 0:
            summary_parts.append(f"{cnt} {sev.value}")

    parts_str = ", ".join(summary_parts)
    return f"Detected {len(signals)} security signal(s): {parts_str}."

def build_threat_report(request_id: str, signals: List[ThreatSignal]) -> ThreatReport:
    """
    Build a ThreatReport aggregating detected signals for a ToolRequest.
    Severity selection and summary narrative generation are strictly deterministic.
    """
    highest_severity = select_highest_severity(signals)
    summary_text = generate_report_summary(signals)

    return ThreatReport(
        request_id=request_id,
        signals=signals,
        overall_severity=highest_severity,
        summary=summary_text,
    )
