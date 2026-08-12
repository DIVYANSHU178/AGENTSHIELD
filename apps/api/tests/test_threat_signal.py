import pytest
from pydantic import ValidationError
from app.security import ThreatSignal, ThreatType, Severity

def test_threat_signal_valid_boundaries():
    s0 = ThreatSignal(
        threat_type=ThreatType.PROMPT_INJECTION,
        severity=Severity.HIGH,
        title="Prompt Injection Match",
        description="Matched override prompt pattern",
        confidence=0.0
    )
    assert s0.confidence == 0.0

    s1 = ThreatSignal(
        threat_type=ThreatType.PROMPT_INJECTION,
        severity=Severity.HIGH,
        title="Prompt Injection Match",
        description="Matched override prompt pattern",
        confidence=1.0
    )
    assert s1.confidence == 1.0

def test_threat_signal_confidence_below_zero():
    with pytest.raises(ValidationError):
        ThreatSignal(
            threat_type=ThreatType.PROMPT_INJECTION,
            severity=Severity.HIGH,
            title="Invalid Signal",
            description="Confidence too low",
            confidence=-0.1
        )

def test_threat_signal_confidence_above_one():
    with pytest.raises(ValidationError):
        ThreatSignal(
            threat_type=ThreatType.PROMPT_INJECTION,
            severity=Severity.HIGH,
            title="Invalid Signal",
            description="Confidence too high",
            confidence=1.5
        )
