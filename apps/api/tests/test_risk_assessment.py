import pytest
from pydantic import ValidationError
from app.security import RiskAssessment, Severity

def test_risk_assessment_boundaries():
    r0 = RiskAssessment(
        request_id="req-100",
        risk_score=0.0,
        severity=Severity.LOW
    )
    assert r0.risk_score == 0.0

    r100 = RiskAssessment(
        request_id="req-100",
        risk_score=100.0,
        severity=Severity.CRITICAL
    )
    assert r100.risk_score == 100.0

def test_risk_assessment_below_zero():
    with pytest.raises(ValidationError):
        RiskAssessment(
            request_id="req-100",
            risk_score=-1.0,
            severity=Severity.LOW
        )

def test_risk_assessment_above_100():
    with pytest.raises(ValidationError):
        RiskAssessment(
            request_id="req-100",
            risk_score=101.0,
            severity=Severity.CRITICAL
        )
