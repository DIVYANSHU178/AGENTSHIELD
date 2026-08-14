import pytest
from pydantic import ValidationError
from app.security.sandbox.contracts import SandboxExecutionLimits

@pytest.mark.parametrize(
    "valid_timeout",
    [
        0.01,    # Minimum exact boundary
        0.011,   # Minimum + epsilon
        1.0,     # Low normal
        5.0,     # Default normal
        50.0,    # Medium normal
        299.9,   # Maximum - epsilon
        300.0,   # Maximum exact boundary
    ],
)
def test_sandbox_timeout_valid_boundaries(valid_timeout: float):
    limits = SandboxExecutionLimits(timeout_seconds=valid_timeout)
    assert limits.timeout_seconds == valid_timeout

@pytest.mark.parametrize(
    "invalid_timeout",
    [
        0.009,            # Minimum - epsilon (below 0.01)
        0.001,            # Far below min
        0.0,              # Zero
        -0.01,            # Negative small
        -1.0,             # Negative normal
        -100.0,           # Negative large
        300.001,          # Maximum + epsilon (above 300.0)
        301.0,            # Above max
        999999.0,         # Far above max
        float("nan"),     # NaN
        float("inf"),     # Infinity
        -float("inf"),    # Negative Infinity
        None,             # None
        "not_a_number",   # Malformed string
    ],
)
def test_sandbox_timeout_invalid_boundaries(invalid_timeout):
    with pytest.raises(ValidationError):
        SandboxExecutionLimits(timeout_seconds=invalid_timeout)
