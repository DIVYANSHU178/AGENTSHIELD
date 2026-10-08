"""
Phase 2.0 / F2 — finite executor timeout validation (defense in depth).

The policy contract (``SandboxExecutionLimits``) already bounds
``timeout_seconds`` to [0.01, 300.0] and rejects NaN/inf/non-numeric. This
suite proves the LOW-LEVEL executor enforces the same discipline itself, so
no caller can accidentally request unbounded execution at the final boundary:

  - ``None`` -> configured finite default.
  - ``math.inf`` / ``-math.inf`` / ``math.nan`` -> rejected.
  - zero / negative values -> rejected.
  - non-numeric values -> rejected.
  - values above the 300s maximum -> rejected.
  - valid finite positives (including the boundaries) -> accepted.
"""

import math
import time

import pytest

from app.security.sandbox.isolation import (
    ExecutionIsolation,
    MAX_EXECUTION_TIMEOUT_SECONDS,
    _validate_timeout,
)


def test_none_resolves_to_configured_default():
    iso = ExecutionIsolation(default_timeout=17.0)
    assert _validate_timeout(None, iso._default_timeout) == 17.0


def test_positive_infinity_rejected():
    with pytest.raises(ValueError, match="infinity|finite"):
        _validate_timeout(math.inf, 30.0)


def test_negative_infinity_rejected():
    with pytest.raises(ValueError, match="infinity|finite"):
        _validate_timeout(-math.inf, 30.0)


def test_nan_rejected():
    with pytest.raises(ValueError, match="NaN|finite"):
        _validate_timeout(math.nan, 30.0)


def test_zero_rejected():
    with pytest.raises(ValueError, match="strictly positive"):
        _validate_timeout(0.0, 30.0)


def test_negative_rejected():
    with pytest.raises(ValueError, match="strictly positive"):
        _validate_timeout(-5.0, 30.0)


def test_non_numeric_rejected():
    with pytest.raises(ValueError, match="numeric"):
        _validate_timeout("not-a-number", 30.0)


def test_above_maximum_rejected():
    with pytest.raises(ValueError, match="maximum"):
        _validate_timeout(MAX_EXECUTION_TIMEOUT_SECONDS + 0.1, 30.0)


def test_valid_finite_values_accepted():
    for v in (0.01, 1.0, 42.5, 300.0):
        assert _validate_timeout(v, 30.0) == v


def test_rejection_occurs_before_spawn():
    """Infinity must be rejected without ever spawning a child process."""
    iso = ExecutionIsolation()
    with pytest.raises(ValueError):
        iso.execute_in_subprocess(
            module_path="app.security.execution.tools.real_calculator",
            function_name="RealCalculatorTool",
            parameters={"expression": "1 + 1"},
            timeout_seconds=math.inf,
        )


def test_valid_timeout_runs_to_completion():
    """A finite explicit timeout still executes normally end-to-end."""
    iso = ExecutionIsolation()
    res = iso.execute_in_subprocess(
        module_path="app.security.execution.tools.real_calculator",
        function_name="RealCalculatorTool",
        parameters={"expression": "12 * 12"},
        timeout_seconds=20.0,
    )
    assert res["success"] is True
    assert res["result"]["result"] == 144