"""
Phase 1.2.3 Regression Coverage: Production Sandbox Subprocess Timeout Remediation.

Defect (Phase 1.2.2 report): ExecutionIsolation applied a single 5.0s wall-clock budget
across the entire child lifecycle (spawn -> interpreter startup -> app imports ->
capability verification -> tool execution -> IPC output).  Measured legitimate child
startup/execution latency is ~1.3-1.6s median with transient tails above 4s, so
legitimate capability-gated executions occasionally crossed 5s and were incorrectly
reported as timeouts (success=False).

These tests prove, against the REAL subprocess path (no mocking):
  A. Normal authorized tool execution succeeds under the configured default budget.
  B. Startup/import overhead across many real executions does NOT get misclassified
     as a timeout.
  C. A genuinely slow child still hits a hard, finite, enforced timeout -> failure ->
     child process terminated (no orphan).
  D. Repeated subprocess executions remain deterministic.
  E. The timeout remediation does not weaken capability/signature verification.

The slow child lives in a dynamically-created stdlib-only module placed on the child's
PYTHONPATH so the full spawn/import cycle is exercised; nothing here weakens or bypasses
the subprocess boundary.
"""

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from app.security.sandbox.isolation import ExecutionIsolation

SLOW_MODULE_NAME = "slow_sandbox_regression_module"

SLOW_MODULE_SRC = '''
import json
import os
import time


class SlowSandboxRegressionTool:
    """Stdlib-only tool used to exercise the real subprocess lifecycle deterministically."""

    def execute(self, params, context=None):
        params = params or {}
        marker_dir = params.get("marker_dir")
        sleep_seconds = float(params.get("sleep_seconds", 30.0))
        if marker_dir:
            os.makedirs(marker_dir, exist_ok=True)
            with open(os.path.join(marker_dir, "started"), "w") as fh:
                fh.write(str(os.getpid()))
        time.sleep(sleep_seconds)
        if marker_dir:
            with open(os.path.join(marker_dir, "completed"), "w") as fh:
                fh.write("done")
        return {"result": "slow-tool-completed"}
'''


def _write_slow_module(target_dir: Path) -> Path:
    module_file = target_dir / f"{SLOW_MODULE_NAME}.py"
    module_file.write_text(SLOW_MODULE_SRC, encoding="utf-8")
    return module_file


def _install_slow_module_on_path(target_dir: Path):
    """Make the dynamic slow module importable by the isolated child process."""
    _write_slow_module(target_dir)
    if str(target_dir) not in sys.path:
        sys.path.insert(0, str(target_dir))


def _pid_is_alive(pid: int) -> bool:
    """Best-effort cross-platform process liveness check (tasklist on Windows)."""
    if pid is None:
        return False
    try:
        proc = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        # tasklist prints the header regardless; a matching row contains the pid.
        return str(pid) in proc.stdout and "No tasks" not in proc.stdout
    except Exception:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False


# ---------------------------------------------------------------------------
# A/B/D. Default budget has headroom; real repeated executions never time out.
# ---------------------------------------------------------------------------

def test_default_timeout_is_bounded_with_startup_headroom():
    """
    The class default must be a finite, enforced bound with material headroom over the
    measured legitimate child lifecycle latency (worst observed ~4.3s), while remaining
    strictly bounded (parity with SandboxExecutionLimits contract max of 300s).
    """
    iso = ExecutionIsolation()
    assert 10.0 <= iso._default_timeout <= 300.0


def test_repeated_real_subprocess_executions_all_succeed_with_default_timeout():
    """
    Run the real calculator tool through the REAL subprocess path (spawn -> imports ->
    execution) enough times to expose lifecycle latency tails. With the remediated
    default budget none of them may be classified as a timeout.
    """
    iso = ExecutionIsolation()  # production default, what services construct
    durations = []
    for i in range(10):
        started = time.perf_counter()
        res = iso.execute_in_subprocess(
            module_path="app.security.execution.tools.real_calculator",
            function_name="RealCalculatorTool",
            parameters={"expression": "12 * 12"},
        )
        elapsed = time.perf_counter() - started
        durations.append(elapsed)
        assert res["success"] is True, f"execution #{i} misclassified: {res}"
        assert res["result"]["result"] == 144

    worst = max(durations)
    # Every real execution completed with 5s+ of headroom under the 30s default,
    # proving startup/import overhead is not a timeout.
    assert worst < 25.0, f"worst real execution took {worst:.2f}s"


# ---------------------------------------------------------------------------
# C. Genuine timeout still fires, fails, and terminates the child (no orphan).
# ---------------------------------------------------------------------------

def test_actual_timeout_terminates_child_and_reports_failure(tmp_path, monkeypatch):
    """
    With an explicit short per-call budget, a deliberately slow child must:
      - raise TimeoutError (failure reported, never 'success'), and
      - have its process terminated (started marker present, completed marker absent,
        recorded child PID no longer alive).
    """
    target_dir = tmp_path / "slow_mod"
    target_dir.mkdir()
    _install_slow_module_on_path(target_dir)
    marker_dir = tmp_path / "markers"

    try:
        iso = ExecutionIsolation()  # default irrelevant; override used below
        started = time.perf_counter()
        with pytest.raises(TimeoutError):
            iso.execute_in_subprocess(
                module_path=SLOW_MODULE_NAME,
                function_name="SlowSandboxRegressionTool",
                parameters={"marker_dir": str(marker_dir), "sleep_seconds": 30.0},
                timeout_seconds=3.0,
            )
        elapsed = time.perf_counter() - started
        assert elapsed < 20.0, "timeout enforcement appears unbounded"

        # Child wrote its start marker (it entered the tool) but was killed before
        # completing -> timeout -> termination semantics preserved.
        started_marker = marker_dir / "started"
        completed_marker = marker_dir / "completed"

        if started_marker.exists():
            child_pid = int(started_marker.read_text(encoding="utf-8").strip())
            assert not completed_marker.exists(), "child completed despite timeout budget"
            time.sleep(0.3)  # allow OS-level reaping to settle
            assert not _pid_is_alive(child_pid), (
                f"child process {child_pid} survived its timeout; orphan detected"
            )
        else:
            # Pathological cold-start: child never even reached the tool body before
            # the budget fired. The TimeoutError above still proves enforcement; the
            # kill+wait in the isolation layer guarantees the spawned child was reaped.
            assert not completed_marker.exists()
    finally:
        if str(target_dir) in sys.path:
            sys.path.remove(str(target_dir))


def test_completion_near_timeout_boundary_succeeds(tmp_path):
    """
    A tool that completes just inside an explicitly configured budget must succeed
    (per-call override honored; boundary not over-triggered).
    """
    target_dir = tmp_path / "slow_mod"
    target_dir.mkdir()
    _install_slow_module_on_path(target_dir)
    marker_dir = tmp_path / "markers"

    try:
        iso = ExecutionIsolation()
        res = iso.execute_in_subprocess(
            module_path=SLOW_MODULE_NAME,
            function_name="SlowSandboxRegressionTool",
            parameters={"marker_dir": str(marker_dir), "sleep_seconds": 0.2},
            timeout_seconds=2.0,
        )
        assert res["success"] is True
        assert res["result"]["result"] == "slow-tool-completed"
        assert (marker_dir / "started").exists()
        assert (marker_dir / "completed").exists()
    finally:
        if str(target_dir) in sys.path:
            sys.path.remove(str(target_dir))


# ---------------------------------------------------------------------------
# E. Remediation must not weaken capability/signature verification.
# ---------------------------------------------------------------------------

def test_forged_capability_still_rejected_through_real_subprocess_path():
    """
    A capability with a forged signature must be rejected by the child's cryptographic
    verification and surfaced as failure -- proving the timeout remediation did not
    bypass AgentShield capability gating in the subprocess boundary.
    """
    iso = ExecutionIsolation()  # production default
    forged = {
        "authorization_id": "auth-forged-0001",
        "request_id": "req-forged-0001",
        "correlation_id": "corr-forged-0001",
        "decision": "ALLOW",
        "request_fingerprint": "f" * 64,
        "policy_id": "policy.allow",
        "risk_score": 0.0,
        "issued_at": "2026-01-01T00:00:00+00:00",
        "expires_at": "2026-12-31T23:59:59+00:00",
        "signature": "0" * 64,
    }
    res = iso.execute_in_subprocess(
        module_path="app.security.execution.tools.real_calculator",
        function_name="RealCalculatorTool",
        parameters={"expression": "6 * 7"},
        capability=forged,
        require_capability=True,
    )
    assert res["success"] is False
    assert res["executed"] is True
    assert res["isolated"] is True
    assert "forged" in res.get("error", "").lower()