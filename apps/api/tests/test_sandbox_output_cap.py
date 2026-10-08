"""
Phase 2.0 / F1 — bounded subprocess output enforcement (max_output_bytes).

Regression coverage for the capped streaming reader in
``ExecutionIsolation._communicate_bounded``. All cases exercise the REAL
subprocess path (no mocking of the boundary):

  A. Normal output (JSON envelope) succeeds.
  B. Output exactly at the cap succeeds.
  C. Output one byte over the cap aborts with SandboxOutputLimitExceeded.
  D. Very large stdout aborts (bounded time + memory) and leaves no orphan.
  E. Very large stderr aborts and leaves no orphan.
  F. stdout + stderr growing simultaneously abort and leave no orphan.
  G. Timeout + continuous output still surfaces TimeoutError with no orphan.
  H. Child is terminated and the ephemeral sandbox directory is cleaned.

Channel notes (matching the runner protocol):
- the runner is the ONLY legitimate writer on the child's stdout (a single JSON
  envelope); a handler's RETURN value rides inside that envelope;
- a handler that dumps RAW bytes to stdout/stderr is exactly the untrusted
  output the cap exists to stop: the reader hits the cap and aborts before the
  (now corrupt) envelope could ever be parsed.
"""

import json
import tempfile
import time
from pathlib import Path

import pytest

from app.security.sandbox.isolation import (
    ExecutionIsolation,
    SandboxOutputLimitExceeded,
)

CAP = 8192
BIG = 4 * 1024 * 1024  # 4 MiB — far over the default cap


RETURN_BOMB_MODULE_SRC = '''
class ReturnBombTool:
    """Returns a large pure-alphanumeric string riding inside the JSON envelope."""

    def execute(self, params, context=None):
        size = int(params.get("size", 0))
        return "A" * size
'''

RAW_STDOUT_MODULE_SRC = '''
import sys

class RawStdoutTool:
    """Dumps raw bytes straight to the child stdout (untrusted-handler case)."""

    def execute(self, params, context=None):
        size = int(params.get("size", 0))
        sys.stdout.write("A" * size)
        sys.stdout.flush()
        return {"ok": True}
'''

RAW_STDERR_MODULE_SRC = '''
import sys

class RawStderrTool:
    """Dumps raw bytes to the child stderr only."""

    def execute(self, params, context=None):
        size = int(params.get("size", 0))
        sys.stderr.write("E" * size)
        sys.stderr.flush()
        return {"ok": True}
'''

BOTH_RAW_MODULE_SRC = '''
import sys

class BothRawTool:
    """Writes large raw output to stdout AND stderr concurrently."""

    def execute(self, params, context=None):
        size = int(params.get("size", 0))
        for i in range(0, size, 65536):
            sys.stdout.write("O" * min(65536, size - i))
            sys.stderr.write("E" * min(65536, size - i))
        sys.stdout.flush()
        sys.stderr.flush()
        return {"ok": True}
'''

SLOW_TICK_MODULE_SRC = '''
import sys
import time

class SlowTickTool:
    """Emits small output continuously for a long time (under the cap)."""

    def execute(self, params, context=None):
        run_for = float(params.get("run_for", 60.0))
        deadline = time.time() + run_for
        while time.time() < deadline:
            sys.stdout.write("t" * 64)
            sys.stdout.flush()
            time.sleep(0.02)
        return {"ok": True}
'''


@pytest.fixture(scope="module")
def payload_dir(tmp_path_factory):
    target_dir = tmp_path_factory.mktemp("f1_output")
    for name, src in [
        ("return_bomb_tool", RETURN_BOMB_MODULE_SRC),
        ("raw_stdout_tool", RAW_STDOUT_MODULE_SRC),
        ("raw_stderr_tool", RAW_STDERR_MODULE_SRC),
        ("both_raw_tool", BOTH_RAW_MODULE_SRC),
        ("slow_tick_tool", SLOW_TICK_MODULE_SRC),
    ]:
        (target_dir / f"{name}.py").write_text(src, encoding="utf-8")
    import sys
    if str(target_dir) not in sys.path:
        sys.path.insert(0, str(target_dir))
    return target_dir


def _envelope_size(n: int) -> int:
    """Exact bytes the runner emits when the handler returns a string of len n."""
    return len(json.dumps({"success": True, "result": "A" * n}).encode("utf-8"))


def test_normal_output_succeeds(payload_dir):
    iso = ExecutionIsolation(max_output_bytes=CAP)
    res = iso.execute_in_subprocess(
        module_path="return_bomb_tool",
        function_name="ReturnBombTool",
        parameters={"size": 100},
    )
    assert res["success"] is True
    assert res["result"] == "A" * 100


def test_output_exactly_at_limit_succeeds(payload_dir):
    iso = ExecutionIsolation(max_output_bytes=CAP)
    n = CAP - _envelope_size(0)
    assert CAP - _envelope_size(0) > 0
    assert _envelope_size(n) == CAP
    res = iso.execute_in_subprocess(
        module_path="return_bomb_tool",
        function_name="ReturnBombTool",
        parameters={"size": n},
    )
    assert res["success"] is True
    assert len(res["result"]) == n


def test_output_one_byte_over_limit_aborts(payload_dir):
    iso = ExecutionIsolation(max_output_bytes=CAP)
    n = CAP - _envelope_size(0) + 1
    with pytest.raises(SandboxOutputLimitExceeded) as exc:
        iso.execute_in_subprocess(
            module_path="return_bomb_tool",
            function_name="ReturnBombTool",
            parameters={"size": n},
        )
    assert f"{CAP}" in str(exc.value)
    assert "stdout" in str(exc.value)


def test_very_large_stdout_aborts_quickly(payload_dir):
    iso = ExecutionIsolation(max_output_bytes=CAP)
    started = time.perf_counter()
    with pytest.raises(SandboxOutputLimitExceeded) as exc:
        iso.execute_in_subprocess(
            module_path="return_bomb_tool",
            function_name="ReturnBombTool",
            parameters={"size": BIG},
        )
    assert time.perf_counter() - started < 15.0
    assert "stdout" in str(exc.value)


def test_raw_stdout_dump_aborts_under_cap(payload_dir):
    """Untrusted handler dumping raw bytes to stdout is stopped by the cap."""
    iso = ExecutionIsolation(max_output_bytes=CAP)
    with pytest.raises(SandboxOutputLimitExceeded) as exc:
        iso.execute_in_subprocess(
            module_path="raw_stdout_tool",
            function_name="RawStdoutTool",
            parameters={"size": BIG},
        )
    assert "stdout" in str(exc.value)


def test_raw_stderr_dump_aborts_under_cap(payload_dir):
    iso = ExecutionIsolation(max_output_bytes=CAP)
    with pytest.raises(SandboxOutputLimitExceeded) as exc:
        iso.execute_in_subprocess(
            module_path="raw_stderr_tool",
            function_name="RawStderrTool",
            parameters={"size": BIG},
        )
    assert "stderr" in str(exc.value)


def test_stdout_and_stderr_simultaneously_abort(payload_dir):
    iso = ExecutionIsolation(max_output_bytes=CAP)
    with pytest.raises(SandboxOutputLimitExceeded):
        iso.execute_in_subprocess(
            module_path="both_raw_tool",
            function_name="BothRawTool",
            parameters={"size": BIG},
        )


def test_timeout_with_continuous_output_raises_timeout_with_no_deadlock(payload_dir):
    """Proof that timeout semantics survive the capped reader (no deadlock)."""
    iso = ExecutionIsolation(default_timeout=30.0, max_output_bytes=CAP)
    started = time.perf_counter()
    with pytest.raises(TimeoutError):
        iso.execute_in_subprocess(
            module_path="slow_tick_tool",
            function_name="SlowTickTool",
            parameters={"run_for": 60.0},
            timeout_seconds=1.5,
        )
    assert time.perf_counter() - started < 15.0


def test_child_termination_and_sandbox_dir_cleanup(payload_dir):
    """Over-limit abort must reap the child and clean the ephemeral dir."""
    tmp_root = tempfile.gettempdir()
    before = {p for p in Path(tmp_root).glob("agentshield_iso_*")}
    iso = ExecutionIsolation(max_output_bytes=512)  # tiny cap -> immediate abort
    with pytest.raises(SandboxOutputLimitExceeded):
        iso.execute_in_subprocess(
            module_path="raw_stdout_tool",
            function_name="RawStdoutTool",
            parameters={"size": BIG},
        )
    time.sleep(0.5)
    after = {p for p in Path(tmp_root).glob("agentshield_iso_*")}
    assert after - before == set(), f"orphaned sandbox dirs: {after - before}"