"""
Subprocess Sandbox Isolation Boundary for AgentShield (SEC-04 Remediation).
Executes tool handlers in dedicated, isolated child processes with sanitized environments,
ephemeral directory containment, and hard process termination on timeout.
"""

import json
import math
import os
import sys
import tempfile
import subprocess
import threading
from typing import Dict, Any, ByteString, Optional, Callable
from app.security.models.utils import utc_now


# Phase 2.0 / F2 — defense-in-depth executor timeout ceiling. Mirrors the
# policy contract (``SandboxExecutionLimits.timeout_seconds`` ge/le bounds)
# at the LOW-LEVEL executor so ``inf``/``NaN``/negative values can never reach
# ``subprocess.wait()`` regardless of the caller's validation path.
MAX_EXECUTION_TIMEOUT_SECONDS = 300.0

# Phase 2.0 / F1 — read granularity for the capped pipe readers. Keeps the
# transient overshoot above ``max_output_bytes`` small (<= one chunk) so the
# resident memory of the parent stays bounded while the child is running.
_IO_CHUNK_BYTES = 65536


def _validate_timeout(value: Optional[float], default: float) -> float:
    """
    Validate and normalize an executor timeout.

    ``None`` selects the configured default (finite). Explicit values must be
    finite, strictly positive floats within
    ``MAX_EXECUTION_TIMEOUT_SECONDS`` — everything else is REJECTED loudly
    (NaN, +/-inf, 0, negatives, non-numeric, over-max) rather than silently
    clamped, so callers can never accidentally request unbounded execution.
    """
    if value is None:
        return default
    try:
        val = float(value)
    except (TypeError, ValueError):
        raise ValueError(
            f"timeout_seconds must be a numeric value, got {value!r}."
        ) from None
    if math.isnan(val) or math.isinf(val):
        raise ValueError(
            "timeout_seconds must be finite — NaN/infinity are not valid "
            "execution budgets (unbounded execution is never permitted)."
        )
    if val <= 0:
        raise ValueError("timeout_seconds must be strictly positive.")
    if val > MAX_EXECUTION_TIMEOUT_SECONDS:
        raise ValueError(
            f"timeout_seconds exceeds the maximum allowed "
            f"{MAX_EXECUTION_TIMEOUT_SECONDS:.2f}s."
        )
    return val


class SandboxOutputLimitExceeded(RuntimeError):
    """Raised when a sandboxed child exceeds ``max_output_bytes``.

    The child is terminated by the capped reader before the exception is
    raised, so no orphan process survives an output-limit abort.
    """


def get_clean_sandbox_environment() -> Dict[str, str]:
    """
    Construct a minimal execution environment stripped of application secrets,
    database connection strings, API keys, and session tokens.
    """
    clean_env: Dict[str, str] = {}
    safe_keys = {
        "SYSTEMROOT",
        "WINDIR",
        "PATH",
        "TEMP",
        "TMP",
        "USER",
        "HOME",
        "LANG",
        "LC_ALL",
        "PYTHONPATH",
        "PYTHONHOME",
        "AGENTSHIELD_AUTHORIZATION_SECRET",
        "AGENTSHIELD_ENVIRONMENT",
        "SANDBOX_ROOT_DIR",
    }
    for key, val in os.environ.items():
        if key.upper() in safe_keys:
            clean_env[key] = val

    # Ensure PYTHONPATH includes project roots and current python environment
    current_cwd = os.path.abspath(os.getcwd())
    path_entries = []
    api_dir = os.path.join(current_cwd, "apps", "api")
    if os.path.isdir(api_dir):
        path_entries.append(api_dir)
    path_entries.append(current_cwd)
    for p in sys.path:
        if p and p not in path_entries and os.path.exists(p):
            path_entries.append(p)
    clean_env["PYTHONPATH"] = os.pathsep.join(path_entries)

    # Propagate authorization secret and environment from active configuration
    try:
        from app.config.settings import settings
        clean_env["AGENTSHIELD_AUTHORIZATION_SECRET"] = settings.get_authorization_secret()
        clean_env["AGENTSHIELD_ENVIRONMENT"] = settings.ENVIRONMENT
    except Exception:
        pass

    return clean_env


class ExecutionIsolation:
    """
    Process-level containment boundary for executing tool handlers safely.
    Provides true OS process separation with hard timeout kills and memory/output caps.
    """

    def __init__(self, default_timeout: float = 30.0, max_output_bytes: int = 512 * 1024) -> None:
        self._default_timeout = default_timeout
        self._max_output_bytes = max_output_bytes

    def _communicate_bounded(
        self,
        proc: subprocess.Popen,
        ipc_payload: bytes,
        timeout: float,
    ) -> tuple:
        """
        Phase 2.0 / F1 — bounded IPC bridge.

        Writes the json IPC payload to the child's stdin and streams stdout /
        stderr into capped byte buffers WHILE the child is running. The bound
        applies at read time (not by truncating a final string): the moment the
        cumulative stdout OR stderr exceeds ``max_output_bytes`` the child is
        killed and ``SandboxOutputLimitExceeded`` is raised. This prevents an
        untrusted/tool handler from generating unbounded memory in the parent,
        preserves hard timeout semantics (kill + wait/reap), and avoids the
        deadlock of naive sequential pipe reads by draining both pipes from
        dedicated reader threads concurrently.

        Returns ``(stdout_bytes, stderr_bytes)`` when the child stays under
        the cap.
        """
        stdout_buf = bytearray()
        stderr_buf = bytearray()
        state = {"overflow": None, "lock": threading.Lock()}
        cap = self._max_output_bytes

        def _write_stdin() -> None:
            try:
                proc.stdin.write(ipc_payload)
                proc.stdin.flush()
            except (BrokenPipeError, OSError, ValueError):
                pass
            finally:
                try:
                    proc.stdin.close()
                except Exception:
                    pass

        def _read_capped(stream, buf: bytearray, reason: str) -> None:
            while True:
                try:
                    chunk = stream.read(_IO_CHUNK_BYTES)
                except (OSError, ValueError):
                    return
                if not chunk:
                    return
                with state["lock"]:
                    if state["overflow"] is not None:
                        return
                    if len(buf) + len(chunk) > cap:
                        # Over the cap: record why, keep a bounded slice for
                        # diagnostics, terminate the child, and stop reading.
                        state["overflow"] = reason
                        room = max(0, cap - len(buf))
                        buf.extend(chunk[:room])
                        try:
                            proc.kill()
                        except Exception:
                            pass
                        return
                    buf.extend(chunk)

        writer = threading.Thread(target=_write_stdin, daemon=True)
        reader_out = threading.Thread(
            target=_read_capped, args=(proc.stdout, stdout_buf, "stdout"), daemon=True
        )
        reader_err = threading.Thread(
            target=_read_capped, args=(proc.stderr, stderr_buf, "stderr"), daemon=True
        )
        writer.start()
        reader_out.start()
        reader_err.start()

        timeout_error: Optional[subprocess.TimeoutExpired] = None
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            timeout_error = exc
            try:
                proc.kill()
                proc.wait()
            finally:
                pass
        finally:
            try:
                proc.stdin.close()
            except Exception:
                pass
            writer.join(timeout=5.0)
            reader_out.join(timeout=5.0)
            reader_err.join(timeout=5.0)
            try:
                proc.stdout.close()
            except Exception:
                pass
            try:
                proc.stderr.close()
            except Exception:
                pass

        if timeout_error is not None:
            raise TimeoutError(
                f"Subprocess execution exceeded timeout limit of {timeout:.2f}s."
            )
        if state["overflow"] is not None:
            raise SandboxOutputLimitExceeded(
                f"Sandboxed child exceeded the max_output_bytes cap of {cap} "
                f"bytes on {state['overflow']} (stdout={len(stdout_buf)} bytes, "
                f"stderr={len(stderr_buf)} bytes). Execution aborted and child "
                "terminated."
            )
        return bytes(stdout_buf), bytes(stderr_buf)

    def execute_in_subprocess(
        self,
        module_path: str,
        function_name: str,
        parameters: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
        timeout_seconds: Optional[float] = None,
        capability: Optional[Dict[str, Any]] = None,
        require_capability: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute a python function in a dedicated, isolated child process.
        Communicates via JSON IPC over stdin/stdout.
        Verifies ExecutionAuthorization capability token cryptographically if supplied or required.
        """
        timeout = _validate_timeout(timeout_seconds, self._default_timeout)
        clean_env = get_clean_sandbox_environment()

        # IPC Runner script that loads target and executes in child process
        runner_code = """
import sys, json, importlib

try:
    input_data = json.loads(sys.stdin.read())
    mod_name = input_data["module"]
    fn_name = input_data["function"]
    params = input_data.get("parameters", {})
    ctx = input_data.get("context", {})
    cap = input_data.get("capability")
    req_cap = input_data.get("require_capability", False)

    if req_cap and not cap:
        raise PermissionError("Execution denied: ExecutionAuthorization capability token is required.")

    if cap:
        import hmac, hashlib
        from datetime import datetime, timezone
        from app.config.settings import settings
        from app.security.enforcement.authorization import calculate_authorization_signature

        secret = settings.get_authorization_secret()
        issued = datetime.fromisoformat(cap["issued_at"])
        expires = datetime.fromisoformat(cap["expires_at"]) if cap.get("expires_at") else None

        expected_sig = calculate_authorization_signature(
            authorization_id=cap["authorization_id"],
            request_id=cap["request_id"],
            correlation_id=cap.get("correlation_id", cap["request_id"]),
            decision_value=cap.get("decision", "ALLOW"),
            request_fingerprint=cap["request_fingerprint"],
            policy_id=cap.get("policy_id", "policy.allow"),
            risk_score=float(cap.get("risk_score", 0.0)),
            issued_at=issued,
            expires_at=expires,
            secret_key=secret,
        )
        if not hmac.compare_digest(expected_sig, cap.get("signature", "")):
            raise PermissionError("Execution denied: Invalid or forged ExecutionAuthorization signature.")

        if expires:
            now = datetime.now(timezone.utc)
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if now > expires:
                raise PermissionError("Execution denied: ExecutionAuthorization capability token has expired.")

    mod = importlib.import_module(mod_name)
    fn = getattr(mod, fn_name)
    
    # If it is a class, instantiate and call execute
    if isinstance(fn, type):
        inst = fn()
        result = inst.execute(params, ctx)
    else:
        result = fn(params)

    out = json.dumps({"success": True, "result": result})
    sys.stdout.write(out)
    sys.stdout.flush()
except Exception as e:
    err = json.dumps({"success": False, "error": str(e), "error_type": type(e).__name__})
    sys.stdout.write(err)
    sys.stdout.flush()
    sys.exit(1)
"""

        ipc_payload = json.dumps({
            "module": module_path,
            "function": function_name,
            "parameters": parameters,
            "context": context or {},
            "capability": capability,
            "require_capability": require_capability,
        })

        with tempfile.TemporaryDirectory(prefix="agentshield_iso_") as temp_dir:
            proc = None
            try:
                proc = subprocess.Popen(
                    [sys.executable, "-c", runner_code],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=temp_dir,
                    env=clean_env,
                    text=False,
                    bufsize=0,
                )
                stdout, stderr = self._communicate_bounded(
                    proc, ipc_payload.encode("utf-8"), timeout
                )
                stdout_text = stdout.decode("utf-8", errors="replace")
                stderr_text = stderr.decode("utf-8", errors="replace")

                if proc.returncode != 0:
                    try:
                        err_data = json.loads(stdout_text)
                        return {
                            "executed": True,
                            "success": False,
                            "error": err_data.get("error", stderr_text.strip() or f"Process exited with code {proc.returncode}"),
                            "error_type": err_data.get("error_type", ""),
                            "isolated": True,
                            "isolation_level": "isolated_subprocess",
                        }
                    except Exception:
                        return {
                            "executed": True,
                            "success": False,
                            "error": stderr_text.strip() or f"Process exited with code {proc.returncode}",
                            "error_type": "SubprocessError",
                            "isolated": True,
                            "isolation_level": "isolated_subprocess",
                        }

                data = json.loads(stdout_text)
                return {
                    "executed": True,
                    "success": data.get("success", False),
                    "result": data.get("result"),
                    "error": data.get("error"),
                    "isolated": True,
                    "isolation_level": "isolated_subprocess",
                }

            except SandboxOutputLimitExceeded:
                # Phase 2.0 / F1 — output-cap aborts surface as their own error
                # type (child already killed + reaped inside _communicate_bounded).
                raise
            except subprocess.TimeoutExpired:
                if proc:
                    proc.kill()
                    proc.wait()
                raise TimeoutError(f"Subprocess execution exceeded timeout limit of {timeout:.2f}s.")
            except TimeoutError:
                # Already converted + child killed/reaped by _communicate_bounded.
                raise
            except Exception as exc:
                if proc:
                    try:
                        proc.kill()
                        proc.wait()
                    except Exception:
                        pass
                raise RuntimeError(f"Subprocess isolation execution failed: {str(exc)}") from exc
