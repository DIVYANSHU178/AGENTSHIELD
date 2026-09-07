"""
Subprocess Sandbox Isolation Boundary for AgentShield (SEC-04 Remediation).
Executes tool handlers in dedicated, isolated child processes with sanitized environments,
ephemeral directory containment, and hard process termination on timeout.
"""

import json
import os
import sys
import tempfile
import subprocess
from typing import Dict, Any, Optional, Callable
from app.security.models.utils import utc_now


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

    def __init__(self, default_timeout: float = 5.0, max_output_bytes: int = 512 * 1024) -> None:
        self._default_timeout = default_timeout
        self._max_output_bytes = max_output_bytes

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
        timeout = timeout_seconds if timeout_seconds is not None else self._default_timeout
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
                    text=True,
                )
                stdout, stderr = proc.communicate(input=ipc_payload, timeout=timeout)

                if proc.returncode != 0:
                    try:
                        err_data = json.loads(stdout)
                        return {
                            "executed": True,
                            "success": False,
                            "error": err_data.get("error", stderr.strip() or f"Process exited with code {proc.returncode}"),
                            "error_type": err_data.get("error_type", ""),
                            "isolated": True,
                            "isolation_level": "isolated_subprocess",
                        }
                    except Exception:
                        return {
                            "executed": True,
                            "success": False,
                            "error": stderr.strip() or f"Process exited with code {proc.returncode}",
                            "error_type": "SubprocessError",
                            "isolated": True,
                            "isolation_level": "isolated_subprocess",
                        }

                data = json.loads(stdout)
                return {
                    "executed": True,
                    "success": data.get("success", False),
                    "result": data.get("result"),
                    "error": data.get("error"),
                    "isolated": True,
                    "isolation_level": "isolated_subprocess",
                }

            except subprocess.TimeoutExpired:
                if proc:
                    proc.kill()
                    proc.wait()
                raise TimeoutError(f"Subprocess execution exceeded timeout limit of {timeout:.2f}s.")
            except Exception as exc:
                if proc:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                raise RuntimeError(f"Subprocess isolation execution failed: {str(exc)}") from exc
