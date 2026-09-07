"""
RealCommandTool: Restricted, isolated shell/binary runner.
Enforces binary allowlists, shell metacharacter rejection, sanitized environment, and strict timeouts.
"""

import os
import shutil
import subprocess
import tempfile
from typing import Dict, Any, Optional, List
from app.security.models import ToolCategory
from app.security.execution.tools.base import BaseTool

ALLOWED_COMMANDS = frozenset({"echo", "date", "whoami", "cat", "head", "wc", "git"})
ALLOWED_GIT_SUBCOMMANDS = frozenset({"status", "log", "--version", "branch"})
SHELL_METACHARACTERS = frozenset({";", "&", "|", "`", "$", "(", ")", "<", ">", "\n", "\r"})
DEFAULT_TIMEOUT_SECONDS = 5.0
MAX_OUTPUT_BYTES = 100 * 1024  # 100 KB


def _sanitize_environment() -> Dict[str, str]:
    """Provide a minimal, sanitized environment with zero secret leakage."""
    clean_env: Dict[str, str] = {}
    for key in ("SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP", "USER", "HOME"):
        val = os.environ.get(key)
        if val:
            clean_env[key] = val
    return clean_env


class RealCommandTool(BaseTool):
    """
    Restricted command runner enforcing binary allowlists and isolated process execution.
    """

    @property
    def name(self) -> str:
        return "command.restricted"

    @property
    def description(self) -> str:
        return "Restricted command executor running allowlisted utilities in an isolated subprocess"

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.UNRESTRICTED  # requires elevated privilege/review

    def execute(self, parameters: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        raw_cmd = parameters.get("command")
        args_param = parameters.get("args")
        binary_param = parameters.get("binary")
        arguments_param = parameters.get("arguments")

        cmd_tokens: List[str] = []
        if isinstance(raw_cmd, str) and raw_cmd.strip():
            # Check for shell metacharacters
            for char in raw_cmd:
                if char in SHELL_METACHARACTERS:
                    raise PermissionError(f"Shell injection detected: metacharacter '{char}' is forbidden.")
            cmd_tokens = raw_cmd.strip().split()
        elif isinstance(args_param, list):
            cmd_tokens = [str(a).strip() for a in args_param if str(a).strip()]
        elif binary_param:
            cmd_tokens = [str(binary_param).strip()]
            if isinstance(arguments_param, list):
                cmd_tokens.extend([str(a).strip() for a in arguments_param if str(a).strip()])

        if not cmd_tokens:
            raise ValueError("Parameter 'command', 'args', or 'binary' is required.")

        binary = cmd_tokens[0].lower()
        # Strip path or extensions (e.g. git.exe -> git)
        base_binary = os.path.basename(binary).replace(".exe", "")

        if base_binary not in ALLOWED_COMMANDS:
            raise PermissionError(
                f"Binary '{base_binary}' is not permitted. Allowed binaries: {sorted(list(ALLOWED_COMMANDS))}"
            )

        if base_binary == "echo":
            out_str = " ".join(cmd_tokens[1:]) + "\n"
            return {
                "binary": "echo",
                "exit_code": 0,
                "stdout": out_str,
                "stderr": "",
                "success": True,
            }

        if base_binary == "git" and len(cmd_tokens) > 1:
            subcmd = cmd_tokens[1].lower()
            if subcmd not in ALLOWED_GIT_SUBCOMMANDS:
                raise PermissionError(f"Git subcommand '{subcmd}' is not permitted.")

        # Find executable path
        resolved_binary = shutil.which(cmd_tokens[0])
        if not resolved_binary:
            # Fallback to direct token if on system path
            resolved_binary = cmd_tokens[0]

        exec_args = [resolved_binary] + cmd_tokens[1:]
        clean_env = _sanitize_environment()

        with tempfile.TemporaryDirectory(prefix="agentshield_cmd_") as temp_dir:
            try:
                proc = subprocess.run(
                    exec_args,
                    shell=False,
                    cwd=temp_dir,
                    env=clean_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=DEFAULT_TIMEOUT_SECONDS,
                )
                stdout = proc.stdout[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
                stderr = proc.stderr[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")

                return {
                    "binary": base_binary,
                    "exit_code": proc.returncode,
                    "stdout": stdout,
                    "stderr": stderr,
                    "success": proc.returncode == 0,
                }
            except subprocess.TimeoutExpired:
                raise TimeoutError(f"Command execution timed out after {DEFAULT_TIMEOUT_SECONDS}s.")
            except Exception as exc:
                raise RuntimeError(f"Command execution failed: {str(exc)}") from exc
