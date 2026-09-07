"""
Comprehensive Test Suite for AgentShield Phase 20: Real Isolated Tools & Sandbox (SEC-04, SEC-06).

Contains >= 25 meaningful, independent tests covering:
1. RealCalculatorTool: pure AST evaluation, math operations, division by zero, attack AST node rejection.
2. RealFileSystemTool: path traversal defense (../, absolute paths, encoded), sandbox confinement, CRUD, size bounds.
3. RealHttpTool: SSRF protection, RFC 1918 blocking, loopback, cloud metadata (169.254.169.254), scheme checks.
4. RealCommandTool: binary allowlists, shell metacharacter injection blocking, git subcommand bounding.
5. ExecutionIsolation: subprocess boundary execution, environment cleansing, error containment.
"""

import os
import tempfile
from pathlib import Path
import pytest

from app.security.execution.tools.real_calculator import RealCalculatorTool
from app.security.execution.tools.real_filesystem import RealFileSystemTool, _resolve_safe_path
from app.security.execution.tools.real_http import RealHttpTool, _validate_safe_url
from app.security.execution.tools.real_command import RealCommandTool
from app.security.sandbox.isolation import ExecutionIsolation, get_clean_sandbox_environment


# ============================================================================
# 1. REAL CALCULATOR TOOL TESTS (Pure AST, Zero eval/exec)
# ============================================================================

def test_calculator_basic_arithmetic():
    calc = RealCalculatorTool()
    res1 = calc.execute({"expression": "10 + 5"})
    assert res1["result"] == 15
    res2 = calc.execute({"expression": "20 - 7"})
    assert res2["result"] == 13
    res3 = calc.execute({"expression": "6 * 7"})
    assert res3["result"] == 42
    res4 = calc.execute({"expression": "100 / 4"})
    assert res4["result"] == 25.0
    res5 = calc.execute({"expression": "17 % 5"})
    assert res5["result"] == 2


def test_calculator_complex_nested_expression():
    calc = RealCalculatorTool()
    res = calc.execute({"expression": "((10 + 20) * 3) / (5 - 2)"})
    assert res["result"] == 30.0


def test_calculator_supported_math_functions():
    calc = RealCalculatorTool()
    res_sqrt = calc.execute({"expression": "sqrt(16) + 4"})
    assert res_sqrt["result"] == 8.0
    res_pi = calc.execute({"expression": "round(pi, 2)"})
    assert res_pi["result"] == 3.14
    res_abs = calc.execute({"expression": "abs(-42)"})
    assert res_abs["result"] == 42


def test_calculator_division_by_zero_rejection():
    calc = RealCalculatorTool()
    with pytest.raises(ZeroDivisionError, match="zero"):
        calc.execute({"expression": "100 / 0"})


def test_calculator_malicious_function_call_rejected():
    calc = RealCalculatorTool()
    # Attempts to call unwhitelisted functions or builtins
    with pytest.raises(ValueError, match="permitted|Unsupported"):
        calc.execute({"expression": "__import__('os').system('whoami')"})


def test_calculator_attribute_access_rejected():
    calc = RealCalculatorTool()
    with pytest.raises(ValueError, match="permitted|Unsupported"):
        calc.execute({"expression": "(1).__class__.__bases__"})


def test_calculator_large_exponentiation_rejected():
    calc = RealCalculatorTool()
    with pytest.raises(ValueError, match="safe limits"):
        calc.execute({"expression": "9999 ** 9999"})


# ============================================================================
# 2. REAL FILESYSTEM TOOL TESTS (Sandbox Confinement & Traversal Defense)
# ============================================================================

def test_filesystem_path_traversal_dot_dot_rejected():
    fs = RealFileSystemTool()
    with pytest.raises(PermissionError, match="Path traversal detected"):
        fs.execute({"operation": "read", "path": "../../etc/passwd"})


def test_filesystem_path_traversal_encoded_rejected():
    fs = RealFileSystemTool()
    with pytest.raises(PermissionError, match="Path traversal detected"):
        fs.execute({"operation": "read", "path": "..%2f..%2fsecrets.json"})


def test_filesystem_absolute_escape_rejected():
    fs = RealFileSystemTool()
    with pytest.raises(PermissionError, match="Path traversal detected"):
        fs.execute({"operation": "write", "path": "C:\\Windows\\System32\\bad.dll", "content": "x"})


def test_filesystem_write_and_read_confinement():
    fs = RealFileSystemTool()
    test_path = "test_subfolder/sample.txt"
    test_content = "AgentShield Real File Isolation Test"

    write_res = fs.execute({"operation": "write", "path": test_path, "content": test_content})
    assert write_res["operation"] == "write"
    assert write_res["bytes_written"] == len(test_content.encode("utf-8"))

    read_res = fs.execute({"operation": "read", "path": test_path})
    assert read_res["content"] == test_content

    # Clean up
    fs.execute({"operation": "delete", "path": test_path})


def test_filesystem_list_and_stat_operations():
    fs = RealFileSystemTool()
    fs.execute({"operation": "write", "path": "dir_test/item1.txt", "content": "123"})
    
    stat_res = fs.execute({"operation": "stat", "path": "dir_test/item1.txt"})
    assert stat_res["is_file"] is True
    assert stat_res["size_bytes"] == 3

    list_res = fs.execute({"operation": "list", "path": "dir_test"})
    assert "item1.txt" in list_res["items"]

    fs.execute({"operation": "delete", "path": "dir_test/item1.txt"})


def test_filesystem_delete_operation():
    fs = RealFileSystemTool()
    fs.execute({"operation": "write", "path": "temp_delete.txt", "content": "delete me"})
    del_res = fs.execute({"operation": "delete", "path": "temp_delete.txt"})
    assert del_res["success"] is True

    with pytest.raises(FileNotFoundError):
        fs.execute({"operation": "read", "path": "temp_delete.txt"})


def test_filesystem_file_size_limit_rejection():
    fs = RealFileSystemTool()
    large_content = "X" * (1024 * 1024 + 50)  # > 1 MB
    with pytest.raises(ValueError, match="exceeds maximum"):
        fs.execute({"operation": "write", "path": "oversized.bin", "content": large_content})


# ============================================================================
# 3. REAL HTTP TOOL TESTS (SSRF & Metadata Defense)
# ============================================================================

def test_http_private_ip_rfc1918_blocked():
    private_targets = [
        "http://10.0.0.1/admin",
        "http://172.16.0.5/api",
        "http://192.168.1.100/status",
    ]
    for url in private_targets:
        with pytest.raises(PermissionError, match="SSRF Protection"):
            _validate_safe_url(url)


def test_http_loopback_blocked():
    loopback_targets = [
        "http://127.0.0.1:8000/api",
        "http://localhost:3000/dashboard",
        "http://0.0.0.0:5000",
    ]
    for url in loopback_targets:
        with pytest.raises(PermissionError, match="SSRF Protection"):
            _validate_safe_url(url)


def test_http_cloud_metadata_blocked():
    metadata_url = "http://169.254.169.254/latest/meta-data/"
    with pytest.raises(PermissionError, match="SSRF Protection"):
        _validate_safe_url(metadata_url)


def test_http_link_local_blocked():
    link_local_url = "http://169.254.1.1/device"
    with pytest.raises(PermissionError, match="SSRF Protection"):
        _validate_safe_url(link_local_url)


def test_http_forbidden_schemes_blocked():
    forbidden_schemes = [
        "file:///etc/passwd",
        "gopher://example.com",
        "ftp://ftp.example.com",
        "data:text/plain;base64,SGVsbG8=",
    ]
    for url in forbidden_schemes:
        with pytest.raises(ValueError, match="Unauthorized URL scheme"):
            _validate_safe_url(url)


def test_http_missing_hostname_rejected():
    with pytest.raises(ValueError, match="valid hostname"):
        _validate_safe_url("http:///path/without/host")


def test_http_valid_scheme_accepted():
    parsed = _validate_safe_url("https://example.com/api/v1/health")
    assert parsed.scheme == "https"
    assert parsed.hostname == "example.com"


# ============================================================================
# 4. REAL COMMAND TOOL TESTS (Binary Allowlist & Metacharacter Rejection)
# ============================================================================

def test_command_allowlisted_echo():
    cmd = RealCommandTool()
    res = cmd.execute({"command": "echo agentshield_verified"})
    assert res["success"] is True
    assert "agentshield_verified" in res["stdout"]


def test_command_non_allowlisted_binary_rejected():
    cmd = RealCommandTool()
    disallowed = ["nc -lvnp 4444", "rm -rf /", "powershell -Command whoami", "python -c 'print(1)'"]
    for bad_cmd in disallowed:
        with pytest.raises(PermissionError, match="not permitted|Forbidden|injection"):
            cmd.execute({"command": bad_cmd})


def test_command_shell_injection_semicolon_rejected():
    cmd = RealCommandTool()
    with pytest.raises(PermissionError, match="Shell injection detected"):
        cmd.execute({"command": "echo safe; cat /etc/passwd"})


def test_command_shell_injection_pipe_rejected():
    cmd = RealCommandTool()
    with pytest.raises(PermissionError, match="Shell injection detected"):
        cmd.execute({"command": "echo secret | whoami"})


def test_command_shell_injection_subshell_rejected():
    cmd = RealCommandTool()
    with pytest.raises(PermissionError, match="Shell injection detected"):
        cmd.execute({"command": "echo $(whoami)"})


def test_command_git_restricted_subcommands():
    cmd = RealCommandTool()
    # git status is allowlisted
    git_status = cmd.execute({"command": "git status"})
    assert "exit_code" in git_status

    # git push is NOT permitted
    with pytest.raises(PermissionError, match="not permitted"):
        cmd.execute({"command": "git push origin master"})


# ============================================================================
# 5. EXECUTION ISOLATION (Process-Level Boundary)
# ============================================================================

def test_execution_isolation_clean_environment():
    env = get_clean_sandbox_environment()
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "DATABASE_URL" not in env
    assert "ADMIN_PASSWORD" not in env
    assert "PATH" in env or "SYSTEMROOT" in env


def test_execution_isolation_runs_in_subprocess():
    isolation = ExecutionIsolation(default_timeout=5.0)
    # Execute RealCalculatorTool via isolated child OS process
    res = isolation.execute_in_subprocess(
        module_path="app.security.execution.tools.real_calculator",
        function_name="RealCalculatorTool",
        parameters={"expression": "12 * 12"},
    )
    assert res["success"] is True
    assert res["result"]["result"] == 144


def test_execution_isolation_catches_runtime_errors():
    isolation = ExecutionIsolation(default_timeout=5.0)
    res = isolation.execute_in_subprocess(
        module_path="app.security.execution.tools.real_calculator",
        function_name="RealCalculatorTool",
        parameters={"expression": "10 / 0"},
    )
    assert res["success"] is False
    assert "ZeroDivisionError" in res.get("error_type", "") or "zero" in res.get("error", "").lower()
