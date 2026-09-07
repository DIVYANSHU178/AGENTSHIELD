"""
RealFileSystemTool: Sandboxed filesystem operations with strict path traversal prevention.
Restricted to an isolated sandbox root directory with enforced size caps.
"""

import os
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional
from app.security.models import ToolCategory
from app.security.execution.tools.base import BaseTool

MAX_FILE_SIZE_BYTES = 1024 * 1024  # 1 MB ceiling


def _get_sandbox_root(session_id: Optional[str] = None) -> Path:
    """Resolve and ensure the authoritative sandbox root directory."""
    base_env = os.environ.get("SANDBOX_ROOT_DIR")
    if base_env:
        root = Path(base_env).resolve()
    else:
        root = Path(tempfile.gettempdir()).resolve() / "agentshield_sandbox"

    if session_id and session_id.strip():
        # Clean alphanumeric session ID
        clean_sess = "".join(c for c in session_id if c.isalnum() or c in ("-", "_"))
        root = root / clean_sess

    root.mkdir(parents=True, exist_ok=True)
    return root


import urllib.parse


def _resolve_safe_path(root: Path, relative_path: str) -> Path:
    """
    Resolve target path and verify it remains strictly within the sandbox root.
    Decodes multi-pass URL percent-encoding to prevent %2e%2e and %252e%252e traversal bypasses.
    Rejects null-byte injection attempts.
    Raises PermissionError on path traversal attempt.
    """
    decoded = relative_path
    for _ in range(3):
        unquoted = urllib.parse.unquote(decoded)
        if unquoted == decoded:
            break
        decoded = unquoted

    if "\x00" in decoded:
        raise PermissionError(f"Null-byte injection detected in path '{relative_path}'.")

    clean_str = decoded.strip()
    raw_path = Path(clean_str)
    if raw_path.is_absolute() or clean_str.startswith("/") or clean_str.startswith("\\"):
        target = (root / clean_str.lstrip("/\\")).resolve() if clean_str.startswith(str(root)) else raw_path.resolve()
    else:
        target = (root / clean_str).resolve()

    # Invariant: target must be root or a descendant of root
    try:
        target.relative_to(root)
    except ValueError:
        raise PermissionError(f"Path traversal detected: target '{relative_path}' escapes sandbox root.")

    return target


class RealFileSystemTool(BaseTool):
    """
    Isolated filesystem operations tool.
    Guarantees confinement to sandbox directory and prevents traversal attacks.
    """

    @property
    def name(self) -> str:
        return "filesystem"

    @property
    def description(self) -> str:
        return "Sandboxed filesystem reader, writer, and directory inspector"

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.READ_WRITE_ISOLATED

    def execute(self, parameters: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        session_id = None
        if context:
            session_id = context.get("session_id") or context.get("task_id")

        root = _get_sandbox_root(session_id)
        operation = str(parameters.get("operation", "read")).lower().strip()
        path_str = str(parameters.get("path", "")).strip()

        if not path_str and operation != "list_directory":
            raise ValueError("Parameter 'path' is required for filesystem operations.")

        target = _resolve_safe_path(root, path_str if path_str else ".")

        if operation in ("read", "read_file"):
            if not target.exists():
                raise FileNotFoundError(f"File not found: '{path_str}'")
            if not target.is_file():
                raise IsADirectoryError(f"Target is a directory, not a file: '{path_str}'")
            if target.stat().st_size > MAX_FILE_SIZE_BYTES:
                raise ValueError(f"File size exceeds maximum allowed limit of {MAX_FILE_SIZE_BYTES} bytes.")

            content = target.read_text(encoding="utf-8", errors="replace")
            return {
                "operation": "read",
                "path": path_str,
                "size_bytes": len(content.encode("utf-8")),
                "content": content,
                "success": True,
            }

        elif operation in ("write", "write_file"):
            content = str(parameters.get("content", ""))
            encoded = content.encode("utf-8")
            if len(encoded) > MAX_FILE_SIZE_BYTES:
                raise ValueError(f"Content exceeds maximum write size of {MAX_FILE_SIZE_BYTES} bytes.")

            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            return {
                "operation": "write",
                "path": path_str,
                "bytes_written": len(encoded),
                "created": True,
                "success": True,
            }

        elif operation in ("list", "list_directory"):
            if not target.exists():
                raise FileNotFoundError(f"Directory not found: '{path_str}'")
            if not target.is_dir():
                raise NotADirectoryError(f"Target is a file, not a directory: '{path_str}'")

            entries = []
            for item in sorted(target.iterdir()):
                entries.append({
                    "name": item.name,
                    "is_dir": item.is_dir(),
                    "size_bytes": item.stat().st_size if item.is_file() else 0,
                })
            return {
                "operation": "list_directory",
                "path": path_str,
                "count": len(entries),
                "entries": entries,
                "items": [item["name"] for item in entries],
                "success": True,
            }

        elif operation in ("stat", "file_stat"):
            if not target.exists():
                raise FileNotFoundError(f"Target does not exist: '{path_str}'")
            st = target.stat()
            return {
                "operation": "file_stat",
                "path": path_str,
                "is_file": target.is_file(),
                "is_dir": target.is_dir(),
                "size_bytes": st.st_size,
                "mtime": st.st_mtime,
            }

        elif operation in ("delete", "delete_file"):
            if not target.exists():
                raise FileNotFoundError(f"File not found: '{path_str}'")
            if target.is_dir():
                raise PermissionError("Directory recursive deletion not allowed via this tool.")
            target.unlink()
            return {
                "operation": "delete",
                "path": path_str,
                "deleted": True,
                "success": True,
            }

        else:
            raise ValueError(f"Unsupported filesystem operation: '{operation}'")
