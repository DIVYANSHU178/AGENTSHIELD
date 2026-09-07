"""
Authoritative Tool Registry Repository for AgentShield (Stage 11).
Backs authorized tool contracts with durable persistence in security_tools.
"""

from datetime import datetime
from typing import Dict, Any, List, Optional, Callable
from sqlalchemy.orm import Session
from sqlalchemy import select, update

from app.models.models import ToolRegistryModel
from app.database.session import SessionLocal
from app.security.models.utils import utc_now, ensure_utc
from app.security.models import ToolCategory, ActionType
from app.security.execution.contracts import ToolExecutionContract
from app.security.execution.tools import (
    RealCalculatorTool,
    RealFileSystemTool,
    RealHttpTool,
    RealCommandTool,
)
from app.security.execution.builtins import safe_health_check_handler


class ToolRegistryRepository:
    """
    Durable repository for authorized tools and capabilities.
    """

    def __init__(self, session_factory: Optional[Callable[[], Session]] = None, auto_seed: bool = True) -> None:
        self._session_factory = session_factory or SessionLocal
        self._memory_tools: Dict[str, Dict[str, Any]] = {}

        if auto_seed:
            self.seed_default_tools()

    def register_tool(
        self,
        tool_id: str,
        name: str,
        category: str,
        description: str,
        risk_classification: str = "MEDIUM",
        handler_type: str = "isolated_process",
        is_enabled: bool = True,
        allowed_environments: Optional[List[str]] = None,
        parameters_schema: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Register or update a tool contract specification."""
        now = utc_now()
        data = {
            "tool_id": tool_id.strip(),
            "name": name.strip(),
            "category": category.strip(),
            "description": description.strip(),
            "risk_classification": risk_classification.strip(),
            "handler_type": handler_type.strip(),
            "is_enabled": is_enabled,
            "allowed_environments": allowed_environments or ["development", "staging", "production"],
            "parameters_schema": parameters_schema or {},
            "created_at": now,
            "updated_at": now,
        }

        try:
            with self._session_factory() as session:
                existing = session.execute(
                    select(ToolRegistryModel).where(ToolRegistryModel.tool_id == tool_id.strip())
                ).scalar_one_or_none()

                if existing:
                    existing.name = name.strip()
                    existing.category = category.strip()
                    existing.description = description.strip()
                    existing.risk_classification = risk_classification.strip()
                    existing.handler_type = handler_type.strip()
                    existing.is_enabled = is_enabled
                    existing.allowed_environments = allowed_environments or ["development", "staging", "production"]
                    existing.parameters_schema = parameters_schema or {}
                    existing.updated_at = now
                else:
                    db_model = ToolRegistryModel(
                        tool_id=tool_id.strip(),
                        name=name.strip(),
                        version="1.0.0",
                        category=category.strip(),
                        description=description.strip(),
                        risk_classification=risk_classification.strip(),
                        handler_type=handler_type.strip(),
                        is_enabled=is_enabled,
                        allowed_environments=allowed_environments or ["development", "staging", "production"],
                        parameters_schema=parameters_schema or {},
                        created_at=now,
                        updated_at=now,
                        metadata_payload={},
                    )
                    session.add(db_model)
                session.commit()
        except Exception:
            pass

        self._memory_tools[tool_id.strip()] = data
        return data

    def get_tool(self, tool_id: str) -> Optional[Dict[str, Any]]:
        """Lookup a registered tool by tool_id or name (supporting dot-notation sub-tools)."""
        if not tool_id:
            return None

        clean_id = tool_id.strip()
        candidates = [clean_id]
        if "." in clean_id:
            base = clean_id.split(".", 1)[0]
            candidates.extend([base, f"{base}.restricted", f"tool-{base}"])
        if not clean_id.startswith("tool-"):
            candidates.append(f"tool-{clean_id}")

        try:
            with self._session_factory() as session:
                row = session.execute(
                    select(ToolRegistryModel).where(
                        (ToolRegistryModel.tool_id.in_(candidates)) | (ToolRegistryModel.name.in_(candidates))
                    )
                ).scalars().first()
                if row:
                    return {
                        "tool_id": row.tool_id,
                        "name": row.name,
                        "category": row.category,
                        "description": row.description,
                        "risk_classification": row.risk_classification,
                        "handler_type": row.handler_type,
                        "is_enabled": row.is_enabled,
                        "allowed_environments": row.allowed_environments,
                        "parameters_schema": row.parameters_schema,
                        "created_at": ensure_utc(row.created_at),
                        "updated_at": ensure_utc(row.updated_at),
                    }
        except Exception:
            pass

        for c in candidates:
            if c in self._memory_tools:
                return self._memory_tools[c]
            for t in self._memory_tools.values():
                if t.get("name") == c or t.get("tool_id") == c:
                    return t
        return None

    def list_tools(self, is_enabled: Optional[bool] = None) -> List[Dict[str, Any]]:
        """List all tools registered in the security catalog."""
        try:
            with self._session_factory() as session:
                query = select(ToolRegistryModel)
                if is_enabled is not None:
                    query = query.where(ToolRegistryModel.is_enabled == is_enabled)
                rows = session.execute(query.order_by(ToolRegistryModel.created_at.asc())).scalars().all()
                if rows:
                    return [
                        {
                            "tool_id": row.tool_id,
                            "name": row.name,
                            "category": row.category,
                            "description": row.description,
                            "risk_classification": row.risk_classification,
                            "handler_type": row.handler_type,
                            "is_enabled": row.is_enabled,
                            "allowed_environments": row.allowed_environments,
                            "parameters_schema": row.parameters_schema,
                            "created_at": ensure_utc(row.created_at),
                            "updated_at": ensure_utc(row.updated_at),
                        }
                        for row in rows
                    ]
        except Exception:
            pass

        items = list(self._memory_tools.values())
        if is_enabled is not None:
            items = [i for i in items if i["is_enabled"] == is_enabled]
        return sorted(items, key=lambda x: str(x.get("created_at", "")))

    def delete_tool(self, tool_id: str) -> bool:
        """Soft-disable a tool by marking is_enabled = False."""
        now = utc_now()
        clean_id = tool_id.strip()
        try:
            with self._session_factory() as session:
                row = session.execute(
                    select(ToolRegistryModel).where(ToolRegistryModel.tool_id == clean_id)
                ).scalar_one_or_none()
                if row:
                    row.is_enabled = False
                    row.updated_at = now
                    session.commit()
                    return True
        except Exception:
            pass

        if clean_id in self._memory_tools:
            self._memory_tools[clean_id]["is_enabled"] = False
            self._memory_tools[clean_id]["updated_at"] = now
            return True
        return False

    def seed_default_tools(self) -> None:
        """Seed default authorized tool contracts."""
        defaults = [
            {
                "tool_id": "tool-calculator",
                "name": "calculator",
                "category": "READ_ONLY",
                "description": "Safe AST-based arithmetic and math evaluator",
                "risk_classification": "LOW",
                "handler_type": "isolated_process",
                "is_enabled": True,
                "parameters_schema": {
                    "type": "object",
                    "properties": {
                        "expression": {"type": "string", "description": "Math expression (e.g. 2 + 2)"},
                        "a": {"type": "number"},
                        "b": {"type": "number"},
                        "op": {"type": "string", "enum": ["add", "sub", "mul", "div", "pow", "mod"]},
                    },
                },
            },
            {
                "tool_id": "tool-filesystem",
                "name": "filesystem",
                "category": "READ_WRITE_ISOLATED",
                "description": "Sandboxed filesystem operations with path traversal defense",
                "risk_classification": "MEDIUM",
                "handler_type": "isolated_process",
                "is_enabled": True,
                "parameters_schema": {
                    "type": "object",
                    "properties": {
                        "operation": {"type": "string", "enum": ["read", "write", "list", "stat", "delete"]},
                        "path": {"type": "string"},
                        "content": {"type": "string"},
                    },
                    "required": ["operation"],
                },
            },
            {
                "tool_id": "tool-http",
                "name": "http",
                "category": "NETWORK_ACCESS",
                "description": "Outbound HTTP client with SSRF defense against private network exfiltration",
                "risk_classification": "MEDIUM",
                "handler_type": "isolated_process",
                "is_enabled": True,
                "parameters_schema": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "format": "uri"},
                        "method": {"type": "string", "enum": ["GET", "POST", "HEAD"]},
                        "headers": {"type": "object"},
                        "data": {"type": "object"},
                    },
                    "required": ["url"],
                },
            },
            {
                "tool_id": "tool-command-restricted",
                "name": "command.restricted",
                "category": "UNRESTRICTED",
                "description": "Restricted command executor with binary allowlist and shell metacharacter rejection",
                "risk_classification": "HIGH",
                "handler_type": "isolated_process",
                "is_enabled": True,
                "parameters_schema": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string"},
                        "args": {"type": "array", "items": {"type": "string"}},
                    },
                },
            },
            {
                "tool_id": "tool-system-health",
                "name": "system.health_check",
                "category": "READ_ONLY",
                "description": "Deterministic system health and diagnostics probe",
                "risk_classification": "LOW",
                "handler_type": "in_process",
                "is_enabled": True,
                "parameters_schema": {"type": "object"},
            },
        ]

        for item in defaults:
            existing = self.get_tool(item["tool_id"])
            if not existing:
                self.register_tool(**item)


# Global singleton
_tool_repo: Optional[ToolRegistryRepository] = None


def get_tool_registry_repository() -> ToolRegistryRepository:
    global _tool_repo
    if _tool_repo is None:
        _tool_repo = ToolRegistryRepository()
    return _tool_repo
