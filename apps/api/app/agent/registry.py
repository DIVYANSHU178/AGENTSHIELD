"""
Authoritative Agent Registry for AgentShield (AGCP v1).
Manages persistent agent registration, capability allowlists, and credential verification.
"""

import hashlib
import hmac
import uuid
from datetime import datetime
from typing import Optional, List, Dict, Tuple, Any, Callable
from sqlalchemy.orm import Session
from sqlalchemy import select, update

from app.agent.models import AgentRegistration, AgentStatus
from app.models.models import AgentRegistrationModel
from app.database.session import SessionLocal
from app.security.models.utils import utc_now, ensure_utc
from app.config.settings import settings


def hash_agent_key(key: str) -> str:
    """Deterministic salted hash for agent API keys."""
    return hashlib.sha256(f"agentshield_agent_key_salt_{key}".encode("utf-8")).hexdigest()


class AgentRegistry:
    """
    Persistent registry for autonomous agents.
    Provides durable persistence with in-memory fallback.
    """

    def __init__(self, session_factory: Optional[Callable[[], Session]] = None, auto_seed: bool = True) -> None:
        self._session_factory = session_factory or SessionLocal
        self._memory_agents: Dict[str, AgentRegistration] = {}
        self._memory_keys: Dict[str, str] = {}  # agent_id -> api_key_hash

        if auto_seed:
            self.seed_default_agents()

    def register(
        self,
        agent: Optional[AgentRegistration] = None,
        api_key: Optional[str] = None,
        **kwargs: Any,
    ) -> Tuple[AgentRegistration, str]:
        """
        Register a new agent with declared capabilities and allowed tools.
        Returns the registered AgentRegistration and the plaintext API key.
        """
        if agent is None:
            name = kwargs.get("name", f"agent_{uuid.uuid4().hex[:8]}")
            agent_id = kwargs.get("agent_id", f"agent_{uuid.uuid4().hex[:10]}")
            scopes = kwargs.get("scopes", ["tools:execute"])
            capabilities = kwargs.get("capabilities", scopes)
            allowed_tools = kwargs.get("allowed_tools", [])
            description = kwargs.get("description", "")
            assigned_roles = kwargs.get("assigned_roles", ["AGENT"])
            max_budget = kwargs.get("max_budget_per_hour", 100.0)
            status = kwargs.get("status", AgentStatus.ACTIVE)
            agent = AgentRegistration(
                agent_id=agent_id,
                name=name,
                description=description,
                capabilities=capabilities,
                scopes=scopes,
                assigned_roles=assigned_roles,
                max_budget_per_hour=max_budget,
                allowed_tools=allowed_tools,
                status=status,
            )

        # Check for duplicate name
        for existing_a in self.list_agents():
            if existing_a.name.lower() == agent.name.lower() and existing_a.agent_id != agent.agent_id:
                raise ValueError(f"Agent with name '{agent.name}' already exists.")

        plain_key = api_key or f"ag_live_{uuid.uuid4().hex}"
        key_hash = hash_agent_key(plain_key)

        now = utc_now()
        agent_with_hash = agent.model_copy(
            update={
                "api_key_hash": key_hash,
                "created_at": now,
                "updated_at": now,
            }
        )

        try:
            with self._session_factory() as session:
                existing = session.execute(
                    select(AgentRegistrationModel).where(AgentRegistrationModel.agent_id == agent.agent_id)
                ).scalar_one_or_none()

                if existing:
                    existing.name = agent.name
                    existing.description = agent.description
                    existing.api_key_prefix = plain_key[:12]
                    existing.is_active = (agent.status == AgentStatus.ACTIVE)
                    existing.allowed_tools = list(agent.allowed_tools)
                    existing.policy_ids = []
                    existing.api_key_hash = key_hash
                    existing.updated_at = now
                else:
                    db_model = AgentRegistrationModel(
                        agent_id=agent.agent_id,
                        name=agent.name,
                        description=agent.description,
                        api_key_hash=key_hash,
                        api_key_prefix=plain_key[:12],
                        is_active=(agent.status == AgentStatus.ACTIVE),
                        allowed_tools=list(agent.allowed_tools),
                        policy_ids=[],
                        created_at=now,
                        updated_at=now,
                        metadata_payload={},
                    )
                    session.add(db_model)
                session.commit()
        except Exception:
            # In-memory fallback
            pass

        self._memory_agents[agent.agent_id] = agent_with_hash
        self._memory_keys[agent.agent_id] = key_hash
        return agent_with_hash, plain_key

    def get(self, agent_id: str) -> Optional[AgentRegistration]:
        """Lookup an agent by ID."""
        if not agent_id:
            return None

        try:
            with self._session_factory() as session:
                row = session.execute(
                    select(AgentRegistrationModel).where(AgentRegistrationModel.agent_id == agent_id.strip())
                ).scalar_one_or_none()
                if row:
                    return AgentRegistration(
                        agent_id=row.agent_id,
                        name=row.name,
                        description=row.description or "",
                        capabilities=list(row.capabilities or []),
                        assigned_roles=list(row.assigned_roles or []),
                        max_budget_per_hour=row.max_budget_per_hour,
                        allowed_tools=list(row.allowed_tools or []),
                        status=AgentStatus(row.status),
                        api_key_hash=row.api_key_hash,
                        created_at=ensure_utc(row.created_at),
                        updated_at=ensure_utc(row.updated_at),
                    )
        except Exception:
            pass

        return self._memory_agents.get(agent_id.strip())

    def list_agents(self, status: Optional[AgentStatus] = None) -> List[AgentRegistration]:
        """List all registered agents, optionally filtered by status."""
        try:
            with self._session_factory() as session:
                query = select(AgentRegistrationModel)
                if status:
                    query = query.where(AgentRegistrationModel.status == status.value)
                rows = session.execute(query.order_by(AgentRegistrationModel.created_at.asc())).scalars().all()
                if rows:
                    return [
                        AgentRegistration(
                            agent_id=row.agent_id,
                            name=row.name,
                            description=row.description or "",
                            capabilities=list(row.capabilities or []),
                            assigned_roles=list(row.assigned_roles or []),
                            max_budget_per_hour=row.max_budget_per_hour,
                            allowed_tools=list(row.allowed_tools or []),
                            status=AgentStatus(row.status),
                            api_key_hash=row.api_key_hash,
                            created_at=ensure_utc(row.created_at),
                            updated_at=ensure_utc(row.updated_at),
                        )
                        for row in rows
                    ]
        except Exception:
            pass

        agents = list(self._memory_agents.values())
        if status:
            agents = [a for a in agents if a.status == status]
        return sorted(agents, key=lambda a: a.created_at)

    def update_status(self, agent_id: str, new_status: AgentStatus) -> Optional[AgentRegistration]:
        """Update an agent's lifecycle status (ACTIVE, SUSPENDED, REVOKED)."""
        now = utc_now()
        try:
            with self._session_factory() as session:
                row = session.execute(
                    select(AgentRegistrationModel).where(AgentRegistrationModel.agent_id == agent_id.strip())
                ).scalar_one_or_none()
                if row:
                    row.status = new_status.value
                    row.updated_at = now
                    session.commit()
        except Exception:
            pass

        if agent_id in self._memory_agents:
            updated = self._memory_agents[agent_id].model_copy(
                update={"status": new_status, "updated_at": now}
            )
            self._memory_agents[agent_id] = updated
            return updated

        return self.get(agent_id)

    def validate_key(self, agent_id: str, api_key: str) -> bool:
        """Verify the provided API key against the registered agent credential."""
        if not agent_id or not api_key:
            return False

        agent = self.get(agent_id)
        if not agent or not agent.api_key_hash:
            return False

        expected_hash = agent.api_key_hash
        provided_hash = hash_agent_key(api_key.strip())
        return hmac.compare_digest(expected_hash, provided_hash)

    def get_by_id(self, agent_id: str) -> Optional[AgentRegistration]:
        """Alias for self.get(agent_id)."""
        return self.get(agent_id)

    def list_all(self, status: Optional[AgentStatus] = None) -> List[AgentRegistration]:
        """Alias for self.list_agents(status)."""
        return self.list_agents(status)

    def get_by_api_key(self, api_key: str) -> Optional[AgentRegistration]:
        """Lookup an agent by raw API key."""
        if not api_key:
            return None
        target_hash = hash_agent_key(api_key.strip())
        for a in self.list_agents():
            if a.api_key_hash and hmac.compare_digest(a.api_key_hash, target_hash):
                return a
        return None

    def seed_default_agents(self) -> None:
        """Seed default reference agents idempotently."""
        defaults = [
            (
                AgentRegistration(
                    agent_id="eos_core",
                    name="EOS Core Agent",
                    description=(
                        "Canonical machine principal for the EOS desktop automation "
                        "client. Evaluates with the standalone AgentShield service on "
                        "127.0.0.1:8001 and executes tools itself after verifying the "
                        "v2 Ed25519 ExecutionAuthorizationToken locally."
                    ),
                    capabilities=["system_telemetry", "desktop_automation"],
                    assigned_roles=["AGENT"],
                    max_budget_per_hour=100.0,
                    allowed_tools=["system_time", "open_app", "wait_for_window", "focus_window"],
                    status=AgentStatus.ACTIVE,
                ),
                settings.AGENTSHIELD_EOS_CORE_DEV_AGENT_KEY,
            ),
            (
                AgentRegistration(
                    agent_id="reference-autonomous-agent",
                    name="Reference Autonomous Agent",
                    description="Autonomous task execution agent operating under security gateway supervision",
                    capabilities=["tool_execution", "math_analysis", "file_operations"],
                    assigned_roles=["AGENT", "OPERATOR"],
                    max_budget_per_hour=100.0,
                    allowed_tools=["calculator", "filesystem", "http", "system.health_check"],
                    status=AgentStatus.ACTIVE,
                ),
                "agk_reference_agent_secret_key",
            ),
            (
                AgentRegistration(
                    agent_id="data-analyst-agent",
                    name="Data Analyst Agent",
                    description="Data processing and arithmetic evaluation agent",
                    capabilities=["tool_execution", "math_analysis"],
                    assigned_roles=["AGENT"],
                    max_budget_per_hour=50.0,
                    allowed_tools=["calculator", "filesystem"],
                    status=AgentStatus.ACTIVE,
                ),
                "agk_data_analyst_key",
            ),
            (
                AgentRegistration(
                    agent_id="ops-agent",
                    name="Operations Agent",
                    description="Operations and telemetry inspection agent",
                    capabilities=["system_health", "telemetry"],
                    assigned_roles=["AGENT", "OPERATOR"],
                    max_budget_per_hour=75.0,
                    allowed_tools=["system.health_check", "command.restricted"],
                    status=AgentStatus.ACTIVE,
                ),
                "agk_ops_agent_key",
            ),
        ]

        for agent, key in defaults:
            existing = self.get(agent.agent_id)
            if not existing:
                self.register(agent, api_key=key)


# Global singleton instance
_agent_registry: Optional[AgentRegistry] = None


def get_agent_registry() -> AgentRegistry:
    global _agent_registry
    if _agent_registry is None:
        _agent_registry = AgentRegistry()
    return _agent_registry
