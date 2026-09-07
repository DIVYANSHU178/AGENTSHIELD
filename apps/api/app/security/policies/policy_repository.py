"""
Authoritative Policy Repository for AgentShield (Stage 10 & 12).
Provides durable persistence and dynamic evaluation for security policies in security_policies table.
"""

from datetime import datetime
from typing import Dict, Any, List, Optional, Callable
from sqlalchemy.orm import Session
from sqlalchemy import select, update

from app.models.models import PolicyDefinitionModel
from app.database.session import SessionLocal
from app.security.models.utils import utc_now, ensure_utc


class PolicyRepository:
    """
    Durable repository for security policies configured in AgentShield.
    """

    def __init__(self, session_factory: Optional[Callable[[], Session]] = None, auto_seed: bool = True) -> None:
        self._session_factory = session_factory or SessionLocal
        self._memory_policies: Dict[str, Dict[str, Any]] = {}

        if auto_seed:
            self.seed_default_policies()

    def create_policy(
        self,
        policy_id: str,
        name: str,
        description: str,
        rule_type: str,
        priority: int = 50,
        conditions: Optional[Dict[str, Any]] = None,
        action: str = "REQUIRE_APPROVAL",
        is_enabled: bool = True,
    ) -> Dict[str, Any]:
        """Create or update a persistent security policy definition."""
        now = utc_now()
        data = {
            "policy_id": policy_id.strip(),
            "name": name.strip(),
            "description": description.strip(),
            "rule_type": rule_type.strip(),
            "priority": priority,
            "conditions": conditions or {},
            "action": action.strip().upper(),
            "is_enabled": is_enabled,
            "created_at": now,
            "updated_at": now,
        }

        try:
            with self._session_factory() as session:
                existing = session.execute(
                    select(PolicyDefinitionModel).where(PolicyDefinitionModel.policy_id == policy_id.strip())
                ).scalar_one_or_none()

                if existing:
                    existing.name = name.strip()
                    existing.description = description.strip()
                    existing.rule_type = rule_type.strip()
                    existing.priority = priority
                    existing.conditions = conditions or {}
                    existing.action = action.strip().upper()
                    existing.is_enabled = is_enabled
                    existing.updated_at = now
                else:
                    db_model = PolicyDefinitionModel(
                        policy_id=policy_id.strip(),
                        name=name.strip(),
                        description=description.strip(),
                        rule_type=rule_type.strip(),
                        priority=priority,
                        conditions=conditions or {},
                        action=action.strip().upper(),
                        is_enabled=is_enabled,
                        created_at=now,
                        updated_at=now,
                        metadata_payload={},
                    )
                    session.add(db_model)
                session.commit()
        except Exception:
            pass

        self._memory_policies[policy_id.strip()] = data
        return data

    def get_policy(self, policy_id: str) -> Optional[Dict[str, Any]]:
        """Lookup policy by ID."""
        if not policy_id:
            return None

        clean_id = policy_id.strip()
        try:
            with self._session_factory() as session:
                row = session.execute(
                    select(PolicyDefinitionModel).where(PolicyDefinitionModel.policy_id == clean_id)
                ).scalar_one_or_none()
                if row:
                    return {
                        "policy_id": row.policy_id,
                        "name": row.name,
                        "description": row.description,
                        "rule_type": row.rule_type,
                        "priority": row.priority,
                        "conditions": row.conditions,
                        "action": row.action,
                        "is_enabled": row.is_enabled,
                        "created_at": ensure_utc(row.created_at),
                        "updated_at": ensure_utc(row.updated_at),
                    }
        except Exception:
            pass

        return self._memory_policies.get(clean_id)

    def list_policies(self, is_enabled: Optional[bool] = None) -> List[Dict[str, Any]]:
        """List policies sorted by priority descending."""
        try:
            with self._session_factory() as session:
                query = select(PolicyDefinitionModel)
                if is_enabled is not None:
                    query = query.where(PolicyDefinitionModel.is_enabled == is_enabled)
                rows = session.execute(query.order_by(PolicyDefinitionModel.priority.desc())).scalars().all()
                if rows:
                    return [
                        {
                            "policy_id": row.policy_id,
                            "name": row.name,
                            "description": row.description,
                            "rule_type": row.rule_type,
                            "priority": row.priority,
                            "conditions": row.conditions,
                            "action": row.action,
                            "is_enabled": row.is_enabled,
                            "created_at": ensure_utc(row.created_at),
                            "updated_at": ensure_utc(row.updated_at),
                        }
                        for row in rows
                    ]
        except Exception:
            pass

        items = list(self._memory_policies.values())
        if is_enabled is not None:
            items = [i for i in items if i["is_enabled"] == is_enabled]
        return sorted(items, key=lambda x: x["priority"], reverse=True)

    def delete_policy(self, policy_id: str) -> bool:
        """Soft-disable a policy (is_enabled = False)."""
        now = utc_now()
        clean_id = policy_id.strip()
        try:
            with self._session_factory() as session:
                row = session.execute(
                    select(PolicyDefinitionModel).where(PolicyDefinitionModel.policy_id == clean_id)
                ).scalar_one_or_none()
                if row:
                    row.is_enabled = False
                    row.updated_at = now
                    session.commit()
                    return True
        except Exception:
            pass

        if clean_id in self._memory_policies:
            self._memory_policies[clean_id]["is_enabled"] = False
            self._memory_policies[clean_id]["updated_at"] = now
            return True
        return False

    def seed_default_policies(self) -> None:
        """Seed default fail-closed policies."""
        defaults = [
            {
                "policy_id": "policy.risk.critical.block",
                "name": "Critical Risk Blocker",
                "description": "Block all actions evaluated with CRITICAL severity",
                "rule_type": "risk_threshold",
                "priority": 100,
                "conditions": {"severity": "CRITICAL"},
                "action": "BLOCK",
                "is_enabled": True,
            },
            {
                "policy_id": "policy.risk.very_high.block",
                "name": "Very High Risk Blocker",
                "description": "Block actions with computed risk score >= 80.0",
                "rule_type": "risk_threshold",
                "priority": 90,
                "conditions": {"min_risk_score": 80.0},
                "action": "BLOCK",
                "is_enabled": True,
            },
            {
                "policy_id": "policy.threat.injection.block",
                "name": "Adversarial Threat Blocker",
                "description": "Block actions with prompt injection or jailbreak detections",
                "rule_type": "threat_signal",
                "priority": 85,
                "conditions": {"threat_types": ["prompt_injection", "jailbreak"]},
                "action": "BLOCK",
                "is_enabled": True,
            },
            {
                "policy_id": "policy.risk.high.approval",
                "name": "High Risk Approval Required",
                "description": "Require human review for HIGH risk score >= 60.0",
                "rule_type": "approval_gate",
                "priority": 70,
                "conditions": {"min_risk_score": 60.0, "severity": "HIGH"},
                "action": "REQUIRE_APPROVAL",
                "is_enabled": True,
            },
            {
                "policy_id": "policy.risk.medium.approval",
                "name": "Medium Risk Approval Required",
                "description": "Require human review for MEDIUM risk score >= 30.0",
                "rule_type": "approval_gate",
                "priority": 50,
                "conditions": {"min_risk_score": 30.0, "severity": "MEDIUM"},
                "action": "REQUIRE_APPROVAL",
                "is_enabled": True,
            },
            {
                "policy_id": "policy.risk.low.allow",
                "name": "Authorized Low-Risk Allow",
                "description": "Explicit allow rule for registered tools within agent capabilities and risk score < 30.0",
                "rule_type": "capability_allow",
                "priority": 10,
                "conditions": {"max_risk_score": 30.0, "zero_threat_signals": True},
                "action": "ALLOW",
                "is_enabled": True,
            },
            {
                "policy_id": "policy.default.deny",
                "name": "Default Fail-Closed Boundary",
                "description": "Catch-all security boundary: Deny all actions not explicitly permitted by prior rules",
                "rule_type": "default_deny",
                "priority": 0,
                "conditions": {},
                "action": "BLOCK",
                "is_enabled": True,
            },
        ]

        for item in defaults:
            existing = self.get_policy(item["policy_id"])
            if not existing:
                self.create_policy(**item)


# Global singleton
_policy_repo: Optional[PolicyRepository] = None


def get_policy_repository() -> PolicyRepository:
    global _policy_repo
    if _policy_repo is None:
        _policy_repo = PolicyRepository()
    return _policy_repo
