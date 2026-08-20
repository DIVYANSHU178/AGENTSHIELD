"""
Authoritative SQLAlchemy ORM Models for AgentShield Phase 13 Persistence Layer.

Defines durable persistence tables for:
- Security audit events (immutable audit trail)
- Security policy decisions
- Threat activity items
- Execution activity items
- Approval requests and resolutions
"""

from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Boolean,
    DateTime,
    Text,
    JSON,
    Index,
)
from app.database.base import Base


class AuditRecordModel(Base):
    """
    Durable, immutable storage for SecurityAuditTrail events.
    """
    __tablename__ = "security_audit_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(64), unique=True, nullable=False, index=True)
    request_id = Column(String(64), nullable=False, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    actor = Column(String(128), nullable=False)
    details = Column(JSON, nullable=False, default=dict)
    metadata_payload = Column(JSON, nullable=False, default=dict)

    __table_args__ = (
        Index("ix_audit_req_time", "request_id", "timestamp"),
    )


class SecurityDecisionModel(Base):
    """
    Durable storage for Phase 4/5 Security Policy Decisions.
    """
    __tablename__ = "security_decisions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    decision_id = Column(String(64), unique=True, nullable=False, index=True)
    request_id = Column(String(64), nullable=False, index=True)
    decision = Column(String(32), nullable=False, index=True)
    risk_score = Column(Float, nullable=False)
    severity = Column(String(32), nullable=False, index=True)
    policy_id = Column(String(128), nullable=True)
    reason = Column(Text, nullable=False)
    threat_count = Column(Integer, nullable=False, default=0)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    metadata_payload = Column(JSON, nullable=False, default=dict)


class ThreatActivityModel(Base):
    """
    Durable storage for detected threat signals across evaluations.
    """
    __tablename__ = "threat_activities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    threat_id = Column(String(64), unique=True, nullable=False, index=True)
    threat_type = Column(String(64), nullable=False, index=True)
    severity = Column(String(32), nullable=False, index=True)
    detector = Column(String(128), nullable=False)
    request_id = Column(String(64), nullable=False, index=True)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=False)
    confidence = Column(Float, nullable=False)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    metadata_payload = Column(JSON, nullable=False, default=dict)


class ExecutionActivityModel(Base):
    """
    Durable storage for runtime execution outcomes from Phase 9 orchestrator.
    """
    __tablename__ = "execution_activities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    execution_id = Column(String(64), unique=True, nullable=False, index=True)
    request_id = Column(String(64), nullable=False, index=True)
    tool_name = Column(String(128), nullable=False)
    tool_category = Column(String(64), nullable=False)
    action = Column(String(64), nullable=False)
    status = Column(String(32), nullable=False, index=True)
    success = Column(Boolean, nullable=False)
    duration_ms = Column(Float, nullable=False, default=0.0)
    error = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    metadata_payload = Column(JSON, nullable=False, default=dict)


class ApprovalRequestModel(Base):
    """
    Durable storage for Phase 11 Approval Workflow requests and resolutions.
    """
    __tablename__ = "approval_requests"

    id = Column(Integer, primary_key=True, autoincrement=True)
    approval_id = Column(String(64), unique=True, nullable=False, index=True)
    request_id = Column(String(64), unique=True, nullable=False, index=True)
    agent_id = Column(String(128), nullable=False)
    agent_name = Column(String(128), nullable=False)
    agent_role = Column(String(128), nullable=True)
    tool_name = Column(String(128), nullable=False)
    tool_category = Column(String(64), nullable=False)
    action = Column(String(64), nullable=False)
    target = Column(String(512), nullable=False)
    parameters = Column(JSON, nullable=False, default=dict)
    destination = Column(String(512), nullable=True)
    request_fingerprint = Column(String(128), nullable=False)
    risk_score = Column(Float, nullable=False)
    severity = Column(String(32), nullable=False)
    decision = Column(String(32), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    status = Column(String(32), nullable=False, index=True)

    # Resolution fields (populated upon approve / reject)
    resolution_id = Column(String(64), nullable=True)
    reviewer_id = Column(String(128), nullable=True)
    reviewer_name = Column(String(128), nullable=True)
    reviewer_role = Column(String(128), nullable=True)
    resolution_decision = Column(String(32), nullable=True)
    resolution_reason = Column(Text, nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    metadata_payload = Column(JSON, nullable=False, default=dict)
