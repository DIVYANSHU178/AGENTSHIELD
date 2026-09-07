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
    execution_result = Column(JSON, nullable=True)
    metadata_payload = Column(JSON, nullable=False, default=dict)


class UserIdentityModel(Base):
    """
    Durable storage for Phase 14 Identity Management and RBAC user accounts.
    Stores salted password hashes with zero plaintext secrets.
    """
    __tablename__ = "security_users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(64), unique=True, nullable=False, index=True)
    username = Column(String(128), unique=True, nullable=False, index=True)
    email = Column(String(256), unique=True, nullable=True, index=True)
    display_name = Column(String(128), nullable=False)
    password_hash = Column(String(256), nullable=False)
    password_salt = Column(String(64), nullable=False)
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    roles = Column(JSON, nullable=False, default=list)
    created_at = Column(DateTime(timezone=True), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, index=True)
    metadata_payload = Column(JSON, nullable=False, default=dict)


class AuthSessionModel(Base):
    """
    Durable storage for Phase 14 Authentication Sessions and Token Revocation.
    """
    __tablename__ = "security_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(64), unique=True, nullable=False, index=True)
    user_id = Column(String(64), nullable=False, index=True)
    username = Column(String(128), nullable=False, index=True)
    issued_at = Column(DateTime(timezone=True), nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    is_revoked = Column(Boolean, nullable=False, default=False, index=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revocation_reason = Column(String(256), nullable=True)
    metadata_payload = Column(JSON, nullable=False, default=dict)


class AuthorizationAuditModel(Base):
    """
    Durable audit log for Phase 14 Authentication and Authorization decisions.
    """
    __tablename__ = "security_auth_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(64), unique=True, nullable=False, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    user_id = Column(String(64), nullable=True, index=True)
    username = Column(String(128), nullable=True, index=True)
    permission = Column(String(64), nullable=True, index=True)
    resource = Column(String(256), nullable=True)
    decision = Column(String(32), nullable=False, index=True)
    reason = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    correlation_id = Column(String(64), nullable=True, index=True)
    metadata_payload = Column(JSON, nullable=False, default=dict)


class AgentRegistrationModel(Base):
    """
    Durable storage for registered autonomous agents in the AgentShield firewall.
    """
    __tablename__ = "security_agents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    agent_id = Column(String(64), unique=True, nullable=False, index=True)
    name = Column(String(128), nullable=False, index=True)
    description = Column(Text, nullable=True)
    api_key_hash = Column(String(256), nullable=False)
    api_key_prefix = Column(String(16), nullable=False, index=True)
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    allowed_tools = Column(JSON, nullable=False, default=list)
    policy_ids = Column(JSON, nullable=False, default=list)
    created_at = Column(DateTime(timezone=True), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, index=True)
    metadata_payload = Column(JSON, nullable=False, default=dict)


class ToolRegistryModel(Base):
    """
    Durable storage for authorized tool specifications and capabilities.
    """
    __tablename__ = "security_tools"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tool_id = Column(String(64), unique=True, nullable=False, index=True)
    name = Column(String(128), unique=True, nullable=False, index=True)
    version = Column(String(32), nullable=False, default="1.0.0")
    category = Column(String(64), nullable=False, index=True)
    description = Column(Text, nullable=False)
    risk_classification = Column(String(32), nullable=False, default="MEDIUM")
    handler_type = Column(String(64), nullable=False, default="isolated_process")
    is_enabled = Column(Boolean, nullable=False, default=True, index=True)
    allowed_environments = Column(JSON, nullable=False, default=list)
    parameters_schema = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, index=True)
    metadata_payload = Column(JSON, nullable=False, default=dict)


class PolicyDefinitionModel(Base):
    """
    Durable storage for configurable, persistent security policies.
    """
    __tablename__ = "security_policies"

    id = Column(Integer, primary_key=True, autoincrement=True)
    policy_id = Column(String(64), unique=True, nullable=False, index=True)
    name = Column(String(128), nullable=False, index=True)
    description = Column(Text, nullable=True)
    rule_type = Column(String(64), nullable=False, index=True)
    priority = Column(Integer, nullable=False, default=50, index=True)
    conditions = Column(JSON, nullable=False, default=dict)
    action = Column(String(32), nullable=False, default="REQUIRE_APPROVAL", index=True)
    is_enabled = Column(Boolean, nullable=False, default=True, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, index=True)
    metadata_payload = Column(JSON, nullable=False, default=dict)
