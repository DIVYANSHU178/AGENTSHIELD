import copy
import hashlib
import hmac
import json
from datetime import datetime
from typing import Dict, Any, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator
from app.security.models import ToolRequest, SecurityDecisionType
from app.security.models.utils import generate_uuid, utc_now, ensure_utc, deep_freeze, FrozenDict
from app.config.settings import settings

def calculate_request_fingerprint(request: ToolRequest) -> str:
    """
    Compute a deterministic SHA-256 fingerprint for a canonical ToolRequest.
    Binds authorization to the exact request content (target, action, parameters, destination, agent).
    Any request parameter tampering will produce a different fingerprint.
    """
    if request is None:
        raise ValueError("Cannot calculate fingerprint for None ToolRequest.")

    params_json = json.dumps(request.parameters or {}, sort_keys=True)
    canonical_str = (
        f"req_id:{request.request_id}|"
        f"agent_id:{request.agent.agent_id}|"
        f"tool_name:{request.tool_name}|"
        f"tool_category:{request.tool_category.value}|"
        f"action:{request.action.value}|"
        f"target:{request.target}|"
        f"destination:{request.destination or ''}|"
        f"params:{params_json}"
    )
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


def build_authorization_signature_payload(
    authorization_id: str,
    request_id: str,
    correlation_id: str,
    decision_value: str,
    request_fingerprint: str,
    policy_id: str,
    risk_score: float,
    issued_at: datetime,
    expires_at: Optional[datetime] = None,
) -> str:
    """
    Construct canonical payload string for cryptographic HMAC signature computation.
    Survives JSON serialization/deserialization roundtrips cleanly.
    Binds all 9 core credential fields:
    authorization_id, request_id, correlation_id, decision, request_fingerprint, policy_id, risk_score, issued_at, expires_at.
    """
    issued_utc = ensure_utc(issued_at)
    issued_iso = issued_utc.isoformat()
    expires_iso = ensure_utc(expires_at).isoformat() if expires_at else ""

    return (
        f"auth_id:{authorization_id}|"
        f"req_id:{request_id}|"
        f"corr_id:{correlation_id}|"
        f"decision:{decision_value}|"
        f"fingerprint:{request_fingerprint}|"
        f"policy_id:{policy_id}|"
        f"risk_score:{risk_score:.2f}|"
        f"issued_at:{issued_iso}|"
        f"expires_at:{expires_iso}"
    )


def calculate_authorization_signature(
    authorization_id: str,
    request_id: str,
    correlation_id: str,
    decision_value: str,
    request_fingerprint: str,
    policy_id: str,
    risk_score: float,
    issued_at: datetime,
    expires_at: Optional[datetime] = None,
    secret_key: Optional[str] = None,
) -> str:
    """
    Calculate HMAC-SHA256 signature for authorization credential fields.
    """
    key = secret_key or settings.get_authorization_secret()
    payload_str = build_authorization_signature_payload(
        authorization_id=authorization_id,
        request_id=request_id,
        correlation_id=correlation_id,
        decision_value=decision_value,
        request_fingerprint=request_fingerprint,
        policy_id=policy_id,
        risk_score=risk_score,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    return hmac.new(key.encode("utf-8"), payload_str.encode("utf-8"), hashlib.sha256).hexdigest()


class ExecutionAuthorization(BaseModel):
    """
    Immutable capability token representing explicit authorization to proceed toward future execution.
    Bound cryptographically to a specific evaluated ToolRequest via request_id, SHA-256 request_fingerprint,
    and an unforgeable HMAC-SHA256 cryptographic signature.

    Can ONLY be issued for SecurityDecisionType.ALLOW.
    """
    model_config = ConfigDict(frozen=True)

    authorization_id: str = Field(default_factory=generate_uuid, description="Unique authorization credential identifier")
    request_id: str = Field(..., description="Correlated ToolRequest identifier")
    correlation_id: str = Field(..., description="Correlation identifier for tracing across security boundary")
    decision: SecurityDecisionType = Field(..., description="Governing decision, MUST be ALLOW")
    request_fingerprint: str = Field(..., description="Deterministic SHA-256 hash of target request contents")
    policy_id: str = Field(..., description="ID of policy rule authorizing execution")
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Evaluated risk score at time of authorization")
    issued_at: datetime = Field(default_factory=utc_now, description="Timezone-aware UTC timestamp of authorization issue")
    expires_at: Optional[datetime] = Field(default=None, description="Optional timezone-aware UTC expiration timestamp")
    signature: str = Field(..., description="HMAC-SHA256 cryptographic signature ensuring credential integrity")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary authorization metadata")

    @field_validator("decision", mode="before")
    @classmethod
    def validate_allow_decision_only(cls, value: Any) -> Any:
        if isinstance(value, SecurityDecisionType):
            if value != SecurityDecisionType.ALLOW:
                raise ValueError(
                    f"ExecutionAuthorization CANNOT be issued for decision '{value.value}'. "
                    f"Only '{SecurityDecisionType.ALLOW.value}' decisions may produce execution authorization."
                )
            return value
        if isinstance(value, str):
            if value.upper() != SecurityDecisionType.ALLOW.value:
                raise ValueError(
                    f"ExecutionAuthorization CANNOT be issued for decision '{value}'. "
                    f"Only '{SecurityDecisionType.ALLOW.value}' decisions may produce execution authorization."
                )
            return SecurityDecisionType.ALLOW
        return value

    @field_validator("authorization_id", "request_id", "correlation_id", "request_fingerprint", "policy_id", "signature", mode="before")
    @classmethod
    def validate_non_empty_str(cls, value: Any, info) -> Any:
        if isinstance(value, str) and not value.strip():
            raise ValueError(f"Field '{info.field_name}' must not be an empty string")
        return value

    @field_validator("metadata", mode="after")
    @classmethod
    def freeze_metadata(cls, value: Any) -> Any:
        if value is None:
            return FrozenDict()
        return deep_freeze(value)

    @field_validator("issued_at", "expires_at", mode="before")
    @classmethod
    def validate_utc_timestamp(cls, value: Any) -> Any:
        if isinstance(value, datetime):
            return ensure_utc(value)
        return value

    def verify_signature(self, secret_key: Optional[str] = None) -> bool:
        """
        Verify the HMAC-SHA256 signature of this ExecutionAuthorization credential.
        Returns True if authentic and untampered, False otherwise. Fails closed on any error.
        """
        try:
            expected_sig = calculate_authorization_signature(
                authorization_id=self.authorization_id,
                request_id=self.request_id,
                correlation_id=self.correlation_id,
                decision_value=self.decision.value,
                request_fingerprint=self.request_fingerprint,
                policy_id=self.policy_id,
                risk_score=self.risk_score,
                issued_at=self.issued_at,
                expires_at=self.expires_at,
                secret_key=secret_key,
            )
            return hmac.compare_digest(expected_sig, self.signature)
        except Exception:
            return False


def mint_execution_authorization(
    request: ToolRequest,
    policy_id: str = "policy.default",
    risk_score: float = 10.0,
    correlation_id: Optional[str] = None,
    ttl_seconds: int = 300,
    secret_key: Optional[str] = None,
) -> ExecutionAuthorization:
    """
    Mint an authoritative, cryptographically signed ExecutionAuthorization capability token.
    Binds the exact request fingerprint and metadata.
    """
    from datetime import timedelta
    req_fingerprint = calculate_request_fingerprint(request)
    issued_at = utc_now()
    expires_at = issued_at + timedelta(seconds=ttl_seconds)
    auth_id = generate_uuid()
    corr_id = correlation_id or request.request_id
    sig = calculate_authorization_signature(
        authorization_id=auth_id,
        request_id=request.request_id,
        correlation_id=corr_id,
        decision_value=SecurityDecisionType.ALLOW.value,
        request_fingerprint=req_fingerprint,
        policy_id=policy_id,
        risk_score=risk_score,
        issued_at=issued_at,
        expires_at=expires_at,
        secret_key=secret_key,
    )
    return ExecutionAuthorization(
        authorization_id=auth_id,
        request_id=request.request_id,
        correlation_id=corr_id,
        decision=SecurityDecisionType.ALLOW,
        request_fingerprint=req_fingerprint,
        policy_id=policy_id,
        risk_score=risk_score,
        issued_at=issued_at,
        expires_at=expires_at,
        signature=sig,
    )
