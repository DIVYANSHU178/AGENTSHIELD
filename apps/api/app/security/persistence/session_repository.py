"""
Session Repository for AgentShield Phase 14.

Provides durable persistence and thread-safe querying for Authentication Sessions and Token Revocation.
Features:
- Safe mapping between SQLAlchemy AuthSessionModel and immutable AuthSession domain model
- Persistent revocation state tracking
- In-memory fallback when no SQLAlchemy session factory is configured
- Deterministic session retrieval and invalidation
"""

import copy
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Callable
from sqlalchemy.orm import Session
from sqlalchemy import select, update
from app.models.models import AuthSessionModel
from app.security.identity.models import AuthSession
from app.security.models.utils import utc_now, ensure_utc


class SessionRepository:
    """
    Repository for persisting and querying authentication sessions and token revocations.
    """

    def __init__(self, session_factory: Optional[Callable[[], Session]] = None) -> None:
        self._session_factory = session_factory
        # In-memory fallback: session_id -> dict
        self._sessions: Dict[str, Dict[str, Any]] = {}

    def create_session(
        self,
        session_id: str,
        user_id: str,
        username: str,
        issued_at: datetime,
        expires_at: datetime,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuthSession:
        """Persist a new authentication session record."""
        now = ensure_utc(issued_at)
        exp = ensure_utc(expires_at)

        if self._session_factory is not None:
            with self._session_factory() as session:
                db_session = AuthSessionModel(
                    session_id=session_id,
                    user_id=user_id,
                    username=username,
                    issued_at=now,
                    expires_at=exp,
                    is_revoked=False,
                    revoked_at=None,
                    revocation_reason=None,
                    metadata_payload=copy.deepcopy(metadata or {}),
                )
                session.add(db_session)
                session.commit()

        self._sessions[session_id] = {
            "session_id": session_id,
            "user_id": user_id,
            "username": username,
            "issued_at": now,
            "expires_at": exp,
            "is_revoked": False,
            "revoked_at": None,
            "revocation_reason": None,
            "metadata": copy.deepcopy(metadata or {}),
        }

        return AuthSession(
            session_id=session_id,
            user_id=user_id,
            username=username,
            issued_at=now,
            expires_at=exp,
            is_revoked=False,
            revoked_at=None,
            revocation_reason=None,
            metadata=copy.deepcopy(metadata or {}),
        )

    def get_session(self, session_id: str) -> Optional[AuthSession]:
        """Retrieve an authentication session by session_id."""
        if self._session_factory is not None:
            with self._session_factory() as session:
                stmt = select(AuthSessionModel).where(AuthSessionModel.session_id == session_id)
                db_session = session.execute(stmt).scalars().first()
                if db_session:
                    return self._to_domain_session(db_session)

        sess_data = self._sessions.get(session_id)
        if sess_data:
            return self._dict_to_domain_session(sess_data)
        return None

    def revoke_session(self, session_id: str, reason: str = "Explicit logout") -> bool:
        """
        Revoke an active session. Returns True if revoked or already revoked, False if not found.
        """
        now = utc_now()
        found = False

        if self._session_factory is not None:
            with self._session_factory() as session:
                stmt = select(AuthSessionModel).where(AuthSessionModel.session_id == session_id)
                db_session = session.execute(stmt).scalars().first()
                if db_session:
                    db_session.is_revoked = True
                    db_session.revoked_at = now
                    db_session.revocation_reason = reason
                    session.commit()
                    found = True

        if session_id in self._sessions:
            self._sessions[session_id]["is_revoked"] = True
            self._sessions[session_id]["revoked_at"] = now
            self._sessions[session_id]["revocation_reason"] = reason
            found = True

        return found

    def list_sessions_for_user(self, user_id: str, active_only: bool = True) -> List[AuthSession]:
        """List sessions for a specific user ID."""
        now = utc_now()
        if self._session_factory is not None:
            with self._session_factory() as session:
                stmt = select(AuthSessionModel).where(AuthSessionModel.user_id == user_id)
                if active_only:
                    stmt = stmt.where(
                        (AuthSessionModel.is_revoked == False) & (AuthSessionModel.expires_at > now)
                    )
                rows = session.execute(stmt).scalars().all()
                return [self._to_domain_session(r) for r in rows]

        res = []
        for s in self._sessions.values():
            if s["user_id"] == user_id:
                sess = self._dict_to_domain_session(s)
                if active_only:
                    if sess.is_valid(now):
                        res.append(sess)
                else:
                    res.append(sess)
        return res

    @staticmethod
    def _to_domain_session(model: AuthSessionModel) -> AuthSession:
        return AuthSession(
            session_id=model.session_id,
            user_id=model.user_id,
            username=model.username,
            issued_at=ensure_utc(model.issued_at),
            expires_at=ensure_utc(model.expires_at),
            is_revoked=model.is_revoked,
            revoked_at=ensure_utc(model.revoked_at) if model.revoked_at else None,
            revocation_reason=model.revocation_reason,
            metadata=copy.deepcopy(model.metadata_payload or {}),
        )

    @staticmethod
    def _dict_to_domain_session(data: Dict[str, Any]) -> AuthSession:
        return AuthSession(
            session_id=data["session_id"],
            user_id=data["user_id"],
            username=data["username"],
            issued_at=ensure_utc(data["issued_at"]),
            expires_at=ensure_utc(data["expires_at"]),
            is_revoked=data.get("is_revoked", False),
            revoked_at=ensure_utc(data["revoked_at"]) if data.get("revoked_at") else None,
            revocation_reason=data.get("revocation_reason"),
            metadata=copy.deepcopy(data.get("metadata") or {}),
        )
