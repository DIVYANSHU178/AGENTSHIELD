"""
Identity Repository for AgentShield Phase 14.

Provides durable persistence and thread-safe querying for User Identities and RBAC roles.
Features:
- Safe mapping between SQLAlchemy UserIdentityModel and immutable UserIdentity domain model
- Zero exposure of password hashes or salts in domain models
- In-memory fallback when no SQLAlchemy session factory is configured
- Deterministic retrieval and update operations
"""

import copy
from datetime import datetime, timezone
from typing import Optional, List, Tuple, Any, Dict, Callable
from sqlalchemy.orm import Session
from sqlalchemy import select, update
from app.models.models import UserIdentityModel
from app.security.identity.models import UserIdentity, Role
from app.security.identity.errors import IdentityAlreadyExistsError, IdentityNotFoundError
from app.security.models.utils import utc_now, ensure_utc


class IdentityRepository:
    """
    Repository for persisting and querying User Identities and RBAC credentials.
    """

    def __init__(self, session_factory: Optional[Callable[[], Session]] = None) -> None:
        self._session_factory = session_factory
        # In-memory storage fallback: user_id -> dict with user data including password_hash & salt
        self._users: Dict[str, Dict[str, Any]] = {}
        self._username_index: Dict[str, str] = {}  # username.lower() -> user_id

    def create_user(
        self,
        user_id: str,
        username: str,
        display_name: str,
        password_hash: str,
        password_salt: str,
        roles: Tuple[Role, ...],
        email: Optional[str] = None,
        is_active: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> UserIdentity:
        """
        Persist a new user identity record.
        Raises IdentityAlreadyExistsError if username or user_id already exists.
        """
        uname_norm = username.strip().lower()
        now = utc_now()
        role_strings = [r.value if isinstance(r, Role) else str(r) for r in roles]

        if self._session_factory is not None:
            with self._session_factory() as session:
                # Check for uniqueness
                stmt = select(UserIdentityModel).where(
                    (UserIdentityModel.user_id == user_id) | (UserIdentityModel.username == uname_norm)
                )
                existing = session.execute(stmt).scalars().first()
                if existing is not None:
                    raise IdentityAlreadyExistsError(f"User with id '{user_id}' or username '{username}' already exists.")

                db_user = UserIdentityModel(
                    user_id=user_id,
                    username=uname_norm,
                    email=email.strip().lower() if email else None,
                    display_name=display_name.strip(),
                    password_hash=password_hash,
                    password_salt=password_salt,
                    is_active=is_active,
                    roles=role_strings,
                    created_at=now,
                    updated_at=now,
                    metadata_payload=copy.deepcopy(metadata or {}),
                )
                session.add(db_user)
                session.commit()

        # In-memory record
        if uname_norm in self._username_index or user_id in self._users:
            if self._session_factory is None:
                raise IdentityAlreadyExistsError(f"User with id '{user_id}' or username '{username}' already exists.")

        self._users[user_id] = {
            "user_id": user_id,
            "username": uname_norm,
            "email": email.strip().lower() if email else None,
            "display_name": display_name.strip(),
            "password_hash": password_hash,
            "password_salt": password_salt,
            "roles": role_strings,
            "is_active": is_active,
            "created_at": now,
            "updated_at": now,
            "metadata": copy.deepcopy(metadata or {}),
        }
        self._username_index[uname_norm] = user_id

        return UserIdentity(
            user_id=user_id,
            username=uname_norm,
            email=email.strip().lower() if email else None,
            display_name=display_name.strip(),
            roles=roles,
            is_active=is_active,
            created_at=now,
            updated_at=now,
            metadata=copy.deepcopy(metadata or {}),
        )

    def get_user_by_id(self, user_id: str) -> Optional[UserIdentity]:
        """Retrieve a user identity by unique user_id."""
        if self._session_factory is not None:
            with self._session_factory() as session:
                stmt = select(UserIdentityModel).where(UserIdentityModel.user_id == user_id)
                db_user = session.execute(stmt).scalars().first()
                if db_user:
                    return self._to_domain_user(db_user)

        user_data = self._users.get(user_id)
        if user_data:
            return self._dict_to_domain_user(user_data)
        return None

    def get_user_by_username(self, username: str) -> Optional[Tuple[UserIdentity, str, str]]:
        """
        Retrieve user identity, password hash, and salt by username.
        Returns (UserIdentity, password_hash, password_salt) or None.
        """
        uname_norm = username.strip().lower()
        if self._session_factory is not None:
            with self._session_factory() as session:
                stmt = select(UserIdentityModel).where(UserIdentityModel.username == uname_norm)
                db_user = session.execute(stmt).scalars().first()
                if db_user:
                    domain_user = self._to_domain_user(db_user)
                    return domain_user, db_user.password_hash, db_user.password_salt

        user_id = self._username_index.get(uname_norm)
        if user_id and user_id in self._users:
            user_data = self._users[user_id]
            return self._dict_to_domain_user(user_data), user_data["password_hash"], user_data["password_salt"]
        return None

    def update_user_roles(self, user_id: str, roles: Tuple[Role, ...]) -> Optional[UserIdentity]:
        """Update assigned roles for a user identity."""
        role_strings = [r.value if isinstance(r, Role) else str(r) for r in roles]
        now = utc_now()

        if self._session_factory is not None:
            with self._session_factory() as session:
                stmt = select(UserIdentityModel).where(UserIdentityModel.user_id == user_id)
                db_user = session.execute(stmt).scalars().first()
                if not db_user:
                    raise IdentityNotFoundError(f"User '{user_id}' not found.")
                db_user.roles = role_strings
                db_user.updated_at = now
                session.commit()
                return self._to_domain_user(db_user)

        if user_id not in self._users:
            raise IdentityNotFoundError(f"User '{user_id}' not found.")
        self._users[user_id]["roles"] = role_strings
        self._users[user_id]["updated_at"] = now
        return self._dict_to_domain_user(self._users[user_id])

    def set_user_active(self, user_id: str, is_active: bool) -> Optional[UserIdentity]:
        """Activate or deactivate a user identity."""
        now = utc_now()
        if self._session_factory is not None:
            with self._session_factory() as session:
                stmt = select(UserIdentityModel).where(UserIdentityModel.user_id == user_id)
                db_user = session.execute(stmt).scalars().first()
                if not db_user:
                    raise IdentityNotFoundError(f"User '{user_id}' not found.")
                db_user.is_active = is_active
                db_user.updated_at = now
                session.commit()
                return self._to_domain_user(db_user)

        if user_id not in self._users:
            raise IdentityNotFoundError(f"User '{user_id}' not found.")
        self._users[user_id]["is_active"] = is_active
        self._users[user_id]["updated_at"] = now
        return self._dict_to_domain_user(self._users[user_id])

    def list_users(self, limit: int = 100) -> List[UserIdentity]:
        """List user identities up to limit."""
        if self._session_factory is not None:
            with self._session_factory() as session:
                stmt = select(UserIdentityModel).order_by(UserIdentityModel.created_at.asc()).limit(limit)
                rows = session.execute(stmt).scalars().all()
                return [self._to_domain_user(r) for r in rows]

        return [self._dict_to_domain_user(u) for u in list(self._users.values())[:limit]]

    def count_users(self) -> int:
        """Count total registered user identities."""
        if self._session_factory is not None:
            with self._session_factory() as session:
                from sqlalchemy import func
                stmt = select(func.count(UserIdentityModel.id))
                return session.execute(stmt).scalar() or 0
        return len(self._users)

    @staticmethod
    def _to_domain_user(model: UserIdentityModel) -> UserIdentity:
        roles_tuple = tuple(Role(r) for r in (model.roles or []))
        return UserIdentity(
            user_id=model.user_id,
            username=model.username,
            email=model.email,
            display_name=model.display_name,
            roles=roles_tuple,
            is_active=model.is_active,
            created_at=ensure_utc(model.created_at),
            updated_at=ensure_utc(model.updated_at),
            metadata=copy.deepcopy(model.metadata_payload or {}),
        )

    @staticmethod
    def _dict_to_domain_user(data: Dict[str, Any]) -> UserIdentity:
        roles_tuple = tuple(Role(r) for r in (data.get("roles") or []))
        return UserIdentity(
            user_id=data["user_id"],
            username=data["username"],
            email=data.get("email"),
            display_name=data["display_name"],
            roles=roles_tuple,
            is_active=data.get("is_active", True),
            created_at=ensure_utc(data["created_at"]),
            updated_at=ensure_utc(data["updated_at"]),
            metadata=copy.deepcopy(data.get("metadata") or {}),
        )
