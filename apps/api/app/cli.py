"""
AgentShield Administrative Command Line Interface (CLI).
Provides production-safe operations including initial administrator bootstrap.
"""

import sys
import os
import argparse
import re
from typing import Optional, List
from app.config import settings
from app.database import init_db
from app.security.identity.models import Role
from app.security.identity.crypto import hash_password
from app.security.persistence.identity_repository import IdentityRepository
from app.security.audit.trail import SecurityAuditTrail
from app.security.models.events import SecurityEvent
from app.security.models.enums import EventType
from app.security.models.utils import generate_uuid, utc_now

FORBIDDEN_PROD_PASSWORDS = frozenset({
    "adminpass123!",
    "reviewerpass123!",
    "operatorpass123!",
    "viewerpass123!",
    "password123!",
    "admin123!",
    "changeme123!",
    "secret123!",
})


def validate_username(username: str) -> None:
    """Validate username according to enterprise constraints."""
    if not username or not username.strip():
        raise ValueError("Username cannot be empty.")
    clean = username.strip()
    if len(clean) < 3:
        raise ValueError("Username must be at least 3 characters long.")
    if len(clean) > 64:
        raise ValueError("Username cannot exceed 64 characters.")
    if not re.match(r"^[a-zA-Z0-9_\-\.]+$", clean):
        raise ValueError("Username may only contain letters, numbers, underscores, hyphens, and dots.")


def validate_password_strength(password: str, is_production: bool = False) -> None:
    """Enforce strict password requirements, especially for production administrators."""
    if not password:
        raise ValueError("Password cannot be empty.")
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters long.")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain at least one lowercase letter.")
    if not re.search(r"[0-9]", password):
        raise ValueError("Password must contain at least one digit.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>\-_=+\\[\]]", password):
        raise ValueError("Password must contain at least one special character.")

    if is_production and password.strip().lower() in FORBIDDEN_PROD_PASSWORDS:
        raise ValueError("Cannot use known demo/default passwords in a production environment.")


def create_admin_command(
    username: str,
    password: str,
    email: Optional[str] = None,
    display_name: Optional[str] = None,
    confirm: bool = False,
    is_production: Optional[bool] = None,
) -> int:
    """
    Idempotent, production-safe administrator creation command.
    Returns 0 on success, non-zero on failure.
    """
    prod = settings.is_production() if is_production is None else is_production
    try:
        validate_username(username)
        validate_password_strength(password, is_production=prod)
    except ValueError as exc:
        sys.stderr.write(f"ERROR: {str(exc)}\n")
        return 1

    clean_user = username.strip()
    clean_email = email.strip() if email and email.strip() else f"{clean_user}@agentshield.local"
    clean_name = display_name.strip() if display_name and display_name.strip() else f"Admin ({clean_user})"

    # Initialize database tables
    init_db()
    repo = IdentityRepository()

    # Idempotent check
    existing = repo.get_user_by_username(clean_user)
    if existing:
        sys.stderr.write(f"ERROR: User '{clean_user}' already exists in database. Refusing to overwrite.\n")
        return 1

    # Check if any admin already exists
    existing_users = repo.list_users(limit=100)
    admins = [u for u in existing_users if Role.ADMIN in u.roles]
    if admins and not confirm:
        sys.stderr.write(f"WARNING: An administrator account already exists ({admins[0].username}). Use --confirm to create an additional administrator.\n")
        return 1

    pwd_hash, pwd_salt = hash_password(password)
    user_id = f"usr-{clean_user}"

    try:
        user = repo.create_user(
            user_id=user_id,
            username=clean_user,
            display_name=clean_name,
            password_hash=pwd_hash,
            password_salt=pwd_salt,
            roles=(Role.ADMIN,),
            email=clean_email,
            is_active=True,
        )

        # Audit bootstrap
        try:
            audit = SecurityAuditTrail()
            event = SecurityEvent(
                event_id=generate_uuid(),
                request_id=f"req-bootstrap-{generate_uuid()[:8]}",
                event_type=EventType.AUTHENTICATION_SUCCESS,
                timestamp=utc_now(),
                actor="cli.create-admin",
                details={
                    "user_id": user.user_id,
                    "username": user.username,
                    "action": "ADMIN_BOOTSTRAP_CREATED",
                    "environment": settings.ENVIRONMENT,
                },
                metadata={"cli": True},
            )
            audit.record(event)
        except Exception:
            pass

        sys.stdout.write(f"SUCCESS: Administrator '{user.username}' created successfully with role ADMIN.\n")
        return 0

    except Exception as exc:
        sys.stderr.write(f"ERROR: Failed to create administrator: {str(exc)}\n")
        return 1


def main(argv: Optional[List[str]] = None) -> int:
    """CLI Entrypoint."""
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="AgentShield System Administration CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    create_admin_parser = subparsers.add_parser("create-admin", help="Bootstrap an initial administrator account")
    create_admin_parser.add_argument("--username", "-u", required=True, help="Administrator username")
    create_admin_parser.add_argument("--password", "-p", required=True, help="Strong password (min 12 chars)")
    create_admin_parser.add_argument("--email", "-e", default=None, help="Administrator email address")
    create_admin_parser.add_argument("--display-name", "-d", default=None, help="Human-readable display name")
    create_admin_parser.add_argument("--confirm", action="store_true", help="Confirm creation even if an admin exists")

    args = parser.parse_args(argv)

    if args.command == "create-admin":
        return create_admin_command(
            username=args.username,
            password=args.password,
            email=args.email,
            display_name=args.display_name,
            confirm=args.confirm,
        )

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
