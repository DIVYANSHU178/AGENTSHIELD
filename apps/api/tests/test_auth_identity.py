"""
Tests for AgentShield Phase 14 Identity Model and RBAC Role Definitions.
"""

import pytest
from pydantic import ValidationError
from app.security.identity.models import Role, Permission, ROLE_PERMISSIONS, UserIdentity
from app.security.identity.crypto import hash_password, verify_password


def test_identity_creation_and_attributes():
    user = UserIdentity(
        user_id="usr-test-01",
        username="alice",
        display_name="Alice Security Lead",
        roles=(Role.SECURITY_REVIEWER,),
        email="alice@agentshield.local",
        is_active=True,
    )
    assert user.user_id == "usr-test-01"
    assert user.username == "alice"
    assert user.display_name == "Alice Security Lead"
    assert user.roles == (Role.SECURITY_REVIEWER,)
    assert user.email == "alice@agentshield.local"
    assert user.is_active is True
    assert user.created_at is not None
    assert user.updated_at is not None


def test_identity_immutability():
    user = UserIdentity(
        user_id="usr-test-02",
        username="bob",
        display_name="Bob Operator",
        roles=(Role.OPERATOR,),
    )
    with pytest.raises(ValidationError):
        user.display_name = "Mutated Name"

    with pytest.raises(ValidationError):
        user.is_active = False


def test_identity_role_and_permission_checks():
    viewer = UserIdentity(
        user_id="usr-viewer",
        username="carol",
        display_name="Carol Viewer",
        roles=(Role.VIEWER,),
    )
    assert viewer.has_role(Role.VIEWER)
    assert not viewer.has_role(Role.ADMIN)
    assert viewer.has_permission(Permission.VIEW_OPERATIONS)
    assert viewer.has_permission(Permission.VIEW_APPROVALS)
    assert not viewer.has_permission(Permission.RESOLVE_APPROVALS)
    assert not viewer.has_permission(Permission.RUN_SCENARIO_LAB)
    assert not viewer.has_permission(Permission.MANAGE_IDENTITIES)

    reviewer = UserIdentity(
        user_id="usr-rev",
        username="alice",
        display_name="Alice Reviewer",
        roles=(Role.SECURITY_REVIEWER,),
    )
    assert reviewer.has_permission(Permission.VIEW_APPROVALS)
    assert reviewer.has_permission(Permission.RESOLVE_APPROVALS)
    assert reviewer.has_permission(Permission.RUN_SCENARIO_LAB)
    assert not reviewer.has_permission(Permission.MANAGE_SECURITY_CONFIGURATION)

    admin = UserIdentity(
        user_id="usr-admin",
        username="root",
        display_name="System Admin",
        roles=(Role.ADMIN,),
    )
    assert admin.has_permission(Permission.RESOLVE_APPROVALS)
    assert admin.has_permission(Permission.MANAGE_IDENTITIES)
    assert admin.has_permission(Permission.MANAGE_ROLES)
    assert admin.has_permission(Permission.MANAGE_SECURITY_CONFIGURATION)


def test_inactive_identity_denies_all_permissions():
    disabled_admin = UserIdentity(
        user_id="usr-disabled-admin",
        username="evil_admin",
        display_name="Disabled Admin",
        roles=(Role.ADMIN,),
        is_active=False,
    )
    assert not disabled_admin.has_permission(Permission.VIEW_OPERATIONS)
    assert not disabled_admin.has_permission(Permission.RESOLVE_APPROVALS)
    assert not disabled_admin.has_permission(Permission.MANAGE_IDENTITIES)
    assert len(disabled_admin.permissions) == 0


def test_identity_empty_fields_validation():
    with pytest.raises(ValueError):
        UserIdentity(user_id="", username="valid", display_name="Valid", roles=(Role.VIEWER,))

    with pytest.raises(ValueError):
        UserIdentity(user_id="usr-1", username="   ", display_name="Valid", roles=(Role.VIEWER,))

    with pytest.raises(ValueError):
        UserIdentity(user_id="usr-1", username="valid", display_name="", roles=(Role.VIEWER,))


def test_role_normalization_from_strings():
    user = UserIdentity(
        user_id="usr-norm",
        username="norm",
        display_name="Normalized",
        roles=["operator", "VIEWER"],  # type: ignore
    )
    assert user.roles == (Role.OPERATOR, Role.VIEWER)


def test_unknown_role_string_rejected():
    with pytest.raises(ValueError):
        UserIdentity(
            user_id="usr-bad",
            username="bad",
            display_name="Bad Role",
            roles=["SUPER_HACKER"],  # type: ignore
        )
