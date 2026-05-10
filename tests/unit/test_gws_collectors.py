"""Unit tests for the Google Workspace collectors and baseline policies.

These tests cover SaaS Posture Spec PR 1:
- ``gws_directory`` collector (users, groups, OUs, role assignments)
- ``gws_security`` collector (tenant-wide security posture)
- The 10 baseline policies under ``policies/saas/google_workspace/``,
  exercised end-to-end through ``PolicyLoader`` + ``PolicyEvaluator``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from stance.collectors.gws_directory import GWSDirectoryCollector
from stance.collectors.gws_security import GWSSecurityCollector
from stance.engine.evaluator import PolicyEvaluator
from stance.engine.loader import PolicyLoader
from stance.models import Asset, AssetCollection


REPO_ROOT = Path(__file__).resolve().parents[2]
GWS_POLICIES_DIR = REPO_ROOT / "policies" / "saas" / "google_workspace"


# --------------------------------------------------------------------------- #
# Fake Google Admin SDK service
# --------------------------------------------------------------------------- #


def _paged_resource(items_key: str, items: list[dict[str, Any]]) -> Any:
    """Build a duck-typed Admin-SDK-style paginated resource."""
    resource = MagicMock()
    request = MagicMock()
    request.execute.return_value = {items_key: items}
    resource.list.return_value = request
    resource.list_next.return_value = None
    return resource


def _make_service(
    users: list[dict[str, Any]] | None = None,
    groups: list[dict[str, Any]] | None = None,
    members: list[dict[str, Any]] | None = None,
    org_units: list[dict[str, Any]] | None = None,
    roles: list[dict[str, Any]] | None = None,
    role_assignments: list[dict[str, Any]] | None = None,
    customer: dict[str, Any] | None = None,
    policies: list[dict[str, Any]] | None = None,
) -> Any:
    service = MagicMock()
    service.users.return_value = _paged_resource("users", users or [])
    service.groups.return_value = _paged_resource("groups", groups or [])
    service.members.return_value = _paged_resource("members", members or [])
    service.orgunits.return_value = _paged_resource(
        "organizationUnits", org_units or []
    )
    service.roles.return_value = _paged_resource("items", roles or [])
    service.roleAssignments.return_value = _paged_resource(
        "items", role_assignments or []
    )

    customers_resource = MagicMock()
    customers_request = MagicMock()
    customers_request.execute.return_value = customer or {
        "id": "C0123abcd",
        "customerDomain": "example.com",
    }
    customers_resource.get.return_value = customers_request
    service.customers.return_value = customers_resource

    policies_resource = MagicMock()
    policies_request = MagicMock()
    policies_request.execute.return_value = {"policies": policies or []}
    policies_resource.list.return_value = policies_request
    service.policies.return_value = policies_resource

    return service


# --------------------------------------------------------------------------- #
# gws_directory
# --------------------------------------------------------------------------- #


class TestGWSDirectoryCollector:
    def test_init_metadata(self):
        c = GWSDirectoryCollector(_make_service(), tenant_id="C0123abcd")
        assert c.collector_name == "gws_directory"
        assert "gws_user" in c.resource_types
        assert "gws_role_assignment" in c.resource_types
        assert c.cloud_provider == "google_workspace"

    def test_collect_users_basic(self):
        users = [
            {
                "id": "u1",
                "primaryEmail": "alice@example.com",
                "name": {"fullName": "Alice"},
                "isAdmin": True,
                "isDelegatedAdmin": False,
                "isEnrolledIn2Sv": True,
                "suspended": False,
                "archived": False,
                "creationTime": "2023-01-01T00:00:00.000Z",
                "lastLoginTime": "2026-05-01T00:00:00.000Z",
                "orgUnitPath": "/",
            },
            {
                "id": "u2",
                "primaryEmail": "bob@example.com",
                "name": {"fullName": "Bob"},
                "isAdmin": False,
                "isDelegatedAdmin": False,
                "isEnrolledIn2Sv": False,
                "suspended": False,
                "archived": False,
                "creationTime": "2024-01-01T00:00:00.000Z",
                "lastLoginTime": "1970-01-01T00:00:00.000Z",
                "orgUnitPath": "/",
            },
        ]
        c = GWSDirectoryCollector(_make_service(users=users), tenant_id="C0123abcd")
        assets = c.collect()

        users_out = [a for a in assets if a.resource_type == "gws_user"]
        assert len(users_out) == 2

        alice = next(a for a in users_out if a.name == "alice@example.com")
        assert alice.cloud_provider == "google_workspace"
        assert alice.account_id == "C0123abcd"
        assert alice.raw_config["is_super_admin"] is True
        assert alice.raw_config["two_factor_enrolled"] is True
        assert alice.raw_config["username"] == "alice"

        bob = next(a for a in users_out if a.name == "bob@example.com")
        # 1970 sentinel → days_since_last_login is None, not "inactive"
        assert bob.raw_config["days_since_last_login"] is None
        assert bob.raw_config["is_inactive"] is False

    def test_collect_groups_external_members(self):
        groups = [{"id": "g1", "email": "team@example.com", "directMembersCount": 3}]
        members = [
            {"email": "internal@example.com", "type": "USER"},
            {"email": "outside@partner.com", "type": "USER"},
        ]
        c = GWSDirectoryCollector(
            _make_service(groups=groups, members=members), tenant_id="C0"
        )
        assets = c.collect()
        groups_out = [a for a in assets if a.resource_type == "gws_group"]
        assert len(groups_out) == 1
        assert groups_out[0].raw_config["external_members_count"] == 1
        assert groups_out[0].raw_config["has_external_members"] is True

    def test_collect_role_assignments(self):
        roles = [
            {
                "roleId": 11,
                "roleName": "_SEED_ADMIN_ROLE",
                "isSystemRole": True,
                "isSuperAdminRole": True,
            },
            {
                "roleId": 22,
                "roleName": "Help Desk Admin",
                "isSystemRole": False,
                "isSuperAdminRole": False,
            },
        ]
        assignments = [
            {
                "roleAssignmentId": "ra-1",
                "roleId": "22",
                "assignedTo": "u-helpdesk",
                "scopeType": "CUSTOMER",
            },
            {
                "roleAssignmentId": "ra-2",
                "roleId": "22",
                "assignedTo": "u-engineering-helpdesk",
                "scopeType": "ORG_UNIT",
                "orgUnitId": "ou-eng",
            },
        ]
        c = GWSDirectoryCollector(
            _make_service(roles=roles, role_assignments=assignments),
            tenant_id="C0",
        )
        assets = c.collect()
        ras = [a for a in assets if a.resource_type == "gws_role_assignment"]
        assert len(ras) == 2
        scoped = next(a for a in ras if a.raw_config["scope_type"] == "ORG_UNIT")
        assert scoped.raw_config["role_name"] == "Help Desk Admin"
        assert scoped.raw_config["is_super_admin_role"] is False

    def test_collect_org_units(self):
        ous = [
            {
                "orgUnitId": "ou-eng",
                "orgUnitPath": "/Engineering",
                "name": "Engineering",
                "parentOrgUnitPath": "/",
                "blockInheritance": False,
            }
        ]
        c = GWSDirectoryCollector(_make_service(org_units=ous), tenant_id="C0")
        assets = c.collect()
        ou = [a for a in assets if a.resource_type == "gws_org_unit"][0]
        assert ou.raw_config["org_unit_path"] == "/Engineering"


# --------------------------------------------------------------------------- #
# gws_security
# --------------------------------------------------------------------------- #


class TestGWSSecurityCollector:
    def test_defaults_when_policy_api_empty(self):
        service = _make_service(
            users=[
                {
                    "id": "u1",
                    "primaryEmail": "admin-alice@example.com",
                    "isAdmin": True,
                    "isDelegatedAdmin": False,
                    "isEnrolledIn2Sv": True,
                    "suspended": False,
                    "archived": False,
                },
                {
                    "id": "u2",
                    "primaryEmail": "carol@example.com",
                    "isAdmin": False,
                    "isDelegatedAdmin": False,
                    "isEnrolledIn2Sv": False,
                    "suspended": False,
                    "archived": False,
                },
            ]
        )
        c = GWSSecurityCollector(service, tenant_id="C0123abcd")
        assets = c.collect()
        assert len(assets) == 1
        cfg = assets[0].raw_config
        assert cfg["two_sv_enforced"] is False  # default
        assert cfg["password_min_length"] == 8
        assert cfg["super_admin_count"] == 1
        assert cfg["super_admins_without_2sv"] == 0
        assert cfg["total_user_count"] == 2
        assert cfg["two_sv_enrollment_percent"] == 50.0
        assert cfg["primary_domain"] == "example.com"

    def test_policy_api_overrides_defaults(self):
        policies = [
            {
                "type": "settings/security.two_step_verification_enforcement",
                "setting": {"value": {"enforcement": True}},
            },
            {
                "type": "settings/security.password_min_length",
                "setting": {"value": {"minimumLength": 14}},
            },
            {
                "type": "settings/security.password_strength",
                "setting": {"value": {"enforce": True}},
            },
            {
                "type": "settings/security.password_reuse_prevention",
                "setting": {"value": {"reuse": 10}},
            },
            {
                "type": "settings/security.session_controls",
                "setting": {"value": {"webSessionDuration": 28800}},
            },
            {
                "type": "settings/security.super_admin_account_recovery",
                "setting": {"value": {"enabled": False}},
            },
            {
                "type": "settings/security.sso",
                "setting": {"value": {"enforced": True}},
            },
        ]
        c = GWSSecurityCollector(
            _make_service(policies=policies), tenant_id="C0123abcd"
        )
        cfg = c.collect()[0].raw_config
        assert cfg["two_sv_enforced"] is True
        assert cfg["password_min_length"] == 14
        assert cfg["password_strength_enforced"] is True
        assert cfg["password_reuse_prevention"] == 10
        assert cfg["session_length_seconds"] == 28800
        assert cfg["account_recovery_enabled_for_admins"] is False
        assert cfg["sso_enforced"] is True


# --------------------------------------------------------------------------- #
# Policy load + evaluation
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def gws_policies():
    loader = PolicyLoader(policy_dirs=[str(GWS_POLICIES_DIR)])
    policies = loader.load_all()
    assert len(policies) >= 10, (
        f"expected at least 10 GWS baseline policies, got {len(policies)}"
    )
    return policies


def _tenant_security_asset(**overrides: Any) -> Asset:
    base = {
        "two_sv_enforced": True,
        "two_sv_grace_period_days": 7,
        "password_strength_enforced": True,
        "password_min_length": 14,
        "password_reuse_prevention": 5,
        "session_length_seconds": 28800,
        "account_recovery_enabled_for_users": True,
        "account_recovery_enabled_for_admins": False,
        "sso_enforced": True,
        "login_challenges_enabled": True,
        "primary_domain": "example.com",
        "customer_id": "C0123abcd",
        "two_sv_enrolled_user_count": 10,
        "total_user_count": 10,
        "two_sv_enrollment_percent": 100.0,
        "super_admin_count": 3,
        "super_admins_without_2sv": 0,
        "delegated_admin_count": 2,
    }
    base.update(overrides)
    return Asset(
        id="gws:tenant_security:C0123abcd",
        cloud_provider="google_workspace",
        account_id="C0123abcd",
        region="global",
        resource_type="gws_tenant_security",
        name="example.com",
        raw_config=base,
    )


def _user_asset(email: str, **overrides: Any) -> Asset:
    username = email.split("@", 1)[0].lower()
    cfg = {
        "user_id": email,
        "primary_email": email,
        "username": username,
        "is_admin": False,
        "is_delegated_admin": False,
        "is_super_admin": False,
        "suspended": False,
        "archived": False,
        "two_factor_enrolled": True,
        "two_factor_enforced": True,
        "is_inactive": False,
        "days_since_last_login": 1,
        "org_unit_path": "/",
    }
    cfg.update(overrides)
    return Asset(
        id=f"gws:user:{email}",
        cloud_provider="google_workspace",
        account_id="C0123abcd",
        region="global",
        resource_type="gws_user",
        name=email,
        raw_config=cfg,
    )


def _role_assignment_asset(**overrides: Any) -> Asset:
    cfg = {
        "role_assignment_id": "ra-1",
        "role_id": "22",
        "role_name": "Help Desk Admin",
        "is_system_role": False,
        "is_super_admin_role": False,
        "assigned_to": "u-helpdesk",
        "scope_type": "ORG_UNIT",
        "org_unit_id": "ou-eng",
    }
    cfg.update(overrides)
    return Asset(
        id=f"gws:role_assignment:{cfg['role_assignment_id']}",
        cloud_provider="google_workspace",
        account_id="C0123abcd",
        region="global",
        resource_type="gws_role_assignment",
        name=cfg["role_name"],
        raw_config=cfg,
    )


class TestGWSPoliciesEndToEnd:
    def test_all_policies_load(self, gws_policies):
        ids = {p.id for p in gws_policies}
        # Spot-check a few representative IDs from the spec.
        assert "gws-auth-001" in ids
        assert "gws-admin-001" in ids
        assert "gws-admin-004" in ids
        assert "gws-user-001" in ids

    def test_compliant_tenant_has_no_findings(self, gws_policies):
        evaluator = PolicyEvaluator()
        assets = AssetCollection(
            [
                _tenant_security_asset(),
                _user_asset("admin-alice@example.com", is_admin=True, is_super_admin=True),
                _role_assignment_asset(),
            ]
        )
        findings, _ = evaluator.evaluate_all(gws_policies, assets)
        offending = [f.rule_id for f in findings]
        assert offending == [], f"unexpected findings on a compliant tenant: {offending}"

    def test_non_enforced_2sv_flags_finding(self, gws_policies):
        evaluator = PolicyEvaluator()
        assets = AssetCollection([_tenant_security_asset(two_sv_enforced=False)])
        findings, _ = evaluator.evaluate_all(gws_policies, assets)
        assert any(f.rule_id == "gws-auth-001" for f in findings)

    def test_weak_password_policy_flags_finding(self, gws_policies):
        evaluator = PolicyEvaluator()
        assets = AssetCollection(
            [_tenant_security_asset(password_min_length=8, password_reuse_prevention=0)]
        )
        findings, _ = evaluator.evaluate_all(gws_policies, assets)
        assert any(f.rule_id == "gws-auth-002" for f in findings)

    def test_session_too_long_flags_finding(self, gws_policies):
        evaluator = PolicyEvaluator()
        assets = AssetCollection(
            [_tenant_security_asset(session_length_seconds=None)]
        )
        findings, _ = evaluator.evaluate_all(gws_policies, assets)
        assert any(f.rule_id == "gws-auth-003" for f in findings)

    def test_super_admin_count_bounds(self, gws_policies):
        evaluator = PolicyEvaluator()
        # too few
        a1 = AssetCollection([_tenant_security_asset(super_admin_count=1)])
        f1, _ = evaluator.evaluate_all(gws_policies, a1)
        assert any(f.rule_id == "gws-admin-001" for f in f1)
        # too many
        a2 = AssetCollection([_tenant_security_asset(super_admin_count=8)])
        f2, _ = evaluator.evaluate_all(gws_policies, a2)
        assert any(f.rule_id == "gws-admin-001" for f in f2)
        # bare-minimum compliant
        a3 = AssetCollection([_tenant_security_asset(super_admin_count=2)])
        f3, _ = evaluator.evaluate_all(gws_policies, a3)
        assert not any(f.rule_id == "gws-admin-001" for f in f3)

    def test_super_admin_without_2sv_flags_finding(self, gws_policies):
        evaluator = PolicyEvaluator()
        assets = AssetCollection(
            [_tenant_security_asset(super_admins_without_2sv=1)]
        )
        findings, _ = evaluator.evaluate_all(gws_policies, assets)
        assert any(f.rule_id == "gws-admin-002" for f in findings)

    def test_delegated_admin_customer_scope_flags_finding(self, gws_policies):
        evaluator = PolicyEvaluator()
        assets = AssetCollection(
            [
                _role_assignment_asset(
                    scope_type="CUSTOMER",
                    is_super_admin_role=False,
                    is_system_role=False,
                )
            ]
        )
        findings, _ = evaluator.evaluate_all(gws_policies, assets)
        assert any(f.rule_id == "gws-admin-003" for f in findings)

    def test_naming_convention_flags_normal_account_with_super_admin(
        self, gws_policies
    ):
        evaluator = PolicyEvaluator()
        bad = _user_asset("alice@example.com", is_admin=True, is_super_admin=True)
        good = _user_asset(
            "admin-alice@example.com", is_admin=True, is_super_admin=True
        )
        findings, _ = evaluator.evaluate_all(
            gws_policies, AssetCollection([bad, good])
        )
        flagged_ids = [
            f.asset_id for f in findings if f.rule_id == "gws-admin-004"
        ]
        assert any("alice@example.com" in x and "admin-" not in x for x in flagged_ids)
        assert not any("admin-alice" in x for x in flagged_ids)

    def test_inactive_admin_flags_finding(self, gws_policies):
        evaluator = PolicyEvaluator()
        bad = _user_asset(
            "stale-admin@example.com",
            is_admin=True,
            is_super_admin=True,
            is_inactive=True,
            days_since_last_login=400,
        )
        good = _user_asset(
            "stale-user@example.com",
            is_admin=False,
            is_super_admin=False,
            is_inactive=True,
            days_since_last_login=400,
        )
        findings, _ = evaluator.evaluate_all(
            gws_policies, AssetCollection([bad, good])
        )
        flagged = [f.asset_id for f in findings if f.rule_id == "gws-user-001"]
        assert any("stale-admin" in x for x in flagged)
        assert not any("stale-user" in x for x in flagged)
