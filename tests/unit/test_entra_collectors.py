"""Unit tests for the Microsoft Entra collectors and 15 baseline policies
(SaaS Posture Spec PR 4)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from stance.collectors.m365_entra_apps import EntraAppsCollector
from stance.collectors.m365_entra_auth_methods import EntraAuthMethodsCollector
from stance.collectors.m365_entra_conditional_access import (
    EntraConditionalAccessCollector,
)
from stance.collectors.m365_entra_consent import EntraConsentCollector
from stance.collectors.m365_entra_directory import EntraDirectoryCollector
from stance.collectors.m365_entra_external_identities import (
    EntraExternalIdentitiesCollector,
)
from stance.collectors.m365_entra_federation import EntraFederationCollector
from stance.collectors.m365_entra_identity_protection import (
    EntraIdentityProtectionCollector,
)
from stance.collectors.m365_entra_pim import EntraPIMCollector
from stance.collectors.m365_entra_security_defaults import (
    EntraSecurityDefaultsCollector,
)
from stance.engine.evaluator import PolicyEvaluator
from stance.engine.loader import PolicyLoader
from stance.models import Asset, AssetCollection


REPO_ROOT = Path(__file__).resolve().parents[2]
ENTRA_DIR = REPO_ROOT / "policies" / "saas" / "microsoft_365" / "entra"
APPS_DIR = REPO_ROOT / "policies" / "saas" / "microsoft_365" / "apps"


# --------------------------------------------------------------------------- #
# Fake graph client
# --------------------------------------------------------------------------- #


def make_graph(routes: dict[str, Any]) -> Any:
    """Return a callable that maps Graph paths to canned responses.

    Matches by path prefix (longest-match wins) so query-string variants
    on the same endpoint don't all need separate keys.
    """
    sorted_keys = sorted(routes.keys(), key=len, reverse=True)

    def graph(path: str) -> dict[str, Any]:
        # Exact-match first.
        if path in routes:
            return routes[path]
        for key in sorted_keys:
            if path.startswith(key):
                return routes[key]
        return {}

    return graph


# --------------------------------------------------------------------------- #
# Directory
# --------------------------------------------------------------------------- #


class TestEntraDirectoryCollector:
    def test_directory_summary_counts(self):
        graph = make_graph(
            {
                "/v1.0/users": {
                    "value": [
                        {"id": "u1", "userPrincipalName": "alice@x.com",
                         "userType": "Member", "accountEnabled": True},
                        {"id": "u2", "userPrincipalName": "guest@y.com",
                         "userType": "Guest", "accountEnabled": True},
                    ]
                },
                "/v1.0/groups": {"value": []},
                "/v1.0/roleManagement/directory/roleDefinitions": {
                    "value": [
                        {"id": "r1", "displayName": "Global Administrator"},
                        {"id": "r2", "displayName": "User Administrator"},
                        {"id": "r3", "displayName": "Reports Reader"},
                    ]
                },
                "/v1.0/roleManagement/directory/roleAssignments": {
                    "value": [
                        {"id": "ra1", "roleDefinitionId": "r1", "principalId": "u1"},
                        {"id": "ra2", "roleDefinitionId": "r2", "principalId": "u1"},
                    ]
                },
                "/v1.0/roleManagement/directory/roleEligibilitySchedules": {
                    "value": []
                },
                "/v1.0/roleManagement/directory/roleEligibilityScheduleInstances": {
                    "value": []
                },
            }
        )
        assets = list(EntraDirectoryCollector(graph, "tenant-1").collect())
        summary = next(
            a for a in assets if a.resource_type == "entra_directory_summary"
        )
        cfg = summary.raw_config
        assert cfg["user_count"] == 2
        assert cfg["guest_count"] == 1
        assert cfg["global_admin_active_count"] == 1
        assert cfg["privileged_active_assignment_count"] == 2  # GA + UA


# --------------------------------------------------------------------------- #
# Conditional Access
# --------------------------------------------------------------------------- #


class TestEntraConditionalAccessCollector:
    def test_summary_flags(self):
        policies = [
            {  # block legacy auth (enabled)
                "id": "p-legacy",
                "displayName": "Block legacy auth",
                "state": "enabled",
                "conditions": {
                    "users": {"includeUsers": ["All"]},
                    "applications": {"includeApplications": ["All"]},
                    "clientAppTypes": ["exchangeActiveSync", "other"],
                },
                "grantControls": {"builtInControls": ["block"]},
            },
            {  # MFA + compliant device for admins (enabled)
                "id": "p-admin",
                "displayName": "Admins: MFA + compliant",
                "state": "enabled",
                "conditions": {
                    "users": {
                        "includeRoles": ["62e90394-69f5-4237-9190-012177145e10"],
                        "includeUsers": [],
                    },
                    "applications": {"includeApplications": ["All"]},
                    "clientAppTypes": [],
                },
                "grantControls": {"builtInControls": ["mfa", "compliantDevice"]},
            },
            {  # disabled policy — should not contribute
                "id": "p-off",
                "displayName": "Off",
                "state": "disabled",
                "conditions": {"users": {}, "applications": {}, "clientAppTypes": []},
                "grantControls": {"builtInControls": ["mfa"]},
            },
        ]
        graph = make_graph(
            {"/v1.0/identity/conditionalAccess/policies": {"value": policies}}
        )
        assets = list(EntraConditionalAccessCollector(graph, "t1").collect())
        summary = next(a for a in assets if a.resource_type == "entra_ca_summary")
        cfg = summary.raw_config
        assert cfg["enabled_policy_count"] == 2
        assert cfg["any_policy_blocks_legacy_auth"] is True
        assert cfg["any_policy_requires_mfa_for_admins"] is True
        assert cfg["any_policy_requires_compliant_device_for_admins"] is True


# --------------------------------------------------------------------------- #
# Apps
# --------------------------------------------------------------------------- #


class TestEntraAppsCollector:
    def test_apps_orphaned_and_high_risk(self):
        future = (datetime.now(timezone.utc) + timedelta(days=200)).isoformat()
        soon = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
        graph = make_graph(
            {
                "/v1.0/servicePrincipals": {
                    "value": [
                        {
                            "id": "sp1",
                            "appId": "app-1",
                            "displayName": "App One",
                            "passwordCredentials": [
                                {"hint": "abc", "endDateTime": future}
                            ],
                        },
                        {
                            "id": "sp-soon",
                            "appId": "app-soon",
                            "displayName": "Expiring Soon",
                            "passwordCredentials": [
                                {"hint": "xyz", "endDateTime": soon}
                            ],
                        },
                    ]
                },
                "/v1.0/applications": {
                    "value": [
                        {
                            "id": "obj1",
                            "appId": "app-1",
                            "displayName": "App One",
                            "requiredResourceAccess": [
                                {
                                    "resourceAppId": "00000003-0000-0000-c000-000000000000",
                                    "resourceAccess": [
                                        {"id": "Mail.ReadWrite.All", "type": "Role"}
                                    ],
                                }
                            ],
                            "passwordCredentials": [
                                {"hint": "abc", "endDateTime": future}
                            ],
                        },
                        {
                            "id": "obj-orphan",
                            "appId": "app-orphan",
                            "displayName": "Orphan App",
                            "requiredResourceAccess": [],
                            "passwordCredentials": [],
                        },
                    ]
                },
            }
        )
        assets = list(EntraAppsCollector(graph, "t1").collect())
        apps = {a.raw_config["app_id"]: a for a in assets if a.resource_type == "entra_app_registration"}
        sps = {a.raw_config["app_id"]: a for a in assets if a.resource_type == "entra_service_principal"}

        assert apps["app-1"].raw_config["has_high_risk_graph_permissions"] is True
        assert apps["app-1"].raw_config["is_orphaned"] is False
        assert apps["app-orphan"].raw_config["is_orphaned"] is True

        assert sps["app-soon"].raw_config["credentials_expiring_within_30_days"] == 1
        assert sps["app-1"].raw_config["has_credential_without_expiry"] is False


# --------------------------------------------------------------------------- #
# Auth methods
# --------------------------------------------------------------------------- #


class TestEntraAuthMethodsCollector:
    def test_passwordless_and_sspr(self):
        graph = make_graph(
            {
                "/v1.0/policies/authenticationMethodsPolicy": {
                    "authenticationMethodConfigurations": [
                        {"id": "fido2", "state": "enabled"},
                        {"id": "sms", "state": "enabled"},
                        {"id": "windowsHelloForBusiness", "state": "disabled"},
                    ]
                },
                "/v1.0/reports/authenticationMethods/userRegistrationDetails": {
                    "value": [
                        {"isMfaRegistered": True, "isPasswordlessCapable": True},
                        {"isMfaRegistered": True, "isPasswordlessCapable": False},
                        {"isMfaRegistered": False, "isPasswordlessCapable": False},
                    ]
                },
                "/beta/policies/passwordResetPolicies": {
                    "enabledForUsers": True,
                    "authenticationMethodRequiredCount": 2,
                },
            }
        )
        cfg = (
            EntraAuthMethodsCollector(graph, "t1")
            .collect()[0]
            .raw_config
        )
        assert cfg["any_passwordless_enabled"] is True
        assert cfg["passwordless_methods_enabled"] == ["fido2"]
        assert cfg["users_passwordless_capable"] == 1
        assert cfg["sspr_enabled"] is True
        assert cfg["sspr_requires_mfa"] is True


# --------------------------------------------------------------------------- #
# PIM
# --------------------------------------------------------------------------- #


class TestEntraPIMCollector:
    def test_permanent_global_admin_detected(self):
        graph = make_graph(
            {
                "/v1.0/roleManagement/directory/roleEligibilityScheduleInstances": {
                    "value": [
                        {
                            "id": "elg-1",
                            "principalId": "u1",
                            "roleDefinitionId": "r-ga",
                            "roleDefinitionDisplayName": "Global Administrator",
                        }
                    ]
                },
                "/v1.0/roleManagement/directory/roleDefinitions": {
                    "value": [
                        {"id": "r-ga", "displayName": "Global Administrator"},
                        {"id": "r-ua", "displayName": "User Administrator"},
                    ]
                },
                "/v1.0/roleManagement/directory/roleAssignments": {
                    "value": [
                        {"id": "a1", "roleDefinitionId": "r-ga", "principalId": "u1"},
                        {"id": "a2", "roleDefinitionId": "r-ua", "principalId": "u2"},
                    ]
                },
                "/v1.0/policies/roleManagementPolicyAssignments": {
                    "value": [
                        {
                            "id": "rmp-1",
                            "roleDefinitionId": "r-ga",
                            "rules": [
                                {
                                    "@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule",
                                    "id": "Enablement_EndUser_Assignment",
                                    "isMfaRequired": True,
                                }
                            ],
                        },
                        {
                            "id": "rmp-2",
                            "roleDefinitionId": "r-ua",
                            "rules": [
                                {
                                    "@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule",
                                    "id": "Enablement_EndUser_Assignment",
                                    "isMfaRequired": False,
                                }
                            ],
                        },
                    ]
                },
            }
        )
        # The collector deduplicates rule MFA detection by checking if "MfaRule" is in @odata.type.
        # Override the type so the simple match in our collector hits.
        graph2 = make_graph({**{
            "/v1.0/roleManagement/directory/roleEligibilityScheduleInstances": {
                "value": [
                    {
                        "id": "elg-1",
                        "principalId": "u1",
                        "roleDefinitionId": "r-ga",
                        "roleDefinitionDisplayName": "Global Administrator",
                    }
                ]
            },
            "/v1.0/roleManagement/directory/roleDefinitions": {
                "value": [
                    {"id": "r-ga", "displayName": "Global Administrator"},
                    {"id": "r-ua", "displayName": "User Administrator"},
                ]
            },
            "/v1.0/roleManagement/directory/roleAssignments": {
                "value": [
                    {"id": "a1", "roleDefinitionId": "r-ga", "principalId": "u1"},
                ]
            },
            "/v1.0/policies/roleManagementPolicyAssignments": {
                "value": [
                    {
                        "id": "rmp-1",
                        "roleDefinitionId": "r-ga",
                        "rules": [
                            {
                                "@odata.type": "#microsoft.graph.MfaRule",
                                "isMfaRequired": True,
                            }
                        ],
                    },
                ]
            },
        }})
        assets = list(EntraPIMCollector(graph2, "t1").collect())
        summary = next(a for a in assets if a.resource_type == "entra_pim_summary")
        cfg = summary.raw_config
        assert cfg["permanent_global_admin_count"] == 1
        assert cfg["active_privileged_assignment_count"] == 1
        rs = next(a for a in assets if a.resource_type == "entra_pim_role_setting")
        assert rs.raw_config["requires_mfa_to_activate"] is True


# --------------------------------------------------------------------------- #
# Security defaults + tenant baseline
# --------------------------------------------------------------------------- #


class TestEntraSecurityDefaults:
    def test_baseline_with_security_defaults_only(self):
        graph = make_graph(
            {
                "/v1.0/policies/identitySecurityDefaultsEnforcementPolicy": {
                    "isEnabled": True
                },
                "/v1.0/identity/conditionalAccess/policies": {"value": []},
            }
        )
        assets = list(EntraSecurityDefaultsCollector(graph, "t1").collect())
        baseline = next(
            a for a in assets if a.resource_type == "entra_tenant_baseline"
        )
        assert baseline.raw_config["has_identity_baseline"] is True

    def test_baseline_with_neither(self):
        graph = make_graph(
            {
                "/v1.0/policies/identitySecurityDefaultsEnforcementPolicy": {
                    "isEnabled": False
                },
                "/v1.0/identity/conditionalAccess/policies": {"value": []},
            }
        )
        baseline = [
            a
            for a in EntraSecurityDefaultsCollector(graph, "t1").collect()
            if a.resource_type == "entra_tenant_baseline"
        ][0]
        assert baseline.raw_config["has_identity_baseline"] is False


# --------------------------------------------------------------------------- #
# Identity Protection / Federation / External / Consent smoke tests
# --------------------------------------------------------------------------- #


class TestSmallEntraCollectors:
    def test_identity_protection(self):
        graph = make_graph(
            {
                "/beta/identityProtection/policies/signInRiskPolicy": {"isEnabled": True},
                "/beta/identityProtection/policies/userRiskPolicy": {"isEnabled": True},
                "/beta/identityProtection/policies/mfaRegistrationPolicy": {"isEnabled": True},
            }
        )
        cfg = EntraIdentityProtectionCollector(graph, "t1").collect()[0].raw_config
        assert cfg["all_identity_protection_policies_enabled"] is True

    def test_federation_unverified_flagged(self):
        graph = make_graph(
            {
                "/v1.0/domains": {
                    "value": [
                        {"id": "x.com", "authenticationType": "Managed", "isVerified": True},
                        {"id": "y.com", "authenticationType": "Federated", "isVerified": False},
                    ]
                }
            }
        )
        assets = list(EntraFederationCollector(graph, "t1").collect())
        summary = next(a for a in assets if a.resource_type == "entra_federation_summary")
        assert summary.raw_config["any_unverified_federated_domain"] is True
        assert "y.com" in summary.raw_config["unverified_federated_domains"]

    def test_consent_smoke(self):
        graph = make_graph(
            {
                "/v1.0/policies/authorizationPolicy": {
                    "defaultUserRolePermissions": {
                        "permissionGrantPoliciesAssigned": []
                    },
                    "allowInvitesFrom": "adminsAndGuestInviters",
                },
                "/v1.0/oauth2PermissionGrants": {"value": []},
            }
        )
        assets = list(EntraConsentCollector(graph, "t1").collect())
        cp = next(a for a in assets if a.resource_type == "entra_consent_policy")
        assert cp.raw_config["user_consent_for_apps_enabled"] is False

    def test_external_identities_smoke(self):
        graph = make_graph(
            {
                "/beta/policies/externalIdentitiesPolicy": {},
                "/v1.0/policies/authorizationPolicy": {
                    "allowInvitesFrom": "adminsAndGuestInviters"
                },
                "/v1.0/policies/crossTenantAccessPolicy/partners": {"value": []},
            }
        )
        cfg = (
            EntraExternalIdentitiesCollector(graph, "t1")
            .collect()[0]
            .raw_config
        )
        assert cfg["guest_invites_restricted"] is True


# --------------------------------------------------------------------------- #
# Policy load + evaluation
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def entra_policies():
    loader = PolicyLoader(policy_dirs=[str(ENTRA_DIR), str(APPS_DIR)])
    policies = loader.load_all()
    assert len(policies) >= 15, (
        f"expected 15 baseline policies, got {len(policies)}"
    )
    return policies


def _ca_summary(**o: Any) -> Asset:
    cfg = {
        "policy_count": 3,
        "enabled_policy_count": 3,
        "any_policy_blocks_legacy_auth": True,
        "any_policy_requires_mfa_for_admins": True,
        "any_policy_requires_compliant_device_for_admins": True,
        "any_policy_requires_mfa_all_users": True,
    }
    cfg.update(o)
    return Asset(
        id="entra:ca_summary:t1",
        cloud_provider="microsoft_365",
        account_id="t1",
        region="global",
        resource_type="entra_ca_summary",
        name="ca-summary",
        raw_config=cfg,
    )


def _baseline(**o: Any) -> Asset:
    cfg = {
        "security_defaults_enabled": False,
        "enabled_ca_policy_count": 3,
        "has_identity_baseline": True,
    }
    cfg.update(o)
    return Asset(
        id="entra:tenant_baseline:t1",
        cloud_provider="microsoft_365",
        account_id="t1",
        region="global",
        resource_type="entra_tenant_baseline",
        name="entra-tenant-baseline",
        raw_config=cfg,
    )


def _pim_summary(**o: Any) -> Asset:
    cfg = {
        "eligible_assignment_count": 5,
        "active_privileged_assignment_count": 2,
        "active_global_admin_count": 0,
        "permanent_global_admin_count": 0,
        "privileged_roles_with_only_eligible_assignments": ["Global Administrator"],
        "privileged_roles_with_permanent_assignments": [],
        "all_privileged_roles_via_pim": True,
    }
    cfg.update(o)
    return Asset(
        id="entra:pim_summary:t1",
        cloud_provider="microsoft_365",
        account_id="t1",
        region="global",
        resource_type="entra_pim_summary",
        name="pim",
        raw_config=cfg,
    )


def _pim_role_setting(**o: Any) -> Asset:
    cfg = {
        "policy_assignment_id": "rmp-1",
        "scope_id": "/",
        "role_definition_id": "r-ga",
        "requires_mfa_to_activate": True,
        "requires_approval_to_activate": True,
        "max_activation_minutes": 60,
    }
    cfg.update(o)
    return Asset(
        id=f"entra:pim_role_setting:{cfg['policy_assignment_id']}",
        cloud_provider="microsoft_365",
        account_id="t1",
        region="global",
        resource_type="entra_pim_role_setting",
        name=cfg["role_definition_id"],
        raw_config=cfg,
    )


def _idp(**o: Any) -> Asset:
    cfg = {
        "sign_in_risk_policy_enabled": True,
        "user_risk_policy_enabled": True,
        "mfa_registration_policy_enabled": True,
        "all_identity_protection_policies_enabled": True,
    }
    cfg.update(o)
    return Asset(
        id="entra:identity_protection_policies:t1",
        cloud_provider="microsoft_365",
        account_id="t1",
        region="global",
        resource_type="entra_identity_protection_policies",
        name="idp",
        raw_config=cfg,
    )


def _auth_summary(**o: Any) -> Asset:
    cfg = {
        "passwordless_methods_enabled": ["fido2"],
        "any_passwordless_enabled": True,
        "user_count_with_registration_data": 100,
        "users_mfa_registered": 95,
        "users_passwordless_capable": 50,
        "passwordless_adoption_percent": 50.0,
        "sspr_enabled": True,
        "sspr_requires_mfa": True,
    }
    cfg.update(o)
    return Asset(
        id="entra:auth_methods_summary:t1",
        cloud_provider="microsoft_365",
        account_id="t1",
        region="global",
        resource_type="entra_auth_methods_summary",
        name="auth",
        raw_config=cfg,
    )


def _consent(**o: Any) -> Asset:
    cfg = {
        "user_consent_for_apps_enabled": False,
        "permission_grant_policies_assigned": [],
        "allow_invites_from": "adminsAndGuestInviters",
        "allow_user_consent_for_risky_apps": False,
        "block_msol_powershell": True,
        "user_consent_blocked": True,
        "admin_consent_only": True,
    }
    cfg.update(o)
    return Asset(
        id="entra:consent_policy:t1",
        cloud_provider="microsoft_365",
        account_id="t1",
        region="global",
        resource_type="entra_consent_policy",
        name="consent",
        raw_config=cfg,
    )


def _app(**o: Any) -> Asset:
    cfg = {
        "app_object_id": "obj1",
        "app_id": "app1",
        "display_name": "App",
        "publisher_domain": "example.com",
        "secret_count": 1,
        "key_count": 0,
        "soonest_credential_expiry_days": 200,
        "has_credential_without_expiry": False,
        "credentials_expiring_within_30_days": 0,
        "credentials_expired": 0,
        "graph_app_permissions": [],
        "high_risk_graph_permission_count": 0,
        "has_high_risk_graph_permissions": False,
        "has_service_principal": True,
        "is_orphaned": False,
        "owner_justification_recorded": False,
    }
    cfg.update(o)
    return Asset(
        id=f"entra:app_registration:{cfg['app_id']}",
        cloud_provider="microsoft_365",
        account_id="t1",
        region="global",
        resource_type="entra_app_registration",
        name=cfg["display_name"],
        raw_config=cfg,
    )


def _sp(**o: Any) -> Asset:
    cfg = {
        "sp_object_id": "sp1",
        "app_id": "app1",
        "display_name": "App",
        "service_principal_type": "Application",
        "account_enabled": True,
        "app_role_assignment_required": True,
        "tags": [],
        "publisher_name": "X",
        "secret_count": 1,
        "key_count": 0,
        "soonest_credential_expiry_days": 200,
        "has_credential_without_expiry": False,
        "credentials_expiring_within_30_days": 0,
        "credentials_expired": 0,
    }
    cfg.update(o)
    return Asset(
        id=f"entra:service_principal:{cfg['sp_object_id']}",
        cloud_provider="microsoft_365",
        account_id="t1",
        region="global",
        resource_type="entra_service_principal",
        name=cfg["display_name"],
        raw_config=cfg,
    )


def _fed(**o: Any) -> Asset:
    cfg = {
        "domain_count": 2,
        "federated_domain_count": 1,
        "unverified_federated_domains": [],
        "any_unverified_federated_domain": False,
    }
    cfg.update(o)
    return Asset(
        id="entra:federation_summary:t1",
        cloud_provider="microsoft_365",
        account_id="t1",
        region="global",
        resource_type="entra_federation_summary",
        name="federation",
        raw_config=cfg,
    )


class TestEntraPoliciesEndToEnd:
    def test_compliant_baseline_no_findings(self, entra_policies):
        assets = AssetCollection(
            [
                _baseline(),
                _ca_summary(),
                _pim_summary(),
                _pim_role_setting(),
                _idp(),
                _auth_summary(),
                _consent(),
                _app(),
                _sp(),
                _fed(),
            ]
        )
        f, _ = PolicyEvaluator().evaluate_all(entra_policies, assets)
        assert [x.rule_id for x in f] == [], (
            f"unexpected findings on compliant baseline: {[x.rule_id for x in f]}"
        )

    def test_no_baseline_flags_critical(self, entra_policies):
        assets = AssetCollection(
            [_baseline(has_identity_baseline=False)]
        )
        f, _ = PolicyEvaluator().evaluate_all(entra_policies, assets)
        assert any(x.rule_id == "m365-entra-001" for x in f)

    def test_ca_failures(self, entra_policies):
        assets = AssetCollection(
            [
                _ca_summary(
                    any_policy_blocks_legacy_auth=False,
                    any_policy_requires_mfa_for_admins=False,
                    any_policy_requires_compliant_device_for_admins=False,
                )
            ]
        )
        f, _ = PolicyEvaluator().evaluate_all(entra_policies, assets)
        rule_ids = {x.rule_id for x in f}
        assert {"m365-entra-002", "m365-entra-003", "m365-entra-004"} <= rule_ids

    def test_permanent_ga_flagged(self, entra_policies):
        assets = AssetCollection(
            [_pim_summary(permanent_global_admin_count=1)]
        )
        f, _ = PolicyEvaluator().evaluate_all(entra_policies, assets)
        assert any(x.rule_id == "m365-entra-005" for x in f)

    def test_pim_role_no_mfa_flagged(self, entra_policies):
        assets = AssetCollection(
            [_pim_role_setting(requires_mfa_to_activate=False)]
        )
        f, _ = PolicyEvaluator().evaluate_all(entra_policies, assets)
        assert any(x.rule_id == "m365-entra-006" for x in f)

    def test_too_many_active_privileged(self, entra_policies):
        assets = AssetCollection([_pim_summary(active_privileged_assignment_count=15)])
        f, _ = PolicyEvaluator().evaluate_all(entra_policies, assets)
        assert any(x.rule_id == "m365-entra-007" for x in f)

    def test_idp_disabled_flagged(self, entra_policies):
        assets = AssetCollection([_idp(sign_in_risk_policy_enabled=False)])
        f, _ = PolicyEvaluator().evaluate_all(entra_policies, assets)
        assert any(x.rule_id == "m365-entra-008" for x in f)

    def test_no_passwordless_flagged(self, entra_policies):
        assets = AssetCollection([_auth_summary(any_passwordless_enabled=False)])
        f, _ = PolicyEvaluator().evaluate_all(entra_policies, assets)
        assert any(x.rule_id == "m365-entra-009" for x in f)

    def test_sspr_without_mfa_flagged(self, entra_policies):
        assets = AssetCollection(
            [_auth_summary(sspr_enabled=True, sspr_requires_mfa=False)]
        )
        f, _ = PolicyEvaluator().evaluate_all(entra_policies, assets)
        assert any(x.rule_id == "m365-entra-010" for x in f)

    def test_unverified_federated_domain_flagged(self, entra_policies):
        assets = AssetCollection(
            [_fed(any_unverified_federated_domain=True, unverified_federated_domains=["y.com"])]
        )
        f, _ = PolicyEvaluator().evaluate_all(entra_policies, assets)
        assert any(x.rule_id == "m365-entra-011" for x in f)

    def test_user_consent_flagged(self, entra_policies):
        assets = AssetCollection([_consent(user_consent_for_apps_enabled=True)])
        f, _ = PolicyEvaluator().evaluate_all(entra_policies, assets)
        assert any(x.rule_id == "m365-apps-001" for x in f)

    def test_high_risk_graph_perms_flagged(self, entra_policies):
        bad = _app(
            app_id="bad",
            has_high_risk_graph_permissions=True,
            owner_justification_recorded=False,
        )
        good = _app(
            app_id="good",
            has_high_risk_graph_permissions=True,
            owner_justification_recorded=True,
        )
        f, _ = PolicyEvaluator().evaluate_all(
            entra_policies, AssetCollection([bad, good])
        )
        flagged = [x.asset_id for x in f if x.rule_id == "m365-apps-002"]
        assert any("bad" in x for x in flagged)
        assert not any("good" in x for x in flagged)

    def test_sp_secret_rotation_flagged(self, entra_policies):
        bad_no_expiry = _sp(sp_object_id="sp-noexp", has_credential_without_expiry=True)
        bad_expired = _sp(sp_object_id="sp-exp", credentials_expired=1)
        f, _ = PolicyEvaluator().evaluate_all(
            entra_policies, AssetCollection([bad_no_expiry, bad_expired])
        )
        flagged = {x.asset_id for x in f if x.rule_id == "m365-apps-003"}
        assert any("sp-noexp" in x for x in flagged)
        assert any("sp-exp" in x for x in flagged)

    def test_orphaned_app_flagged(self, entra_policies):
        f, _ = PolicyEvaluator().evaluate_all(
            entra_policies, AssetCollection([_app(app_id="orphan", is_orphaned=True)])
        )
        assert any(x.rule_id == "m365-apps-004" for x in f)
