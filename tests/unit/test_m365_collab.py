"""Unit tests for the SharePoint, OneDrive, and Exchange collectors and the
10 PR-5 baseline policies."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from stance.collectors.m365_exchange import M365ExchangeCollector
from stance.collectors.m365_onedrive import M365OneDriveCollector
from stance.collectors.m365_sharepoint_sites import M365SharePointSitesCollector
from stance.collectors.m365_sharepoint_tenant import M365SharePointTenantCollector
from stance.engine.evaluator import PolicyEvaluator
from stance.engine.loader import PolicyLoader
from stance.models import Asset, AssetCollection


REPO_ROOT = Path(__file__).resolve().parents[2]
M365_BASE = REPO_ROOT / "policies" / "saas" / "microsoft_365"


def make_graph(routes: dict[str, Any]) -> Any:
    sorted_keys = sorted(routes.keys(), key=len, reverse=True)

    def graph(path: str) -> dict[str, Any]:
        if path in routes:
            return routes[path]
        for key in sorted_keys:
            if path.startswith(key):
                return routes[key]
        return {}

    return graph


# --------------------------------------------------------------------------- #
# Collector smoke tests
# --------------------------------------------------------------------------- #


class TestSharePointTenant:
    def test_open_defaults(self):
        graph = make_graph({"/v1.0/admin/sharepoint/settings": {}})
        cfg = (
            M365SharePointTenantCollector(graph, "t1")
            .collect()[0]
            .raw_config
        )
        assert cfg["sharing_capability_rank"] == 3
        assert cfg["external_sharing_restricted"] is False
        assert cfg["anonymous_links_disabled"] is False

    def test_locked_down(self):
        graph = make_graph(
            {
                "/v1.0/admin/sharepoint/settings": {
                    "sharingCapability": "externalUserSharingOnly",
                    "sharingDomainRestrictionMode": "allowList",
                    "sharingAllowedDomainList": ["partner.com"],
                    "idleSessionSignOut": {
                        "isEnabled": True,
                        "signOutAfterInSeconds": 3600,
                    },
                }
            }
        )
        cfg = (
            M365SharePointTenantCollector(graph, "t1")
            .collect()[0]
            .raw_config
        )
        assert cfg["anonymous_links_disabled"] is True
        assert cfg["external_sharing_domain_allowlist_enforced"] is True
        assert cfg["idle_session_timeout_enabled"] is True
        assert cfg["idle_session_timeout_minutes"] == 60


class TestSharePointSites:
    def test_per_site_external_users(self):
        graph = make_graph(
            {
                "/v1.0/sites": {
                    "value": [
                        {"id": "s1", "displayName": "HR", "webUrl": "https://x"},
                        {"id": "s2", "displayName": "Public", "webUrl": "https://y"},
                    ]
                },
                "/v1.0/admin/sharepoint/sites/s1": {
                    "sharingCapability": "disabled",
                    "externalUserCount": 0,
                    "sensitivityLabel": {"id": "lbl-1", "displayName": "Confidential"},
                },
                "/v1.0/admin/sharepoint/sites/s2": {
                    "sharingCapability": "externalUserAndGuestSharing",
                    "externalUserCount": 14,
                },
            }
        )
        assets = list(M365SharePointSitesCollector(graph, "t1").collect())
        by_id = {a.raw_config["site_id"]: a for a in assets}
        assert by_id["s1"].raw_config["is_labelled"] is True
        assert by_id["s1"].raw_config["external_sharing_restricted"] is True
        assert by_id["s2"].raw_config["has_external_users"] is True
        assert by_id["s2"].raw_config["sharing_capability_rank"] == 3


class TestOneDrive:
    def test_managed_devices_only(self):
        graph = make_graph(
            {
                "/v1.0/admin/sharepoint/settings": {
                    "oneDriveSharingCapability": "externalUserSharingOnly",
                    "oneDriveSyncRestrictions": {
                        "allowSyncOnlyOnManagedDevices": True
                    },
                }
            }
        )
        cfg = (
            M365OneDriveCollector(graph, "t1")
            .collect()[0]
            .raw_config
        )
        assert cfg["sync_to_managed_devices_only"] is True
        assert cfg["sharing_capability_rank"] == 2


class TestExchange:
    def test_org_config_and_transport_rules(self):
        graph = make_graph(
            {
                "/beta/admin/exchange/organizationConfig": {
                    "oAuth2ClientProfileEnabled": True,
                    "auditDisabled": False,
                    "isMailboxAuditEnabledByDefault": True,
                    "transportRulesReviewed": True,
                },
                "/beta/admin/exchange/remoteDomains/Default": {
                    "identity": "Default",
                    "autoForwardEnabled": False,
                },
                "/beta/admin/exchange/transportRules": {
                    "value": [
                        {"id": "tr-1", "name": "Block .exe", "state": "Enabled"},
                        {"id": "tr-2", "name": "Disabled rule", "state": "Disabled"},
                    ]
                },
            }
        )
        assets = list(M365ExchangeCollector(graph, "t1").collect())
        org = next(a for a in assets if a.resource_type == "exchange_org_config")
        rules = [a for a in assets if a.resource_type == "exchange_transport_rule"]
        assert org.raw_config["modern_auth_enforced"] is True
        assert org.raw_config["mailbox_audit_enabled_by_default"] is True
        assert org.raw_config["org_wide_mail_forwarding_allowed"] is False
        assert org.raw_config["transport_rule_count"] == 2
        assert org.raw_config["enabled_transport_rule_count"] == 1
        assert len(rules) == 2


# --------------------------------------------------------------------------- #
# Policy load + evaluate
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def pr5_policies():
    dirs = [
        str(M365_BASE / "sharepoint"),
        str(M365_BASE / "onedrive"),
        str(M365_BASE / "exchange"),
    ]
    loader = PolicyLoader(policy_dirs=dirs)
    policies = loader.load_all()
    assert len(policies) >= 10, (
        f"expected 10 PR5 policies, got {len(policies)}"
    )
    return policies


def _sp_tenant(**o: Any) -> Asset:
    cfg = {
        "sharing_capability": "externalUserSharingOnly",
        "sharing_capability_rank": 2,
        "anonymous_links_disabled": True,
        "external_sharing_restricted": False,
        "default_link_type": "internal",
        "default_link_to_existing_access": True,
        "domain_restriction_mode": "allowList",
        "sharing_allowed_domains": ["partner.com"],
        "sharing_blocked_domains": [],
        "external_sharing_domain_allowlist_enforced": True,
        "idle_session_timeout_enabled": True,
        "idle_session_timeout_minutes": 60,
        "external_user_expiration_required": True,
        "block_download_for_anonymous": True,
    }
    cfg.update(o)
    return Asset(
        id="sharepoint:tenant_settings:t1",
        cloud_provider="microsoft_365",
        account_id="t1",
        region="global",
        resource_type="sharepoint_tenant_settings",
        name="sp",
        raw_config=cfg,
    )


def _onedrive(**o: Any) -> Asset:
    cfg = {
        "sharing_capability": "externalUserSharingOnly",
        "sharing_capability_rank": 2,
        "external_sharing_restricted": False,
        "default_link_type": "internal",
        "sync_to_managed_devices_only": True,
        "sync_blocked_domains": [],
        "sync_blocked_file_extensions": ["pst"],
        "block_macos_sync": False,
        "block_download_unmanaged_devices": True,
    }
    cfg.update(o)
    return Asset(
        id="onedrive:settings:t1",
        cloud_provider="microsoft_365",
        account_id="t1",
        region="global",
        resource_type="onedrive_settings",
        name="od",
        raw_config=cfg,
    )


def _exchange(**o: Any) -> Asset:
    cfg = {
        "modern_auth_enforced": True,
        "mailbox_audit_enabled_by_default": True,
        "auto_forward_enabled_default_remote_domain": False,
        "org_wide_mail_forwarding_allowed": False,
        "smtp_basic_auth_disabled": True,
        "default_remote_domain_id": "Default",
        "transport_rule_count": 0,
        "enabled_transport_rule_count": 0,
        "transport_rules_reviewed": True,
    }
    cfg.update(o)
    return Asset(
        id="exchange:org_config:t1",
        cloud_provider="microsoft_365",
        account_id="t1",
        region="global",
        resource_type="exchange_org_config",
        name="exo",
        raw_config=cfg,
    )


class TestPR5PoliciesEndToEnd:
    def test_compliant_baseline(self, pr5_policies):
        assets = AssetCollection([_sp_tenant(), _onedrive(), _exchange()])
        f, _ = PolicyEvaluator().evaluate_all(pr5_policies, assets)
        assert [x.rule_id for x in f] == [], (
            f"unexpected findings: {[x.rule_id for x in f]}"
        )

    def test_sp_open_sharing_flags(self, pr5_policies):
        assets = AssetCollection(
            [
                _sp_tenant(
                    sharing_capability_rank=3,
                    anonymous_links_disabled=False,
                    external_sharing_restricted=False,
                    external_sharing_domain_allowlist_enforced=False,
                )
            ]
        )
        f, _ = PolicyEvaluator().evaluate_all(pr5_policies, assets)
        rule_ids = {x.rule_id for x in f}
        assert {
            "m365-sharepoint-001",
            "m365-sharepoint-002",
            "m365-sharepoint-004",
        } <= rule_ids

    def test_sp_idle_off_flags(self, pr5_policies):
        assets = AssetCollection([_sp_tenant(idle_session_timeout_enabled=False)])
        f, _ = PolicyEvaluator().evaluate_all(pr5_policies, assets)
        assert any(x.rule_id == "m365-sharepoint-003" for x in f)

    def test_onedrive_open_sharing_flags(self, pr5_policies):
        assets = AssetCollection([_onedrive(sharing_capability_rank=3)])
        f, _ = PolicyEvaluator().evaluate_all(pr5_policies, assets)
        assert any(x.rule_id == "m365-onedrive-001" for x in f)

    def test_onedrive_unmanaged_sync_flags(self, pr5_policies):
        assets = AssetCollection([_onedrive(sync_to_managed_devices_only=False)])
        f, _ = PolicyEvaluator().evaluate_all(pr5_policies, assets)
        assert any(x.rule_id == "m365-onedrive-002" for x in f)

    def test_exchange_modern_auth_off_flags(self, pr5_policies):
        assets = AssetCollection([_exchange(modern_auth_enforced=False)])
        f, _ = PolicyEvaluator().evaluate_all(pr5_policies, assets)
        assert any(x.rule_id == "m365-exchange-001" for x in f)

    def test_exchange_forwarding_allowed_flags(self, pr5_policies):
        assets = AssetCollection(
            [_exchange(org_wide_mail_forwarding_allowed=True)]
        )
        f, _ = PolicyEvaluator().evaluate_all(pr5_policies, assets)
        assert any(x.rule_id == "m365-exchange-002" for x in f)

    def test_exchange_unreviewed_rules_flag(self, pr5_policies):
        assets = AssetCollection(
            [_exchange(transport_rule_count=3, transport_rules_reviewed=False)]
        )
        f, _ = PolicyEvaluator().evaluate_all(pr5_policies, assets)
        assert any(x.rule_id == "m365-exchange-003" for x in f)

    def test_exchange_audit_off_flags(self, pr5_policies):
        assets = AssetCollection([_exchange(mailbox_audit_enabled_by_default=False)])
        f, _ = PolicyEvaluator().evaluate_all(pr5_policies, assets)
        assert any(x.rule_id == "m365-exchange-004" for x in f)
