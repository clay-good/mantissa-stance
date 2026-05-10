"""Unit tests for the GWS remaining-surfaces collectors and 11 baseline
policies (SaaS Posture Spec PR 3): Gmail, Calendar, Chrome, Mobile, Vault,
Context-Aware Access."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from stance.collectors.gws_calendar import GWSCalendarCollector
from stance.collectors.gws_chrome import GWSChromeCollector
from stance.collectors.gws_context_aware import GWSContextAwareCollector
from stance.collectors.gws_gmail import GWSGmailCollector
from stance.collectors.gws_mobile import GWSMobileCollector
from stance.collectors.gws_vault import GWSVaultCollector
from stance.engine.evaluator import PolicyEvaluator
from stance.engine.loader import PolicyLoader
from stance.models import Asset, AssetCollection


REPO_ROOT = Path(__file__).resolve().parents[2]
GWS_BASE = REPO_ROOT / "policies" / "saas" / "google_workspace"


# --------------------------------------------------------------------------- #
# Service builders
# --------------------------------------------------------------------------- #


def _paged(items_key: str, items: list[dict[str, Any]]) -> Any:
    r = MagicMock()
    req = MagicMock()
    req.execute.return_value = {items_key: items}
    r.list.return_value = req
    r.list_next.return_value = None
    return r


def _policy_service(policies: list[dict[str, Any]] | None = None) -> Any:
    s = MagicMock()
    s.policies.return_value = _paged("policies", policies or [])
    return s


def _vault_service(rules: list[dict[str, Any]], holds_by_matter: dict[str, list[dict[str, Any]]] | None = None) -> Any:
    s = MagicMock()

    rules_resource = MagicMock()
    rules_request = MagicMock()
    rules_request.execute.return_value = {"retentionRules": rules}
    rules_resource.list.return_value = rules_request
    s.retentionRules.return_value = rules_resource

    matters_resource = MagicMock()
    matters_request = MagicMock()
    matters_request.execute.return_value = {
        "matters": [{"matterId": k} for k in (holds_by_matter or {}).keys()]
    }
    matters_resource.list.return_value = matters_request

    holds_resource = MagicMock()

    def _holds_list(*, matterId: str) -> Any:
        req = MagicMock()
        req.execute.return_value = {"holds": (holds_by_matter or {}).get(matterId, [])}
        return req

    holds_resource.list.side_effect = _holds_list
    matters_resource.holds.return_value = holds_resource
    s.matters.return_value = matters_resource
    return s


def _caa_service(
    levels: list[dict[str, Any]] | None = None,
    bindings: list[dict[str, Any]] | None = None,
) -> Any:
    s = MagicMock()
    s.accessLevels.return_value = _paged("accessLevels", levels or [])
    s.accessLevelBindings.return_value = _paged(
        "accessLevelBindings", bindings or []
    )
    return s


# --------------------------------------------------------------------------- #
# Collector smoke tests
# --------------------------------------------------------------------------- #


class TestSurfaceCollectorsSmoke:
    def test_gmail_defaults_open(self):
        cfg = GWSGmailCollector(_policy_service(), tenant_id="C0").collect()[0].raw_config
        assert cfg["attachment_compliance_enabled"] is False
        assert cfg["org_wide_forwarding_allowed"] is True
        assert cfg["smime_or_confidential_mode_enabled"] is True  # confidential default

    def test_gmail_lockdown_via_policy_api(self):
        policies = [
            {"type": "settings/gmail.attachment_compliance", "setting": {"value": {"enabled": True}}},
            {"type": "settings/gmail.external_recipient_warning", "setting": {"value": {"enabled": True}}},
            {"type": "settings/gmail.org_wide_forwarding", "setting": {"value": {"allowed": False}}},
            {"type": "settings/gmail.smime", "setting": {"value": {"enabled": True}}},
        ]
        cfg = GWSGmailCollector(_policy_service(policies), tenant_id="C0").collect()[0].raw_config
        assert cfg["attachment_compliance_enabled"] is True
        assert cfg["external_recipient_warning_enabled"] is True
        assert cfg["org_wide_forwarding_allowed"] is False
        assert cfg["smime_or_confidential_mode_enabled"] is True

    def test_calendar_default_is_open(self):
        cfg = GWSCalendarCollector(_policy_service(), tenant_id="C0").collect()[0].raw_config
        assert cfg["external_sharing_default"] == "READ_WRITE"
        assert cfg["external_sharing_restricted"] is False

    def test_chrome_allowlist_only_via_policy(self):
        policies = [
            {"type": "settings/chrome.enterprise_enrollment", "setting": {"value": {"enforced": True}}},
            {"type": "settings/chrome.extension_install_mode", "setting": {"value": {"mode": "ALLOWLIST"}}},
            {"type": "settings/chrome.safe_browsing", "setting": {"value": {"mode": "ENHANCED"}}},
        ]
        cfg = GWSChromeCollector(_policy_service(policies), tenant_id="C0").collect()[0].raw_config
        assert cfg["enterprise_policies_enforced"] is True
        assert cfg["extension_allowlist_only"] is True
        assert cfg["safe_browsing_enforced"] is True

    def test_mobile_advanced_required_derivation(self):
        policies = [
            {"type": "settings/mobile.management_mode", "setting": {"value": {"mode": "ADVANCED"}}},
            {"type": "settings/mobile.screen_lock_required", "setting": {"value": {"required": True}}},
        ]
        cfg = GWSMobileCollector(_policy_service(policies), tenant_id="C0").collect()[0].raw_config
        assert cfg["advanced_management_required"] is True
        assert cfg["screen_lock_required"] is True

    def test_vault_core_service_coverage(self):
        rules = [
            {"corpus": "MAIL"},
            {"corpus": "DRIVE"},
            {"corpus": "GROUPS"},
            {"corpus": "HANGOUTS_CHAT"},
            {"corpus": "VOICE"},
            {"corpus": "CALENDAR"},
        ]
        cfg = (
            GWSVaultCollector(_vault_service(rules), tenant_id="C0")
            .collect()[0]
            .raw_config
        )
        assert cfg["all_core_services_covered"] is True
        assert cfg["core_services_missing"] == []
        assert cfg["retention_rule_count"] == 6

    def test_vault_partial_coverage(self):
        rules = [{"corpus": "MAIL"}, {"corpus": "DRIVE"}]
        cfg = (
            GWSVaultCollector(_vault_service(rules), tenant_id="C0")
            .collect()[0]
            .raw_config
        )
        assert cfg["all_core_services_covered"] is False
        assert "GROUPS" in cfg["core_services_missing"]

    def test_caa_summary_admin_binding(self):
        levels = [{"name": "accessLevels/al-1", "title": "corp-and-managed"}]
        bindings = [
            {
                "name": "alb-1",
                "accessLevel": "accessLevels/al-1",
                "roleName": "_SEED_ADMIN_ROLE",
            },
            {
                "name": "alb-2",
                "accessLevel": "accessLevels/al-1",
                "roleName": "Help Desk Admin",
            },
            {
                "name": "alb-3",
                "accessLevel": "accessLevels/al-1",
                "roleName": "Sales Reader",
            },
        ]
        assets = list(GWSContextAwareCollector(
            _caa_service(levels, bindings), tenant_id="C0"
        ).collect())
        summary = next(a for a in assets if a.resource_type == "gws_caa_summary")
        assert summary.raw_config["any_admin_role_bound"] is True
        assert summary.raw_config["admin_role_binding_count"] == 2  # both contain "admin"

    def test_caa_summary_no_admin_binding(self):
        bindings = [
            {"name": "alb-1", "accessLevel": "al-1", "roleName": "Sales Reader"}
        ]
        assets = list(GWSContextAwareCollector(
            _caa_service([], bindings), tenant_id="C0"
        ).collect())
        summary = next(a for a in assets if a.resource_type == "gws_caa_summary")
        assert summary.raw_config["any_admin_role_bound"] is False


# --------------------------------------------------------------------------- #
# Policy load + evaluate
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def pr3_policies():
    dirs = [
        str(GWS_BASE / "gmail"),
        str(GWS_BASE / "chrome"),
        str(GWS_BASE / "mobile"),
        str(GWS_BASE / "context-aware"),
        str(GWS_BASE / "vault"),
    ]
    loader = PolicyLoader(policy_dirs=dirs)
    policies = loader.load_all()
    assert len(policies) >= 11, (
        f"expected 11 PR3 baseline policies, got {len(policies)}"
    )
    return policies


def _gmail_asset(**o: Any) -> Asset:
    cfg = {
        "attachment_compliance_enabled": True,
        "content_compliance_enabled": True,
        "smime_enabled": False,
        "confidential_mode_enabled": True,
        "external_recipient_warning_enabled": True,
        "org_wide_forwarding_allowed": False,
        "allowlist_required": True,
        "spam_filter_enabled": True,
        "smime_or_confidential_mode_enabled": True,
    }
    cfg.update(o)
    return Asset(
        id="gws:gmail_settings:C0",
        cloud_provider="google_workspace",
        account_id="C0",
        region="global",
        resource_type="gws_gmail_settings",
        name="example.com",
        raw_config=cfg,
    )


def _chrome_asset(**o: Any) -> Asset:
    cfg = {
        "enterprise_policies_enforced": True,
        "extension_install_mode": "ALLOWLIST",
        "extension_allowlist": ["abcd"],
        "safe_browsing_mode": "ENHANCED",
        "password_manager_enforced": True,
        "force_install_count": 1,
        "extension_allowlist_only": True,
        "safe_browsing_enforced": True,
    }
    cfg.update(o)
    return Asset(
        id="gws:chrome_policy:C0",
        cloud_provider="google_workspace",
        account_id="C0",
        region="global",
        resource_type="gws_chrome_policy",
        name="example.com",
        raw_config=cfg,
    )


def _mobile_asset(**o: Any) -> Asset:
    cfg = {
        "management_mode": "ADVANCED",
        "screen_lock_required": True,
        "encryption_required": True,
        "device_approval_required": True,
        "allow_personal_devices": False,
        "advanced_management_required": True,
    }
    cfg.update(o)
    return Asset(
        id="gws:mobile_settings:C0",
        cloud_provider="google_workspace",
        account_id="C0",
        region="global",
        resource_type="gws_mobile_settings",
        name="example.com",
        raw_config=cfg,
    )


def _vault_asset(**o: Any) -> Asset:
    cfg = {
        "retention_rule_count": 6,
        "legal_hold_count": 0,
        "services_covered": ["MAIL", "DRIVE", "GROUPS", "HANGOUTS_CHAT", "VOICE", "CALENDAR"],
        "core_services_covered": ["MAIL", "DRIVE", "GROUPS", "HANGOUTS_CHAT", "VOICE", "CALENDAR"],
        "core_services_missing": [],
        "all_core_services_covered": True,
    }
    cfg.update(o)
    return Asset(
        id="gws:vault_retention:C0",
        cloud_provider="google_workspace",
        account_id="C0",
        region="global",
        resource_type="gws_vault_retention",
        name="example.com",
        raw_config=cfg,
    )


def _caa_summary(**o: Any) -> Asset:
    cfg = {
        "access_level_count": 1,
        "binding_count": 1,
        "admin_role_binding_count": 1,
        "admin_roles_with_caa": ["_SEED_ADMIN_ROLE"],
        "any_admin_role_bound": True,
    }
    cfg.update(o)
    return Asset(
        id="gws:caa_summary:C0",
        cloud_provider="google_workspace",
        account_id="C0",
        region="global",
        resource_type="gws_caa_summary",
        name="context-aware-access",
        raw_config=cfg,
    )


class TestPR3PoliciesEndToEnd:
    def test_compliant_baseline_no_findings(self, pr3_policies):
        assets = AssetCollection(
            [_gmail_asset(), _chrome_asset(), _mobile_asset(), _vault_asset(), _caa_summary()]
        )
        f, _ = PolicyEvaluator().evaluate_all(pr3_policies, assets)
        assert [x.rule_id for x in f] == [], (
            f"unexpected findings: {[x.rule_id for x in f]}"
        )

    def test_gmail_failures(self, pr3_policies):
        assets = AssetCollection(
            [
                _gmail_asset(
                    attachment_compliance_enabled=False,
                    external_recipient_warning_enabled=False,
                    org_wide_forwarding_allowed=True,
                    smime_or_confidential_mode_enabled=False,
                )
            ]
        )
        f, _ = PolicyEvaluator().evaluate_all(pr3_policies, assets)
        rule_ids = {x.rule_id for x in f}
        assert {"gws-gmail-001", "gws-gmail-002", "gws-gmail-003", "gws-gmail-004"} <= rule_ids

    def test_chrome_failures(self, pr3_policies):
        assets = AssetCollection(
            [
                _chrome_asset(
                    enterprise_policies_enforced=False,
                    extension_allowlist_only=False,
                    safe_browsing_enforced=False,
                )
            ]
        )
        f, _ = PolicyEvaluator().evaluate_all(pr3_policies, assets)
        rule_ids = {x.rule_id for x in f}
        assert {"gws-chrome-001", "gws-chrome-002", "gws-chrome-003"} <= rule_ids

    def test_mobile_failures(self, pr3_policies):
        assets = AssetCollection(
            [
                _mobile_asset(
                    advanced_management_required=False, screen_lock_required=False
                )
            ]
        )
        f, _ = PolicyEvaluator().evaluate_all(pr3_policies, assets)
        rule_ids = {x.rule_id for x in f}
        assert {"gws-mobile-001", "gws-mobile-002"} <= rule_ids

    def test_caa_no_admin_binding_flags(self, pr3_policies):
        assets = AssetCollection([_caa_summary(any_admin_role_bound=False)])
        f, _ = PolicyEvaluator().evaluate_all(pr3_policies, assets)
        assert any(x.rule_id == "gws-caa-001" for x in f)

    def test_vault_partial_coverage_flags(self, pr3_policies):
        assets = AssetCollection(
            [
                _vault_asset(
                    all_core_services_covered=False,
                    core_services_missing=["GROUPS", "VOICE"],
                )
            ]
        )
        f, _ = PolicyEvaluator().evaluate_all(pr3_policies, assets)
        assert any(x.rule_id == "gws-vault-001" for x in f)
