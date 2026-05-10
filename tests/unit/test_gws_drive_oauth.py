"""Unit tests for the GWS Drive-settings and OAuth-apps collectors and the
8 drive/oauth baseline policies (SaaS Posture Spec PR 2)."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from stance.collectors.gws_drive_settings import GWSDriveSettingsCollector
from stance.collectors.gws_oauth_apps import GWSOAuthAppsCollector
from stance.engine.evaluator import PolicyEvaluator
from stance.engine.loader import PolicyLoader
from stance.models import Asset, AssetCollection


REPO_ROOT = Path(__file__).resolve().parents[2]
DRIVE_DIR = REPO_ROOT / "policies" / "saas" / "google_workspace" / "drive"
OAUTH_DIR = REPO_ROOT / "policies" / "saas" / "google_workspace" / "oauth"


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #


def _paged(items_key: str, items: list[dict[str, Any]]) -> Any:
    r = MagicMock()
    req = MagicMock()
    req.execute.return_value = {items_key: items}
    r.list.return_value = req
    r.list_next.return_value = None
    return r


def _drive_service(
    policies: list[dict[str, Any]] | None = None,
    drives: list[dict[str, Any]] | None = None,
    permissions_by_drive: dict[str, list[dict[str, Any]]] | None = None,
) -> Any:
    s = MagicMock()
    s.policies.return_value = _paged("policies", policies or [])
    s.drives.return_value = _paged("drives", drives or [])

    # permissions().list(fileId=...) → page that has items keyed by fileId
    perms_resource = MagicMock()
    perms_resource.list_next.return_value = None

    def perms_list(*, fileId: str, **_kw: Any) -> Any:
        req = MagicMock()
        req.execute.return_value = {
            "permissions": (permissions_by_drive or {}).get(fileId, [])
        }
        return req

    perms_resource.list.side_effect = perms_list
    s.permissions.return_value = perms_resource
    return s


def _oauth_service(tokens_by_user: dict[str, list[dict[str, Any]]]) -> Any:
    s = MagicMock()
    tokens_resource = MagicMock()

    def tokens_list(*, userKey: str) -> Any:
        req = MagicMock()
        req.execute.return_value = {"items": tokens_by_user.get(userKey, [])}
        return req

    tokens_resource.list.side_effect = tokens_list
    s.tokens.return_value = tokens_resource
    return s


# --------------------------------------------------------------------------- #
# gws_drive_settings
# --------------------------------------------------------------------------- #


class TestGWSDriveSettingsCollector:
    def test_defaults_emit_open_posture(self):
        c = GWSDriveSettingsCollector(
            _drive_service(), tenant_id="C0", primary_domain="example.com"
        )
        assets = c.collect()
        ts = next(a for a in assets if a.resource_type == "gws_drive_settings")
        # Workspace defaults are open-by-default; the policy should fire.
        assert ts.raw_config["external_sharing_mode"] == "ON"
        assert ts.raw_config["external_sharing_restricted"] is False
        assert ts.raw_config["link_sharing_default_private"] is False
        assert ts.raw_config["trust_rules_enabled"] is False

    def test_policy_api_locks_down_sharing(self):
        policies = [
            {
                "type": "settings/drive.sharing_options",
                "setting": {"value": {"mode": "ALLOWLIST"}},
            },
            {
                "type": "settings/drive.link_sharing_defaults",
                "setting": {"value": {"defaultAccess": "DOMAIN"}},
            },
            {
                "type": "settings/drive.trust_rules_enabled",
                "setting": {"value": {"enabled": True}},
            },
        ]
        c = GWSDriveSettingsCollector(
            _drive_service(policies=policies),
            tenant_id="C0",
            primary_domain="example.com",
        )
        ts = c.collect()[0].raw_config
        assert ts["external_sharing_restricted"] is True
        assert ts["link_sharing_default_private"] is True
        assert ts["trust_rules_enabled"] is True

    def test_shared_drives_with_external_members(self):
        drives = [
            {
                "id": "d1",
                "name": "Engineering",
                "restrictions": {"domainUsersOnly": True, "driveMembersOnly": True},
            },
            {
                "id": "d2",
                "name": "Public",
                "restrictions": {"domainUsersOnly": False, "driveMembersOnly": False},
            },
        ]
        perms = {
            "d2": [
                {"emailAddress": "alice@example.com", "domain": "example.com"},
                {"emailAddress": "ext@partner.com", "domain": "partner.com"},
                {"type": "anyone"},
            ],
        }
        c = GWSDriveSettingsCollector(
            _drive_service(drives=drives, permissions_by_drive=perms),
            tenant_id="C0",
            primary_domain="example.com",
        )
        sd = [a for a in c.collect() if a.resource_type == "gws_shared_drive"]
        assert len(sd) == 2
        d2 = next(a for a in sd if a.raw_config["drive_id"] == "d2")
        assert d2.raw_config["external_member_count"] == 2  # partner.com + anyone
        assert d2.raw_config["has_external_members"] is True
        d1 = next(a for a in sd if a.raw_config["drive_id"] == "d1")
        assert d1.raw_config["domain_users_only"] is True
        assert d1.raw_config["drive_members_only"] is True


# --------------------------------------------------------------------------- #
# gws_oauth_apps
# --------------------------------------------------------------------------- #


class TestGWSOAuthAppsCollector:
    def test_aggregates_scopes_and_user_count(self):
        tokens = {
            "alice@example.com": [
                {
                    "clientId": "abc-1234",
                    "displayText": "Acme Sales",
                    "scopes": ["https://www.googleapis.com/auth/drive"],
                }
            ],
            "bob@example.com": [
                {
                    "clientId": "abc-1234",
                    "displayText": "Acme Sales",
                    "scopes": [
                        "https://www.googleapis.com/auth/drive",
                        "https://www.googleapis.com/auth/gmail.modify",
                    ],
                }
            ],
            "carol@example.com": [
                {
                    "clientId": "1234.apps.googleusercontent.com",
                    "displayText": "Google Calendar",
                    "scopes": ["https://www.googleapis.com/auth/calendar"],
                }
            ],
        }
        c = GWSOAuthAppsCollector(
            _oauth_service(tokens),
            tenant_id="C0",
            users=list(tokens.keys()),
        )
        assets = list(c.collect())
        by_id = {a.raw_config["client_id"]: a for a in assets}

        acme = by_id["abc-1234"]
        assert acme.raw_config["user_count"] == 2
        assert acme.raw_config["has_drive_full_scope"] is True
        assert acme.raw_config["has_gmail_full_scope"] is True
        assert acme.raw_config["scope_risk"] == "high"
        assert acme.raw_config["is_google_app"] is False
        assert acme.raw_config["verified"] is False

        gcal = by_id["1234.apps.googleusercontent.com"]
        assert gcal.raw_config["is_google_app"] is True
        assert gcal.raw_config["verified"] is True
        assert gcal.raw_config["scope_risk"] == "data"

    def test_trust_and_dwd_flags(self):
        tokens = {
            "alice@example.com": [
                {
                    "clientId": "trusted-1",
                    "displayText": "Trusted",
                    "scopes": ["https://www.googleapis.com/auth/drive"],
                },
                {
                    "clientId": "dwd-1",
                    "displayText": "DWD App",
                    "scopes": [
                        "https://www.googleapis.com/auth/admin.directory.user"
                    ],
                },
            ]
        }
        c = GWSOAuthAppsCollector(
            _oauth_service(tokens),
            tenant_id="C0",
            users=["alice@example.com"],
            trusted_client_ids={"trusted-1"},
            domain_wide_delegated_client_ids={"dwd-1"},
        )
        by_id = {
            a.raw_config["client_id"]: a.raw_config for a in c.collect()
        }
        assert by_id["trusted-1"]["is_trusted"] is True
        assert by_id["trusted-1"]["verified"] is True
        assert by_id["dwd-1"]["domain_wide_delegated"] is True
        assert by_id["dwd-1"]["scope_risk"] == "critical"


# --------------------------------------------------------------------------- #
# Policy load + evaluation
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def drive_oauth_policies():
    loader = PolicyLoader(policy_dirs=[str(DRIVE_DIR), str(OAUTH_DIR)])
    policies = loader.load_all()
    assert len(policies) >= 8, f"expected 8 baseline policies, got {len(policies)}"
    return policies


def _drive_settings_asset(**overrides: Any) -> Asset:
    cfg = {
        "external_sharing_mode": "ALLOWLIST",
        "link_sharing_default": "DOMAIN",
        "shared_drive_creation_allowed": False,
        "warn_on_external_sharing": True,
        "allow_publishing_to_web": False,
        "default_target_audiences": ["partners"],
        "trust_rules_enabled": True,
        "shared_drive_default_membership": "DOMAIN",
        "external_sharing_disabled": False,
        "external_sharing_restricted": True,
        "link_sharing_default_private": True,
    }
    cfg.update(overrides)
    return Asset(
        id="gws:drive_settings:C0",
        cloud_provider="google_workspace",
        account_id="C0",
        region="global",
        resource_type="gws_drive_settings",
        name="example.com",
        raw_config=cfg,
    )


def _shared_drive_asset(**overrides: Any) -> Asset:
    cfg = {
        "drive_id": "d1",
        "drive_name": "Engineering",
        "hidden": False,
        "domain_users_only": True,
        "copy_requires_writer_permission": True,
        "drive_members_only": True,
        "admin_managed_restrictions": True,
        "external_member_count": 0,
        "has_external_members": False,
    }
    cfg.update(overrides)
    return Asset(
        id=f"gws:shared_drive:{cfg['drive_id']}",
        cloud_provider="google_workspace",
        account_id="C0",
        region="global",
        resource_type="gws_shared_drive",
        name=cfg["drive_name"],
        raw_config=cfg,
    )


def _oauth_app_asset(**overrides: Any) -> Asset:
    cfg = {
        "client_id": "abc-1234",
        "display_text": "Acme Sales",
        "scopes": [],
        "scope_count": 0,
        "scope_risk": "data",
        "scope_tiers": ["data"],
        "user_count": 1,
        "users_sample": ["alice@example.com"],
        "is_google_app": False,
        "is_trusted": True,
        "verified": True,
        "domain_wide_delegated": False,
        "anonymous": False,
        "native_app": False,
        "has_drive_full_scope": False,
        "has_gmail_full_scope": False,
        "has_admin_directory_scope": False,
    }
    cfg.update(overrides)
    return Asset(
        id=f"gws:oauth_app:{cfg['client_id']}",
        cloud_provider="google_workspace",
        account_id="C0",
        region="global",
        resource_type="gws_oauth_app",
        name=cfg["display_text"],
        raw_config=cfg,
    )


class TestDriveOAuthPoliciesEndToEnd:
    def test_compliant_baseline(self, drive_oauth_policies):
        evaluator = PolicyEvaluator()
        assets = AssetCollection(
            [
                _drive_settings_asset(),
                _shared_drive_asset(),
                _oauth_app_asset(),
            ]
        )
        findings, _ = evaluator.evaluate_all(drive_oauth_policies, assets)
        assert [f.rule_id for f in findings] == [], (
            f"unexpected findings on compliant baseline: {[f.rule_id for f in findings]}"
        )

    def test_open_external_sharing_flags(self, drive_oauth_policies):
        evaluator = PolicyEvaluator()
        assets = AssetCollection(
            [_drive_settings_asset(external_sharing_restricted=False)]
        )
        f, _ = evaluator.evaluate_all(drive_oauth_policies, assets)
        assert any(x.rule_id == "gws-drive-001" for x in f)

    def test_link_sharing_anyone_flags(self, drive_oauth_policies):
        evaluator = PolicyEvaluator()
        assets = AssetCollection(
            [_drive_settings_asset(link_sharing_default_private=False)]
        )
        f, _ = evaluator.evaluate_all(drive_oauth_policies, assets)
        assert any(x.rule_id == "gws-drive-002" for x in f)

    def test_trust_rules_disabled_flags(self, drive_oauth_policies):
        evaluator = PolicyEvaluator()
        assets = AssetCollection([_drive_settings_asset(trust_rules_enabled=False)])
        f, _ = evaluator.evaluate_all(drive_oauth_policies, assets)
        assert any(x.rule_id == "gws-drive-003" for x in f)

    def test_open_shared_drive_flags(self, drive_oauth_policies):
        evaluator = PolicyEvaluator()
        bad = _shared_drive_asset(
            drive_id="d2", domain_users_only=False, drive_members_only=False
        )
        good = _shared_drive_asset(drive_id="d1")
        f, _ = evaluator.evaluate_all(
            drive_oauth_policies, AssetCollection([bad, good])
        )
        flagged = [x.asset_id for x in f if x.rule_id == "gws-drive-004"]
        assert any("d2" in a for a in flagged)
        assert not any("d1" in a for a in flagged)

    def test_unverified_drive_full_scope_flags(self, drive_oauth_policies):
        evaluator = PolicyEvaluator()
        bad = _oauth_app_asset(
            client_id="bad-1",
            verified=False,
            is_trusted=False,
            scopes=["https://www.googleapis.com/auth/drive"],
            scope_risk="high",
            has_drive_full_scope=True,
        )
        good_verified = _oauth_app_asset(
            client_id="good-1",
            verified=True,
            scopes=["https://www.googleapis.com/auth/drive"],
            scope_risk="high",
            has_drive_full_scope=True,
        )
        f, _ = evaluator.evaluate_all(
            drive_oauth_policies, AssetCollection([bad, good_verified])
        )
        flagged = [x.asset_id for x in f if x.rule_id == "gws-oauth-001"]
        assert any("bad-1" in a for a in flagged)
        assert not any("good-1" in a for a in flagged)

    def test_unverified_gmail_full_scope_flags(self, drive_oauth_policies):
        evaluator = PolicyEvaluator()
        bad = _oauth_app_asset(
            client_id="bad-2",
            verified=False,
            is_trusted=False,
            scopes=["https://mail.google.com/"],
            scope_risk="high",
            has_gmail_full_scope=True,
        )
        f, _ = evaluator.evaluate_all(drive_oauth_policies, AssetCollection([bad]))
        assert any(x.rule_id == "gws-oauth-002" for x in f)

    def test_unverified_dwd_flags_critical(self, drive_oauth_policies):
        evaluator = PolicyEvaluator()
        bad = _oauth_app_asset(
            client_id="dwd-bad",
            verified=False,
            is_trusted=False,
            domain_wide_delegated=True,
            scopes=["https://www.googleapis.com/auth/admin.directory.user"],
            scope_risk="critical",
            has_admin_directory_scope=True,
        )
        f, _ = evaluator.evaluate_all(drive_oauth_policies, AssetCollection([bad]))
        assert any(x.rule_id == "gws-oauth-003" for x in f)

    def test_high_risk_app_not_trusted_flags(self, drive_oauth_policies):
        evaluator = PolicyEvaluator()
        bad = _oauth_app_asset(
            client_id="risky",
            verified=False,
            is_trusted=False,
            is_google_app=False,
            scope_risk="high",
        )
        f, _ = evaluator.evaluate_all(drive_oauth_policies, AssetCollection([bad]))
        assert any(x.rule_id == "gws-oauth-004" for x in f)
