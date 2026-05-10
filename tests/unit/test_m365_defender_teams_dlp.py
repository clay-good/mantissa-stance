"""Unit tests for the M365 Defender / Teams / Intune / DLP / Labels /
Secure-Score / Power-Platform collectors and the 10 PR-6 baseline policies.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from stance.collectors.m365_defender import M365DefenderCollector
from stance.collectors.m365_dlp_policies import M365DLPPoliciesCollector
from stance.collectors.m365_intune_compliance import (
    M365IntuneComplianceCollector,
)
from stance.collectors.m365_power_platform import M365PowerPlatformCollector
from stance.collectors.m365_secure_score import M365SecureScoreCollector
from stance.collectors.m365_sensitivity_labels import (
    M365SensitivityLabelsCollector,
)
from stance.collectors.m365_teams import M365TeamsCollector
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


class TestDefender:
    def test_summary_no_defender(self):
        graph = make_graph({})
        cfg = (
            M365DefenderCollector(graph, "t1")
            .collect()
            .assets[-1]
            .raw_config
        )
        assert cfg["any_safe_links_policy_enabled"] is False
        assert cfg["any_anti_phish_strict_policy_enabled"] is False

    def test_summary_strict_anti_phish(self):
        graph = make_graph(
            {
                "/beta/security/threatProtection/safeLinksPolicies": {
                    "value": [{"id": "sl-1", "isEnabled": True}]
                },
                "/beta/security/threatProtection/safeAttachmentsPolicies": {
                    "value": [{"id": "sa-1", "isEnabled": True}]
                },
                "/beta/security/threatProtection/antiPhishingPolicies": {
                    "value": [
                        {
                            "id": "ap-1",
                            "isEnabled": True,
                            "name": "Strict Anti-Phish",
                            "preset": "Strict",
                        }
                    ]
                },
            }
        )
        cfg = next(
            a.raw_config
            for a in M365DefenderCollector(graph, "t1").collect()
            if a.resource_type == "defender_policy_summary"
        )
        assert cfg["any_anti_phish_strict_policy_enabled"] is True


class TestTeams:
    def test_open_defaults(self):
        cfg = (
            M365TeamsCollector(make_graph({}), "t1")
            .collect()[0]
            .raw_config
        )
        # Defaults: federation open, guest allowed.
        assert cfg["external_access_restricted"] is False
        assert cfg["guest_access_controlled"] is False
        assert cfg["app_permission_policy_enforced"] is False

    def test_locked_down(self):
        graph = make_graph(
            {
                "/beta/admin/teams/federationConfiguration": {
                    "allowFederatedUsers": True,
                    "federationMode": "allowlist",
                    "allowedDomains": ["partner.com"],
                },
                "/beta/admin/teams/guestAccessConfiguration": {
                    "allowGuestUser": True,
                    "allowMakePrivateCalls": False,
                    "allowMeetNow": False,
                },
                "/beta/admin/teams/appSetupPolicy": {
                    "defaultPolicy": "AllowSpecificApps"
                },
            }
        )
        cfg = M365TeamsCollector(graph, "t1").collect()[0].raw_config
        assert cfg["external_access_restricted"] is True
        assert cfg["guest_access_controlled"] is True
        assert cfg["app_permission_policy_enforced"] is True


class TestIntune:
    def test_corporate_platforms_missing(self):
        graph = make_graph(
            {
                "/v1.0/deviceManagement/deviceCompliancePolicies": {
                    "value": [
                        {
                            "id": "p-win",
                            "displayName": "Windows baseline",
                            "@odata.type": "#microsoft.graph.windows10CompliancePolicy",
                        }
                    ]
                },
                "/v1.0/deviceManagement/deviceCompliancePolicies/p-win/assignments": {
                    "value": [{"id": "asg-1"}]
                },
            }
        )
        assets = list(M365IntuneComplianceCollector(graph, "t1").collect())
        summary = next(
            a for a in assets if a.resource_type == "intune_compliance_summary"
        )
        assert "iOS" in summary.raw_config["corporate_platforms_missing_policy"]
        assert "windows10" in summary.raw_config["platforms_with_assigned_policy"]
        assert summary.raw_config["all_corporate_platforms_covered"] is False


class TestDLP:
    def test_enabled_with_sensitive(self):
        graph = make_graph(
            {
                "/beta/security/dataLossPreventionPolicies": {
                    "value": [
                        {
                            "id": "dlp-1",
                            "name": "PII protection",
                            "mode": "Enable",
                            "rules": [
                                {
                                    "conditions": [
                                        {
                                            "sensitiveInformationTypes": [
                                                {"name": "Credit card number"}
                                            ]
                                        }
                                    ]
                                }
                            ],
                        }
                    ]
                }
            }
        )
        summary = next(
            a.raw_config
            for a in M365DLPPoliciesCollector(graph, "t1").collect()
            if a.resource_type == "m365_dlp_summary"
        )
        assert summary["any_enabled_policy_covers_sensitive_info"] is True


class TestLabels:
    def test_labels_published_with_mandatory(self):
        graph = make_graph(
            {
                "/v1.0/security/informationProtection/sensitivityLabels": {
                    "value": [
                        {"id": "lbl-1", "displayName": "Confidential", "isActive": True},
                    ]
                },
                "/beta/security/informationProtection/labelPolicy": {
                    "mandatoryLabelingEnabled": True,
                    "defaultLabelId": "lbl-1",
                },
            }
        )
        summary = next(
            a.raw_config
            for a in M365SensitivityLabelsCollector(graph, "t1").collect()
            if a.resource_type == "m365_label_policy_summary"
        )
        assert summary["any_label_published"] is True
        assert summary["mandatory_labeling_enabled"] is True


class TestSecureScore:
    def test_score_percentage(self):
        graph = make_graph(
            {
                "/v1.0/security/secureScores": {
                    "value": [
                        {"currentScore": 75, "maxScore": 100, "activeUserCount": 50}
                    ]
                }
            }
        )
        cfg = M365SecureScoreCollector(graph, "t1").collect()[0].raw_config
        assert cfg["score_percentage"] == 75.0


class TestPowerPlatform:
    def test_tenant_default_dlp(self):
        graph = make_graph(
            {
                "/providers/PowerPlatform.Governance/v1/policies": {
                    "value": [
                        {
                            "name": "tenant-default",
                            "displayName": "Tenant default",
                            "environmentType": "AllEnvironments",
                            "connectorGroups": {
                                "Confidential": [{"name": "sql"}],
                                "General": [{"name": "twitter"}],
                                "Blocked": [{"name": "http"}],
                            },
                        }
                    ]
                }
            }
        )
        assets = list(M365PowerPlatformCollector(graph, "t1").collect())
        summary = next(
            a for a in assets if a.resource_type == "power_platform_dlp_summary"
        )
        assert summary.raw_config["any_tenant_default_policy"] is True


# --------------------------------------------------------------------------- #
# Policy load + evaluate
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def pr6_policies():
    dirs = [
        str(M365_BASE / "defender"),
        str(M365_BASE / "teams"),
        str(M365_BASE / "dlp"),
        str(M365_BASE / "info-protection"),
        str(M365_BASE / "intune"),
    ]
    loader = PolicyLoader(policy_dirs=dirs)
    policies = loader.load_all()
    assert len(policies) >= 10, (
        f"expected 10 PR6 policies, got {len(policies)}"
    )
    return policies


def _defender(**o: Any) -> Asset:
    cfg = {
        "safe_links_policy_count": 1,
        "safe_attachments_policy_count": 1,
        "anti_phish_policy_count": 1,
        "any_safe_links_policy_enabled": True,
        "any_safe_attachments_policy_enabled": True,
        "any_anti_phish_policy_enabled": True,
        "any_anti_phish_strict_policy_enabled": True,
    }
    cfg.update(o)
    return Asset(
        id="defender:summary:t1",
        cloud_provider="microsoft_365",
        account_id="t1",
        region="global",
        resource_type="defender_policy_summary",
        name="def",
        raw_config=cfg,
    )


def _teams(**o: Any) -> Asset:
    cfg = {
        "external_access_enabled": True,
        "external_access_restricted": True,
        "federation_mode": "allowlist",
        "allowed_domains": ["p.com"],
        "blocked_domains": [],
        "allow_teams_consumer": False,
        "allow_skype_users": True,
        "guest_access_enabled": True,
        "guest_can_make_calls": False,
        "guest_can_share_screen": True,
        "guest_can_meet_now": False,
        "guest_access_controlled": True,
        "app_permission_policy_default": "AllowSpecificApps",
        "app_permission_policy_enforced": True,
        "anonymous_join_allowed": False,
    }
    cfg.update(o)
    return Asset(
        id="teams:settings:t1",
        cloud_provider="microsoft_365",
        account_id="t1",
        region="global",
        resource_type="teams_settings",
        name="teams",
        raw_config=cfg,
    )


def _dlp_summary(**o: Any) -> Asset:
    cfg = {
        "policy_count": 1,
        "enabled_policy_count": 1,
        "any_enabled_policy_covers_sensitive_info": True,
    }
    cfg.update(o)
    return Asset(
        id="m365:dlp_summary:t1",
        cloud_provider="microsoft_365",
        account_id="t1",
        region="global",
        resource_type="m365_dlp_summary",
        name="dlp",
        raw_config=cfg,
    )


def _label_summary(**o: Any) -> Asset:
    cfg = {
        "label_count": 1,
        "active_label_count": 1,
        "any_label_published": True,
        "mandatory_labeling_enabled": True,
        "default_label_id": "lbl-1",
        "downgrade_justification_required": True,
    }
    cfg.update(o)
    return Asset(
        id="m365:label_policy_summary:t1",
        cloud_provider="microsoft_365",
        account_id="t1",
        region="global",
        resource_type="m365_label_policy_summary",
        name="lp",
        raw_config=cfg,
    )


def _intune(**o: Any) -> Asset:
    cfg = {
        "policy_count": 4,
        "assigned_policy_count": 4,
        "platforms_with_assigned_policy": [
            "androidWorkProfile",
            "iOS",
            "macOS",
            "windows10",
        ],
        "corporate_platforms_missing_policy": [],
        "all_corporate_platforms_covered": True,
    }
    cfg.update(o)
    return Asset(
        id="intune:compliance_summary:t1",
        cloud_provider="microsoft_365",
        account_id="t1",
        region="global",
        resource_type="intune_compliance_summary",
        name="intune",
        raw_config=cfg,
    )


class TestPR6PoliciesEndToEnd:
    def test_compliant_baseline(self, pr6_policies):
        assets = AssetCollection(
            [_defender(), _teams(), _dlp_summary(), _label_summary(), _intune()]
        )
        f, _ = PolicyEvaluator().evaluate_all(pr6_policies, assets)
        assert [x.rule_id for x in f] == [], (
            f"unexpected findings: {[x.rule_id for x in f]}"
        )

    def test_defender_failures(self, pr6_policies):
        assets = AssetCollection(
            [
                _defender(
                    any_safe_links_policy_enabled=False,
                    any_safe_attachments_policy_enabled=False,
                    any_anti_phish_strict_policy_enabled=False,
                )
            ]
        )
        f, _ = PolicyEvaluator().evaluate_all(pr6_policies, assets)
        rule_ids = {x.rule_id for x in f}
        assert {
            "m365-defender-001",
            "m365-defender-002",
            "m365-defender-003",
        } <= rule_ids

    def test_teams_failures(self, pr6_policies):
        assets = AssetCollection(
            [
                _teams(
                    external_access_restricted=False,
                    guest_access_controlled=False,
                    app_permission_policy_enforced=False,
                )
            ]
        )
        f, _ = PolicyEvaluator().evaluate_all(pr6_policies, assets)
        rule_ids = {x.rule_id for x in f}
        assert {
            "m365-teams-001",
            "m365-teams-002",
            "m365-teams-003",
        } <= rule_ids

    def test_dlp_no_sensitive_flags(self, pr6_policies):
        assets = AssetCollection(
            [_dlp_summary(any_enabled_policy_covers_sensitive_info=False)]
        )
        f, _ = PolicyEvaluator().evaluate_all(pr6_policies, assets)
        assert any(x.rule_id == "m365-dlp-001" for x in f)

    def test_no_labels_flags(self, pr6_policies):
        assets = AssetCollection(
            [_label_summary(any_label_published=False, mandatory_labeling_enabled=False)]
        )
        f, _ = PolicyEvaluator().evaluate_all(pr6_policies, assets)
        rule_ids = {x.rule_id for x in f}
        assert {"m365-info-001", "m365-info-002"} <= rule_ids

    def test_intune_missing_platform_flags(self, pr6_policies):
        assets = AssetCollection(
            [
                _intune(
                    all_corporate_platforms_covered=False,
                    corporate_platforms_missing_policy=["iOS"],
                )
            ]
        )
        f, _ = PolicyEvaluator().evaluate_all(pr6_policies, assets)
        assert any(x.rule_id == "m365-intune-001" for x in f)
