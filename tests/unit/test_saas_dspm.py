"""Unit tests for the SaaS DSPM scanners (PR 8): SharePoint, OneDrive,
Exchange. Plus the exposure-score helper, the finding→asset adapter, and
end-to-end evaluation of the two ``policies/saas/dspm/*.yaml`` rules."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from stance.cspm.cis_benchmark import BenchmarkType
from stance.dspm.classifier import ClassificationLevel
from stance.dspm.extended._finding_to_asset import finding_to_asset
from stance.dspm.extended._saas_exposure import (
    compute_exposure_score,
    severity_band,
)
from stance.dspm.extended.base import (
    ExtendedScanConfig,
    ExtendedSourceType,
)
from stance.dspm.extended.m365_exchange import M365ExchangeDSPMScanner
from stance.dspm.extended.m365_onedrive import M365OneDriveDSPMScanner
from stance.dspm.extended.m365_sharepoint import M365SharePointDSPMScanner
from stance.engine.evaluator import PolicyEvaluator
from stance.engine.loader import PolicyLoader
from stance.models import Asset, AssetCollection


REPO_ROOT = Path(__file__).resolve().parents[2]
DSPM_POLICY_DIR = REPO_ROOT / "policies" / "saas" / "dspm"


# A document obviously sensitive to the existing detector — the detector
# matches credit-card patterns out of the box.
_PII_DOC = (
    "Customer record:\n"
    "Name: Jane Doe\n"
    "Email: jane.doe@example.com\n"
    "Card number: 4111-1111-1111-1111\n"
    "SSN: 123-45-6789\n"
)


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
# Exposure score helper
# --------------------------------------------------------------------------- #


class TestExposureScore:
    def test_public_data_is_zero(self):
        assert (
            compute_exposure_score(
                ClassificationLevel.PUBLIC,
                has_external_sharing=True,
                external_user_count=100,
                link_type="anyone",
                total_user_count=100,
            )
            == 0.0
        )

    def test_restricted_anyone_link_high(self):
        score = compute_exposure_score(
            ClassificationLevel.RESTRICTED,
            has_external_sharing=True,
            external_user_count=20,
            link_type="anyone",
            total_user_count=50,
        )
        assert 40.0 <= score <= 100.0
        assert severity_band(score) in ("medium", "high", "critical")

    def test_internal_only_low(self):
        score = compute_exposure_score(
            ClassificationLevel.INTERNAL,
            has_external_sharing=False,
            external_user_count=0,
            link_type="private",
            total_user_count=2,
        )
        assert score < 25.0
        assert severity_band(score) in ("info", "low")

    def test_severity_band_thresholds(self):
        assert severity_band(0.0) == "info"
        assert severity_band(24.99) == "low"
        assert severity_band(25.0) == "medium"
        assert severity_band(50.0) == "high"
        assert severity_band(75.0) == "critical"


# --------------------------------------------------------------------------- #
# SharePoint scanner
# --------------------------------------------------------------------------- #


class TestSharePointScanner:
    def test_sensitive_file_emits_finding(self):
        graph = make_graph(
            {
                "/v1.0/sites/site-1": {
                    "id": "site-1",
                    "displayName": "HR",
                    "webUrl": "https://contoso.sharepoint.com/sites/HR",
                },
                "/v1.0/admin/sharepoint/sites/site-1": {
                    "sharingCapability": "externalUserAndGuestSharing",
                    "externalUserCount": 5,
                    "defaultSharingLinkType": "anyone",
                },
                "/v1.0/sites/site-1/drive/root/children": {
                    "value": [
                        {
                            "id": "item-1",
                            "name": "secrets.txt",
                            "size": 100,
                            "file": {},
                            "permissions": [
                                {"link": {"scope": "anonymous"}}
                            ],
                        }
                    ]
                },
            }
        )

        def loader(site_id: str, item_id: str) -> str:
            return _PII_DOC

        scanner = M365SharePointDSPMScanner(
            graph,
            tenant_id="t1",
            primary_domain="contoso.com",
            content_loader=loader,
            scan_config=ExtendedScanConfig(sample_size=10),
        )
        result = scanner.scan("site-1")
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.source_type == ExtendedSourceType.M365_SHAREPOINT
        assert f.metadata["exposure_score"] > 0
        assert f.metadata["site_external_user_count"] == 5
        # Anonymous link → exposure should be in the "high" band.
        assert f.metadata["item_link_type"] == "anonymous"

    def test_clean_file_no_finding(self):
        graph = make_graph(
            {
                "/v1.0/sites/site-1": {"id": "site-1", "webUrl": "https://x"},
                "/v1.0/admin/sharepoint/sites/site-1": {},
                "/v1.0/sites/site-1/drive/root/children": {
                    "value": [
                        {
                            "id": "item-2",
                            "name": "harmless.txt",
                            "file": {},
                            "permissions": [],
                        }
                    ]
                },
            }
        )
        scanner = M365SharePointDSPMScanner(
            graph,
            tenant_id="t1",
            content_loader=lambda *_: "Hello world. Nothing sensitive.",
            scan_config=ExtendedScanConfig(sample_size=5),
        )
        result = scanner.scan("site-1")
        assert result.findings == []
        assert result.summary.total_objects_scanned == 1


# --------------------------------------------------------------------------- #
# OneDrive scanner
# --------------------------------------------------------------------------- #


class TestOneDriveScanner:
    def test_external_share_pushes_score(self):
        graph = make_graph(
            {
                "/v1.0/users/u1": {
                    "id": "u1",
                    "userPrincipalName": "alice@contoso.com",
                    "accountEnabled": True,
                },
                "/v1.0/users/u1/drive/root/children": {
                    "value": [
                        {
                            "id": "od-1",
                            "name": "leaks.txt",
                            "file": {},
                            "permissions": [
                                {"link": {"scope": "anyone"}},
                                {
                                    "grantedToIdentitiesV2": [
                                        {"user": {"email": "ext@partner.com"}}
                                    ]
                                },
                            ],
                        }
                    ]
                },
            }
        )

        scanner = M365OneDriveDSPMScanner(
            graph,
            tenant_id="t1",
            primary_domain="contoso.com",
            content_loader=lambda *_: _PII_DOC,
            scan_config=ExtendedScanConfig(sample_size=5),
        )
        result = scanner.scan("u1")
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.metadata["external_perm_count"] >= 1
        assert f.metadata["item_link_type"] == "anyone"


# --------------------------------------------------------------------------- #
# Exchange scanner
# --------------------------------------------------------------------------- #


class TestExchangeScanner:
    def test_external_recipient_lifts_score(self):
        graph = make_graph(
            {
                "/v1.0/users/u1": {
                    "id": "u1",
                    "userPrincipalName": "alice@contoso.com",
                },
                "/v1.0/users/u1/messages": {
                    "value": [
                        {
                            "id": "m-1",
                            "subject": "Customer details",
                            "body": {"content": _PII_DOC},
                            "toRecipients": [
                                {"emailAddress": {"address": "bob@contoso.com"}},
                                {"emailAddress": {"address": "client@partner.com"}},
                            ],
                        }
                    ]
                },
            }
        )
        scanner = M365ExchangeDSPMScanner(
            graph,
            tenant_id="t1",
            primary_domain="contoso.com",
            scan_config=ExtendedScanConfig(sample_size=5),
            mailbox_sample=5,
        )
        result = scanner.scan("u1")
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.metadata["external_recipient_count"] == 1
        assert f.metadata["exposure_score"] > 0


# --------------------------------------------------------------------------- #
# CIS benchmark enum
# --------------------------------------------------------------------------- #


class TestCISBenchmarkEnum:
    def test_saas_benchmarks_present(self):
        assert (
            BenchmarkType.GOOGLE_WORKSPACE_FOUNDATIONS.value
            == "cis-google-workspace-foundations"
        )
        assert (
            BenchmarkType.MICROSOFT_365_FOUNDATIONS.value
            == "cis-microsoft-365-foundations"
        )

    def test_policy_framework_strings_match_enum(self):
        # Sample a few policies that reference the new framework strings.
        sample = [
            REPO_ROOT
            / "policies/saas/google_workspace/auth/enforce-2sv-org-wide.yaml",
            REPO_ROOT
            / "policies/saas/microsoft_365/entra/ca-block-legacy-auth.yaml",
            REPO_ROOT / "policies/saas/dspm/no-pii-in-anyone-with-link-files.yaml",
        ]
        for path in sample:
            text = path.read_text()
            assert BenchmarkType.GOOGLE_WORKSPACE_FOUNDATIONS.value in text or (
                BenchmarkType.MICROSOFT_365_FOUNDATIONS.value in text
            )


# --------------------------------------------------------------------------- #
# DSPM policies end-to-end
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def dspm_policies():
    loader = PolicyLoader(policy_dirs=[str(DSPM_POLICY_DIR)])
    policies = loader.load_all()
    assert len(policies) >= 2, f"expected 2 dspm policies, got {len(policies)}"
    return policies


def _dspm_finding_asset(**overrides: Any) -> Asset:
    cfg = {
        "finding_id": "f-1",
        "source_type": "m365_sharepoint",
        "source_location": "https://contoso/x.txt",
        "object_type": "file",
        "object_name": "x.txt",
        "classification": "internal",
        "categories": [],
        "has_pii": False,
        "has_pci": False,
        "has_phi": False,
        "link_type": "specific_people",
        "has_anyone_with_link": False,
        "has_external_sharing": False,
        "external_user_count": 0,
        "exposure_score": 5.0,
        "severity_band": "low",
    }
    cfg.update(overrides)
    return Asset(
        id=f"dspm:finding:{cfg['finding_id']}",
        cloud_provider="microsoft_365",
        account_id="t1",
        region="global",
        resource_type="dspm_finding",
        name=cfg["object_name"],
        raw_config=cfg,
    )


class TestDSPMPoliciesEndToEnd:
    def test_compliant_baseline(self, dspm_policies):
        asset = _dspm_finding_asset()
        f, _ = PolicyEvaluator().evaluate_all(
            dspm_policies, AssetCollection([asset])
        )
        assert [x.rule_id for x in f] == []

    def test_pii_with_anyone_link_flagged(self, dspm_policies):
        asset = _dspm_finding_asset(
            finding_id="f-pii",
            classification="restricted",
            categories=["pii_ssn"],
            has_pii=True,
            link_type="anyone",
            has_anyone_with_link=True,
            has_external_sharing=True,
            external_user_count=20,
            exposure_score=88.0,
            severity_band="critical",
        )
        f, _ = PolicyEvaluator().evaluate_all(
            dspm_policies, AssetCollection([asset])
        )
        rule_ids = {x.rule_id for x in f}
        assert "saas-dspm-001" in rule_ids
        assert "saas-dspm-002" in rule_ids

    def test_internal_external_share_allowed(self, dspm_policies):
        asset = _dspm_finding_asset(
            classification="internal",
            has_external_sharing=True,
            external_user_count=3,
        )
        f, _ = PolicyEvaluator().evaluate_all(
            dspm_policies, AssetCollection([asset])
        )
        # Only saas-dspm-001 (PII rule) and saas-dspm-002 should not fire.
        assert all(x.rule_id != "saas-dspm-002" for x in f)

    def test_confidential_external_share_flagged(self, dspm_policies):
        asset = _dspm_finding_asset(
            classification="confidential",
            has_external_sharing=True,
            external_user_count=4,
        )
        f, _ = PolicyEvaluator().evaluate_all(
            dspm_policies, AssetCollection([asset])
        )
        assert any(x.rule_id == "saas-dspm-002" for x in f)


# --------------------------------------------------------------------------- #
# finding_to_asset adapter
# --------------------------------------------------------------------------- #


class TestFindingToAsset:
    def test_adapter_round_trip(self):
        # Build a real finding via the SharePoint scanner, convert it.
        graph = make_graph(
            {
                "/v1.0/sites/s1": {"id": "s1", "webUrl": "https://x"},
                "/v1.0/admin/sharepoint/sites/s1": {
                    "sharingCapability": "externalUserAndGuestSharing",
                    "externalUserCount": 3,
                    "defaultSharingLinkType": "anyone",
                },
                "/v1.0/sites/s1/drive/root/children": {
                    "value": [
                        {
                            "id": "i1",
                            "name": "leak.txt",
                            "file": {},
                            "permissions": [{"link": {"scope": "anonymous"}}],
                        }
                    ]
                },
            }
        )
        scanner = M365SharePointDSPMScanner(
            graph,
            tenant_id="t1",
            content_loader=lambda *_: _PII_DOC,
            scan_config=ExtendedScanConfig(sample_size=5),
        )
        result = scanner.scan("s1")
        assert result.findings
        asset = finding_to_asset(result.findings[0], tenant_id="t1")
        assert asset.resource_type == "dspm_finding"
        cfg = asset.raw_config
        assert cfg["has_pii"] is True or cfg["has_pci"] is True
        assert cfg["has_anyone_with_link"] is True
        assert cfg["exposure_score"] > 0
