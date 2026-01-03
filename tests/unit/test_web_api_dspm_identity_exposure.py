"""
Unit tests for DSPM, Identity, and Exposure web API endpoints.

Tests cover all new API endpoints in stance.web.server:
- /api/dspm/* endpoints
- /api/identity/* endpoints
- /api/exposure/* endpoints
"""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from stance.web.server import StanceRequestHandler


# =============================================================================
# DSPM API Tests
# =============================================================================


class TestDSPMScanEndpoint:
    """Tests for /api/dspm/scan endpoint."""

    def test_scan_requires_target(self):
        """Test that target parameter is required."""
        handler = StanceRequestHandler.__new__(StanceRequestHandler)
        result = handler._dspm_scan({"cloud": ["aws"]})
        assert "error" in result
        assert "target" in result["error"]

    def test_scan_requires_cloud(self):
        """Test that cloud parameter is required."""
        handler = StanceRequestHandler.__new__(StanceRequestHandler)
        result = handler._dspm_scan({"target": ["my-bucket"]})
        assert "error" in result
        assert "cloud" in result["error"]

    def test_scan_unknown_cloud_fails(self):
        """Test that unknown cloud provider returns error."""
        handler = StanceRequestHandler.__new__(StanceRequestHandler)
        result = handler._dspm_scan({
            "target": ["my-bucket"],
            "cloud": ["unknown"]
        })
        assert "error" in result
        assert "Unknown cloud provider" in result["error"]

    def test_scan_aws_success(self):
        """Test successful AWS S3 scan."""
        with patch("stance.dspm.scanners.S3DataScanner") as mock_scanner_class:
            mock_scanner = MagicMock()
            mock_result = MagicMock()
            mock_result.target = "my-bucket"
            mock_result.cloud_provider = "aws"
            mock_result.started_at = datetime.now(timezone.utc)
            mock_result.completed_at = datetime.now(timezone.utc)
            mock_result.summary = MagicMock()
            mock_result.summary.total_objects = 100
            mock_result.summary.objects_scanned = 50
            mock_result.summary.findings_count = 3
            mock_result.findings = []
            mock_scanner.scan.return_value = mock_result
            mock_scanner_class.return_value = mock_scanner

            handler = StanceRequestHandler.__new__(StanceRequestHandler)
            result = handler._dspm_scan({
                "target": ["my-bucket"],
                "cloud": ["aws"],
                "sample_size": ["100"]
            })

            assert result["target"] == "my-bucket"
            assert result["cloud"] == "aws"
            assert result["summary"]["total_objects"] == 100

    def test_scan_gcp_success(self):
        """Test successful GCP GCS scan."""
        with patch("stance.dspm.scanners.GCSDataScanner") as mock_scanner_class:
            mock_scanner = MagicMock()
            mock_result = MagicMock()
            mock_result.target = "gcs-bucket"
            mock_result.cloud_provider = "gcp"
            mock_result.started_at = None
            mock_result.completed_at = None
            mock_result.summary = None
            mock_result.findings = []
            mock_scanner.scan.return_value = mock_result
            mock_scanner_class.return_value = mock_scanner

            handler = StanceRequestHandler.__new__(StanceRequestHandler)
            result = handler._dspm_scan({
                "target": ["gcs-bucket"],
                "cloud": ["gcp"]
            })

            assert result["target"] == "gcs-bucket"
            assert result["cloud"] == "gcp"

    def test_scan_azure_success(self):
        """Test successful Azure Blob scan."""
        with patch("stance.dspm.scanners.AzureBlobDataScanner") as mock_scanner_class:
            mock_scanner = MagicMock()
            mock_result = MagicMock()
            mock_result.target = "azure-container"
            mock_result.cloud_provider = "azure"
            mock_result.started_at = None
            mock_result.completed_at = None
            mock_result.summary = None
            mock_result.findings = []
            mock_scanner.scan.return_value = mock_result
            mock_scanner_class.return_value = mock_scanner

            handler = StanceRequestHandler.__new__(StanceRequestHandler)
            result = handler._dspm_scan({
                "target": ["azure-container"],
                "cloud": ["azure"]
            })

            assert result["target"] == "azure-container"
            assert result["cloud"] == "azure"


class TestDSPMAccessEndpoint:
    """Tests for /api/dspm/access endpoint."""

    def test_access_requires_target(self):
        """Test that target parameter is required."""
        handler = StanceRequestHandler.__new__(StanceRequestHandler)
        result = handler._dspm_access({"cloud": ["aws"]})
        assert "error" in result
        assert "target" in result["error"]

    def test_access_requires_cloud(self):
        """Test that cloud parameter is required."""
        handler = StanceRequestHandler.__new__(StanceRequestHandler)
        result = handler._dspm_access({"target": ["my-bucket"]})
        assert "error" in result
        assert "cloud" in result["error"]

    def test_access_aws_success(self):
        """Test successful AWS CloudTrail access analysis."""
        with patch("stance.dspm.access.CloudTrailAccessAnalyzer") as mock_analyzer_class:
            mock_analyzer = MagicMock()
            mock_result = MagicMock()
            mock_result.target = "my-bucket"
            mock_result.cloud_provider = "aws"
            mock_result.analysis_period_days = 180
            mock_result.summary = MagicMock()
            mock_result.summary.total_principals = 50
            mock_result.summary.stale_access_count = 10
            mock_result.summary.over_privileged_count = 5
            mock_result.findings = []
            mock_analyzer.analyze.return_value = mock_result
            mock_analyzer_class.return_value = mock_analyzer

            handler = StanceRequestHandler.__new__(StanceRequestHandler)
            result = handler._dspm_access({
                "target": ["my-bucket"],
                "cloud": ["aws"],
                "stale_days": ["90"],
                "lookback_days": ["180"]
            })

            assert result["target"] == "my-bucket"
            assert result["cloud"] == "aws"
            assert result["summary"]["total_principals"] == 50


class TestDSPMCostEndpoint:
    """Tests for /api/dspm/cost endpoint."""

    def test_cost_requires_target(self):
        """Test that target parameter is required."""
        handler = StanceRequestHandler.__new__(StanceRequestHandler)
        result = handler._dspm_cost({"cloud": ["aws"]})
        assert "error" in result
        assert "target" in result["error"]

    def test_cost_aws_success(self):
        """Test successful AWS S3 cost analysis."""
        with patch("stance.dspm.cost.S3CostAnalyzer") as mock_analyzer_class:
            mock_analyzer = MagicMock()
            mock_result = MagicMock()
            mock_result.target = "my-bucket"
            mock_result.cloud_provider = "aws"
            mock_result.metrics = MagicMock()
            mock_result.metrics.total_size_bytes = 10 * 1024 * 1024 * 1024
            mock_result.metrics.object_count = 1000
            mock_result.metrics.estimated_monthly_cost = 25.50
            mock_result.potential_monthly_savings = 10.25
            mock_result.findings = []
            mock_analyzer.analyze.return_value = mock_result
            mock_analyzer_class.return_value = mock_analyzer

            handler = StanceRequestHandler.__new__(StanceRequestHandler)
            result = handler._dspm_cost({
                "target": ["my-bucket"],
                "cloud": ["aws"],
                "cold_days": ["90"]
            })

            assert result["target"] == "my-bucket"
            assert result["metrics"]["total_size_bytes"] == 10 * 1024 * 1024 * 1024
            assert result["potential_monthly_savings"] == 10.25


class TestDSPMClassifyEndpoint:
    """Tests for /api/dspm/classify endpoint."""

    def test_classify_requires_text(self):
        """Test that text parameter is required."""
        handler = StanceRequestHandler.__new__(StanceRequestHandler)
        result = handler._dspm_classify({})
        assert "error" in result
        assert "text" in result["error"]

    def test_classify_success(self):
        """Test successful text classification."""
        with patch("stance.dspm.classifier.DataClassifier") as mock_classifier_class, \
             patch("stance.dspm.detector.SensitiveDataDetector") as mock_detector_class:

            mock_classifier = MagicMock()
            mock_classification = MagicMock()
            mock_classification.level = MagicMock()
            mock_classification.level.value = "CONFIDENTIAL"
            mock_classification.categories = []
            mock_classification.confidence = 0.95
            mock_classifier.classify.return_value = mock_classification
            mock_classifier_class.return_value = mock_classifier

            mock_detector = MagicMock()
            mock_detection = MagicMock()
            mock_detection.matches = []
            mock_detector.detect.return_value = mock_detection
            mock_detector_class.return_value = mock_detector

            handler = StanceRequestHandler.__new__(StanceRequestHandler)
            result = handler._dspm_classify({
                "text": ["SSN: 123-45-6789"]
            })

            assert "classification" in result
            assert result["classification"]["level"] == "CONFIDENTIAL"


class TestDSPMSummaryEndpoint:
    """Tests for /api/dspm/summary endpoint."""

    def test_summary_returns_features(self):
        """Test that summary returns available features."""
        handler = StanceRequestHandler.__new__(StanceRequestHandler)
        result = handler._dspm_summary(None)

        assert "available_features" in result
        assert len(result["available_features"]) == 4
        assert "supported_clouds" in result
        assert "aws" in result["supported_clouds"]


# =============================================================================
# Identity API Tests
# =============================================================================


class TestIdentityWhoCanAccessEndpoint:
    """Tests for /api/identity/who-can-access endpoint."""

    def test_who_can_access_requires_resource(self):
        """Test that resource parameter is required."""
        handler = StanceRequestHandler.__new__(StanceRequestHandler)
        result = handler._identity_who_can_access({"cloud": ["aws"]})
        assert "error" in result
        assert "resource" in result["error"]

    def test_who_can_access_requires_cloud(self):
        """Test that cloud parameter is required."""
        handler = StanceRequestHandler.__new__(StanceRequestHandler)
        result = handler._identity_who_can_access({"resource": ["my-bucket"]})
        assert "error" in result
        assert "cloud" in result["error"]

    def test_who_can_access_aws_success(self):
        """Test successful AWS access mapping."""
        with patch("stance.identity.AWSDataAccessMapper") as mock_mapper_class:
            mock_mapper = MagicMock()
            mock_result = MagicMock()
            mock_result.resource_id = "arn:aws:s3:::my-bucket"
            mock_result.cloud_provider = "aws"

            mock_access = MagicMock()
            mock_access.principal = MagicMock()
            mock_access.principal.id = "user:admin"
            mock_access.principal.type = MagicMock()
            mock_access.principal.type.value = "user"
            mock_access.principal.name = "admin"
            mock_access.permission_level = MagicMock()
            mock_access.permission_level.value = "full_control"
            mock_access.source = "bucket_policy"

            mock_result.access_list = [mock_access]
            mock_mapper.who_can_access.return_value = mock_result
            mock_mapper_class.return_value = mock_mapper

            handler = StanceRequestHandler.__new__(StanceRequestHandler)
            result = handler._identity_who_can_access({
                "resource": ["arn:aws:s3:::my-bucket"],
                "cloud": ["aws"]
            })

            assert result["resource"] == "arn:aws:s3:::my-bucket"
            assert result["cloud"] == "aws"
            assert result["total_principals"] == 1
            assert result["principals"][0]["principal_name"] == "admin"

    def test_who_can_access_gcp_success(self):
        """Test successful GCP access mapping."""
        with patch("stance.identity.GCPDataAccessMapper") as mock_mapper_class:
            mock_mapper = MagicMock()
            mock_result = MagicMock()
            mock_result.resource_id = "gs://gcs-bucket"
            mock_result.cloud_provider = "gcp"
            mock_result.access_list = []
            mock_mapper.who_can_access.return_value = mock_result
            mock_mapper_class.return_value = mock_mapper

            handler = StanceRequestHandler.__new__(StanceRequestHandler)
            result = handler._identity_who_can_access({
                "resource": ["gs://gcs-bucket"],
                "cloud": ["gcp"]
            })

            assert result["resource"] == "gs://gcs-bucket"
            assert result["cloud"] == "gcp"

    def test_who_can_access_azure_success(self):
        """Test successful Azure access mapping."""
        with patch("stance.identity.AzureDataAccessMapper") as mock_mapper_class:
            mock_mapper = MagicMock()
            mock_result = MagicMock()
            mock_result.resource_id = "/subscriptions/.../storageAccounts/test"
            mock_result.cloud_provider = "azure"
            mock_result.access_list = []
            mock_mapper.who_can_access.return_value = mock_result
            mock_mapper_class.return_value = mock_mapper

            handler = StanceRequestHandler.__new__(StanceRequestHandler)
            result = handler._identity_who_can_access({
                "resource": ["/subscriptions/.../storageAccounts/test"],
                "cloud": ["azure"]
            })

            assert result["cloud"] == "azure"


class TestIdentityExposureEndpoint:
    """Tests for /api/identity/exposure endpoint."""

    def test_exposure_requires_principal(self):
        """Test that principal parameter is required."""
        handler = StanceRequestHandler.__new__(StanceRequestHandler)
        result = handler._identity_exposure({})
        assert "error" in result
        assert "principal" in result["error"]

    def test_exposure_success(self):
        """Test successful principal exposure analysis."""
        with patch("stance.identity.exposure.PrincipalExposureAnalyzer") as mock_analyzer_class:
            mock_analyzer = MagicMock()
            mock_result = MagicMock()
            mock_result.principal_id = "user:admin"
            mock_result.summary = MagicMock()
            mock_result.summary.total_resources = 100
            mock_result.summary.sensitive_resources = 25
            mock_result.summary.critical_exposures = 5
            mock_result.summary.high_exposures = 10
            mock_result.risk_score = 75
            mock_result.exposures = []
            mock_analyzer.analyze_principal_exposure.return_value = mock_result
            mock_analyzer_class.return_value = mock_analyzer

            handler = StanceRequestHandler.__new__(StanceRequestHandler)
            result = handler._identity_exposure({
                "principal": ["user:admin"]
            })

            assert result["principal"] == "user:admin"
            assert result["risk_score"] == 75
            assert result["summary"]["sensitive_resources"] == 25


class TestIdentityOverprivilegedEndpoint:
    """Tests for /api/identity/overprivileged endpoint."""

    def test_overprivileged_requires_cloud(self):
        """Test that cloud parameter is required."""
        handler = StanceRequestHandler.__new__(StanceRequestHandler)
        result = handler._identity_overprivileged({})
        assert "error" in result
        assert "cloud" in result["error"]

    def test_overprivileged_success(self):
        """Test successful over-privileged analysis."""
        with patch("stance.identity.overprivileged.OverPrivilegedAnalyzer") as mock_analyzer_class:
            mock_analyzer = MagicMock()
            mock_result = MagicMock()
            mock_result.cloud_provider = "aws"
            mock_result.analysis_period_days = 90
            mock_result.summary = MagicMock()
            mock_result.summary.total_principals = 100
            mock_result.summary.over_privileged_count = 15
            mock_result.summary.unused_admin_count = 5
            mock_result.summary.stale_elevated_count = 10
            mock_result.findings = []
            mock_analyzer.analyze.return_value = mock_result
            mock_analyzer_class.return_value = mock_analyzer

            handler = StanceRequestHandler.__new__(StanceRequestHandler)
            result = handler._identity_overprivileged({
                "cloud": ["aws"],
                "days": ["90"]
            })

            assert result["cloud"] == "aws"
            assert result["analysis_period_days"] == 90
            assert result["summary"]["over_privileged_count"] == 15


class TestIdentitySummaryEndpoint:
    """Tests for /api/identity/summary endpoint."""

    def test_summary_returns_features(self):
        """Test that summary returns available features."""
        handler = StanceRequestHandler.__new__(StanceRequestHandler)
        result = handler._identity_summary(None)

        assert "available_features" in result
        assert len(result["available_features"]) == 3
        assert "supported_clouds" in result
        assert "principal_types" in result


# =============================================================================
# Exposure API Tests
# =============================================================================


class TestExposureInventoryEndpoint:
    """Tests for /api/exposure/inventory endpoint."""

    def test_inventory_success(self):
        """Test successful public asset inventory."""
        with patch("stance.exposure.inventory.PublicAssetInventory") as mock_inventory_class:
            mock_inventory = MagicMock()
            mock_result = MagicMock()
            mock_result.summary = MagicMock()
            mock_result.summary.total_public_assets = 10
            mock_result.summary.internet_facing = 8
            mock_result.summary.with_sensitive_data = 3
            mock_result.summary.by_cloud = {"aws": 5, "gcp": 3, "azure": 2}
            mock_result.summary.by_type = {}
            mock_result.assets = []
            mock_inventory.discover.return_value = mock_result
            mock_inventory_class.return_value = mock_inventory

            handler = StanceRequestHandler.__new__(StanceRequestHandler)
            result = handler._exposure_inventory({})

            assert result["summary"]["total_public_assets"] == 10
            assert result["summary"]["internet_facing"] == 8

    def test_inventory_with_filters(self):
        """Test inventory with cloud and region filters."""
        with patch("stance.exposure.inventory.PublicAssetInventory") as mock_inventory_class:
            mock_inventory = MagicMock()
            mock_result = MagicMock()
            mock_result.summary = MagicMock()
            mock_result.summary.total_public_assets = 5
            mock_result.summary.internet_facing = 4
            mock_result.summary.with_sensitive_data = 1
            mock_result.summary.by_cloud = {"aws": 5}
            mock_result.summary.by_type = {}
            mock_result.assets = []
            mock_inventory.discover.return_value = mock_result
            mock_inventory_class.return_value = mock_inventory

            handler = StanceRequestHandler.__new__(StanceRequestHandler)
            result = handler._exposure_inventory({
                "cloud": ["aws"],
                "region": ["us-east-1"]
            })

            assert result["summary"]["total_public_assets"] == 5


class TestExposureCertificatesEndpoint:
    """Tests for /api/exposure/certificates endpoint."""

    def test_certificates_success(self):
        """Test successful certificate monitoring."""
        with patch("stance.exposure.certificates.CertificateMonitor") as mock_monitor_class:
            mock_monitor = MagicMock()
            mock_result = MagicMock()
            mock_result.summary = MagicMock()
            mock_result.summary.total_certificates = 10
            mock_result.summary.expired = 1
            mock_result.summary.expiring_soon = 2
            mock_result.summary.weak_key = 0
            mock_result.summary.weak_algorithm = 0
            mock_result.certificates = []
            mock_result.findings = []
            mock_monitor.analyze.return_value = mock_result
            mock_monitor_class.return_value = mock_monitor

            handler = StanceRequestHandler.__new__(StanceRequestHandler)
            result = handler._exposure_certificates({})

            assert result["summary"]["total_certificates"] == 10
            assert result["summary"]["expired"] == 1

    def test_certificates_with_expiring_filter(self):
        """Test certificates with expiring_within filter."""
        with patch("stance.exposure.certificates.CertificateMonitor") as mock_monitor_class:
            mock_monitor = MagicMock()
            mock_result = MagicMock()
            mock_result.summary = MagicMock()
            mock_result.summary.total_certificates = 5
            mock_result.summary.expired = 0
            mock_result.summary.expiring_soon = 3
            mock_result.summary.weak_key = 0
            mock_result.summary.weak_algorithm = 0
            mock_result.certificates = []
            mock_result.findings = []
            mock_monitor.analyze.return_value = mock_result
            mock_monitor_class.return_value = mock_monitor

            handler = StanceRequestHandler.__new__(StanceRequestHandler)
            result = handler._exposure_certificates({
                "expiring_within": ["60"]
            })

            assert result["summary"]["expiring_soon"] == 3


class TestExposureDNSEndpoint:
    """Tests for /api/exposure/dns endpoint."""

    def test_dns_success(self):
        """Test successful DNS analysis."""
        with patch("stance.exposure.dns.DNSInventory") as mock_inventory_class:
            mock_inventory = MagicMock()
            mock_result = MagicMock()
            mock_result.summary = MagicMock()
            mock_result.summary.total_zones = 3
            mock_result.summary.total_records = 50
            mock_result.summary.dangling_records = 2
            mock_result.summary.takeover_risk = 1
            mock_result.zones = []
            mock_result.findings = []
            mock_inventory.analyze.return_value = mock_result
            mock_inventory_class.return_value = mock_inventory

            handler = StanceRequestHandler.__new__(StanceRequestHandler)
            result = handler._exposure_dns({})

            assert result["summary"]["total_zones"] == 3
            assert result["summary"]["dangling_records"] == 2

    def test_dns_with_zone_filter(self):
        """Test DNS with zone filter."""
        with patch("stance.exposure.dns.DNSInventory") as mock_inventory_class:
            mock_inventory = MagicMock()
            mock_result = MagicMock()
            mock_result.summary = MagicMock()
            mock_result.summary.total_zones = 1
            mock_result.summary.total_records = 20
            mock_result.summary.dangling_records = 0
            mock_result.summary.takeover_risk = 0
            mock_result.zones = []
            mock_result.findings = []
            mock_inventory.analyze.return_value = mock_result
            mock_inventory_class.return_value = mock_inventory

            handler = StanceRequestHandler.__new__(StanceRequestHandler)
            result = handler._exposure_dns({
                "zone": ["example.com"]
            })

            assert result["summary"]["total_zones"] == 1


class TestExposureSensitiveEndpoint:
    """Tests for /api/exposure/sensitive endpoint."""

    def test_sensitive_success(self):
        """Test successful sensitive data exposure analysis."""
        with patch("stance.exposure.sensitive.SensitiveDataExposureAnalyzer") as mock_analyzer_class:
            mock_analyzer = MagicMock()
            mock_result = MagicMock()
            mock_result.summary = MagicMock()
            mock_result.summary.total_exposures = 5
            mock_result.summary.critical_exposures = 1
            mock_result.summary.high_exposures = 2
            mock_result.summary.pii_exposures = 2
            mock_result.summary.pci_exposures = 1
            mock_result.summary.phi_exposures = 0
            mock_result.findings = []
            mock_analyzer.analyze.return_value = mock_result
            mock_analyzer_class.return_value = mock_analyzer

            handler = StanceRequestHandler.__new__(StanceRequestHandler)
            result = handler._exposure_sensitive({})

            assert result["summary"]["total_exposures"] == 5
            assert result["summary"]["pii_exposures"] == 2

    def test_sensitive_with_classification_filter(self):
        """Test sensitive with classification filter."""
        with patch("stance.exposure.sensitive.SensitiveDataExposureAnalyzer") as mock_analyzer_class:
            mock_analyzer = MagicMock()
            mock_result = MagicMock()
            mock_result.summary = MagicMock()
            mock_result.summary.total_exposures = 2
            mock_result.summary.critical_exposures = 2
            mock_result.summary.high_exposures = 0
            mock_result.summary.pii_exposures = 1
            mock_result.summary.pci_exposures = 1
            mock_result.summary.phi_exposures = 0
            mock_result.findings = []
            mock_analyzer.analyze.return_value = mock_result
            mock_analyzer_class.return_value = mock_analyzer

            handler = StanceRequestHandler.__new__(StanceRequestHandler)
            result = handler._exposure_sensitive({
                "classification": ["confidential"]
            })

            assert result["summary"]["total_exposures"] == 2


class TestExposureSummaryEndpoint:
    """Tests for /api/exposure/summary endpoint."""

    def test_summary_returns_features(self):
        """Test that summary returns available features."""
        handler = StanceRequestHandler.__new__(StanceRequestHandler)
        result = handler._exposure_summary(None)

        assert "available_features" in result
        assert len(result["available_features"]) == 4
        assert "supported_clouds" in result
        assert "exposure_types" in result
        assert "risk_levels" in result


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestAPIErrorHandling:
    """Tests for error handling in API endpoints."""

    def test_dspm_scan_handles_exception(self):
        """Test that DSPM scan handles exceptions gracefully."""
        with patch("stance.dspm.scanners.S3DataScanner") as mock_scanner_class:
            mock_scanner_class.side_effect = Exception("Connection failed")

            handler = StanceRequestHandler.__new__(StanceRequestHandler)
            result = handler._dspm_scan({
                "target": ["my-bucket"],
                "cloud": ["aws"]
            })

            assert "error" in result
            assert "Connection failed" in result["error"]

    def test_identity_exposure_handles_exception(self):
        """Test that identity exposure handles exceptions gracefully."""
        with patch("stance.identity.exposure.PrincipalExposureAnalyzer") as mock_analyzer_class:
            mock_analyzer_class.side_effect = Exception("API error")

            handler = StanceRequestHandler.__new__(StanceRequestHandler)
            result = handler._identity_exposure({
                "principal": ["user:admin"]
            })

            assert "error" in result
            assert "API error" in result["error"]

    def test_exposure_inventory_handles_exception(self):
        """Test that exposure inventory handles exceptions gracefully."""
        with patch("stance.exposure.inventory.PublicAssetInventory") as mock_inventory_class:
            mock_inventory_class.side_effect = Exception("Discovery failed")

            handler = StanceRequestHandler.__new__(StanceRequestHandler)
            result = handler._exposure_inventory({})

            assert "error" in result
            assert "Discovery failed" in result["error"]
