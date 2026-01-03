"""
Unit tests for the Exposure CLI commands.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone, timedelta
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from stance.cli_exposure import (
    cmd_exposure,
    _cmd_exposure_inventory,
    _cmd_exposure_certificates,
    _cmd_exposure_dns,
    _cmd_exposure_sensitive,
)


class TestCmdExposure:
    """Tests for cmd_exposure routing function."""

    def test_no_action_shows_help(self, capsys):
        """Test that no action shows help text."""
        args = argparse.Namespace(exposure_action=None)

        result = cmd_exposure(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Usage: stance exposure" in captured.out
        assert "inventory" in captured.out
        assert "certificates" in captured.out
        assert "dns" in captured.out
        assert "sensitive" in captured.out

    def test_unknown_action_fails(self, capsys):
        """Test that unknown action returns error."""
        args = argparse.Namespace(exposure_action="unknown")

        result = cmd_exposure(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Unknown" in captured.out

    def test_routes_to_inventory(self):
        """Test routing to inventory command."""
        with patch("stance.cli_exposure._cmd_exposure_inventory") as mock_inv:
            mock_inv.return_value = 0
            args = argparse.Namespace(exposure_action="inventory")

            result = cmd_exposure(args)

            mock_inv.assert_called_once_with(args)
            assert result == 0

    def test_routes_to_certificates(self):
        """Test routing to certificates command."""
        with patch("stance.cli_exposure._cmd_exposure_certificates") as mock_cert:
            mock_cert.return_value = 0
            args = argparse.Namespace(exposure_action="certificates")

            result = cmd_exposure(args)

            mock_cert.assert_called_once_with(args)
            assert result == 0

    def test_routes_to_dns(self):
        """Test routing to dns command."""
        with patch("stance.cli_exposure._cmd_exposure_dns") as mock_dns:
            mock_dns.return_value = 0
            args = argparse.Namespace(exposure_action="dns")

            result = cmd_exposure(args)

            mock_dns.assert_called_once_with(args)
            assert result == 0

    def test_routes_to_sensitive(self):
        """Test routing to sensitive command."""
        with patch("stance.cli_exposure._cmd_exposure_sensitive") as mock_sens:
            mock_sens.return_value = 0
            args = argparse.Namespace(exposure_action="sensitive")

            result = cmd_exposure(args)

            mock_sens.assert_called_once_with(args)
            assert result == 0


class TestCmdExposureInventory:
    """Tests for _cmd_exposure_inventory function."""

    def test_inventory_table_output(self, capsys):
        """Test inventory with table output."""
        with patch("stance.cli_exposure.PublicAssetInventory") as mock_inventory_class:
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

            args = argparse.Namespace(
                cloud=None,
                region=None,
                type=None,
                format="table",
            )

            result = _cmd_exposure_inventory(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "Public Asset Inventory" in captured.out
            assert "10" in captured.out  # total

    def test_inventory_json_output(self, capsys):
        """Test inventory with JSON output."""
        with patch("stance.cli_exposure.PublicAssetInventory") as mock_inventory_class:
            mock_inventory = MagicMock()
            mock_result = MagicMock()
            mock_result.summary = MagicMock()
            mock_result.summary.total_public_assets = 5
            mock_result.summary.internet_facing = 4
            mock_result.summary.with_sensitive_data = 1
            mock_result.summary.by_cloud = {"aws": 5}
            mock_result.summary.by_type = {"s3_bucket": 3, "ec2_instance": 2}
            mock_result.assets = []
            mock_inventory.discover.return_value = mock_result
            mock_inventory_class.return_value = mock_inventory

            args = argparse.Namespace(
                cloud="aws",
                region="us-east-1",
                type=None,
                format="json",
            )

            result = _cmd_exposure_inventory(args)

            assert result == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert "summary" in data
            assert data["summary"]["total_public_assets"] == 5

    def test_inventory_with_assets(self, capsys):
        """Test inventory shows asset details."""
        with patch("stance.cli_exposure.PublicAssetInventory") as mock_inventory_class:
            mock_inventory = MagicMock()
            mock_result = MagicMock()
            mock_result.summary = MagicMock()
            mock_result.summary.total_public_assets = 2
            mock_result.summary.internet_facing = 2
            mock_result.summary.with_sensitive_data = 1
            mock_result.summary.by_cloud = {"aws": 2}
            mock_result.summary.by_type = {}

            mock_asset1 = MagicMock()
            mock_asset1.resource_id = "public-bucket-123"
            mock_asset1.resource_type = "s3_bucket"
            mock_asset1.cloud_provider = "aws"
            mock_asset1.region = "us-east-1"
            mock_asset1.exposure_type = MagicMock()
            mock_asset1.exposure_type.value = "internet_facing"
            mock_asset1.risk_score = 85
            mock_asset1.has_sensitive_data = True

            mock_asset2 = MagicMock()
            mock_asset2.resource_id = "public-instance-456"
            mock_asset2.resource_type = "ec2_instance"
            mock_asset2.cloud_provider = "aws"
            mock_asset2.region = "us-west-2"
            mock_asset2.exposure_type = MagicMock()
            mock_asset2.exposure_type.value = "internet_facing"
            mock_asset2.risk_score = 60
            mock_asset2.has_sensitive_data = False

            mock_result.assets = [mock_asset1, mock_asset2]
            mock_inventory.discover.return_value = mock_result
            mock_inventory_class.return_value = mock_inventory

            args = argparse.Namespace(
                cloud=None,
                region=None,
                type=None,
                format="table",
            )

            result = _cmd_exposure_inventory(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "Public Assets" in captured.out
            assert "public-bucket-123" in captured.out
            assert "[SENSITIVE]" in captured.out

    def test_inventory_handles_exception(self, capsys):
        """Test inventory handles exceptions gracefully."""
        with patch("stance.cli_exposure.PublicAssetInventory") as mock_inventory_class:
            mock_inventory_class.side_effect = Exception("API error")

            args = argparse.Namespace(
                cloud=None,
                region=None,
                type=None,
                format="table",
            )

            result = _cmd_exposure_inventory(args)

            assert result == 1
            captured = capsys.readouterr()
            assert "Error" in captured.out


class TestCmdExposureCertificates:
    """Tests for _cmd_exposure_certificates function."""

    def test_certificates_table_output(self, capsys):
        """Test certificates with table output."""
        with patch("stance.cli_exposure.CertificateMonitor") as mock_monitor_class:
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

            args = argparse.Namespace(
                cloud=None,
                domain=None,
                expiring_within=30,
                format="table",
            )

            result = _cmd_exposure_certificates(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "Certificate Monitoring" in captured.out
            assert "10" in captured.out  # total

    def test_certificates_json_output(self, capsys):
        """Test certificates with JSON output."""
        with patch("stance.cli_exposure.CertificateMonitor") as mock_monitor_class:
            mock_monitor = MagicMock()
            mock_result = MagicMock()
            mock_result.summary = MagicMock()
            mock_result.summary.total_certificates = 5
            mock_result.summary.expired = 0
            mock_result.summary.expiring_soon = 1
            mock_result.summary.weak_key = 1
            mock_result.summary.weak_algorithm = 0
            mock_result.certificates = []
            mock_result.findings = []
            mock_monitor.analyze.return_value = mock_result
            mock_monitor_class.return_value = mock_monitor

            args = argparse.Namespace(
                cloud="aws",
                domain=None,
                expiring_within=30,
                format="json",
            )

            result = _cmd_exposure_certificates(args)

            assert result == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert "summary" in data
            assert data["summary"]["total_certificates"] == 5

    def test_certificates_with_findings(self, capsys):
        """Test certificates shows findings."""
        with patch("stance.cli_exposure.CertificateMonitor") as mock_monitor_class:
            mock_monitor = MagicMock()
            mock_result = MagicMock()
            mock_result.summary = MagicMock()
            mock_result.summary.total_certificates = 3
            mock_result.summary.expired = 1
            mock_result.summary.expiring_soon = 1
            mock_result.summary.weak_key = 0
            mock_result.summary.weak_algorithm = 0

            mock_finding = MagicMock()
            mock_finding.domain = "expired.example.com"
            mock_finding.finding_type = MagicMock()
            mock_finding.finding_type.value = "expired"
            mock_finding.severity = MagicMock()
            mock_finding.severity.value = "critical"
            mock_finding.message = "Certificate has expired"

            mock_cert = MagicMock()
            mock_cert.domain = "example.com"
            mock_cert.cloud_provider = "aws"
            mock_cert.status = MagicMock()
            mock_cert.status.value = "valid"
            mock_cert.expires_at = datetime.now(timezone.utc) + timedelta(days=30)
            mock_cert.days_until_expiry = 30
            mock_cert.key_size = 2048
            mock_cert.algorithm = "RSA"
            mock_cert.cert_type = MagicMock()
            mock_cert.cert_type.value = "managed"

            mock_result.certificates = [mock_cert]
            mock_result.findings = [mock_finding]
            mock_monitor.analyze.return_value = mock_result
            mock_monitor_class.return_value = mock_monitor

            args = argparse.Namespace(
                cloud=None,
                domain=None,
                expiring_within=30,
                format="table",
            )

            result = _cmd_exposure_certificates(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "Certificate Findings" in captured.out
            assert "expired.example.com" in captured.out


class TestCmdExposureDNS:
    """Tests for _cmd_exposure_dns function."""

    def test_dns_table_output(self, capsys):
        """Test DNS analysis with table output."""
        with patch("stance.cli_exposure.DNSInventory") as mock_inventory_class:
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

            args = argparse.Namespace(
                zone=None,
                cloud=None,
                format="table",
            )

            result = _cmd_exposure_dns(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "DNS Inventory Analysis" in captured.out
            assert "3" in captured.out  # total zones

    def test_dns_json_output(self, capsys):
        """Test DNS analysis with JSON output."""
        with patch("stance.cli_exposure.DNSInventory") as mock_inventory_class:
            mock_inventory = MagicMock()
            mock_result = MagicMock()
            mock_result.summary = MagicMock()
            mock_result.summary.total_zones = 2
            mock_result.summary.total_records = 30
            mock_result.summary.dangling_records = 1
            mock_result.summary.takeover_risk = 0
            mock_result.zones = []
            mock_result.findings = []
            mock_inventory.analyze.return_value = mock_result
            mock_inventory_class.return_value = mock_inventory

            args = argparse.Namespace(
                zone="example.com",
                cloud="aws",
                format="json",
            )

            result = _cmd_exposure_dns(args)

            assert result == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert "summary" in data
            assert data["summary"]["total_zones"] == 2

    def test_dns_with_findings(self, capsys):
        """Test DNS shows dangling record findings."""
        with patch("stance.cli_exposure.DNSInventory") as mock_inventory_class:
            mock_inventory = MagicMock()
            mock_result = MagicMock()
            mock_result.summary = MagicMock()
            mock_result.summary.total_zones = 1
            mock_result.summary.total_records = 20
            mock_result.summary.dangling_records = 2
            mock_result.summary.takeover_risk = 1

            mock_finding = MagicMock()
            mock_finding.record_name = "old-app.example.com"
            mock_finding.record_type = "CNAME"
            mock_finding.finding_type = MagicMock()
            mock_finding.finding_type.value = "dangling_cname"
            mock_finding.severity = MagicMock()
            mock_finding.severity.value = "high"
            mock_finding.target = "deleted-app.herokuapp.com"
            mock_finding.takeover_risk = True
            mock_finding.recommendation = "Delete dangling record"

            mock_zone = MagicMock()
            mock_zone.name = "example.com"
            mock_zone.cloud_provider = "aws"
            mock_zone.record_count = 20

            mock_result.zones = [mock_zone]
            mock_result.findings = [mock_finding]
            mock_inventory.analyze.return_value = mock_result
            mock_inventory_class.return_value = mock_inventory

            args = argparse.Namespace(
                zone=None,
                cloud=None,
                format="table",
            )

            result = _cmd_exposure_dns(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "DNS Findings" in captured.out
            assert "old-app.example.com" in captured.out
            assert "YES" in captured.out  # takeover risk


class TestCmdExposureSensitive:
    """Tests for _cmd_exposure_sensitive function."""

    def test_sensitive_table_output(self, capsys):
        """Test sensitive data exposure with table output."""
        with patch("stance.cli_exposure.SensitiveDataExposureAnalyzer") as mock_analyzer_class:
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

            args = argparse.Namespace(
                cloud=None,
                classification=None,
                format="table",
            )

            result = _cmd_exposure_sensitive(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "Sensitive Data Exposure Analysis" in captured.out
            assert "5" in captured.out  # total

    def test_sensitive_json_output(self, capsys):
        """Test sensitive data exposure with JSON output."""
        with patch("stance.cli_exposure.SensitiveDataExposureAnalyzer") as mock_analyzer_class:
            mock_analyzer = MagicMock()
            mock_result = MagicMock()
            mock_result.summary = MagicMock()
            mock_result.summary.total_exposures = 3
            mock_result.summary.critical_exposures = 0
            mock_result.summary.high_exposures = 1
            mock_result.summary.pii_exposures = 1
            mock_result.summary.pci_exposures = 0
            mock_result.summary.phi_exposures = 1
            mock_result.findings = []
            mock_analyzer.analyze.return_value = mock_result
            mock_analyzer_class.return_value = mock_analyzer

            args = argparse.Namespace(
                cloud="gcp",
                classification=None,
                format="json",
            )

            result = _cmd_exposure_sensitive(args)

            assert result == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert "summary" in data
            assert data["summary"]["total_exposures"] == 3

    def test_sensitive_with_findings(self, capsys):
        """Test sensitive shows exposure findings."""
        with patch("stance.cli_exposure.SensitiveDataExposureAnalyzer") as mock_analyzer_class:
            mock_analyzer = MagicMock()
            mock_result = MagicMock()
            mock_result.summary = MagicMock()
            mock_result.summary.total_exposures = 1
            mock_result.summary.critical_exposures = 1
            mock_result.summary.high_exposures = 0
            mock_result.summary.pii_exposures = 1
            mock_result.summary.pci_exposures = 0
            mock_result.summary.phi_exposures = 0

            mock_finding = MagicMock()
            mock_finding.resource_id = "public-bucket/customer-data.csv"
            mock_finding.exposure_type = MagicMock()
            mock_finding.exposure_type.value = "public_bucket"
            mock_finding.classification = MagicMock()
            mock_finding.classification.value = "confidential"
            mock_finding.categories = []
            mock_finding.risk_level = MagicMock()
            mock_finding.risk_level.value = "critical"
            mock_finding.risk_score = 95
            mock_finding.compliance_impact = ["GDPR", "CCPA"]
            mock_finding.recommendation = "Remove public access"

            mock_result.findings = [mock_finding]
            mock_analyzer.analyze.return_value = mock_result
            mock_analyzer_class.return_value = mock_analyzer

            args = argparse.Namespace(
                cloud=None,
                classification=None,
                format="table",
            )

            result = _cmd_exposure_sensitive(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "Exposure Findings" in captured.out
            assert "customer-data.csv" in captured.out
            assert "confidential" in captured.out

    def test_sensitive_handles_exception(self, capsys):
        """Test sensitive handles exceptions gracefully."""
        with patch("stance.cli_exposure.SensitiveDataExposureAnalyzer") as mock_analyzer_class:
            mock_analyzer_class.side_effect = Exception("API error")

            args = argparse.Namespace(
                cloud=None,
                classification=None,
                format="table",
            )

            result = _cmd_exposure_sensitive(args)

            assert result == 1
            captured = capsys.readouterr()
            assert "Error" in captured.out
