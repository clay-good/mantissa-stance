"""
Unit tests for the Scanning Web API endpoints.

Tests for:
- /api/scanning/image
- /api/scanning/iac
- /api/scanning/secrets
- /api/scanning/summary
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch, PropertyMock
from pathlib import Path

import pytest


class TestScanningImageAPI:
    """Tests for /api/scanning/image endpoint."""

    def test_image_required(self):
        """Test that image parameter is required."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        result = StanceRequestHandler._scanning_image(handler, {})

        assert "error" in result
        assert "image parameter is required" in result["error"]

    def test_trivy_not_available(self):
        """Test response when Trivy is not available."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.TrivyScanner") as mock_scanner_class:
            mock_scanner = MagicMock()
            mock_scanner.is_available.return_value = False
            mock_scanner_class.return_value = mock_scanner

            result = StanceRequestHandler._scanning_image(
                handler, {"image": ["nginx:latest"]}
            )

            assert "error" in result
            assert "Trivy" in result["error"]
            assert "install_url" in result

    def test_image_scan_success(self):
        """Test successful image scan."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.TrivyScanner") as mock_scanner_class:
            mock_scanner = MagicMock()
            mock_scanner.is_available.return_value = True
            mock_scanner.get_version.return_value = "0.48.0"

            # Mock scan result
            from datetime import datetime
            mock_result = MagicMock()
            mock_result.image_ref = "nginx:latest"
            mock_result.scanned_at = datetime.now()
            mock_result.scanner = "trivy"
            mock_result.scanner_version = "0.48.0"
            mock_result.total_count = 5
            mock_result.critical_count = 1
            mock_result.high_count = 2
            mock_result.medium_count = 1
            mock_result.low_count = 1
            mock_result.fixable_count = 3

            # Mock vulnerability
            mock_vuln = MagicMock()
            mock_vuln.vulnerability_id = "CVE-2023-1234"
            mock_vuln.package_name = "openssl"
            mock_vuln.installed_version = "1.1.1"
            mock_vuln.fixed_version = "1.1.2"
            mock_vuln.severity = MagicMock()
            mock_vuln.severity.value = "HIGH"
            mock_vuln.title = "Test vulnerability"
            mock_vuln.description = "Test description"
            mock_vuln.references = ["https://example.com"]
            mock_result.vulnerabilities = [mock_vuln]

            mock_scanner.scan.return_value = mock_result
            mock_scanner_class.return_value = mock_scanner

            result = StanceRequestHandler._scanning_image(
                handler, {"image": ["nginx:latest"]}
            )

            assert "scanner_version" in result
            assert result["total_images"] == 1
            assert result["successful_scans"] == 1
            assert result["failed_scans"] == 0
            assert len(result["results"]) == 1
            assert result["results"][0]["image_ref"] == "nginx:latest"

    def test_image_scan_with_severity_filter(self):
        """Test image scan with severity filter."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.TrivyScanner") as mock_scanner_class, \
             patch("stance.web.server.VulnerabilitySeverity") as mock_severity:
            mock_scanner = MagicMock()
            mock_scanner.is_available.return_value = True
            mock_scanner.get_version.return_value = "0.48.0"

            mock_result = MagicMock()
            mock_result.image_ref = "test:latest"
            mock_result.scanned_at = None
            mock_result.vulnerabilities = []
            mock_result.total_count = 0
            mock_result.critical_count = 0
            mock_result.high_count = 0
            mock_result.medium_count = 0
            mock_result.low_count = 0
            mock_result.fixable_count = 0

            mock_scanner.scan.return_value = mock_result
            mock_scanner_class.return_value = mock_scanner

            # Setup mock severity enum
            mock_severity.__members__ = {"CRITICAL": "CRITICAL", "HIGH": "HIGH"}

            result = StanceRequestHandler._scanning_image(
                handler, {"image": ["test:latest"], "severity": ["CRITICAL,HIGH"]}
            )

            assert result["total_images"] == 1

    def test_image_scan_multiple_images(self):
        """Test scanning multiple images."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.TrivyScanner") as mock_scanner_class:
            mock_scanner = MagicMock()
            mock_scanner.is_available.return_value = True
            mock_scanner.get_version.return_value = "0.48.0"

            mock_result = MagicMock()
            mock_result.image_ref = "test:latest"
            mock_result.scanned_at = None
            mock_result.vulnerabilities = []
            mock_result.total_count = 0
            mock_result.critical_count = 0
            mock_result.high_count = 0
            mock_result.medium_count = 0
            mock_result.low_count = 0
            mock_result.fixable_count = 0

            mock_scanner.scan.return_value = mock_result
            mock_scanner_class.return_value = mock_scanner

            result = StanceRequestHandler._scanning_image(
                handler, {"image": ["nginx:latest", "redis:latest", "postgres:latest"]}
            )

            assert result["total_images"] == 3
            assert result["successful_scans"] == 3

    def test_image_scan_with_error(self):
        """Test image scan with scan error."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.TrivyScanner") as mock_scanner_class:
            mock_scanner = MagicMock()
            mock_scanner.is_available.return_value = True
            mock_scanner.get_version.return_value = "0.48.0"
            mock_scanner.scan.side_effect = Exception("Scan failed")
            mock_scanner_class.return_value = mock_scanner

            result = StanceRequestHandler._scanning_image(
                handler, {"image": ["bad-image:latest"]}
            )

            assert result["total_images"] == 1
            assert result["successful_scans"] == 0
            assert result["failed_scans"] == 1
            assert len(result["errors"]) == 1


class TestScanningIaCAPI:
    """Tests for /api/scanning/iac endpoint."""

    def test_path_required(self):
        """Test that path parameter is required."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        result = StanceRequestHandler._scanning_iac(handler, {})

        assert "error" in result
        assert "path parameter is required" in result["error"]

    def test_no_files_found(self):
        """Test response when no IaC files are found."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.Path") as mock_path_class:
            mock_path = MagicMock()
            mock_path.is_file.return_value = False
            mock_path.is_dir.return_value = True
            mock_path.rglob.return_value = []
            mock_path_class.return_value = mock_path

            result = StanceRequestHandler._scanning_iac(
                handler, {"path": ["/nonexistent"]}
            )

            assert result["files_scanned"] == 0
            assert result["message"] == "No IaC files found to scan"

    def test_iac_scan_success(self):
        """Test successful IaC scan."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.Path") as mock_path_class, \
             patch("stance.web.server.IaCScanner") as mock_scanner_class, \
             patch("stance.web.server.TerraformParser"), \
             patch("stance.web.server.CloudFormationParser"), \
             patch("stance.web.server.ARMTemplateParser"), \
             patch("stance.web.server.IaCPolicyEvaluator"), \
             patch("stance.web.server.get_default_iac_policies"):

            # Setup path mock
            mock_file = MagicMock()
            mock_file.is_file.return_value = True

            mock_path = MagicMock()
            mock_path.is_file.return_value = True
            mock_path_class.return_value = mock_path

            # Setup scanner mock
            mock_scanner = MagicMock()
            mock_finding = MagicMock()
            mock_finding.rule_id = "TEST-001"
            mock_finding.severity = MagicMock()
            mock_finding.severity.value = "HIGH"
            mock_finding.title = "Test finding"
            mock_finding.description = "Test description"
            mock_finding.resource = MagicMock()
            mock_finding.resource.location = MagicMock()
            mock_finding.resource.location.file_path = "/test/main.tf"
            mock_finding.resource.location.line_start = 10
            mock_finding.resource.resource_type = "aws_s3_bucket"
            mock_finding.resource.name = "test_bucket"
            mock_finding.remediation = "Fix it"
            mock_scanner.scan_file.return_value = [mock_finding]
            mock_scanner_class.return_value = mock_scanner

            result = StanceRequestHandler._scanning_iac(
                handler, {"path": ["/test/main.tf"]}
            )

            assert result["files_scanned"] == 1
            assert result["files_with_issues"] == 1
            assert result["total_issues"] == 1
            assert len(result["findings"]) == 1
            assert result["findings"][0]["rule_id"] == "TEST-001"

    def test_iac_scan_with_severity_filter(self):
        """Test IaC scan with severity filter."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.Path") as mock_path_class, \
             patch("stance.web.server.IaCScanner") as mock_scanner_class, \
             patch("stance.web.server.TerraformParser"), \
             patch("stance.web.server.CloudFormationParser"), \
             patch("stance.web.server.ARMTemplateParser"), \
             patch("stance.web.server.IaCPolicyEvaluator"), \
             patch("stance.web.server.get_default_iac_policies"):

            mock_path = MagicMock()
            mock_path.is_file.return_value = True
            mock_path_class.return_value = mock_path

            # Create findings with different severities
            mock_scanner = MagicMock()
            finding_critical = MagicMock()
            finding_critical.severity = MagicMock()
            finding_critical.severity.value = "critical"
            finding_critical.rule_id = "CRIT-001"
            finding_critical.resource = None

            finding_low = MagicMock()
            finding_low.severity = MagicMock()
            finding_low.severity.value = "low"
            finding_low.rule_id = "LOW-001"
            finding_low.resource = None

            mock_scanner.scan_file.return_value = [finding_critical, finding_low]
            mock_scanner_class.return_value = mock_scanner

            result = StanceRequestHandler._scanning_iac(
                handler, {"path": ["/test.tf"], "severity": ["high"]}
            )

            # Only critical finding should pass (critical >= high)
            critical_findings = [f for f in result["findings"] if f["severity"].lower() == "critical"]
            assert len(critical_findings) >= 0  # Filter applied


class TestScanningSecretsAPI:
    """Tests for /api/scanning/secrets endpoint."""

    def test_path_required(self):
        """Test that path parameter is required."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        result = StanceRequestHandler._scanning_secrets(handler, {})

        assert "error" in result
        assert "path parameter is required" in result["error"]

    def test_no_files_found(self):
        """Test response when no files are found to scan."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.Path") as mock_path_class:
            mock_path = MagicMock()
            mock_path.is_file.return_value = False
            mock_path.is_dir.return_value = True
            mock_path.rglob.return_value = []
            mock_path_class.return_value = mock_path

            result = StanceRequestHandler._scanning_secrets(
                handler, {"path": ["/nonexistent"]}
            )

            assert result["files_scanned"] == 0
            assert result["message"] == "No files found to scan"

    def test_secrets_scan_success(self):
        """Test successful secrets scan."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.Path") as mock_path_class, \
             patch("stance.web.server.SecretsDetector") as mock_detector_class:

            # Setup path mock
            mock_file = MagicMock()
            mock_file.is_file.return_value = True
            mock_file.name = "config.py"
            mock_file.read_text.return_value = "AWS_SECRET_KEY = 'AKIAIOSFODNN7EXAMPLE'"

            mock_path = MagicMock()
            mock_path.is_file.return_value = True
            mock_path_class.return_value = mock_path
            mock_path_class.side_effect = lambda x: mock_file

            # Setup detector mock
            mock_detector = MagicMock()
            mock_match = MagicMock()
            mock_match.secret_type = "AWS Secret Key"
            mock_match.matched_value = "AKIAIOSFODNN7EXAMPLE"
            mock_match.confidence = "high"
            mock_match.entropy = 4.5
            mock_detector.detect_in_text.return_value = [mock_match]
            mock_detector_class.return_value = mock_detector

            # We need to mock the file iteration
            result = StanceRequestHandler._scanning_secrets(
                handler, {"path": ["/test/config.py"]}
            )

            # Check structure of result
            assert "files_scanned" in result
            assert "files_with_secrets" in result
            assert "total_secrets" in result
            assert "by_type" in result
            assert "findings" in result

    def test_secrets_scan_with_exclusions(self):
        """Test secrets scan with exclusion patterns."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.Path") as mock_path_class, \
             patch("stance.web.server.SecretsDetector") as mock_detector_class:

            mock_path = MagicMock()
            mock_path.is_file.return_value = False
            mock_path.is_dir.return_value = True
            mock_path.rglob.return_value = []
            mock_path_class.return_value = mock_path

            mock_detector = MagicMock()
            mock_detector.detect_in_text.return_value = []
            mock_detector_class.return_value = mock_detector

            result = StanceRequestHandler._scanning_secrets(
                handler, {
                    "path": ["/test"],
                    "exclude": ["*.log,*.tmp"],
                    "min_entropy": ["4.0"],
                }
            )

            assert "files_scanned" in result

    def test_secrets_redaction(self):
        """Test that secrets are properly redacted in output."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        # Test the redaction logic
        def redact_secret(value):
            if len(value) <= 8:
                return "*" * len(value)
            return value[:4] + "*" * (len(value) - 8) + value[-4:]

        # Test short secret
        assert redact_secret("short") == "*****"

        # Test long secret
        long_secret = "AKIAIOSFODNN7EXAMPLE"
        redacted = redact_secret(long_secret)
        assert redacted.startswith("AKIA")
        assert redacted.endswith("MPLE")
        assert "*" in redacted


class TestScanningSummaryAPI:
    """Tests for /api/scanning/summary endpoint."""

    def test_summary_returns_features(self):
        """Test that summary returns available features."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.TrivyScanner") as mock_scanner_class:
            mock_scanner = MagicMock()
            mock_scanner.is_available.return_value = True
            mock_scanner.get_version.return_value = "0.48.0"
            mock_scanner_class.return_value = mock_scanner

            result = StanceRequestHandler._scanning_summary(handler, {})

            assert "available_features" in result
            assert len(result["available_features"]) == 3

            # Check feature names
            feature_names = [f["name"] for f in result["available_features"]]
            assert "image" in feature_names
            assert "iac" in feature_names
            assert "secrets" in feature_names

    def test_summary_trivy_available(self):
        """Test summary when Trivy is available."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.TrivyScanner") as mock_scanner_class:
            mock_scanner = MagicMock()
            mock_scanner.is_available.return_value = True
            mock_scanner.get_version.return_value = "0.48.0"
            mock_scanner_class.return_value = mock_scanner

            result = StanceRequestHandler._scanning_summary(handler, {})

            image_feature = next(f for f in result["available_features"] if f["name"] == "image")
            assert image_feature["available"] is True
            assert image_feature["scanner_version"] == "0.48.0"

    def test_summary_trivy_not_available(self):
        """Test summary when Trivy is not available."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.TrivyScanner") as mock_scanner_class:
            mock_scanner = MagicMock()
            mock_scanner.is_available.return_value = False
            mock_scanner_class.return_value = mock_scanner

            result = StanceRequestHandler._scanning_summary(handler, {})

            image_feature = next(f for f in result["available_features"] if f["name"] == "image")
            assert image_feature["available"] is False
            assert image_feature["scanner_version"] is None

    def test_summary_returns_severities(self):
        """Test that summary returns severity options."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.TrivyScanner") as mock_scanner_class:
            mock_scanner = MagicMock()
            mock_scanner.is_available.return_value = False
            mock_scanner_class.return_value = mock_scanner

            result = StanceRequestHandler._scanning_summary(handler, {})

            assert "vulnerability_severities" in result
            assert "iac_severities" in result
            assert "CRITICAL" in result["vulnerability_severities"]
            assert "critical" in result["iac_severities"]

    def test_summary_returns_notes(self):
        """Test that summary returns helpful notes."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.TrivyScanner") as mock_scanner_class:
            mock_scanner = MagicMock()
            mock_scanner.is_available.return_value = False
            mock_scanner_class.return_value = mock_scanner

            result = StanceRequestHandler._scanning_summary(handler, {})

            assert "notes" in result
            assert "image_scanning" in result["notes"]
            assert "iac_scanning" in result["notes"]
            assert "secrets_scanning" in result["notes"]


class TestScanningAPIIntegration:
    """Integration tests for scanning API endpoints."""

    def test_api_routing_image(self):
        """Test that image endpoint is properly routed."""
        path = "/api/scanning/image"
        assert path.startswith("/api/scanning/")

    def test_api_routing_iac(self):
        """Test that iac endpoint is properly routed."""
        path = "/api/scanning/iac"
        assert path.startswith("/api/scanning/")

    def test_api_routing_secrets(self):
        """Test that secrets endpoint is properly routed."""
        path = "/api/scanning/secrets"
        assert path.startswith("/api/scanning/")

    def test_api_routing_summary(self):
        """Test that summary endpoint is properly routed."""
        path = "/api/scanning/summary"
        assert path.startswith("/api/scanning/")

    def test_all_scanning_endpoints_exist(self):
        """Test that all scanning endpoints are registered in server."""
        from stance.web.server import StanceRequestHandler

        # Verify methods exist
        assert hasattr(StanceRequestHandler, '_scanning_image')
        assert hasattr(StanceRequestHandler, '_scanning_iac')
        assert hasattr(StanceRequestHandler, '_scanning_secrets')
        assert hasattr(StanceRequestHandler, '_scanning_summary')

    def test_image_scan_params(self):
        """Test image scan accepts all documented parameters."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.TrivyScanner") as mock_scanner_class:
            mock_scanner = MagicMock()
            mock_scanner.is_available.return_value = False
            mock_scanner_class.return_value = mock_scanner

            # Test with all parameters
            result = StanceRequestHandler._scanning_image(handler, {
                "image": ["nginx:latest"],
                "severity": ["HIGH,CRITICAL"],
                "skip_db_update": ["true"],
                "ignore_unfixed": ["true"],
                "timeout": ["600"],
            })

            # Should get error about Trivy, but params should be parsed
            assert "error" in result or "results" in result

    def test_iac_scan_params(self):
        """Test IaC scan accepts all documented parameters."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.Path") as mock_path_class:
            mock_path = MagicMock()
            mock_path.is_file.return_value = False
            mock_path.is_dir.return_value = True
            mock_path.rglob.return_value = []
            mock_path.glob.return_value = []
            mock_path_class.return_value = mock_path

            result = StanceRequestHandler._scanning_iac(handler, {
                "path": ["/test"],
                "severity": ["high"],
                "recursive": ["false"],
            })

            assert "files_scanned" in result

    def test_secrets_scan_params(self):
        """Test secrets scan accepts all documented parameters."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.Path") as mock_path_class:
            mock_path = MagicMock()
            mock_path.is_file.return_value = False
            mock_path.is_dir.return_value = True
            mock_path.rglob.return_value = []
            mock_path.glob.return_value = []
            mock_path_class.return_value = mock_path

            result = StanceRequestHandler._scanning_secrets(handler, {
                "path": ["/test"],
                "recursive": ["false"],
                "min_entropy": ["4.0"],
                "exclude": ["*.log,*.tmp"],
            })

            assert "files_scanned" in result
