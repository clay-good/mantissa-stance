"""
Tests for the container image scanner base module.
"""

import pytest
from datetime import datetime
from unittest.mock import Mock, patch

from stance.scanner.base import (
    VulnerabilitySeverity,
    Vulnerability,
    ScanResult,
    ImageScanner,
    ScannerError,
    ScannerNotAvailableError,
    ScannerTimeoutError,
)
from stance.models.finding import Finding, Severity


class TestVulnerabilitySeverity:
    """Tests for VulnerabilitySeverity enum."""

    def test_severity_values(self):
        """Test that all severity values are defined."""
        assert VulnerabilitySeverity.CRITICAL.value == "CRITICAL"
        assert VulnerabilitySeverity.HIGH.value == "HIGH"
        assert VulnerabilitySeverity.MEDIUM.value == "MEDIUM"
        assert VulnerabilitySeverity.LOW.value == "LOW"
        assert VulnerabilitySeverity.UNKNOWN.value == "UNKNOWN"

    def test_from_string(self):
        """Test creating severity from string."""
        assert VulnerabilitySeverity.from_string("CRITICAL") == VulnerabilitySeverity.CRITICAL
        assert VulnerabilitySeverity.from_string("critical") == VulnerabilitySeverity.CRITICAL
        assert VulnerabilitySeverity.from_string("HIGH") == VulnerabilitySeverity.HIGH
        assert VulnerabilitySeverity.from_string("invalid") == VulnerabilitySeverity.UNKNOWN

    def test_to_stance_severity(self):
        """Test converting to Stance severity."""
        assert VulnerabilitySeverity.CRITICAL.to_stance_severity() == Severity.CRITICAL
        assert VulnerabilitySeverity.HIGH.to_stance_severity() == Severity.HIGH
        assert VulnerabilitySeverity.MEDIUM.to_stance_severity() == Severity.MEDIUM
        assert VulnerabilitySeverity.LOW.to_stance_severity() == Severity.LOW
        assert VulnerabilitySeverity.UNKNOWN.to_stance_severity() == Severity.INFO


class TestVulnerability:
    """Tests for Vulnerability dataclass."""

    def test_basic_vulnerability(self):
        """Test creating a basic vulnerability."""
        vuln = Vulnerability(
            vulnerability_id="CVE-2023-12345",
            package_name="openssl",
            installed_version="1.1.1k",
            severity=VulnerabilitySeverity.HIGH,
        )

        assert vuln.vulnerability_id == "CVE-2023-12345"
        assert vuln.package_name == "openssl"
        assert vuln.installed_version == "1.1.1k"
        assert vuln.severity == VulnerabilitySeverity.HIGH
        assert vuln.fixed_version is None

    def test_vulnerability_with_fix(self):
        """Test vulnerability with fix available."""
        vuln = Vulnerability(
            vulnerability_id="CVE-2023-12345",
            package_name="openssl",
            installed_version="1.1.1k",
            fixed_version="1.1.1n",
            is_fixable=True,
            severity=VulnerabilitySeverity.HIGH,
        )

        assert vuln.fixed_version == "1.1.1n"
        assert vuln.is_fixable is True

    def test_vulnerability_with_cvss(self):
        """Test vulnerability with CVSS score."""
        vuln = Vulnerability(
            vulnerability_id="CVE-2023-12345",
            package_name="openssl",
            installed_version="1.1.1k",
            severity=VulnerabilitySeverity.CRITICAL,
            cvss_score=9.8,
        )

        assert vuln.cvss_score == 9.8

    def test_to_finding(self):
        """Test converting vulnerability to Finding."""
        vuln = Vulnerability(
            vulnerability_id="CVE-2023-12345",
            package_name="openssl",
            installed_version="1.1.1k",
            fixed_version="1.1.1n",
            is_fixable=True,
            severity=VulnerabilitySeverity.HIGH,
            title="OpenSSL buffer overflow",
            description="A buffer overflow vulnerability in OpenSSL.",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-12345"],
        )

        finding = vuln.to_finding(image_reference="nginx:1.21")

        assert isinstance(finding, Finding)
        assert finding.severity == Severity.HIGH
        assert "CVE-2023-12345" in finding.title
        assert "openssl" in finding.title
        assert "nginx:1.21" in finding.asset_id


class TestScanResult:
    """Tests for ScanResult dataclass."""

    def test_empty_scan_result(self):
        """Test scan result with no vulnerabilities."""
        result = ScanResult(
            image_reference="nginx:1.21",
            scanner_name="trivy",
            vulnerabilities=[],
        )

        assert result.image_reference == "nginx:1.21"
        assert result.vulnerability_count == 0
        assert result.critical_count == 0
        assert result.high_count == 0
        assert result.fixable_count == 0

    def test_scan_result_with_vulnerabilities(self):
        """Test scan result with vulnerabilities."""
        vulns = [
            Vulnerability(
                vulnerability_id="CVE-2023-0001",
                package_name="pkg1",
                installed_version="1.0",
                severity=VulnerabilitySeverity.CRITICAL,
            ),
            Vulnerability(
                vulnerability_id="CVE-2023-0002",
                package_name="pkg2",
                installed_version="2.0",
                severity=VulnerabilitySeverity.HIGH,
                fixed_version="2.1",
                is_fixable=True,
            ),
            Vulnerability(
                vulnerability_id="CVE-2023-0003",
                package_name="pkg3",
                installed_version="3.0",
                severity=VulnerabilitySeverity.MEDIUM,
            ),
        ]

        result = ScanResult(
            image_reference="myapp:latest",
            scanner_name="trivy",
            vulnerabilities=vulns,
        )

        assert result.vulnerability_count == 3
        assert result.critical_count == 1
        assert result.high_count == 1
        assert result.medium_count == 1
        assert result.low_count == 0
        assert result.fixable_count == 1

    def test_scan_result_to_findings(self):
        """Test converting scan result to findings."""
        vulns = [
            Vulnerability(
                vulnerability_id="CVE-2023-0001",
                package_name="pkg1",
                installed_version="1.0",
                severity=VulnerabilitySeverity.HIGH,
            ),
        ]

        result = ScanResult(
            image_reference="myapp:latest",
            scanner_name="trivy",
            vulnerabilities=vulns,
        )

        findings = result.to_findings()
        assert len(findings) == 1
        assert "myapp:latest" in findings[0].asset_id


class TestScannerErrors:
    """Tests for scanner error classes."""

    def test_scanner_error(self):
        """Test base scanner error."""
        error = ScannerError("Scan failed")
        assert str(error) == "Scan failed"

    def test_scanner_not_available_error(self):
        """Test scanner not available error."""
        error = ScannerNotAvailableError("trivy not found")
        assert "trivy" in str(error)

    def test_scanner_timeout_error(self):
        """Test scanner timeout error."""
        error = ScannerTimeoutError("Scan timed out after 300s")
        assert "300" in str(error)


class TestImageScannerABC:
    """Tests for ImageScanner abstract base class."""

    def test_cannot_instantiate_directly(self):
        """Test that ImageScanner cannot be instantiated directly."""
        with pytest.raises(TypeError):
            ImageScanner()

    def test_concrete_implementation(self):
        """Test creating a concrete implementation."""
        class MockScanner(ImageScanner):
            scanner_name = "mock"

            def is_available(self) -> bool:
                return True

            def get_version(self):
                return "1.0.0"

            def scan(self, image_reference, **kwargs):
                return ScanResult(
                    image_reference=image_reference,
                    scanner_name=self.scanner_name,
                    vulnerabilities=[],
                )

        scanner = MockScanner()
        assert scanner.is_available()
        assert scanner.get_version() == "1.0.0"

        result = scanner.scan("nginx:1.21")
        assert result.image_reference == "nginx:1.21"
