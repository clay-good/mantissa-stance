"""
Tests for the Trivy scanner implementation.
"""

import json
import pytest
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

from stance.scanner.trivy import TrivyScanner, scan_image, scan_images
from stance.scanner.base import (
    VulnerabilitySeverity,
    ScanResult,
    ScannerNotAvailableError,
    ScannerTimeoutError,
)


class TestTrivyScanner:
    """Tests for TrivyScanner class."""

    def test_init_default(self):
        """Test default initialization."""
        scanner = TrivyScanner()
        assert scanner._trivy_path is None

    def test_init_custom_path(self):
        """Test initialization with custom path."""
        scanner = TrivyScanner(trivy_path="/usr/local/bin/trivy")
        assert scanner._trivy_path == "/usr/local/bin/trivy"

    @patch("stance.scanner.trivy.subprocess.run")
    @patch("stance.scanner.trivy.shutil.which")
    def test_is_available_true(self, mock_which, mock_run):
        """Test is_available returns True when trivy is installed."""
        mock_which.return_value = "/usr/local/bin/trivy"
        mock_run.return_value = MagicMock(returncode=0)

        scanner = TrivyScanner()
        assert scanner.is_available() is True

    @patch("stance.scanner.trivy.shutil.which")
    def test_is_available_false(self, mock_which):
        """Test is_available returns False when trivy is not installed."""
        mock_which.return_value = None

        scanner = TrivyScanner()
        assert scanner.is_available() is False

    @patch("stance.scanner.trivy.subprocess.run")
    @patch("stance.scanner.trivy.shutil.which")
    def test_get_version(self, mock_which, mock_run):
        """Test getting trivy version."""
        mock_which.return_value = "/usr/local/bin/trivy"
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Version: 0.48.0\nVulnerability DB:\n  Version: 2",
        )

        scanner = TrivyScanner()
        version = scanner.get_version()

        assert "0.48.0" in version

    @patch("stance.scanner.trivy.shutil.which")
    def test_get_version_not_available(self, mock_which):
        """Test get_version returns None when trivy not installed."""
        mock_which.return_value = None

        scanner = TrivyScanner()
        version = scanner.get_version()

        assert version is None

    @patch("stance.scanner.trivy.subprocess.run")
    @patch("stance.scanner.trivy.shutil.which")
    def test_scan_success(self, mock_which, mock_run):
        """Test successful image scan."""
        mock_which.return_value = "/usr/local/bin/trivy"
        trivy_output = {
            "Results": [
                {
                    "Target": "nginx:1.21 (debian 11.6)",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-12345",
                            "PkgName": "openssl",
                            "InstalledVersion": "1.1.1k",
                            "FixedVersion": "1.1.1n",
                            "Severity": "HIGH",
                            "Title": "OpenSSL vulnerability",
                            "Description": "A vulnerability in OpenSSL",
                            "CVSS": {
                                "nvd": {"V3Score": 7.5}
                            },
                        }
                    ],
                }
            ]
        }

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(trivy_output),
            stderr="",
        )

        scanner = TrivyScanner()
        result = scanner.scan("nginx:1.21")

        assert result.image_reference == "nginx:1.21"
        assert result.scanner_name == "trivy"
        assert len(result.vulnerabilities) == 1
        assert result.vulnerabilities[0].vulnerability_id == "CVE-2023-12345"
        assert result.vulnerabilities[0].severity == VulnerabilitySeverity.HIGH

    @patch("stance.scanner.trivy.subprocess.run")
    @patch("stance.scanner.trivy.shutil.which")
    def test_scan_no_vulnerabilities(self, mock_which, mock_run):
        """Test scanning image with no vulnerabilities."""
        mock_which.return_value = "/usr/local/bin/trivy"
        trivy_output = {
            "Results": [
                {
                    "Target": "alpine:3.18",
                    "Vulnerabilities": None,
                }
            ]
        }

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(trivy_output),
            stderr="",
        )

        scanner = TrivyScanner()
        result = scanner.scan("alpine:3.18")

        assert result.image_reference == "alpine:3.18"
        assert len(result.vulnerabilities) == 0

    @patch("stance.scanner.trivy.subprocess.run")
    @patch("stance.scanner.trivy.shutil.which")
    def test_scan_timeout(self, mock_which, mock_run):
        """Test scan timeout."""
        mock_which.return_value = "/usr/local/bin/trivy"
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired("trivy", 300)

        scanner = TrivyScanner()
        with pytest.raises(ScannerTimeoutError):
            scanner.scan("nginx:1.21", timeout_seconds=300)

    @patch("stance.scanner.trivy.subprocess.run")
    @patch("stance.scanner.trivy.shutil.which")
    def test_scan_with_options(self, mock_which, mock_run):
        """Test scan with various options."""
        mock_which.return_value = "/usr/local/bin/trivy"
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"Results": []}),
            stderr="",
        )

        scanner = TrivyScanner()
        scanner.scan(
            "nginx:1.21",
            skip_db_update=True,
            ignore_unfixed=True,
            timeout_seconds=600,
        )

        # Verify correct arguments were passed - check last call (the scan, not version)
        # subprocess.run might be called multiple times
        call_args_list = mock_run.call_args_list
        # Find the call that has "image" in it (the scan command)
        scan_call = None
        for call in call_args_list:
            cmd = call[0][0]
            if "image" in cmd:
                scan_call = call
                break

        assert scan_call is not None, "No scan command found in calls"
        cmd = scan_call[0][0]
        assert "--skip-db-update" in cmd
        assert "--ignore-unfixed" in cmd

    @patch("stance.scanner.trivy.shutil.which")
    def test_scan_not_available(self, mock_which):
        """Test scan raises error when trivy not available."""
        mock_which.return_value = None

        scanner = TrivyScanner()
        with pytest.raises(ScannerNotAvailableError):
            scanner.scan("nginx:1.21")


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    @patch("stance.scanner.trivy.subprocess.run")
    @patch("stance.scanner.trivy.shutil.which")
    def test_scan_image(self, mock_which, mock_run):
        """Test scan_image convenience function."""
        mock_which.return_value = "/usr/local/bin/trivy"
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"Results": []}),
            stderr="",
        )

        result = scan_image("nginx:1.21")

        assert isinstance(result, ScanResult)
        assert result.image_reference == "nginx:1.21"

    @patch("stance.scanner.trivy.subprocess.run")
    @patch("stance.scanner.trivy.shutil.which")
    def test_scan_images(self, mock_which, mock_run):
        """Test scan_images convenience function."""
        mock_which.return_value = "/usr/local/bin/trivy"
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"Results": []}),
            stderr="",
        )

        results = scan_images(["nginx:1.21", "alpine:3.18"])

        assert len(results) == 2
        assert results[0].image_reference == "nginx:1.21"
        assert results[1].image_reference == "alpine:3.18"


class TestTrivyOutputParsing:
    """Tests for Trivy output parsing."""

    @patch("stance.scanner.trivy.subprocess.run")
    @patch("stance.scanner.trivy.shutil.which")
    def test_parse_multiple_targets(self, mock_which, mock_run):
        """Test parsing output with multiple targets."""
        mock_which.return_value = "/usr/local/bin/trivy"
        trivy_output = {
            "Results": [
                {
                    "Target": "test:latest (debian 11)",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-0001",
                            "PkgName": "pkg1",
                            "InstalledVersion": "1.0",
                            "Severity": "HIGH",
                        },
                    ],
                },
                {
                    "Target": "usr/local/lib/python3.9/site-packages",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-0002",
                            "PkgName": "requests",
                            "InstalledVersion": "2.20.0",
                            "Severity": "MEDIUM",
                        },
                    ],
                },
            ]
        }

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(trivy_output),
            stderr="",
        )

        scanner = TrivyScanner()
        result = scanner.scan("test:latest")

        # Should aggregate vulnerabilities from all targets
        assert len(result.vulnerabilities) == 2

    @patch("stance.scanner.trivy.subprocess.run")
    @patch("stance.scanner.trivy.shutil.which")
    def test_parse_cvss_scores(self, mock_which, mock_run):
        """Test parsing CVSS scores from trivy output."""
        mock_which.return_value = "/usr/local/bin/trivy"
        trivy_output = {
            "Results": [
                {
                    "Target": "test:latest",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-0001",
                            "PkgName": "pkg1",
                            "InstalledVersion": "1.0",
                            "Severity": "CRITICAL",
                            "CVSS": {
                                "nvd": {
                                    "V3Score": 9.8,
                                    "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                },
                            },
                        },
                    ],
                }
            ]
        }

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(trivy_output),
            stderr="",
        )

        scanner = TrivyScanner()
        result = scanner.scan("test:latest")

        vuln = result.vulnerabilities[0]
        assert vuln.cvss_score == 9.8

    @patch("stance.scanner.trivy.subprocess.run")
    @patch("stance.scanner.trivy.shutil.which")
    def test_parse_references(self, mock_which, mock_run):
        """Test parsing references from trivy output."""
        mock_which.return_value = "/usr/local/bin/trivy"
        trivy_output = {
            "Results": [
                {
                    "Target": "test:latest",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-0001",
                            "PkgName": "pkg1",
                            "InstalledVersion": "1.0",
                            "Severity": "HIGH",
                            "References": [
                                "https://nvd.nist.gov/vuln/detail/CVE-2023-0001",
                                "https://github.com/advisories/GHSA-xxxx",
                            ],
                        },
                    ],
                }
            ]
        }

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(trivy_output),
            stderr="",
        )

        scanner = TrivyScanner()
        result = scanner.scan("test:latest")

        vuln = result.vulnerabilities[0]
        assert len(vuln.references) == 2
        assert "nvd.nist.gov" in vuln.references[0]
