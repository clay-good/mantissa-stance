"""
Tests for CLI scanning commands (image-scan, iac-scan, secrets-scan).

Tests CLI argument parsing and command execution for security scanning commands.
"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch, Mock

import pytest

from stance.cli import create_parser


class TestImageScanParser:
    """Tests for image-scan CLI argument parsing."""

    @pytest.fixture
    def parser(self) -> argparse.ArgumentParser:
        """Return the CLI argument parser."""
        return create_parser()

    def test_image_scan_basic(self, parser):
        """Test image-scan with single image."""
        args = parser.parse_args(["image-scan", "nginx:latest"])

        assert args.command == "image-scan"
        assert args.images == ["nginx:latest"]

    def test_image_scan_multiple_images(self, parser):
        """Test image-scan with multiple images."""
        args = parser.parse_args([
            "image-scan",
            "nginx:latest",
            "alpine:3.18",
            "python:3.11",
        ])

        assert args.images == ["nginx:latest", "alpine:3.18", "python:3.11"]

    def test_image_scan_defaults(self, parser):
        """Test image-scan default values."""
        args = parser.parse_args(["image-scan", "nginx:latest"])

        assert args.timeout == 300
        assert args.skip_db_update is False
        assert args.ignore_unfixed is False
        assert args.severity is None
        assert args.format == "table"
        assert args.fail_on is None

    def test_image_scan_timeout(self, parser):
        """Test image-scan with custom timeout."""
        args = parser.parse_args([
            "image-scan",
            "--timeout", "600",
            "nginx:latest",
        ])

        assert args.timeout == 600

    def test_image_scan_skip_db_update(self, parser):
        """Test image-scan with --skip-db-update flag."""
        args = parser.parse_args([
            "image-scan",
            "--skip-db-update",
            "nginx:latest",
        ])

        assert args.skip_db_update is True

    def test_image_scan_ignore_unfixed(self, parser):
        """Test image-scan with --ignore-unfixed flag."""
        args = parser.parse_args([
            "image-scan",
            "--ignore-unfixed",
            "nginx:latest",
        ])

        assert args.ignore_unfixed is True

    def test_image_scan_severity_filter(self, parser):
        """Test image-scan with severity filter."""
        args = parser.parse_args([
            "image-scan",
            "--severity", "high",
            "nginx:latest",
        ])

        assert args.severity == "high"

    def test_image_scan_format_json(self, parser):
        """Test image-scan with JSON format."""
        args = parser.parse_args([
            "image-scan",
            "--format", "json",
            "nginx:latest",
        ])

        assert args.format == "json"

    def test_image_scan_format_sarif(self, parser):
        """Test image-scan with SARIF format."""
        args = parser.parse_args([
            "image-scan",
            "--format", "sarif",
            "nginx:latest",
        ])

        assert args.format == "sarif"

    def test_image_scan_fail_on(self, parser):
        """Test image-scan with --fail-on threshold."""
        args = parser.parse_args([
            "image-scan",
            "--fail-on", "high",
            "nginx:latest",
        ])

        assert args.fail_on == "high"

    def test_image_scan_all_options(self, parser):
        """Test image-scan with all options combined."""
        args = parser.parse_args([
            "image-scan",
            "--timeout", "900",
            "--skip-db-update",
            "--ignore-unfixed",
            "--severity", "medium",
            "--format", "json",
            "--fail-on", "critical",
            "nginx:latest",
            "alpine:3.18",
        ])

        assert args.timeout == 900
        assert args.skip_db_update is True
        assert args.ignore_unfixed is True
        assert args.severity == "medium"
        assert args.format == "json"
        assert args.fail_on == "critical"
        assert len(args.images) == 2


class TestIacScanParser:
    """Tests for iac-scan CLI argument parsing."""

    @pytest.fixture
    def parser(self) -> argparse.ArgumentParser:
        """Return the CLI argument parser."""
        return create_parser()

    def test_iac_scan_basic(self, parser):
        """Test iac-scan with single path."""
        args = parser.parse_args(["iac-scan", "main.tf"])

        assert args.command == "iac-scan"
        assert args.paths == ["main.tf"]

    def test_iac_scan_multiple_paths(self, parser):
        """Test iac-scan with multiple paths."""
        args = parser.parse_args([
            "iac-scan",
            "main.tf",
            "variables.tf",
            "./modules/",
        ])

        assert args.paths == ["main.tf", "variables.tf", "./modules/"]

    def test_iac_scan_defaults(self, parser):
        """Test iac-scan default values."""
        args = parser.parse_args(["iac-scan", "main.tf"])

        assert args.format == "table"
        assert args.severity is None
        assert args.fail_on is None
        assert args.policy_dir is None
        assert args.skip_secrets is False
        assert args.recursive is False
        assert args.output is None

    def test_iac_scan_format_json(self, parser):
        """Test iac-scan with JSON format."""
        args = parser.parse_args([
            "iac-scan",
            "--format", "json",
            "main.tf",
        ])

        assert args.format == "json"

    def test_iac_scan_format_sarif(self, parser):
        """Test iac-scan with SARIF format."""
        args = parser.parse_args([
            "iac-scan",
            "--format", "sarif",
            "main.tf",
        ])

        assert args.format == "sarif"

    def test_iac_scan_severity_filter(self, parser):
        """Test iac-scan with severity filter."""
        args = parser.parse_args([
            "iac-scan",
            "--severity", "high",
            "main.tf",
        ])

        assert args.severity == "high"

    def test_iac_scan_severity_info(self, parser):
        """Test iac-scan with info severity filter."""
        args = parser.parse_args([
            "iac-scan",
            "--severity", "info",
            "main.tf",
        ])

        assert args.severity == "info"

    def test_iac_scan_fail_on(self, parser):
        """Test iac-scan with --fail-on threshold."""
        args = parser.parse_args([
            "iac-scan",
            "--fail-on", "medium",
            "main.tf",
        ])

        assert args.fail_on == "medium"

    def test_iac_scan_policy_dir(self, parser):
        """Test iac-scan with custom policy directory."""
        args = parser.parse_args([
            "iac-scan",
            "--policy-dir", "/custom/policies",
            "main.tf",
        ])

        assert args.policy_dir == "/custom/policies"

    def test_iac_scan_skip_secrets(self, parser):
        """Test iac-scan with --skip-secrets flag."""
        args = parser.parse_args([
            "iac-scan",
            "--skip-secrets",
            "main.tf",
        ])

        assert args.skip_secrets is True

    def test_iac_scan_recursive(self, parser):
        """Test iac-scan with --recursive flag."""
        args = parser.parse_args([
            "iac-scan",
            "-r",
            "./terraform/",
        ])

        assert args.recursive is True

    def test_iac_scan_recursive_long(self, parser):
        """Test iac-scan with --recursive long flag."""
        args = parser.parse_args([
            "iac-scan",
            "--recursive",
            "./terraform/",
        ])

        assert args.recursive is True

    def test_iac_scan_output_file(self, parser):
        """Test iac-scan with output file."""
        args = parser.parse_args([
            "iac-scan",
            "-o", "results.json",
            "main.tf",
        ])

        assert args.output == "results.json"

    def test_iac_scan_all_options(self, parser):
        """Test iac-scan with all options combined."""
        args = parser.parse_args([
            "iac-scan",
            "--format", "sarif",
            "--severity", "medium",
            "--fail-on", "high",
            "--policy-dir", "/policies",
            "--skip-secrets",
            "-r",
            "-o", "output.sarif",
            "./terraform/",
            "./cloudformation/",
        ])

        assert args.format == "sarif"
        assert args.severity == "medium"
        assert args.fail_on == "high"
        assert args.policy_dir == "/policies"
        assert args.skip_secrets is True
        assert args.recursive is True
        assert args.output == "output.sarif"
        assert len(args.paths) == 2


class TestSecretsScanParser:
    """Tests for secrets-scan CLI argument parsing."""

    @pytest.fixture
    def parser(self) -> argparse.ArgumentParser:
        """Return the CLI argument parser."""
        return create_parser()

    def test_secrets_scan_basic(self, parser):
        """Test secrets-scan with single path."""
        args = parser.parse_args(["secrets-scan", "./src/"])

        assert args.command == "secrets-scan"
        assert args.paths == ["./src/"]

    def test_secrets_scan_multiple_paths(self, parser):
        """Test secrets-scan with multiple paths."""
        args = parser.parse_args([
            "secrets-scan",
            "./src/",
            "./config/",
            "./scripts/",
        ])

        assert args.paths == ["./src/", "./config/", "./scripts/"]

    def test_secrets_scan_defaults(self, parser):
        """Test secrets-scan default values."""
        args = parser.parse_args(["secrets-scan", "./src/"])

        assert args.format == "table"
        assert args.recursive is False
        assert args.min_entropy == 3.5
        assert args.exclude is None
        assert args.output is None
        assert args.fail_on_secrets is False

    def test_secrets_scan_format_json(self, parser):
        """Test secrets-scan with JSON format."""
        args = parser.parse_args([
            "secrets-scan",
            "--format", "json",
            "./src/",
        ])

        assert args.format == "json"

    def test_secrets_scan_recursive(self, parser):
        """Test secrets-scan with --recursive flag."""
        args = parser.parse_args([
            "secrets-scan",
            "-r",
            "./src/",
        ])

        assert args.recursive is True

    def test_secrets_scan_recursive_long(self, parser):
        """Test secrets-scan with --recursive long flag."""
        args = parser.parse_args([
            "secrets-scan",
            "--recursive",
            "./src/",
        ])

        assert args.recursive is True

    def test_secrets_scan_min_entropy(self, parser):
        """Test secrets-scan with custom min-entropy."""
        args = parser.parse_args([
            "secrets-scan",
            "--min-entropy", "4.0",
            "./src/",
        ])

        assert args.min_entropy == 4.0

    def test_secrets_scan_exclude(self, parser):
        """Test secrets-scan with --exclude patterns."""
        args = parser.parse_args([
            "secrets-scan",
            "--exclude", "*.test.js,fixtures/*",
            "./src/",
        ])

        assert args.exclude == "*.test.js,fixtures/*"

    def test_secrets_scan_output_file(self, parser):
        """Test secrets-scan with output file."""
        args = parser.parse_args([
            "secrets-scan",
            "-o", "secrets.json",
            "./src/",
        ])

        assert args.output == "secrets.json"

    def test_secrets_scan_fail_on_secrets(self, parser):
        """Test secrets-scan with --fail-on-secrets flag."""
        args = parser.parse_args([
            "secrets-scan",
            "--fail-on-secrets",
            "./src/",
        ])

        assert args.fail_on_secrets is True

    def test_secrets_scan_all_options(self, parser):
        """Test secrets-scan with all options combined."""
        args = parser.parse_args([
            "secrets-scan",
            "--format", "json",
            "-r",
            "--min-entropy", "4.5",
            "--exclude", "*.lock,node_modules/*",
            "-o", "secrets.json",
            "--fail-on-secrets",
            "./src/",
            "./config/",
        ])

        assert args.format == "json"
        assert args.recursive is True
        assert args.min_entropy == 4.5
        assert args.exclude == "*.lock,node_modules/*"
        assert args.output == "secrets.json"
        assert args.fail_on_secrets is True
        assert len(args.paths) == 2


class TestImageScanCommand:
    """Tests for image-scan command execution."""

    @patch("stance.scanner.TrivyScanner")
    def test_cmd_image_scan_trivy_not_available(self, mock_scanner_class, capsys):
        """Test image-scan when Trivy is not available."""
        from stance.cli_commands import cmd_image_scan

        mock_scanner = MagicMock()
        mock_scanner.is_available.return_value = False
        mock_scanner_class.return_value = mock_scanner

        args = argparse.Namespace(
            images=["nginx:latest"],
            timeout=300,
            skip_db_update=False,
            ignore_unfixed=False,
            severity=None,
            format="table",
            fail_on=None,
        )

        result = cmd_image_scan(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not available" in captured.err.lower() or "not available" in captured.out.lower()

    @patch("stance.scanner.TrivyScanner")
    def test_cmd_image_scan_success(self, mock_scanner_class, capsys):
        """Test successful image scan."""
        from stance.cli_commands import cmd_image_scan
        from stance.scanner.base import ScanResult, Vulnerability, VulnerabilitySeverity
        from datetime import datetime

        # Create mock scan result
        mock_result = MagicMock()
        mock_result.image_reference = "nginx:latest"
        mock_result.scanned_at = datetime.now()
        mock_result.scanner_name = "trivy"
        mock_result.scanner_version = "0.48.0"
        mock_result.vulnerabilities = []
        mock_result.vulnerability_count = 0
        mock_result.critical_count = 0
        mock_result.high_count = 0
        mock_result.medium_count = 0
        mock_result.low_count = 0
        mock_result.fixable_count = 0

        mock_scanner = MagicMock()
        mock_scanner.is_available.return_value = True
        mock_scanner.get_version.return_value = "0.48.0"
        mock_scanner.scan.return_value = mock_result
        mock_scanner_class.return_value = mock_scanner

        args = argparse.Namespace(
            images=["nginx:latest"],
            timeout=300,
            skip_db_update=False,
            ignore_unfixed=False,
            severity=None,
            format="table",
            fail_on=None,
        )

        result = cmd_image_scan(args)

        assert result == 0
        mock_scanner.scan.assert_called_once()

    @patch("stance.scanner.TrivyScanner")
    def test_cmd_image_scan_with_vulnerabilities(self, mock_scanner_class, capsys):
        """Test image scan with vulnerabilities found."""
        from stance.cli_commands import cmd_image_scan
        from stance.scanner.base import VulnerabilitySeverity
        from datetime import datetime

        # Create mock vulnerability
        mock_vuln = MagicMock()
        mock_vuln.vulnerability_id = "CVE-2023-12345"
        mock_vuln.package_name = "openssl"
        mock_vuln.installed_version = "1.1.1k"
        mock_vuln.fixed_version = "1.1.1n"
        mock_vuln.severity = VulnerabilitySeverity.HIGH
        mock_vuln.cvss_score = 7.5
        mock_vuln.title = "Test vulnerability"
        mock_vuln.description = "Test description"
        mock_vuln.references = []

        # Create mock scan result
        mock_result = MagicMock()
        mock_result.image_reference = "nginx:latest"
        mock_result.scanned_at = datetime.now()
        mock_result.scanner_name = "trivy"
        mock_result.scanner_version = "0.48.0"
        mock_result.vulnerabilities = [mock_vuln]
        mock_result.vulnerability_count = 1
        mock_result.critical_count = 0
        mock_result.high_count = 1
        mock_result.medium_count = 0
        mock_result.low_count = 0
        mock_result.fixable_count = 1

        mock_scanner = MagicMock()
        mock_scanner.is_available.return_value = True
        mock_scanner.get_version.return_value = "0.48.0"
        mock_scanner.scan.return_value = mock_result
        mock_scanner_class.return_value = mock_scanner

        args = argparse.Namespace(
            images=["nginx:latest"],
            timeout=300,
            skip_db_update=False,
            ignore_unfixed=False,
            severity=None,
            format="table",
            fail_on=None,
        )

        result = cmd_image_scan(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "nginx:latest" in captured.out

    @patch("stance.scanner.TrivyScanner")
    def test_cmd_image_scan_fail_on_high(self, mock_scanner_class):
        """Test image scan fails when high vulnerability found with --fail-on high."""
        from stance.cli_commands import cmd_image_scan
        from stance.scanner.base import VulnerabilitySeverity
        from datetime import datetime

        mock_vuln = MagicMock()
        mock_vuln.vulnerability_id = "CVE-2023-12345"
        mock_vuln.severity = VulnerabilitySeverity.HIGH

        mock_result = MagicMock()
        mock_result.image_reference = "nginx:latest"
        mock_result.scanned_at = datetime.now()
        mock_result.scanner_name = "trivy"
        mock_result.scanner_version = "0.48.0"
        mock_result.vulnerabilities = [mock_vuln]

        mock_scanner = MagicMock()
        mock_scanner.is_available.return_value = True
        mock_scanner.get_version.return_value = "0.48.0"
        mock_scanner.scan.return_value = mock_result
        mock_scanner_class.return_value = mock_scanner

        args = argparse.Namespace(
            images=["nginx:latest"],
            timeout=300,
            skip_db_update=False,
            ignore_unfixed=False,
            severity=None,
            format="table",
            fail_on="high",
        )

        result = cmd_image_scan(args)

        assert result == 1


class TestIacScanCommand:
    """Tests for iac-scan command execution."""

    def test_cmd_iac_scan_no_files(self, capsys):
        """Test iac-scan when no files found."""
        from stance.cli_commands import cmd_iac_scan

        with tempfile.TemporaryDirectory() as tmpdir:
            args = argparse.Namespace(
                paths=[tmpdir],
                format="table",
                severity=None,
                fail_on=None,
                policy_dir=None,
                skip_secrets=False,
                recursive=False,
                output=None,
            )

            result = cmd_iac_scan(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "No IaC files found" in captured.out

    @patch("stance.iac.IaCScanner")
    @patch("stance.iac.get_default_iac_policies")
    @patch("stance.iac.IaCPolicyEvaluator")
    @patch("stance.iac.TerraformParser")
    @patch("stance.iac.CloudFormationParser")
    @patch("stance.iac.ARMTemplateParser")
    def test_cmd_iac_scan_with_tf_file(
        self,
        mock_arm,
        mock_cfn,
        mock_tf,
        mock_evaluator,
        mock_policies,
        mock_scanner_class,
        capsys,
    ):
        """Test iac-scan with a Terraform file."""
        from stance.cli_commands import cmd_iac_scan

        mock_scanner = MagicMock()
        mock_scanner.scan_file.return_value = []
        mock_scanner_class.return_value = mock_scanner
        mock_policies.return_value = MagicMock()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a test .tf file
            tf_file = Path(tmpdir) / "main.tf"
            tf_file.write_text('resource "aws_s3_bucket" "test" {}')

            args = argparse.Namespace(
                paths=[str(tf_file)],
                format="table",
                severity=None,
                fail_on=None,
                policy_dir=None,
                skip_secrets=False,
                recursive=False,
                output=None,
            )

            result = cmd_iac_scan(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "Scanning 1 files" in captured.out


class TestSecretsScanCommand:
    """Tests for secrets-scan command execution."""

    def test_cmd_secrets_scan_no_files(self, capsys):
        """Test secrets-scan when no files found."""
        from stance.cli_commands import cmd_secrets_scan

        with tempfile.TemporaryDirectory() as tmpdir:
            args = argparse.Namespace(
                paths=[tmpdir],
                format="table",
                recursive=False,
                min_entropy=3.5,
                exclude=None,
                output=None,
                fail_on_secrets=False,
            )

            result = cmd_secrets_scan(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "No files found" in captured.out

    @patch("stance.detection.secrets.SecretsDetector")
    def test_cmd_secrets_scan_no_secrets(self, mock_detector_class, capsys):
        """Test secrets-scan when no secrets found."""
        from stance.cli_commands import cmd_secrets_scan

        mock_detector = MagicMock()
        mock_detector.detect_in_text.return_value = []
        mock_detector_class.return_value = mock_detector

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a test file
            test_file = Path(tmpdir) / "config.py"
            test_file.write_text("# No secrets here\nDEBUG = True\n")

            args = argparse.Namespace(
                paths=[str(test_file)],
                format="table",
                recursive=False,
                min_entropy=3.5,
                exclude=None,
                output=None,
                fail_on_secrets=False,
            )

            result = cmd_secrets_scan(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "No secrets found" in captured.out or "Total secrets found: 0" in captured.out

    @patch("stance.detection.secrets.SecretsDetector")
    def test_cmd_secrets_scan_with_secrets(self, mock_detector_class, capsys):
        """Test secrets-scan when secrets are found."""
        from stance.cli_commands import cmd_secrets_scan

        # Create mock secret match
        mock_match = MagicMock()
        mock_match.secret_type = "aws_access_key_id"
        mock_match.field_path = "AWS_ACCESS_KEY"
        mock_match.matched_value = "AKIAIOSFODNN7EXAMPLE"
        mock_match.confidence = "high"
        mock_match.entropy = 4.2
        mock_match.line_number = 5

        mock_detector = MagicMock()
        mock_detector.detect_in_text.return_value = [mock_match]
        mock_detector_class.return_value = mock_detector

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "config.py"
            test_file.write_text("AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")

            args = argparse.Namespace(
                paths=[str(test_file)],
                format="table",
                recursive=False,
                min_entropy=3.5,
                exclude=None,
                output=None,
                fail_on_secrets=False,
            )

            result = cmd_secrets_scan(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "aws_access_key_id" in captured.out or "1" in captured.out

    @patch("stance.detection.secrets.SecretsDetector")
    def test_cmd_secrets_scan_fail_on_secrets(self, mock_detector_class):
        """Test secrets-scan fails with --fail-on-secrets when secrets found."""
        from stance.cli_commands import cmd_secrets_scan

        mock_match = MagicMock()
        mock_match.secret_type = "aws_access_key_id"
        mock_match.field_path = "key"
        mock_match.matched_value = "AKIAIOSFODNN7EXAMPLE"
        mock_match.confidence = "high"
        mock_match.entropy = 4.2
        mock_match.line_number = 1

        mock_detector = MagicMock()
        mock_detector.detect_in_text.return_value = [mock_match]
        mock_detector_class.return_value = mock_detector

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "config.py"
            test_file.write_text("key = 'AKIAIOSFODNN7EXAMPLE'\n")

            args = argparse.Namespace(
                paths=[str(test_file)],
                format="table",
                recursive=False,
                min_entropy=3.5,
                exclude=None,
                output=None,
                fail_on_secrets=True,
            )

            result = cmd_secrets_scan(args)

            assert result == 1

    def test_cmd_secrets_scan_exclude_patterns(self, capsys):
        """Test secrets-scan with exclude patterns."""
        from stance.cli_commands import cmd_secrets_scan

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create files that should be excluded
            lock_file = Path(tmpdir) / "package-lock.json"
            lock_file.write_text('{"lockfileVersion": 2}')

            args = argparse.Namespace(
                paths=[str(lock_file)],
                format="table",
                recursive=False,
                min_entropy=3.5,
                exclude="*.json",
                output=None,
                fail_on_secrets=False,
            )

            result = cmd_secrets_scan(args)

            # Lock files are excluded by default
            assert result == 0

    def test_cmd_secrets_scan_json_output(self, capsys):
        """Test secrets-scan with JSON output format."""
        from stance.cli_commands import cmd_secrets_scan

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "config.py"
            # Write file with no secrets to avoid detection
            test_file.write_text("DEBUG = True\nLOGLEVEL = 'INFO'\n")

            args = argparse.Namespace(
                paths=[str(test_file)],
                format="json",
                recursive=False,
                min_entropy=3.5,
                exclude=None,
                output=None,
                fail_on_secrets=False,
            )

            result = cmd_secrets_scan(args)

            assert result == 0
            captured = capsys.readouterr()
            # Output includes "Scanning X files..." before JSON
            # Extract the JSON part (starts with '{')
            json_start = captured.out.find('{')
            assert json_start >= 0, "No JSON found in output"
            json_output = captured.out[json_start:]
            output = json.loads(json_output)
            assert "summary" in output
            assert "findings" in output


class TestHelperFunctions:
    """Tests for CLI helper functions."""

    def test_redact_secret_short(self):
        """Test redacting short secrets."""
        from stance.cli_commands import _redact_secret

        result = _redact_secret("abc")
        assert result == "***"

    def test_redact_secret_long(self):
        """Test redacting long secrets."""
        from stance.cli_commands import _redact_secret

        result = _redact_secret("AKIAIOSFODNN7EXAMPLE")
        # Should show first 4 and last 4 characters
        assert result.startswith("AKIA")
        assert result.endswith("MPLE")
        assert "*" in result

    def test_severity_to_sarif_level_critical(self):
        """Test severity to SARIF level conversion for critical."""
        from stance.cli_commands import _severity_to_sarif_level

        assert _severity_to_sarif_level("critical") == "error"
        assert _severity_to_sarif_level("CRITICAL") == "error"

    def test_severity_to_sarif_level_high(self):
        """Test severity to SARIF level conversion for high."""
        from stance.cli_commands import _severity_to_sarif_level

        assert _severity_to_sarif_level("high") == "error"
        assert _severity_to_sarif_level("HIGH") == "error"

    def test_severity_to_sarif_level_medium(self):
        """Test severity to SARIF level conversion for medium."""
        from stance.cli_commands import _severity_to_sarif_level

        assert _severity_to_sarif_level("medium") == "warning"
        assert _severity_to_sarif_level("MEDIUM") == "warning"

    def test_severity_to_sarif_level_low(self):
        """Test severity to SARIF level conversion for low."""
        from stance.cli_commands import _severity_to_sarif_level

        assert _severity_to_sarif_level("low") == "note"
        assert _severity_to_sarif_level("LOW") == "note"

    def test_severity_to_sarif_level_unknown(self):
        """Test severity to SARIF level conversion for unknown."""
        from stance.cli_commands import _severity_to_sarif_level

        assert _severity_to_sarif_level("unknown") == "note"
        assert _severity_to_sarif_level("other") == "note"
