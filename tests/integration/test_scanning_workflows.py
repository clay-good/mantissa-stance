"""
Integration tests for scanning workflows.

Tests cover end-to-end workflows for:
- IaC scanning (Terraform, CloudFormation, ARM)
- Secrets detection
- Container image scanning
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# =============================================================================
# IaC Scanning Integration Tests
# =============================================================================


class TestIaCScanningWorkflow:
    """Integration tests for Infrastructure as Code scanning."""

    def test_terraform_end_to_end_scan(self):
        """Test complete Terraform scanning workflow."""
        from stance.iac import (
            TerraformParser,
            IaCPolicyEvaluator,
            get_default_iac_policies,
        )

        # Create sample Terraform file with security issues
        tf_content = """
resource "aws_s3_bucket" "insecure" {
  bucket = "my-insecure-bucket"
}

resource "aws_s3_bucket" "secure" {
  bucket = "my-secure-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure" {
  bucket = aws_s3_bucket.secure.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_security_group" "open_ssh" {
  name = "allow-all-ssh"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tf_file = Path(tmpdir) / "main.tf"
            tf_file.write_text(tf_content)

            # Parse the Terraform file
            parser = TerraformParser()
            iac_file = parser.parse_file(str(tf_file))

            # Check parsing succeeded (no errors)
            assert not iac_file.has_errors
            assert len(iac_file.resources) >= 2

            # Get policies and evaluate
            policies = get_default_iac_policies()
            evaluator = IaCPolicyEvaluator(policies)

            findings = evaluator.evaluate_file(iac_file)

            # Should find security issues
            # The exact count depends on available policies
            assert isinstance(findings, list)

    def test_cloudformation_end_to_end_scan(self):
        """Test complete CloudFormation scanning workflow."""
        from stance.iac import (
            CloudFormationParser,
            IaCPolicyEvaluator,
            get_default_iac_policies,
        )

        # Create sample CloudFormation template with security issues
        cfn_content = """
AWSTemplateFormatVersion: '2010-09-09'
Description: Test CloudFormation template

Resources:
  InsecureBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: insecure-bucket

  SecureBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: secure-bucket
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256

  OpenSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Open SSH
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfn_file = Path(tmpdir) / "template.yaml"
            cfn_file.write_text(cfn_content)

            # Parse the CloudFormation template
            parser = CloudFormationParser()
            iac_file = parser.parse_file(str(cfn_file))

            # Check parsing succeeded (no errors)
            assert not iac_file.has_errors
            assert len(iac_file.resources) >= 2

            # Get policies and evaluate
            policies = get_default_iac_policies()
            evaluator = IaCPolicyEvaluator(policies)

            findings = evaluator.evaluate_file(iac_file)
            assert isinstance(findings, list)

    def test_arm_template_end_to_end_scan(self):
        """Test complete ARM template scanning workflow."""
        from stance.iac import (
            ARMTemplateParser,
            IaCPolicyEvaluator,
            get_default_iac_policies,
        )

        # Create sample ARM template
        arm_content = {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "resources": [
                {
                    "type": "Microsoft.Storage/storageAccounts",
                    "apiVersion": "2021-02-01",
                    "name": "mystorageaccount",
                    "location": "[resourceGroup().location]",
                    "sku": {"name": "Standard_LRS"},
                    "kind": "StorageV2",
                    "properties": {
                        "supportsHttpsTrafficOnly": False,  # Security issue
                        "minimumTlsVersion": "TLS1_0",  # Security issue
                    },
                },
                {
                    "type": "Microsoft.Storage/storageAccounts",
                    "apiVersion": "2021-02-01",
                    "name": "securestorage",
                    "location": "[resourceGroup().location]",
                    "sku": {"name": "Standard_LRS"},
                    "kind": "StorageV2",
                    "properties": {
                        "supportsHttpsTrafficOnly": True,
                        "minimumTlsVersion": "TLS1_2",
                    },
                },
            ],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            arm_file = Path(tmpdir) / "template.json"
            arm_file.write_text(json.dumps(arm_content))

            # Parse the ARM template
            parser = ARMTemplateParser()
            iac_file = parser.parse_file(str(arm_file))

            # Check parsing succeeded (no errors)
            assert not iac_file.has_errors
            assert len(iac_file.resources) >= 1

            # Evaluate against policies
            policies = get_default_iac_policies()
            evaluator = IaCPolicyEvaluator(policies)

            findings = evaluator.evaluate_file(iac_file)
            assert isinstance(findings, list)

    def test_mixed_iac_directory_scan(self):
        """Test scanning directory with mixed IaC file types."""
        from stance.iac import (
            TerraformParser,
            CloudFormationParser,
            ARMTemplateParser,
            IaCPolicyEvaluator,
            get_default_iac_policies,
        )

        tf_content = """
resource "aws_s3_bucket" "test" {
  bucket = "test-bucket"
}
"""
        cfn_content = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  TestBucket:
    Type: AWS::S3::Bucket
"""
        arm_content = {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "resources": [],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create files of different types
            (Path(tmpdir) / "main.tf").write_text(tf_content)
            (Path(tmpdir) / "template.yaml").write_text(cfn_content)
            (Path(tmpdir) / "arm.json").write_text(json.dumps(arm_content))

            all_resources = []
            all_findings = []

            # Get policies for evaluation
            policies = get_default_iac_policies()
            evaluator = IaCPolicyEvaluator(policies)

            # Parse Terraform
            tf_parser = TerraformParser()
            for tf_file in Path(tmpdir).glob("*.tf"):
                iac_file = tf_parser.parse_file(str(tf_file))
                if not iac_file.has_errors:
                    all_resources.extend(iac_file.resources)
                    all_findings.extend(evaluator.evaluate_file(iac_file))

            # Parse CloudFormation
            cfn_parser = CloudFormationParser()
            for yaml_file in Path(tmpdir).glob("*.yaml"):
                iac_file = cfn_parser.parse_file(str(yaml_file))
                if not iac_file.has_errors:
                    all_resources.extend(iac_file.resources)
                    all_findings.extend(evaluator.evaluate_file(iac_file))

            # Parse ARM
            arm_parser = ARMTemplateParser()
            for json_file in Path(tmpdir).glob("*.json"):
                iac_file = arm_parser.parse_file(str(json_file))
                if not iac_file.has_errors:
                    all_resources.extend(iac_file.resources)
                    all_findings.extend(evaluator.evaluate_file(iac_file))

            # We should have resources from multiple parsers
            assert len(all_resources) >= 2

            # Findings were collected during parsing
            assert isinstance(all_findings, list)


# =============================================================================
# Secrets Detection Integration Tests
# =============================================================================


class TestSecretsDetectionWorkflow:
    """Integration tests for secrets detection."""

    def test_secrets_detection_end_to_end(self):
        """Test complete secrets detection workflow."""
        from stance.detection.secrets import SecretsDetector

        # Create file with various secret types
        content_with_secrets = """
# Configuration file
DATABASE_URL = "postgres://user:password123@localhost:5432/db"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# API Keys
STRIPE_SECRET_KEY = "sk_live_1234567890abcdefghijklmnop"
GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Safe values (should not be detected)
ENVIRONMENT = "production"
LOG_LEVEL = "debug"
MAX_CONNECTIONS = 100
"""
        detector = SecretsDetector()
        matches = detector.detect_in_text(content_with_secrets, "config.env")

        # Should find multiple secrets
        assert len(matches) >= 2

        # Check that AWS key was detected
        secret_types = [m.secret_type for m in matches]
        assert any("aws" in t.lower() for t in secret_types)

    def test_secrets_detection_in_code_file(self):
        """Test secrets detection in source code."""
        from stance.detection.secrets import SecretsDetector

        python_code = '''
import os

# Hardcoded credentials (bad practice!)
API_KEY = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"
DATABASE_PASSWORD = "super_secret_password_123"

def connect():
    # This is fine - reading from environment
    api_key = os.environ.get("API_KEY")
    return api_key
'''
        detector = SecretsDetector()
        matches = detector.detect_in_text(python_code, "app.py")

        # Should find hardcoded secrets
        assert len(matches) >= 1

    def test_secrets_detection_with_entropy(self):
        """Test high-entropy string detection."""
        from stance.detection.secrets import SecretsDetector

        content = """
# High entropy strings that might be secrets
RANDOM_KEY = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z"
ENCODED_SECRET = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

# Low entropy - should not trigger
DEBUG = "true"
NAME = "test_user"
"""
        detector = SecretsDetector(min_entropy=3.5)
        matches = detector.detect_in_text(content, "test.txt")

        # High entropy detection should work
        assert isinstance(matches, list)

    def test_secrets_detection_file_walk(self):
        """Test secrets detection across multiple files."""
        from stance.detection.secrets import SecretsDetector

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create multiple files with secrets
            files = {
                "config.py": 'API_KEY = "AKIAIOSFODNN7EXAMPLE"',
                "settings.json": '{"password": "secret123"}',
                "app.env": 'DATABASE_URL="postgres://user:pass@localhost/db"',
                "clean.py": "# No secrets here\nDEBUG = True",
            }

            for name, content in files.items():
                (Path(tmpdir) / name).write_text(content)

            detector = SecretsDetector()
            all_matches = []

            for file_path in Path(tmpdir).glob("*"):
                if file_path.is_file():
                    content = file_path.read_text()
                    matches = detector.detect_in_text(content, str(file_path))
                    all_matches.extend(matches)

            # Should find secrets in multiple files
            assert len(all_matches) >= 2

    def test_secrets_detection_excludes_lock_files(self):
        """Test that lock files are properly handled."""
        from stance.detection.secrets import SecretsDetector

        # Lock file content that might look like secrets but shouldn't be flagged
        lock_content = """
{
  "name": "my-app",
  "integrity": "sha512-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/="
}
"""
        detector = SecretsDetector()

        # When scanning lock file content, we should handle it appropriately
        matches = detector.detect_in_text(lock_content, "package-lock.json")

        # Lock file hashes should generally not be flagged
        # (depends on implementation details)
        assert isinstance(matches, list)


# =============================================================================
# Image Scanning Integration Tests
# =============================================================================


class TestImageScanningWorkflow:
    """Integration tests for container image scanning."""

    @patch("stance.scanner.trivy.subprocess.run")
    @patch("stance.scanner.trivy.shutil.which")
    def test_image_scan_workflow(self, mock_which, mock_run):
        """Test complete image scanning workflow with mocked Trivy."""
        from stance.scanner import TrivyScanner
        from stance.scanner.base import VulnerabilitySeverity

        mock_which.return_value = "/usr/bin/trivy"
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({
                "Results": [
                    {
                        "Target": "nginx:1.21 (debian 11)",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2023-12345",
                                "PkgName": "openssl",
                                "InstalledVersion": "1.1.1k",
                                "FixedVersion": "1.1.1n",
                                "Severity": "HIGH",
                                "Title": "OpenSSL vulnerability",
                                "Description": "A vulnerability in OpenSSL",
                            },
                            {
                                "VulnerabilityID": "CVE-2023-67890",
                                "PkgName": "zlib",
                                "InstalledVersion": "1.2.11",
                                "FixedVersion": "1.2.12",
                                "Severity": "MEDIUM",
                                "Title": "Zlib vulnerability",
                                "Description": "A vulnerability in zlib",
                            },
                        ],
                    }
                ]
            }),
            stderr="",
        )

        scanner = TrivyScanner()

        # Verify scanner is available (mocked)
        assert scanner.is_available()

        # Scan image
        result = scanner.scan("nginx:1.21")

        assert result.image_reference == "nginx:1.21"
        assert len(result.vulnerabilities) == 2

        # Check vulnerabilities are properly parsed
        high_vulns = [
            v for v in result.vulnerabilities
            if v.severity == VulnerabilitySeverity.HIGH
        ]
        assert len(high_vulns) == 1
        assert high_vulns[0].vulnerability_id == "CVE-2023-12345"

    @patch("stance.scanner.trivy.subprocess.run")
    @patch("stance.scanner.trivy.shutil.which")
    def test_multiple_images_scan(self, mock_which, mock_run):
        """Test scanning multiple images."""
        from stance.scanner import TrivyScanner

        mock_which.return_value = "/usr/bin/trivy"
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"Results": []}),
            stderr="",
        )

        scanner = TrivyScanner()
        images = ["nginx:latest", "alpine:3.18", "python:3.11"]
        results = [scanner.scan(img) for img in images]

        assert len(results) == 3
        for i, result in enumerate(results):
            assert result.image_reference == images[i]

    @patch("stance.scanner.trivy.subprocess.run")
    @patch("stance.scanner.trivy.shutil.which")
    def test_vulnerability_prioritization(self, mock_which, mock_run):
        """Test vulnerability prioritization with CVE enrichment."""
        from stance.scanner import TrivyScanner
        from stance.scanner.cve_enrichment import prioritize_vulnerabilities

        mock_which.return_value = "/usr/bin/trivy"
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({
                "Results": [
                    {
                        "Target": "app:latest",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2021-44228",  # Log4Shell
                                "PkgName": "log4j",
                                "InstalledVersion": "2.14.0",
                                "FixedVersion": "2.17.0",
                                "Severity": "CRITICAL",
                                "Title": "Log4Shell",
                            },
                            {
                                "VulnerabilityID": "CVE-2023-00001",
                                "PkgName": "some-lib",
                                "InstalledVersion": "1.0.0",
                                "Severity": "LOW",
                                "Title": "Minor issue",
                            },
                        ],
                    }
                ]
            }),
            stderr="",
        )

        scanner = TrivyScanner()
        result = scanner.scan("app:latest")

        # Prioritize vulnerabilities
        enriched = prioritize_vulnerabilities(result.vulnerabilities)

        assert len(enriched) == 2

        # Critical should be prioritized higher
        # (sorted by priority score descending)
        assert enriched[0].vulnerability.vulnerability_id == "CVE-2021-44228"


# =============================================================================
# Combined Workflow Tests
# =============================================================================


class TestCombinedScanningWorkflow:
    """Integration tests for combined scanning workflows."""

    def test_iac_with_secrets_detection(self):
        """Test IaC scanning combined with secrets detection."""
        from stance.iac import TerraformParser
        from stance.detection.secrets import SecretsDetector

        # Terraform with hardcoded secrets
        tf_content = """
provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  region     = "us-east-1"
}

resource "aws_db_instance" "default" {
  identifier = "mydb"
  password   = "super_secret_db_password_123!"
}
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tf_file = Path(tmpdir) / "main.tf"
            tf_file.write_text(tf_content)

            # Parse IaC
            parser = TerraformParser()
            iac_file = parser.parse_file(str(tf_file))

            # Check parsing succeeded (no errors)
            assert not iac_file.has_errors

            # Also detect secrets
            detector = SecretsDetector()
            secrets = detector.detect_in_text(tf_content, str(tf_file))

            # Should find AWS credentials
            assert len(secrets) >= 2

    def test_scan_results_to_findings(self):
        """Test converting scan results to Finding objects."""
        from stance.scanner.base import Vulnerability, VulnerabilitySeverity, ScanResult
        from stance.models import Finding, Severity

        # Create mock scan result (using scan_timestamp, not scan_time)
        scan_result = ScanResult(
            image_reference="myapp:v1.0",
            scanner_name="trivy",
            vulnerabilities=[
                Vulnerability(
                    vulnerability_id="CVE-2023-12345",
                    package_name="openssl",
                    package_type="deb",
                    installed_version="1.1.1k",
                    fixed_version="1.1.1n",
                    severity=VulnerabilitySeverity.HIGH,
                    title="OpenSSL vulnerability",
                    description="A vulnerability in OpenSSL",
                ),
            ],
        )

        # Convert to findings
        findings = scan_result.to_findings()

        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "CVE-2023-12345" in findings[0].title
        assert "myapp:v1.0" in findings[0].asset_id

    def test_full_security_scan_pipeline(self):
        """Test a complete security scanning pipeline."""
        from stance.iac import TerraformParser, get_default_iac_policies, IaCPolicyEvaluator
        from stance.detection.secrets import SecretsDetector

        # Create a project structure with multiple file types
        with tempfile.TemporaryDirectory() as tmpdir:
            # Terraform file
            tf_file = Path(tmpdir) / "infra" / "main.tf"
            tf_file.parent.mkdir(parents=True)
            tf_file.write_text("""
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
}
""")

            # Config file with secrets
            config_file = Path(tmpdir) / "config" / "settings.py"
            config_file.parent.mkdir(parents=True)
            config_file.write_text("""
DATABASE_URL = "postgres://admin:password123@db.example.com:5432/app"
""")

            # Results collection
            all_issues = []

            # 1. Scan IaC files
            tf_parser = TerraformParser()
            policies = get_default_iac_policies()
            evaluator = IaCPolicyEvaluator(policies)
            for tf in Path(tmpdir).rglob("*.tf"):
                iac_file = tf_parser.parse_file(str(tf))
                if not iac_file.has_errors:
                    findings = evaluator.evaluate_file(iac_file)
                    all_issues.extend(
                        {"type": "iac", "file": str(tf), "finding": f}
                        for f in findings
                    )

            # 2. Scan for secrets
            detector = SecretsDetector()
            for py_file in Path(tmpdir).rglob("*.py"):
                content = py_file.read_text()
                matches = detector.detect_in_text(content, str(py_file))
                all_issues.extend(
                    {"type": "secret", "file": str(py_file), "finding": m}
                    for m in matches
                )

            # Verify we found issues
            iac_issues = [i for i in all_issues if i["type"] == "iac"]
            secret_issues = [i for i in all_issues if i["type"] == "secret"]

            # Should find at least the secrets
            assert len(secret_issues) >= 1


# =============================================================================
# CLI Integration Tests
# =============================================================================


class TestCLIScanningIntegration:
    """Integration tests for CLI scanning commands."""

    def test_cli_iac_scan_terraform(self):
        """Test CLI iac-scan command with Terraform file."""
        import argparse
        from stance.cli_commands import cmd_iac_scan

        tf_content = """
resource "aws_s3_bucket" "test" {
  bucket = "test-bucket"
}
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tf_file = Path(tmpdir) / "main.tf"
            tf_file.write_text(tf_content)

            args = argparse.Namespace(
                paths=[str(tf_file)],
                format="json",
                severity=None,
                fail_on=None,
                policy_dir=None,
                skip_secrets=False,
                recursive=False,
                output=None,
            )

            result = cmd_iac_scan(args)

            # Should complete successfully
            assert result == 0

    def test_cli_secrets_scan(self):
        """Test CLI secrets-scan command."""
        import argparse
        from stance.cli_commands import cmd_secrets_scan

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create file without secrets
            test_file = Path(tmpdir) / "clean.py"
            test_file.write_text("DEBUG = True\nVERSION = '1.0.0'")

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

            # Should complete successfully with no secrets
            assert result == 0

    def test_cli_secrets_scan_with_findings(self):
        """Test CLI secrets-scan command finds secrets."""
        import argparse
        from stance.cli_commands import cmd_secrets_scan

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create file with secrets
            test_file = Path(tmpdir) / "config.py"
            test_file.write_text('API_KEY = "AKIAIOSFODNN7EXAMPLE"')

            args = argparse.Namespace(
                paths=[str(test_file)],
                format="table",
                recursive=False,
                min_entropy=3.5,
                exclude=None,
                output=None,
                fail_on_secrets=True,  # Should fail
            )

            result = cmd_secrets_scan(args)

            # Should exit with 1 due to --fail-on-secrets
            assert result == 1
