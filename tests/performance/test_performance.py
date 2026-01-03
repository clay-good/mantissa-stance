"""
Performance tests for Mantissa Stance.

Tests measure execution time and resource usage for:
- IaC file parsing (Terraform, CloudFormation, ARM)
- Secrets detection at scale
- Policy evaluation with large asset sets
- Storage operations
"""

from __future__ import annotations

import json
import statistics
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from unittest.mock import MagicMock, patch

import pytest

# Performance thresholds (in seconds)
THRESHOLDS = {
    "parse_terraform_small": 0.1,      # 10 resources
    "parse_terraform_medium": 0.5,     # 100 resources
    "parse_terraform_large": 2.0,      # 1000 resources
    "parse_cloudformation_small": 0.1,
    "parse_cloudformation_medium": 0.5,
    "parse_cloudformation_large": 2.0,
    "secrets_scan_small": 0.1,         # 10 files
    "secrets_scan_medium": 0.5,        # 100 files
    "secrets_scan_large": 2.0,         # 1000 files
    "policy_eval_small": 0.1,          # 10 assets
    "policy_eval_medium": 0.5,         # 100 assets
    "policy_eval_large": 2.0,          # 1000 assets
    "storage_write_small": 0.1,
    "storage_write_medium": 0.5,
    "storage_read_small": 0.1,
    "storage_read_medium": 0.5,
}


def measure_time(func: Callable, iterations: int = 3) -> dict:
    """
    Measure execution time of a function.

    Returns:
        Dictionary with min, max, mean, median times in seconds
    """
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        func()
        end = time.perf_counter()
        times.append(end - start)

    return {
        "min": min(times),
        "max": max(times),
        "mean": statistics.mean(times),
        "median": statistics.median(times),
        "times": times,
    }


def generate_terraform_content(resource_count: int) -> str:
    """Generate Terraform content with specified number of resources."""
    resources = []
    for i in range(resource_count):
        resources.append(f'''
resource "aws_s3_bucket" "bucket_{i}" {{
  bucket = "my-bucket-{i}"
  tags = {{
    Name        = "bucket-{i}"
    Environment = "test"
    Index       = "{i}"
  }}
}}

resource "aws_s3_bucket_versioning" "bucket_{i}_versioning" {{
  bucket = aws_s3_bucket.bucket_{i}.id
  versioning_configuration {{
    status = "Enabled"
  }}
}}
''')
    return "\n".join(resources)


def generate_cloudformation_content(resource_count: int) -> str:
    """Generate CloudFormation content with specified number of resources."""
    resources = {}
    for i in range(resource_count):
        resources[f"Bucket{i}"] = {
            "Type": "AWS::S3::Bucket",
            "Properties": {
                "BucketName": f"my-bucket-{i}",
                "Tags": [
                    {"Key": "Name", "Value": f"bucket-{i}"},
                    {"Key": "Environment", "Value": "test"},
                    {"Key": "Index", "Value": str(i)},
                ],
            },
        }

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": f"Performance test template with {resource_count} resources",
        "Resources": resources,
    }

    # Return as YAML-like format for CloudFormation parser
    import yaml
    return yaml.dump(template, default_flow_style=False)


def generate_file_with_potential_secrets(content_lines: int) -> str:
    """Generate file content with various patterns for secrets detection."""
    lines = []
    for i in range(content_lines):
        # Mix of secret-like and non-secret content
        if i % 10 == 0:
            lines.append(f'API_KEY_{i} = "sk_test_{"x" * 24}"')
        elif i % 10 == 1:
            lines.append(f'DATABASE_URL_{i} = "postgres://user:pass{i}@localhost/db"')
        elif i % 10 == 2:
            lines.append(f'AWS_KEY_{i} = "AKIA{"X" * 16}"')
        else:
            lines.append(f'CONFIG_VALUE_{i} = "{i}"')
            lines.append(f'DEBUG_{i} = True')
            lines.append(f'# Comment line {i}')
    return "\n".join(lines)


# =============================================================================
# IaC Parsing Performance Tests
# =============================================================================


class TestTerraformParsingPerformance:
    """Performance tests for Terraform parsing."""

    def test_parse_small_terraform(self):
        """Test parsing 10 Terraform resources."""
        from stance.iac import TerraformParser

        content = generate_terraform_content(10)

        with tempfile.TemporaryDirectory() as tmpdir:
            tf_file = Path(tmpdir) / "main.tf"
            tf_file.write_text(content)

            parser = TerraformParser()

            def parse():
                return parser.parse_file(str(tf_file))

            result = measure_time(parse)

            assert result["median"] < THRESHOLDS["parse_terraform_small"], \
                f"Parsing took {result['median']:.3f}s, expected < {THRESHOLDS['parse_terraform_small']}s"

            # Verify parsing worked
            iac_file = parser.parse_file(str(tf_file))
            assert len(iac_file.resources) >= 10

    def test_parse_medium_terraform(self):
        """Test parsing 100 Terraform resources."""
        from stance.iac import TerraformParser

        content = generate_terraform_content(100)

        with tempfile.TemporaryDirectory() as tmpdir:
            tf_file = Path(tmpdir) / "main.tf"
            tf_file.write_text(content)

            parser = TerraformParser()

            def parse():
                return parser.parse_file(str(tf_file))

            result = measure_time(parse)

            assert result["median"] < THRESHOLDS["parse_terraform_medium"], \
                f"Parsing took {result['median']:.3f}s, expected < {THRESHOLDS['parse_terraform_medium']}s"

    def test_parse_large_terraform(self):
        """Test parsing 500 Terraform resources."""
        from stance.iac import TerraformParser

        # Use 500 instead of 1000 for faster CI
        content = generate_terraform_content(500)

        with tempfile.TemporaryDirectory() as tmpdir:
            tf_file = Path(tmpdir) / "main.tf"
            tf_file.write_text(content)

            parser = TerraformParser()

            def parse():
                return parser.parse_file(str(tf_file))

            result = measure_time(parse, iterations=2)

            assert result["median"] < THRESHOLDS["parse_terraform_large"], \
                f"Parsing took {result['median']:.3f}s, expected < {THRESHOLDS['parse_terraform_large']}s"


class TestCloudFormationParsingPerformance:
    """Performance tests for CloudFormation parsing."""

    def test_parse_small_cloudformation(self):
        """Test parsing 10 CloudFormation resources."""
        from stance.iac import CloudFormationParser

        content = generate_cloudformation_content(10)

        with tempfile.TemporaryDirectory() as tmpdir:
            cfn_file = Path(tmpdir) / "template.yaml"
            cfn_file.write_text(content)

            parser = CloudFormationParser()

            def parse():
                return parser.parse_file(str(cfn_file))

            result = measure_time(parse)

            assert result["median"] < THRESHOLDS["parse_cloudformation_small"], \
                f"Parsing took {result['median']:.3f}s, expected < {THRESHOLDS['parse_cloudformation_small']}s"

    def test_parse_medium_cloudformation(self):
        """Test parsing 100 CloudFormation resources."""
        from stance.iac import CloudFormationParser

        content = generate_cloudformation_content(100)

        with tempfile.TemporaryDirectory() as tmpdir:
            cfn_file = Path(tmpdir) / "template.yaml"
            cfn_file.write_text(content)

            parser = CloudFormationParser()

            def parse():
                return parser.parse_file(str(cfn_file))

            result = measure_time(parse)

            assert result["median"] < THRESHOLDS["parse_cloudformation_medium"], \
                f"Parsing took {result['median']:.3f}s, expected < {THRESHOLDS['parse_cloudformation_medium']}s"


# =============================================================================
# Secrets Detection Performance Tests
# =============================================================================


class TestSecretsDetectionPerformance:
    """Performance tests for secrets detection."""

    def test_scan_small_file_set(self):
        """Test scanning 10 files for secrets."""
        from stance.detection.secrets import SecretsDetector

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create 10 files
            for i in range(10):
                content = generate_file_with_potential_secrets(50)
                (Path(tmpdir) / f"config_{i}.py").write_text(content)

            detector = SecretsDetector()

            def scan():
                all_matches = []
                for f in Path(tmpdir).glob("*.py"):
                    content = f.read_text()
                    matches = detector.detect_in_text(content, str(f))
                    all_matches.extend(matches)
                return all_matches

            result = measure_time(scan)

            assert result["median"] < THRESHOLDS["secrets_scan_small"], \
                f"Scanning took {result['median']:.3f}s, expected < {THRESHOLDS['secrets_scan_small']}s"

    def test_scan_medium_file_set(self):
        """Test scanning 50 files for secrets."""
        from stance.detection.secrets import SecretsDetector

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create 50 files
            for i in range(50):
                content = generate_file_with_potential_secrets(100)
                (Path(tmpdir) / f"config_{i}.py").write_text(content)

            detector = SecretsDetector()

            def scan():
                all_matches = []
                for f in Path(tmpdir).glob("*.py"):
                    content = f.read_text()
                    matches = detector.detect_in_text(content, str(f))
                    all_matches.extend(matches)
                return all_matches

            result = measure_time(scan, iterations=2)

            assert result["median"] < THRESHOLDS["secrets_scan_medium"], \
                f"Scanning took {result['median']:.3f}s, expected < {THRESHOLDS['secrets_scan_medium']}s"

    def test_scan_large_content(self):
        """Test scanning a large file for secrets."""
        from stance.detection.secrets import SecretsDetector

        # Generate a file with 5000 lines
        content = generate_file_with_potential_secrets(5000)

        detector = SecretsDetector()

        def scan():
            return detector.detect_in_text(content, "large_config.py")

        result = measure_time(scan)

        # Should still be fast for single file
        assert result["median"] < 1.0, \
            f"Scanning large file took {result['median']:.3f}s, expected < 1.0s"


# =============================================================================
# Policy Evaluation Performance Tests
# =============================================================================


class TestPolicyEvaluationPerformance:
    """Performance tests for policy evaluation."""

    def _create_assets(self, count: int):
        """Create sample assets for testing."""
        from stance.models import Asset, AssetCollection, NETWORK_EXPOSURE_INTERNAL

        assets = []
        for i in range(count):
            assets.append(Asset(
                id=f"arn:aws:s3:::bucket-{i}",
                cloud_provider="aws",
                account_id="123456789012",
                region="us-east-1",
                resource_type="aws_s3_bucket",
                name=f"bucket-{i}",
                tags={"Environment": "test", "Index": str(i)},
                network_exposure=NETWORK_EXPOSURE_INTERNAL,
                created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
                last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
                raw_config={
                    "encryption": {"enabled": i % 2 == 0},  # Half encrypted
                    "versioning": {"enabled": i % 3 == 0},  # Third versioned
                },
            ))
        return AssetCollection(assets)

    def _create_policies(self):
        """Create sample policies for testing."""
        from stance.models import (
            Policy, PolicyCollection, Check, CheckType,
            Severity, Remediation, ComplianceMapping,
        )

        policies = [
            Policy(
                id="aws-s3-001",
                name="S3 Encryption",
                description="Ensure S3 bucket encryption is enabled",
                enabled=True,
                severity=Severity.HIGH,
                resource_type="aws_s3_bucket",
                check=Check(
                    check_type=CheckType.EXPRESSION,
                    expression="resource.encryption.enabled == true",
                ),
                compliance=[
                    ComplianceMapping(framework="cis-aws", version="1.5.0", control="2.1.1"),
                ],
                remediation=Remediation(guidance="Enable encryption", automation_supported=False),
                tags=["s3", "encryption"],
                references=[],
            ),
            Policy(
                id="aws-s3-002",
                name="S3 Versioning",
                description="Ensure S3 bucket versioning is enabled",
                enabled=True,
                severity=Severity.MEDIUM,
                resource_type="aws_s3_bucket",
                check=Check(
                    check_type=CheckType.EXPRESSION,
                    expression="resource.versioning.enabled == true",
                ),
                compliance=[],
                remediation=Remediation(guidance="Enable versioning", automation_supported=False),
                tags=["s3", "versioning"],
                references=[],
            ),
        ]
        return PolicyCollection(policies)

    def test_evaluate_small_asset_set(self):
        """Test policy evaluation on 10 assets."""
        from stance.engine import PolicyEvaluator

        assets = self._create_assets(10)
        policies = self._create_policies()
        evaluator = PolicyEvaluator()

        def evaluate():
            return evaluator.evaluate_all(policies, assets)

        result = measure_time(evaluate)

        assert result["median"] < THRESHOLDS["policy_eval_small"], \
            f"Evaluation took {result['median']:.3f}s, expected < {THRESHOLDS['policy_eval_small']}s"

    def test_evaluate_medium_asset_set(self):
        """Test policy evaluation on 100 assets."""
        from stance.engine import PolicyEvaluator

        assets = self._create_assets(100)
        policies = self._create_policies()
        evaluator = PolicyEvaluator()

        def evaluate():
            return evaluator.evaluate_all(policies, assets)

        result = measure_time(evaluate)

        assert result["median"] < THRESHOLDS["policy_eval_medium"], \
            f"Evaluation took {result['median']:.3f}s, expected < {THRESHOLDS['policy_eval_medium']}s"

    def test_evaluate_large_asset_set(self):
        """Test policy evaluation on 500 assets."""
        from stance.engine import PolicyEvaluator

        assets = self._create_assets(500)
        policies = self._create_policies()
        evaluator = PolicyEvaluator()

        def evaluate():
            return evaluator.evaluate_all(policies, assets)

        result = measure_time(evaluate, iterations=2)

        assert result["median"] < THRESHOLDS["policy_eval_large"], \
            f"Evaluation took {result['median']:.3f}s, expected < {THRESHOLDS['policy_eval_large']}s"


# =============================================================================
# Storage Performance Tests
# =============================================================================


class TestStoragePerformance:
    """Performance tests for storage operations."""

    def _create_assets(self, count: int):
        """Create sample assets for storage testing."""
        from stance.models import Asset, AssetCollection, NETWORK_EXPOSURE_INTERNAL

        assets = []
        for i in range(count):
            assets.append(Asset(
                id=f"arn:aws:s3:::bucket-{i}",
                cloud_provider="aws",
                account_id="123456789012",
                region="us-east-1",
                resource_type="aws_s3_bucket",
                name=f"bucket-{i}",
                tags={"Environment": "test"},
                network_exposure=NETWORK_EXPOSURE_INTERNAL,
                created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
                last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
                raw_config={"encryption": {"enabled": True}},
            ))
        return AssetCollection(assets)

    def _create_findings(self, count: int):
        """Create sample findings for storage testing."""
        from stance.models import (
            Finding, FindingCollection, FindingType,
            Severity, FindingStatus,
        )

        findings = []
        for i in range(count):
            findings.append(Finding(
                id=f"finding-{i}",
                asset_id=f"arn:aws:s3:::bucket-{i % 100}",
                finding_type=FindingType.MISCONFIGURATION,
                severity=Severity.HIGH if i % 2 == 0 else Severity.MEDIUM,
                status=FindingStatus.OPEN,
                title=f"Finding {i}",
                description=f"Description for finding {i}",
                rule_id=f"rule-{i % 10}",
                first_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
                last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
            ))
        return FindingCollection(findings)

    def test_write_small_dataset(self, tmp_path):
        """Test writing 10 assets and findings."""
        from stance.storage import LocalStorage

        assets = self._create_assets(10)
        findings = self._create_findings(10)

        db_path = str(tmp_path / "stance.db")
        storage = LocalStorage(db_path=db_path)
        snapshot_id = "20240115-120000"

        def write():
            storage.store_assets(assets, snapshot_id)
            storage.store_findings(findings, snapshot_id)

        result = measure_time(write)

        assert result["median"] < THRESHOLDS["storage_write_small"], \
            f"Write took {result['median']:.3f}s, expected < {THRESHOLDS['storage_write_small']}s"

    def test_write_medium_dataset(self, tmp_path):
        """Test writing 100 assets and findings."""
        from stance.storage import LocalStorage

        assets = self._create_assets(100)
        findings = self._create_findings(100)

        db_path = str(tmp_path / "stance.db")
        storage = LocalStorage(db_path=db_path)
        snapshot_id = "20240115-120000"

        def write():
            storage.store_assets(assets, snapshot_id)
            storage.store_findings(findings, snapshot_id)

        result = measure_time(write)

        assert result["median"] < THRESHOLDS["storage_write_medium"], \
            f"Write took {result['median']:.3f}s, expected < {THRESHOLDS['storage_write_medium']}s"

    def test_read_performance(self, tmp_path):
        """Test reading stored assets and findings."""
        from stance.storage import LocalStorage

        assets = self._create_assets(100)
        findings = self._create_findings(100)

        db_path = str(tmp_path / "stance.db")
        storage = LocalStorage(db_path=db_path)
        snapshot_id = "20240115-120000"

        # Write first
        storage.store_assets(assets, snapshot_id)
        storage.store_findings(findings, snapshot_id)

        def read():
            storage.get_assets(snapshot_id)
            storage.get_findings(snapshot_id)

        result = measure_time(read)

        assert result["median"] < THRESHOLDS["storage_read_medium"], \
            f"Read took {result['median']:.3f}s, expected < {THRESHOLDS['storage_read_medium']}s"


# =============================================================================
# Benchmark Summary Report
# =============================================================================


class TestBenchmarkSummary:
    """Generate a summary of all performance benchmarks."""

    def test_generate_benchmark_report(self, tmp_path, capsys):
        """Generate and print benchmark summary."""
        from stance.iac import TerraformParser
        from stance.detection.secrets import SecretsDetector
        from stance.engine import PolicyEvaluator
        from stance.models import (
            Asset, AssetCollection, Policy, PolicyCollection,
            Check, CheckType, Severity, Remediation,
            NETWORK_EXPOSURE_INTERNAL,
        )

        results = {}

        # Terraform parsing benchmark
        tf_content = generate_terraform_content(50)
        with tempfile.TemporaryDirectory() as tmpdir:
            tf_file = Path(tmpdir) / "main.tf"
            tf_file.write_text(tf_content)
            parser = TerraformParser()

            timing = measure_time(lambda: parser.parse_file(str(tf_file)))
            results["Terraform (50 resources)"] = timing["median"]

        # Secrets detection benchmark
        content = generate_file_with_potential_secrets(500)
        detector = SecretsDetector()
        timing = measure_time(lambda: detector.detect_in_text(content, "test.py"))
        results["Secrets (500 lines)"] = timing["median"]

        # Policy evaluation benchmark
        assets = AssetCollection([
            Asset(
                id=f"arn:aws:s3:::bucket-{i}",
                cloud_provider="aws",
                account_id="123456789012",
                region="us-east-1",
                resource_type="aws_s3_bucket",
                name=f"bucket-{i}",
                tags={},
                network_exposure=NETWORK_EXPOSURE_INTERNAL,
                raw_config={"encryption": {"enabled": i % 2 == 0}},
            )
            for i in range(50)
        ])

        policies = PolicyCollection([
            Policy(
                id="test-policy",
                name="Test",
                description="Test policy",
                enabled=True,
                severity=Severity.HIGH,
                resource_type="aws_s3_bucket",
                check=Check(check_type=CheckType.EXPRESSION, expression="resource.encryption.enabled == true"),
                compliance=[],
                remediation=Remediation(guidance="Fix it", automation_supported=False),
                tags=[],
                references=[],
            ),
        ])

        evaluator = PolicyEvaluator()
        timing = measure_time(lambda: evaluator.evaluate_all(policies, assets))
        results["Policy eval (50 assets)"] = timing["median"]

        # Print benchmark report
        print("\n" + "=" * 60)
        print("PERFORMANCE BENCHMARK SUMMARY")
        print("=" * 60)
        for name, time_sec in results.items():
            status = "PASS" if time_sec < 0.5 else "SLOW"
            print(f"{name:30} {time_sec*1000:8.2f} ms  [{status}]")
        print("=" * 60)

        # All benchmarks should complete
        assert len(results) == 3
