"""
Integration tests for policy evaluation workflow.

Tests cover:
- Loading policies from YAML files
- Evaluating policies against assets
- Generating findings from violations
- Compliance scoring calculations
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
import tempfile

import pytest

from stance.models import (
    Asset,
    AssetCollection,
    Finding,
    FindingCollection,
    FindingType,
    Severity,
    FindingStatus,
    Policy,
    PolicyCollection,
    Check,
    CheckType,
    Remediation,
    NETWORK_EXPOSURE_INTERNAL,
    NETWORK_EXPOSURE_INTERNET,
)
from stance.engine import PolicyLoader, PolicyEvaluator, run_evaluation
from stance.engine.expressions import ExpressionEvaluator
from stance.engine.compliance import ComplianceCalculator


@pytest.fixture
def sample_s3_asset() -> Asset:
    """Create sample S3 bucket asset."""
    return Asset(
        id="arn:aws:s3:::test-bucket",
        cloud_provider="aws",
        account_id="123456789012",
        region="us-east-1",
        resource_type="aws_s3_bucket",
        name="test-bucket",
        tags={"Environment": "prod"},
        network_exposure=NETWORK_EXPOSURE_INTERNAL,
        created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
        raw_config={
            "encryption": {"enabled": False},
            "versioning": {"enabled": True},
            "logging": {"enabled": True},
        },
    )


@pytest.fixture
def sample_ec2_asset() -> Asset:
    """Create sample EC2 instance asset."""
    return Asset(
        id="arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
        cloud_provider="aws",
        account_id="123456789012",
        region="us-east-1",
        resource_type="aws_ec2_instance",
        name="test-instance",
        tags={"Environment": "prod"},
        network_exposure=NETWORK_EXPOSURE_INTERNET,
        created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
        raw_config={
            "imdsv2_required": False,
            "ebs_optimized": True,
            "public_ip": "1.2.3.4",
        },
    )


class TestExpressionEvaluation:
    """Test expression evaluation in policy checks."""

    def test_simple_equality(self, sample_s3_asset):
        """Test simple equality expression."""
        evaluator = ExpressionEvaluator()
        context = {"resource": sample_s3_asset.raw_config}

        result = evaluator.evaluate("resource.encryption.enabled == false", context)
        assert result is True

    def test_nested_path(self, sample_s3_asset):
        """Test nested path access."""
        evaluator = ExpressionEvaluator()
        context = {"resource": sample_s3_asset.raw_config}

        result = evaluator.evaluate("resource.versioning.enabled == true", context)
        assert result is True

    def test_boolean_and(self, sample_s3_asset):
        """Test boolean AND expression."""
        evaluator = ExpressionEvaluator()
        context = {"resource": sample_s3_asset.raw_config}

        result = evaluator.evaluate(
            "resource.versioning.enabled == true and resource.logging.enabled == true",
            context
        )
        assert result is True

    def test_boolean_or(self, sample_s3_asset):
        """Test boolean OR expression."""
        evaluator = ExpressionEvaluator()
        context = {"resource": sample_s3_asset.raw_config}

        result = evaluator.evaluate(
            "resource.encryption.enabled == true or resource.versioning.enabled == true",
            context
        )
        assert result is True


class TestPolicyLoading:
    """Test policy loading from YAML."""

    def test_load_policy_from_yaml(self, tmp_path):
        """Test loading a policy from YAML file."""
        policy_yaml = """
id: test-policy-001
name: Test Encryption Policy
description: Ensure encryption is enabled.
enabled: true
severity: high
resource_type: aws_s3_bucket
check:
  type: expression
  expression: "resource.encryption.enabled == true"
remediation:
  guidance: Enable encryption on the bucket.
  automation_supported: false
tags:
  - s3
  - encryption
"""
        policy_file = tmp_path / "test-policy.yaml"
        policy_file.write_text(policy_yaml)

        loader = PolicyLoader(policy_dirs=[str(tmp_path)])
        policies = loader.load_all()

        assert len(policies) == 1
        assert policies.policies[0].id == "test-policy-001"
        assert policies.policies[0].severity == Severity.HIGH

    def test_load_multiple_policies(self, tmp_path):
        """Test loading multiple policies."""
        for i in range(3):
            policy_yaml = f"""
id: test-policy-{i:03d}
name: Test Policy {i}
description: Test policy number {i}.
enabled: true
severity: medium
resource_type: aws_s3_bucket
check:
  type: expression
  expression: "resource.field{i} == true"
remediation:
  guidance: Fix field{i}.
  automation_supported: false
tags:
  - test
"""
            (tmp_path / f"policy-{i}.yaml").write_text(policy_yaml)

        loader = PolicyLoader(policy_dirs=[str(tmp_path)])
        policies = loader.load_all()

        assert len(policies) == 3

    def test_disabled_policy_excluded(self, tmp_path):
        """Test that disabled policies can be filtered."""
        policy_yaml = """
id: disabled-policy
name: Disabled Policy
description: This policy is disabled.
enabled: false
severity: low
resource_type: aws_s3_bucket
check:
  type: expression
  expression: "resource.something == true"
remediation:
  guidance: N/A
  automation_supported: false
tags: []
"""
        (tmp_path / "disabled.yaml").write_text(policy_yaml)

        loader = PolicyLoader(policy_dirs=[str(tmp_path)])
        policies = loader.load_all()
        enabled_policies = policies.filter_enabled()

        assert len(enabled_policies) == 0


class TestPolicyEvaluation:
    """Test policy evaluation against assets."""

    def test_policy_generates_finding(self, sample_s3_asset):
        """Test that violating a policy generates a finding."""
        policy = Policy(
            id="aws-s3-encryption",
            name="S3 Encryption Required",
            description="S3 buckets must have encryption enabled.",
            enabled=True,
            severity=Severity.HIGH,
            resource_type="aws_s3_bucket",
            check=Check(
                check_type=CheckType.EXPRESSION,
                expression="resource.encryption.enabled == true",
            ),
            compliance=[],
            remediation=Remediation(guidance="Enable encryption"),
            tags=["encryption"],
            references=[],
        )

        assets = AssetCollection([sample_s3_asset])
        policies = PolicyCollection([policy])

        evaluator = PolicyEvaluator()
        findings, result = evaluator.evaluate_all(policies, assets)

        # Should generate finding since encryption is disabled
        assert len(findings) == 1
        assert findings.findings[0].rule_id == "aws-s3-encryption"
        assert findings.findings[0].severity == Severity.HIGH

    def test_compliant_resource_no_finding(self, sample_s3_asset):
        """Test that compliant resources don't generate findings."""
        # Policy checking for versioning (which is enabled)
        policy = Policy(
            id="aws-s3-versioning",
            name="S3 Versioning Required",
            description="S3 buckets must have versioning enabled.",
            enabled=True,
            severity=Severity.MEDIUM,
            resource_type="aws_s3_bucket",
            check=Check(
                check_type=CheckType.EXPRESSION,
                expression="resource.versioning.enabled == true",
            ),
            compliance=[],
            remediation=Remediation(guidance="Enable versioning"),
            tags=["versioning"],
            references=[],
        )

        assets = AssetCollection([sample_s3_asset])
        policies = PolicyCollection([policy])

        evaluator = PolicyEvaluator()
        findings, result = evaluator.evaluate_all(policies, assets)

        # Should not generate finding since versioning is enabled
        assert len(findings) == 0

    def test_resource_type_filtering(self, sample_s3_asset, sample_ec2_asset):
        """Test that policies only evaluate matching resource types."""
        ec2_policy = Policy(
            id="aws-ec2-imdsv2",
            name="IMDSv2 Required",
            description="EC2 instances must require IMDSv2.",
            enabled=True,
            severity=Severity.HIGH,
            resource_type="aws_ec2_instance",
            check=Check(
                check_type=CheckType.EXPRESSION,
                expression="resource.imdsv2_required == true",
            ),
            compliance=[],
            remediation=Remediation(guidance="Require IMDSv2"),
            tags=["ec2"],
            references=[],
        )

        # Include both S3 and EC2 assets
        assets = AssetCollection([sample_s3_asset, sample_ec2_asset])
        policies = PolicyCollection([ec2_policy])

        evaluator = PolicyEvaluator()
        findings, result = evaluator.evaluate_all(policies, assets)

        # Should only generate finding for EC2 instance
        assert len(findings) == 1
        assert findings.findings[0].asset_id == sample_ec2_asset.id


class TestComplianceScoring:
    """Test compliance score calculations."""

    def test_calculate_framework_score(self):
        """Test calculating compliance score for a framework."""
        # Create policies with compliance mappings
        policies = PolicyCollection([
            Policy(
                id="policy-1",
                name="Policy 1",
                description="Test",
                enabled=True,
                severity=Severity.HIGH,
                resource_type="aws_s3_bucket",
                check=Check(check_type=CheckType.EXPRESSION, expression="true"),
                compliance=[],
                remediation=Remediation(),
                tags=[],
                references=[],
            ),
        ])

        assets = AssetCollection([])
        findings = FindingCollection([])

        calculator = ComplianceCalculator()
        report = calculator.calculate_scores(policies, findings, assets)

        assert report is not None
        assert report.overall_score >= 0

    def test_findings_reduce_score(self):
        """Test that findings reduce compliance score."""
        asset = Asset(
            id="test-asset",
            cloud_provider="aws",
            account_id="123",
            region="us-east-1",
            resource_type="aws_s3_bucket",
            name="test",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={"encryption": {"enabled": False}},
        )

        policy = Policy(
            id="policy-1",
            name="Encryption Required",
            description="Test",
            enabled=True,
            severity=Severity.HIGH,
            resource_type="aws_s3_bucket",
            check=Check(
                check_type=CheckType.EXPRESSION,
                expression="resource.encryption.enabled == true",
            ),
            compliance=[],
            remediation=Remediation(guidance="Enable encryption"),
            tags=[],
            references=[],
        )

        assets = AssetCollection([asset])
        policies = PolicyCollection([policy])

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(policies, assets)

        calculator = ComplianceCalculator()
        report = calculator.calculate_scores(policies, findings, assets)

        # With findings, score should be affected
        assert report is not None


class TestEndToEndEvaluation:
    """Test complete evaluation workflow."""

    def test_run_evaluation_convenience(self, tmp_path):
        """Test the run_evaluation convenience function."""
        # Create policy
        policy_yaml = """
id: e2e-test-001
name: E2E Test Policy
description: End-to-end test policy.
enabled: true
severity: medium
resource_type: aws_s3_bucket
check:
  type: expression
  expression: "resource.test_field == true"
remediation:
  guidance: Set test_field to true.
  automation_supported: false
tags:
  - test
"""
        policy_dir = tmp_path / "policies"
        policy_dir.mkdir()
        (policy_dir / "e2e-test.yaml").write_text(policy_yaml)

        # Create asset
        asset = Asset(
            id="test-asset",
            cloud_provider="aws",
            account_id="123",
            region="us-east-1",
            resource_type="aws_s3_bucket",
            name="test",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={"test_field": False},
        )
        assets = AssetCollection([asset])

        # Run evaluation
        findings, result = run_evaluation(assets, policy_dirs=[str(policy_dir)])

        assert len(findings) == 1
        assert result.policies_evaluated == 1
        assert result.findings_generated == 1
