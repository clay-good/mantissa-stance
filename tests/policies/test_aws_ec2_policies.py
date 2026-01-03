"""
Tests for AWS EC2 policies.

Validates all EC2-related security policies work correctly.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from stance.models import (
    Asset,
    AssetCollection,
    Severity,
    NETWORK_EXPOSURE_INTERNAL,
    NETWORK_EXPOSURE_INTERNET,
)
from stance.engine import PolicyLoader, PolicyEvaluator


@pytest.fixture
def policy_loader():
    """Load AWS EC2 policies."""
    policy_dir = Path(__file__).parent.parent.parent / "policies" / "aws" / "ec2"
    if not policy_dir.exists():
        pytest.skip("AWS EC2 policies directory not found")
    return PolicyLoader(policy_dirs=[str(policy_dir)])


@pytest.fixture
def policies(policy_loader):
    """Load all EC2 policies."""
    return policy_loader.load_all()


class TestSecurityGroupSSHPolicy:
    """Tests for security-group-ssh.yaml policy."""

    def test_policy_loads(self, policies):
        """Test SSH security group policy loads correctly."""
        policy = policies.get_by_id("aws-ec2-001")
        if policy is None:
            pytest.skip("EC2 SSH security group policy not found")

        assert policy.name is not None
        assert policy.severity == Severity.HIGH

    def test_restricted_ssh_passes(self, policies):
        """Test restricted SSH access passes validation."""
        asset = Asset(
            id="arn:aws:ec2:us-east-1:123456789012:security-group/sg-12345",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_security_group",
            name="restricted-sg",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={
                # Policy checks: '0.0.0.0/0' not_in resource.ssh_open_cidrs
                # Restricted CIDRs should pass
                "ssh_open_cidrs": ["10.0.0.0/8"],
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(policies, AssetCollection([asset]))

        ssh_findings = [f for f in findings if f.rule_id == "aws-ec2-001"]
        # Restricted to internal CIDR should pass
        assert len(ssh_findings) == 0

    def test_open_ssh_generates_finding(self, policies):
        """Test open SSH access generates finding."""
        asset = Asset(
            id="arn:aws:ec2:us-east-1:123456789012:security-group/sg-open",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_security_group",
            name="open-ssh-sg",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNET,
            raw_config={
                # Policy checks: '0.0.0.0/0' not_in resource.ssh_open_cidrs
                # 0.0.0.0/0 should generate finding
                "ssh_open_cidrs": ["0.0.0.0/0"],
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(policies, AssetCollection([asset]))

        ssh_findings = [f for f in findings if f.rule_id == "aws-ec2-001"]
        assert len(ssh_findings) == 1
        assert ssh_findings[0].severity == Severity.HIGH


class TestSecurityGroupRDPPolicy:
    """Tests for security-group-rdp.yaml policy."""

    def test_policy_loads(self, policies):
        """Test RDP security group policy loads correctly."""
        policy = policies.get_by_id("aws-ec2-002")
        if policy is None:
            pytest.skip("EC2 RDP security group policy not found")

        assert policy.name is not None
        assert policy.severity == Severity.HIGH

    def test_open_rdp_generates_finding(self, policies):
        """Test open RDP access generates finding."""
        asset = Asset(
            id="arn:aws:ec2:us-east-1:123456789012:security-group/sg-rdp",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_security_group",
            name="open-rdp-sg",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNET,
            raw_config={
                # Policy checks: '0.0.0.0/0' not_in resource.rdp_open_cidrs
                # 0.0.0.0/0 should generate finding
                "rdp_open_cidrs": ["0.0.0.0/0"],
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(policies, AssetCollection([asset]))

        rdp_findings = [f for f in findings if f.rule_id == "aws-ec2-002"]
        assert len(rdp_findings) == 1


class TestIMDSv2Policy:
    """Tests for imdsv2-required.yaml policy."""

    def test_policy_loads(self, policies):
        """Test IMDSv2 policy loads correctly."""
        policy = policies.get_by_id("aws-ec2-003")
        if policy is None:
            pytest.skip("EC2 IMDSv2 policy not found")

        assert policy.name is not None

    def test_imdsv2_enabled_passes(self, policies):
        """Test instance with IMDSv2 required passes."""
        asset = Asset(
            id="arn:aws:ec2:us-east-1:123456789012:instance/i-secure",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_ec2_instance",
            name="secure-instance",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={
                "metadata_options": {
                    "http_tokens": "required",
                    "http_endpoint": "enabled",
                },
                "imdsv2_required": True,
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(policies, AssetCollection([asset]))

        imds_findings = [f for f in findings if f.rule_id == "aws-ec2-003"]
        assert len(imds_findings) == 0

    def test_imdsv1_generates_finding(self, policies):
        """Test instance with IMDSv1 generates finding."""
        asset = Asset(
            id="arn:aws:ec2:us-east-1:123456789012:instance/i-insecure",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_ec2_instance",
            name="insecure-instance",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={
                "metadata_options": {
                    "http_tokens": "optional",
                    "http_endpoint": "enabled",
                },
                "imdsv2_required": False,
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(policies, AssetCollection([asset]))

        imds_findings = [f for f in findings if f.rule_id == "aws-ec2-003"]
        assert len(imds_findings) == 1


class TestEBSEncryptionPolicy:
    """Tests for ebs-encryption.yaml policy."""

    def test_policy_loads(self, policies):
        """Test EBS encryption policy loads correctly."""
        policy = policies.get_by_id("aws-ec2-004")
        if policy is None:
            pytest.skip("EC2 EBS encryption policy not found")

        assert policy.name is not None

    def test_encrypted_volume_passes(self, policies):
        """Test encrypted EBS volume passes."""
        asset = Asset(
            id="arn:aws:ec2:us-east-1:123456789012:volume/vol-encrypted",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_ebs_volume",
            name="encrypted-volume",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={
                "encrypted": True,
                "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/xxx",
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(policies, AssetCollection([asset]))

        ebs_findings = [f for f in findings if f.rule_id == "aws-ec2-004"]
        assert len(ebs_findings) == 0


class TestEC2PolicySchema:
    """Test EC2 policy schema validation."""

    def test_all_ec2_policies_have_valid_resource_type(self, policies):
        """Test all EC2 policies target EC2 resources."""
        valid_prefixes = ["aws_ec2", "aws_security_group", "aws_ebs"]
        for policy in policies:
            assert any(
                policy.resource_type.startswith(prefix)
                for prefix in valid_prefixes
            ), f"Policy {policy.id} has unexpected resource type: {policy.resource_type}"

    def test_security_group_policies_are_high_severity(self, policies):
        """Test security group policies have appropriate severity."""
        for policy in policies:
            if "security_group" in policy.resource_type:
                # Security group misconfigurations should be high severity
                assert policy.severity in [Severity.CRITICAL, Severity.HIGH]
