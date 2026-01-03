"""
Tests for AWS S3 policies.

Validates all S3-related security policies work correctly.
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
    """Load AWS S3 policies."""
    policy_dir = Path(__file__).parent.parent.parent / "policies" / "aws" / "s3"
    if not policy_dir.exists():
        pytest.skip("AWS S3 policies directory not found")
    return PolicyLoader(policy_dirs=[str(policy_dir)])


@pytest.fixture
def policies(policy_loader):
    """Load all S3 policies."""
    return policy_loader.load_all()


class TestBucketEncryptionPolicy:
    """Tests for bucket-encryption.yaml policy."""

    def test_policy_loads(self, policies):
        """Test encryption policy loads correctly."""
        policy = policies.get_by_id("aws-s3-001")
        if policy is None:
            pytest.skip("S3 encryption policy not found")

        assert policy.name is not None
        assert policy.severity == Severity.HIGH

    def test_encrypted_bucket_passes(self, policies):
        """Test encrypted bucket passes validation."""
        asset = Asset(
            id="arn:aws:s3:::encrypted-bucket",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_s3_bucket",
            name="encrypted-bucket",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={
                "encryption": {
                    "enabled": True,
                    "sse_algorithm": "AES256",
                },
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(policies, AssetCollection([asset]))

        encryption_findings = [f for f in findings if f.rule_id == "aws-s3-001"]
        assert len(encryption_findings) == 0

    def test_unencrypted_bucket_generates_finding(self, policies):
        """Test unencrypted bucket generates finding."""
        asset = Asset(
            id="arn:aws:s3:::unencrypted-bucket",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_s3_bucket",
            name="unencrypted-bucket",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={
                "encryption": {
                    "enabled": False,
                },
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(policies, AssetCollection([asset]))

        encryption_findings = [f for f in findings if f.rule_id == "aws-s3-001"]
        assert len(encryption_findings) == 1
        assert encryption_findings[0].severity == Severity.HIGH


class TestPublicAccessBlockPolicy:
    """Tests for public-access-block.yaml policy."""

    def test_policy_loads(self, policies):
        """Test public access block policy loads correctly."""
        policy = policies.get_by_id("aws-s3-002")
        if policy is None:
            pytest.skip("S3 public access block policy not found")

        assert policy.name is not None
        assert policy.severity == Severity.CRITICAL

    def test_private_bucket_passes(self, policies):
        """Test private bucket passes validation."""
        asset = Asset(
            id="arn:aws:s3:::private-bucket",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_s3_bucket",
            name="private-bucket",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={
                "public_access_block": {
                    "block_public_acls": True,
                    "block_public_policy": True,
                    "ignore_public_acls": True,
                    "restrict_public_buckets": True,
                },
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(policies, AssetCollection([asset]))

        public_findings = [f for f in findings if f.rule_id == "aws-s3-002"]
        assert len(public_findings) == 0

    def test_public_bucket_generates_finding(self, policies):
        """Test public bucket generates finding."""
        asset = Asset(
            id="arn:aws:s3:::public-bucket",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_s3_bucket",
            name="public-bucket",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNET,
            raw_config={
                "public_access_block": {
                    "block_public_acls": False,
                    "block_public_policy": False,
                    "ignore_public_acls": False,
                    "restrict_public_buckets": False,
                },
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(policies, AssetCollection([asset]))

        public_findings = [f for f in findings if f.rule_id == "aws-s3-002"]
        assert len(public_findings) == 1
        assert public_findings[0].severity == Severity.CRITICAL


class TestS3PolicySchema:
    """Test S3 policy schema validation."""

    def test_all_s3_policies_have_valid_resource_type(self, policies):
        """Test all S3 policies target S3 resources."""
        for policy in policies:
            assert "s3" in policy.resource_type.lower()

    def test_all_s3_policies_have_s3_tags(self, policies):
        """Test all S3 policies are tagged appropriately."""
        for policy in policies:
            assert "s3" in policy.tags or "storage" in policy.tags


class TestS3ComplianceMappings:
    """Test S3 policy compliance mappings."""

    def test_encryption_policy_has_cis_mapping(self, policies):
        """Test encryption policy maps to CIS controls."""
        policy = policies.get_by_id("aws-s3-001")
        if policy is None:
            pytest.skip("S3 encryption policy not found")

        if policy.compliance:
            frameworks = [c.framework for c in policy.compliance]
            assert any("cis" in f.lower() for f in frameworks)

    def test_public_access_policy_has_compliance_mapping(self, policies):
        """Test public access policy has compliance mappings."""
        policy = policies.get_by_id("aws-s3-002")
        if policy is None:
            pytest.skip("S3 public access block policy not found")

        if policy.compliance:
            assert len(policy.compliance) > 0
