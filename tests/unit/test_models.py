"""
Tests for Mantissa Stance data models.

Tests Asset, Finding, and Policy models including:
- Creation and immutability
- Serialization/deserialization
- Collection filtering
"""

from __future__ import annotations

from datetime import datetime, timezone

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
    ComplianceMapping,
    Remediation,
    NETWORK_EXPOSURE_INTERNET,
    NETWORK_EXPOSURE_INTERNAL,
    NETWORK_EXPOSURE_ISOLATED,
)


class TestAsset:
    """Tests for the Asset data model."""

    def test_asset_creation(self, sample_asset: Asset):
        """Test Asset can be created with required fields."""
        assert sample_asset.id == "arn:aws:s3:::test-bucket"
        assert sample_asset.cloud_provider == "aws"
        assert sample_asset.account_id == "123456789012"
        assert sample_asset.region == "us-east-1"
        assert sample_asset.resource_type == "aws_s3_bucket"
        assert sample_asset.name == "test-bucket"

    def test_asset_immutability(self, sample_asset: Asset):
        """Test Asset is frozen (immutable)."""
        with pytest.raises(AttributeError):
            sample_asset.name = "new-name"

    def test_asset_to_dict(self, sample_asset: Asset):
        """Test Asset serializes to dict correctly."""
        data = sample_asset.to_dict()

        assert data["id"] == "arn:aws:s3:::test-bucket"
        assert data["cloud_provider"] == "aws"
        assert data["account_id"] == "123456789012"
        assert data["resource_type"] == "aws_s3_bucket"
        assert data["name"] == "test-bucket"
        assert data["tags"] == {"Environment": "test", "Team": "security"}
        assert data["network_exposure"] == NETWORK_EXPOSURE_INTERNAL
        assert "raw_config" in data

    def test_asset_from_dict(self, sample_asset: Asset):
        """Test Asset deserializes from dict correctly."""
        data = sample_asset.to_dict()
        restored = Asset.from_dict(data)

        assert restored.id == sample_asset.id
        assert restored.cloud_provider == sample_asset.cloud_provider
        assert restored.name == sample_asset.name
        assert restored.resource_type == sample_asset.resource_type
        assert restored.network_exposure == sample_asset.network_exposure

    def test_asset_is_internet_facing(
        self,
        sample_asset: Asset,
        sample_internet_facing_asset: Asset,
    ):
        """Test is_internet_facing method."""
        assert not sample_asset.is_internet_facing()
        assert sample_internet_facing_asset.is_internet_facing()

    def test_asset_get_tag(self, sample_asset: Asset):
        """Test tag retrieval with default."""
        assert sample_asset.get_tag("Environment") == "test"
        assert sample_asset.get_tag("Team") == "security"
        assert sample_asset.get_tag("Missing") == ""
        assert sample_asset.get_tag("Missing", "default") == "default"


class TestAssetCollection:
    """Tests for the AssetCollection class."""

    def test_asset_collection_length(self, asset_collection: AssetCollection):
        """Test collection length."""
        assert len(asset_collection) == 3

    def test_asset_collection_iteration(self, asset_collection: AssetCollection):
        """Test collection can be iterated."""
        assets = list(asset_collection)
        assert len(assets) == 3
        assert all(isinstance(a, Asset) for a in assets)

    def test_asset_collection_filter_by_type(self, asset_collection: AssetCollection):
        """Test filtering by resource type."""
        s3_assets = asset_collection.filter_by_type("aws_s3_bucket")
        assert len(s3_assets) == 2

        ec2_assets = asset_collection.filter_by_type("aws_ec2_instance")
        assert len(ec2_assets) == 1

    def test_asset_collection_filter_by_region(self, asset_collection: AssetCollection):
        """Test filtering by region."""
        us_east_assets = asset_collection.filter_by_region("us-east-1")
        assert len(us_east_assets) == 3

        us_west_assets = asset_collection.filter_by_region("us-west-2")
        assert len(us_west_assets) == 0

    def test_asset_collection_filter_internet_facing(
        self, asset_collection: AssetCollection
    ):
        """Test filtering internet-facing assets."""
        internet_facing = asset_collection.filter_internet_facing()
        assert len(internet_facing) == 2  # public bucket and EC2

    def test_asset_collection_filter_by_tag(self, asset_collection: AssetCollection):
        """Test filtering by tag."""
        test_env = asset_collection.filter_by_tag("Environment", "test")
        assert len(test_env) == 1

        prod_env = asset_collection.filter_by_tag("Environment", "prod")
        assert len(prod_env) == 2

    def test_asset_collection_to_list(self, asset_collection: AssetCollection):
        """Test converting to list of dicts."""
        items = asset_collection.to_list()
        assert len(items) == 3
        assert all(isinstance(item, dict) for item in items)


class TestFinding:
    """Tests for the Finding data model."""

    def test_finding_creation(self, sample_finding: Finding):
        """Test Finding creation with various types."""
        assert sample_finding.id == "finding-001"
        assert sample_finding.finding_type == FindingType.MISCONFIGURATION
        assert sample_finding.severity == Severity.HIGH
        assert sample_finding.status == FindingStatus.OPEN

    def test_finding_vulnerability_creation(
        self, sample_vulnerability_finding: Finding
    ):
        """Test vulnerability Finding creation."""
        assert sample_vulnerability_finding.finding_type == FindingType.VULNERABILITY
        assert sample_vulnerability_finding.cve_id == "CVE-2024-0001"
        assert sample_vulnerability_finding.cvss_score == 9.8

    def test_finding_is_critical(
        self,
        sample_finding: Finding,
        sample_vulnerability_finding: Finding,
    ):
        """Test severity check methods."""
        assert not sample_finding.is_critical()
        assert sample_finding.is_high_or_critical()

        assert sample_vulnerability_finding.is_critical()
        assert sample_vulnerability_finding.is_high_or_critical()

    def test_finding_is_vulnerability(
        self,
        sample_finding: Finding,
        sample_vulnerability_finding: Finding,
    ):
        """Test type check methods."""
        assert not sample_finding.is_vulnerability()
        assert sample_finding.is_misconfiguration()

        assert sample_vulnerability_finding.is_vulnerability()
        assert not sample_vulnerability_finding.is_misconfiguration()

    def test_finding_is_open(self, sample_finding: Finding):
        """Test status check."""
        assert sample_finding.is_open()

    def test_finding_has_fix_available(self, sample_vulnerability_finding: Finding):
        """Test fix availability check."""
        assert sample_vulnerability_finding.has_fix_available()

    def test_finding_to_dict(self, sample_finding: Finding):
        """Test Finding serializes to dict."""
        data = sample_finding.to_dict()

        assert data["id"] == "finding-001"
        assert data["finding_type"] == "misconfiguration"
        assert data["severity"] == "high"
        assert data["status"] == "open"
        assert data["rule_id"] == "aws-s3-001"

    def test_finding_from_dict(self, sample_finding: Finding):
        """Test Finding deserializes from dict."""
        data = sample_finding.to_dict()
        restored = Finding.from_dict(data)

        assert restored.id == sample_finding.id
        assert restored.finding_type == sample_finding.finding_type
        assert restored.severity == sample_finding.severity


class TestFindingCollection:
    """Tests for the FindingCollection class."""

    def test_finding_collection_length(self, finding_collection: FindingCollection):
        """Test collection length."""
        assert len(finding_collection) == 4

    def test_finding_collection_filter_by_severity(
        self, finding_collection: FindingCollection
    ):
        """Test severity filtering."""
        critical = finding_collection.filter_by_severity(Severity.CRITICAL)
        assert len(critical) == 1

        high = finding_collection.filter_by_severity(Severity.HIGH)
        assert len(high) == 1

    def test_finding_collection_filter_by_status(
        self, finding_collection: FindingCollection
    ):
        """Test status filtering."""
        open_findings = finding_collection.filter_by_status(FindingStatus.OPEN)
        assert len(open_findings) == 3

        resolved = finding_collection.filter_by_status(FindingStatus.RESOLVED)
        assert len(resolved) == 1

    def test_finding_collection_filter_by_type(
        self, finding_collection: FindingCollection
    ):
        """Test type filtering."""
        misconfigs = finding_collection.filter_by_type(FindingType.MISCONFIGURATION)
        assert len(misconfigs) == 3

        vulns = finding_collection.filter_by_type(FindingType.VULNERABILITY)
        assert len(vulns) == 1

    def test_finding_collection_filter_by_asset(
        self, finding_collection: FindingCollection
    ):
        """Test asset filtering."""
        bucket_findings = finding_collection.filter_by_asset(
            "arn:aws:s3:::test-bucket"
        )
        assert len(bucket_findings) == 3

    def test_finding_collection_count_by_severity(
        self, finding_collection: FindingCollection
    ):
        """Test severity counting."""
        counts = finding_collection.count_by_severity()

        assert counts[Severity.CRITICAL] == 1
        assert counts[Severity.HIGH] == 1
        assert counts[Severity.MEDIUM] == 1
        assert counts[Severity.LOW] == 1
        assert counts[Severity.INFO] == 0

    def test_finding_collection_count_by_severity_dict(
        self, finding_collection: FindingCollection
    ):
        """Test severity counting with string keys."""
        counts = finding_collection.count_by_severity_dict()

        assert counts["critical"] == 1
        assert counts["high"] == 1
        assert counts["medium"] == 1
        assert counts["low"] == 1

    def test_finding_collection_filter_critical(
        self, finding_collection: FindingCollection
    ):
        """Test critical filter shortcut."""
        critical = finding_collection.filter_critical()
        assert len(critical) == 1

    def test_finding_collection_filter_open(
        self, finding_collection: FindingCollection
    ):
        """Test open filter shortcut."""
        open_findings = finding_collection.filter_open()
        assert len(open_findings) == 3

    def test_finding_collection_get_by_id(
        self, finding_collection: FindingCollection
    ):
        """Test finding by ID."""
        finding = finding_collection.get_by_id("finding-001")
        assert finding is not None
        assert finding.id == "finding-001"

        not_found = finding_collection.get_by_id("nonexistent")
        assert not_found is None

    def test_finding_collection_merge(self, finding_collection: FindingCollection):
        """Test merging collections."""
        new_finding = Finding(
            id="new-finding",
            asset_id="test",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.INFO,
            status=FindingStatus.OPEN,
            title="New finding",
            description="Test",
        )
        new_collection = FindingCollection([new_finding])

        merged = finding_collection.merge(new_collection)
        assert len(merged) == 5


class TestSeverityEnum:
    """Tests for Severity enum."""

    def test_severity_from_string(self):
        """Test creating Severity from string."""
        assert Severity.from_string("critical") == Severity.CRITICAL
        assert Severity.from_string("CRITICAL") == Severity.CRITICAL
        assert Severity.from_string("high") == Severity.HIGH
        assert Severity.from_string("medium") == Severity.MEDIUM
        assert Severity.from_string("low") == Severity.LOW
        assert Severity.from_string("info") == Severity.INFO

    def test_severity_from_string_invalid(self):
        """Test invalid severity raises error."""
        with pytest.raises(ValueError):
            Severity.from_string("invalid")


class TestFindingStatusEnum:
    """Tests for FindingStatus enum."""

    def test_status_from_string(self):
        """Test creating FindingStatus from string."""
        assert FindingStatus.from_string("open") == FindingStatus.OPEN
        assert FindingStatus.from_string("resolved") == FindingStatus.RESOLVED
        assert FindingStatus.from_string("suppressed") == FindingStatus.SUPPRESSED
        assert FindingStatus.from_string("false_positive") == FindingStatus.FALSE_POSITIVE

    def test_status_from_string_invalid(self):
        """Test invalid status raises error."""
        with pytest.raises(ValueError):
            FindingStatus.from_string("invalid")


class TestPolicy:
    """Tests for the Policy data model."""

    def test_policy_creation(self, sample_policy: Policy):
        """Test Policy creation."""
        assert sample_policy.id == "aws-s3-001"
        assert sample_policy.name == "S3 Bucket Encryption"
        assert sample_policy.severity == Severity.HIGH
        assert sample_policy.enabled is True

    def test_policy_check(self, sample_policy: Policy):
        """Test Policy check access."""
        assert sample_policy.check.check_type == CheckType.EXPRESSION
        assert "encryption.enabled" in sample_policy.check.expression

    def test_policy_compliance_mappings(self, sample_policy: Policy):
        """Test compliance mappings."""
        assert len(sample_policy.compliance) == 2
        assert sample_policy.compliance[0].framework == "cis-aws-foundations"
        assert sample_policy.compliance[0].control == "2.1.1"

    def test_policy_to_dict(self, sample_policy: Policy):
        """Test Policy serializes to dict."""
        data = sample_policy.to_dict()

        assert data["id"] == "aws-s3-001"
        assert data["severity"] == "high"
        assert data["enabled"] is True
        assert "check" in data

    def test_policy_from_dict(self, sample_policy: Policy):
        """Test Policy deserializes from dict."""
        data = sample_policy.to_dict()
        restored = Policy.from_dict(data)

        assert restored.id == sample_policy.id
        assert restored.severity == sample_policy.severity
        assert restored.check.check_type == sample_policy.check.check_type


class TestPolicyCollection:
    """Tests for the PolicyCollection class."""

    def test_policy_collection_length(self, policy_collection: PolicyCollection):
        """Test collection length."""
        assert len(policy_collection) == 2

    def test_policy_collection_filter_by_severity(
        self, policy_collection: PolicyCollection
    ):
        """Test severity filtering."""
        high = policy_collection.filter_by_severity(Severity.HIGH)
        assert len(high) == 1

        medium = policy_collection.filter_by_severity(Severity.MEDIUM)
        assert len(medium) == 1

    def test_policy_collection_filter_by_resource_type(
        self, policy_collection: PolicyCollection
    ):
        """Test resource type filtering."""
        s3_policies = policy_collection.filter_by_resource_type("aws_s3_bucket")
        assert len(s3_policies) == 2

        ec2_policies = policy_collection.filter_by_resource_type("aws_ec2_instance")
        assert len(ec2_policies) == 0

    def test_policy_collection_filter_enabled(
        self, policy_collection: PolicyCollection
    ):
        """Test enabled filtering."""
        enabled = policy_collection.filter_enabled()
        assert len(enabled) == 2

    def test_policy_collection_get_by_id(
        self, policy_collection: PolicyCollection
    ):
        """Test getting policy by ID."""
        policy = policy_collection.get_by_id("aws-s3-001")
        assert policy is not None
        assert policy.id == "aws-s3-001"

        not_found = policy_collection.get_by_id("nonexistent")
        assert not_found is None
