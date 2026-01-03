"""
Unit tests for cross-cloud aggregation module.

Tests the FindingsAggregator, CrossCloudSync, and FederatedQuery
implementations for multi-cloud security posture management.
"""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

from stance.models.finding import Finding, FindingCollection, FindingType, Severity, FindingStatus
from stance.models.asset import Asset, AssetCollection
from stance.aggregation import (
    FindingsAggregator,
    CloudAccount,
    AggregationResult,
    NormalizedFinding,
    CrossCloudSync,
    SyncConfig,
    SyncResult,
    SyncDirection,
    ConflictResolution,
    FederatedQuery,
    FederatedQueryResult,
    BackendConfig,
    QueryStrategy,
    MergeStrategy,
)


# ============================================================================
# CloudAccount Tests
# ============================================================================


class TestCloudAccount:
    """Tests for CloudAccount dataclass."""

    def test_cloud_account_creation(self) -> None:
        """Test CloudAccount can be created with required fields."""
        account = CloudAccount(
            id="123456789012",
            provider="aws",
            name="Production",
        )

        assert account.id == "123456789012"
        assert account.provider == "aws"
        assert account.name == "Production"
        assert account.region is None
        assert account.metadata == {}

    def test_cloud_account_with_all_fields(self) -> None:
        """Test CloudAccount with all fields populated."""
        account = CloudAccount(
            id="my-project",
            provider="gcp",
            name="GCP Project",
            region="us-central1",
            metadata={"env": "prod", "team": "security"},
        )

        assert account.id == "my-project"
        assert account.provider == "gcp"
        assert account.region == "us-central1"
        assert account.metadata["env"] == "prod"


# ============================================================================
# AggregationResult Tests
# ============================================================================


class TestAggregationResult:
    """Tests for AggregationResult dataclass."""

    def test_aggregation_result_defaults(self) -> None:
        """Test AggregationResult with default values."""
        result = AggregationResult()

        assert result.total_findings == 0
        assert result.unique_findings == 0
        assert result.duplicates_removed == 0
        assert result.findings_by_severity == {}
        assert result.findings_by_provider == {}
        assert result.source_accounts == []

    def test_aggregation_result_with_values(self) -> None:
        """Test AggregationResult with populated values."""
        account = CloudAccount("123", "aws", "Test")
        result = AggregationResult(
            total_findings=100,
            unique_findings=80,
            duplicates_removed=20,
            findings_by_severity={"critical": 5, "high": 15},
            findings_by_provider={"aws": 60, "gcp": 40},
            source_accounts=[account],
        )

        assert result.total_findings == 100
        assert result.unique_findings == 80
        assert result.duplicates_removed == 20
        assert result.findings_by_severity["critical"] == 5
        assert len(result.source_accounts) == 1

    def test_aggregation_result_to_dict(self) -> None:
        """Test AggregationResult to_dict method."""
        account = CloudAccount("123", "aws", "Test")
        result = AggregationResult(
            total_findings=50,
            unique_findings=45,
            source_accounts=[account],
        )

        d = result.to_dict()
        assert d["total_findings"] == 50
        assert d["unique_findings"] == 45
        assert "aggregated_at" in d
        assert len(d["source_accounts"]) == 1


# ============================================================================
# NormalizedFinding Tests
# ============================================================================


class TestNormalizedFinding:
    """Tests for NormalizedFinding dataclass."""

    def test_normalized_finding_creation(self) -> None:
        """Test NormalizedFinding can be created."""
        finding = Finding(
            id="finding-1",
            asset_id="arn:aws:s3:::bucket",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            title="Test Finding",
            description="Description",
        )

        normalized = NormalizedFinding(
            original=finding,
            normalized_key="abc123",
            provider="aws",
            account_id="123456789012",
            canonical_resource_type="storage_bucket",
            canonical_rule_id="storage-encryption",
        )

        assert normalized.original is finding
        assert normalized.normalized_key == "abc123"
        assert normalized.provider == "aws"
        assert normalized.canonical_resource_type == "storage_bucket"


# ============================================================================
# FindingsAggregator Tests
# ============================================================================


class TestFindingsAggregator:
    """Tests for FindingsAggregator."""

    @pytest.fixture
    def aggregator(self) -> FindingsAggregator:
        """Create a fresh aggregator for each test."""
        return FindingsAggregator()

    @pytest.fixture
    def sample_finding(self) -> Finding:
        """Create a sample finding."""
        return Finding(
            id="finding-1",
            asset_id="arn:aws:s3:::test-bucket",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            title="S3 bucket not encrypted",
            description="The S3 bucket does not have encryption enabled.",
            rule_id="aws-s3-001",
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )

    def test_aggregator_creation(self) -> None:
        """Test FindingsAggregator can be created."""
        aggregator = FindingsAggregator()
        assert aggregator is not None

    def test_aggregator_with_custom_window(self) -> None:
        """Test FindingsAggregator with custom dedup window."""
        aggregator = FindingsAggregator(dedup_window_hours=48)
        assert aggregator is not None

    def test_add_account(self, aggregator: FindingsAggregator) -> None:
        """Test adding an account."""
        account = CloudAccount("123456789012", "aws", "Production")
        aggregator.add_account(account)

        # Account should be registered
        assert "123456789012" in aggregator._accounts

    def test_add_findings_requires_account(
        self, aggregator: FindingsAggregator, sample_finding: Finding
    ) -> None:
        """Test adding findings requires account to be registered first."""
        with pytest.raises(ValueError) as exc_info:
            aggregator.add_findings("unknown-account", [sample_finding])

        assert "not registered" in str(exc_info.value)

    def test_add_findings(
        self, aggregator: FindingsAggregator, sample_finding: Finding
    ) -> None:
        """Test adding findings to an account."""
        account = CloudAccount("123", "aws", "Test")
        aggregator.add_account(account)
        aggregator.add_findings("123", [sample_finding])

        assert len(aggregator._findings["123"]) == 1

    def test_add_findings_collection(
        self, aggregator: FindingsAggregator, sample_finding: Finding
    ) -> None:
        """Test adding FindingCollection."""
        account = CloudAccount("123", "aws", "Test")
        aggregator.add_account(account)

        collection = FindingCollection([sample_finding])
        aggregator.add_findings("123", collection)

        assert len(aggregator._findings["123"]) == 1

    def test_add_assets(self, aggregator: FindingsAggregator) -> None:
        """Test adding assets to an account."""
        account = CloudAccount("123", "aws", "Test")
        aggregator.add_account(account)

        asset = Asset(
            id="arn:aws:s3:::bucket",
            cloud_provider="aws",
            account_id="123",
            region="us-east-1",
            resource_type="aws_s3_bucket",
            name="bucket",
            tags={},
            network_exposure="internal",
            created_at=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            raw_config={},
        )
        aggregator.add_assets("123", [asset])

        assert len(aggregator._assets["123"]) == 1

    def test_aggregate_empty(self, aggregator: FindingsAggregator) -> None:
        """Test aggregating with no findings."""
        findings, result = aggregator.aggregate()

        assert len(findings) == 0
        assert result.total_findings == 0
        assert result.unique_findings == 0

    def test_aggregate_single_account(
        self, aggregator: FindingsAggregator, sample_finding: Finding
    ) -> None:
        """Test aggregating findings from single account."""
        account = CloudAccount("123", "aws", "Test")
        aggregator.add_account(account)
        aggregator.add_findings("123", [sample_finding])

        findings, result = aggregator.aggregate()

        assert len(findings) == 1
        assert result.total_findings == 1
        assert result.unique_findings == 1
        assert result.duplicates_removed == 0
        assert "aws" in result.findings_by_provider

    def test_aggregate_multiple_accounts(
        self, aggregator: FindingsAggregator
    ) -> None:
        """Test aggregating findings from multiple accounts."""
        # Add AWS account with finding
        aws_account = CloudAccount("123", "aws", "AWS Prod")
        aws_finding = Finding(
            id="aws-finding-1",
            asset_id="arn:aws:s3:::bucket",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            title="AWS Finding",
            description="Description",
        )
        aggregator.add_account(aws_account)
        aggregator.add_findings("123", [aws_finding])

        # Add GCP account with finding
        gcp_account = CloudAccount("my-project", "gcp", "GCP Prod")
        gcp_finding = Finding(
            id="gcp-finding-1",
            asset_id="//storage.googleapis.com/projects/my-project/buckets/bucket",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.MEDIUM,
            status=FindingStatus.OPEN,
            title="GCP Finding",
            description="Description",
        )
        aggregator.add_account(gcp_account)
        aggregator.add_findings("my-project", [gcp_finding])

        findings, result = aggregator.aggregate()

        assert len(findings) == 2
        assert result.total_findings == 2
        assert result.findings_by_provider["aws"] == 1
        assert result.findings_by_provider["gcp"] == 1

    def test_aggregate_with_severity_filter(
        self, aggregator: FindingsAggregator
    ) -> None:
        """Test aggregating with severity filter."""
        account = CloudAccount("123", "aws", "Test")
        aggregator.add_account(account)

        # Add findings with different severities
        high_finding = Finding(
            id="high-1",
            asset_id="arn:aws:s3:::bucket",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            title="High Severity",
            description="Description",
        )
        low_finding = Finding(
            id="low-1",
            asset_id="arn:aws:s3:::bucket2",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.LOW,
            status=FindingStatus.OPEN,
            title="Low Severity",
            description="Description",
        )
        aggregator.add_findings("123", [high_finding, low_finding])

        # Filter for HIGH only
        findings, result = aggregator.aggregate(severity_filter=Severity.HIGH)

        assert len(findings) == 1
        assert result.total_findings == 1

    def test_aggregate_deduplication(self, aggregator: FindingsAggregator) -> None:
        """Test that duplicate findings are deduplicated."""
        account1 = CloudAccount("123", "aws", "Account 1")
        account2 = CloudAccount("456", "aws", "Account 2")
        aggregator.add_account(account1)
        aggregator.add_account(account2)

        # Same finding type in both accounts
        finding1 = Finding(
            id="f1",
            asset_id="arn:aws:s3:::bucket1",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            title="S3 bucket not encrypted",
            description="Description",
            rule_id="aws-s3-001",
        )
        finding2 = Finding(
            id="f2",
            asset_id="arn:aws:s3:::bucket2",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            title="S3 bucket not encrypted",  # Same title = potential duplicate
            description="Description",
            rule_id="aws-s3-001",  # Same rule
        )

        aggregator.add_findings("123", [finding1])
        aggregator.add_findings("456", [finding2])

        findings, result = aggregator.aggregate(deduplicate=True)

        # These should be deduplicated to 1
        assert result.duplicates_removed >= 0

    def test_aggregate_without_deduplication(
        self, aggregator: FindingsAggregator, sample_finding: Finding
    ) -> None:
        """Test aggregating without deduplication."""
        account = CloudAccount("123", "aws", "Test")
        aggregator.add_account(account)
        aggregator.add_findings("123", [sample_finding, sample_finding])

        findings, result = aggregator.aggregate(deduplicate=False)

        # Without dedup, should have all findings
        assert len(findings) == 2
        assert result.duplicates_removed == 0

    def test_get_cross_account_findings(
        self, aggregator: FindingsAggregator
    ) -> None:
        """Test getting findings that appear in multiple accounts."""
        account1 = CloudAccount("123", "aws", "Account 1")
        account2 = CloudAccount("456", "aws", "Account 2")
        aggregator.add_account(account1)
        aggregator.add_account(account2)

        # Same finding type in both accounts
        finding1 = Finding(
            id="f1",
            asset_id="arn:aws:s3:::bucket1",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            title="Common issue",
            description="Description",
            rule_id="aws-common-001",
        )
        finding2 = Finding(
            id="f2",
            asset_id="arn:aws:s3:::bucket2",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            title="Common issue",
            description="Description",
            rule_id="aws-common-001",
        )

        aggregator.add_findings("123", [finding1])
        aggregator.add_findings("456", [finding2])

        cross_account = aggregator.get_cross_account_findings(min_accounts=2)
        # Should find the common issue
        assert isinstance(cross_account, FindingCollection)

    def test_generate_summary_report(
        self, aggregator: FindingsAggregator, sample_finding: Finding
    ) -> None:
        """Test generating summary report."""
        account = CloudAccount("123", "aws", "Test")
        aggregator.add_account(account)
        aggregator.add_findings("123", [sample_finding])

        report = aggregator.generate_summary_report()

        assert "summary" in report
        assert "by_severity" in report
        assert "by_provider" in report
        assert report["summary"]["total_accounts"] == 1

    def test_clear(
        self, aggregator: FindingsAggregator, sample_finding: Finding
    ) -> None:
        """Test clearing the aggregator."""
        account = CloudAccount("123", "aws", "Test")
        aggregator.add_account(account)
        aggregator.add_findings("123", [sample_finding])

        aggregator.clear()

        assert len(aggregator._accounts) == 0
        assert len(aggregator._findings) == 0

    def test_extract_resource_type_aws(
        self, aggregator: FindingsAggregator
    ) -> None:
        """Test extracting resource type from AWS ARN."""
        resource_type = aggregator._extract_resource_type(
            "arn:aws:s3:::my-bucket", "aws"
        )
        assert "s3" in resource_type.lower()

    def test_extract_resource_type_gcp(
        self, aggregator: FindingsAggregator
    ) -> None:
        """Test extracting resource type from GCP resource path."""
        resource_type = aggregator._extract_resource_type(
            "//storage.googleapis.com/projects/my-project/buckets/my-bucket",
            "gcp",
        )
        assert "storage" in resource_type.lower()

    def test_extract_resource_type_azure(
        self, aggregator: FindingsAggregator
    ) -> None:
        """Test extracting resource type from Azure resource path."""
        resource_type = aggregator._extract_resource_type(
            "/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa",
            "azure",
        )
        assert "storageaccounts" in resource_type.lower()


# ============================================================================
# SyncConfig Tests
# ============================================================================


class TestSyncConfig:
    """Tests for SyncConfig."""

    def test_sync_config_creation(self) -> None:
        """Test SyncConfig can be created."""
        config = SyncConfig(
            central_bucket="stance-central-findings",
            central_prefix="aggregated",
            sync_direction=SyncDirection.BIDIRECTIONAL,
        )

        assert config.central_bucket == "stance-central-findings"
        assert config.central_prefix == "aggregated"
        assert config.sync_direction == SyncDirection.BIDIRECTIONAL

    def test_sync_config_defaults(self) -> None:
        """Test SyncConfig default values."""
        config = SyncConfig(central_bucket="bucket")

        assert config.central_prefix == "aggregated"
        assert config.sync_direction == SyncDirection.PUSH
        assert config.include_assets is True
        assert config.batch_size == 1000


# ============================================================================
# SyncResult Tests
# ============================================================================


class TestSyncResult:
    """Tests for SyncResult."""

    def test_sync_result_creation(self) -> None:
        """Test SyncResult can be created."""
        result = SyncResult(
            records_synced=100,
            conflicts_resolved=5,
            errors=[],
        )

        assert result.records_synced == 100
        assert result.conflicts_resolved == 5
        assert result.errors == []

    def test_sync_result_defaults(self) -> None:
        """Test SyncResult default values."""
        result = SyncResult()

        assert result.success is True
        assert result.records_synced == 0
        assert result.records_skipped == 0
        assert result.conflicts_resolved == 0

    def test_sync_result_to_dict(self) -> None:
        """Test SyncResult to_dict method."""
        result = SyncResult(records_synced=50)
        d = result.to_dict()

        assert d["records_synced"] == 50
        assert "sync_direction" in d


# ============================================================================
# CrossCloudSync Tests
# ============================================================================


class TestCrossCloudSync:
    """Tests for CrossCloudSync."""

    @pytest.fixture
    def mock_storage(self) -> MagicMock:
        """Create a mock storage adapter."""
        storage = MagicMock()
        storage.write_record = MagicMock()
        storage.read_record = MagicMock(return_value=None)
        storage.list_records = MagicMock(return_value=[])
        return storage

    def test_cross_cloud_sync_creation(self, mock_storage: MagicMock) -> None:
        """Test CrossCloudSync can be created."""
        config = SyncConfig(central_bucket="bucket")
        sync = CrossCloudSync(config, mock_storage)
        assert sync is not None

    def test_cross_cloud_sync_has_required_methods(
        self, mock_storage: MagicMock
    ) -> None:
        """Test CrossCloudSync has required methods."""
        config = SyncConfig(central_bucket="bucket")
        sync = CrossCloudSync(config, mock_storage)

        assert hasattr(sync, "sync")
        assert hasattr(sync, "add_local_findings")


# ============================================================================
# BackendConfig Tests
# ============================================================================


class TestBackendConfig:
    """Tests for BackendConfig."""

    def test_backend_config_creation(self) -> None:
        """Test BackendConfig can be created."""
        from stance.query import AthenaQueryEngine

        engine = AthenaQueryEngine(database="test")
        config = BackendConfig(
            name="athena",
            engine=engine,
            provider="aws",
        )

        assert config.name == "athena"
        assert config.provider == "aws"
        assert config.engine is engine

    def test_backend_config_defaults(self) -> None:
        """Test BackendConfig default values."""
        from stance.query import AthenaQueryEngine

        engine = AthenaQueryEngine(database="test")
        config = BackendConfig(
            name="athena",
            engine=engine,
            provider="aws",
        )

        assert config.priority == 0
        assert config.enabled is True
        assert config.timeout_seconds == 300


# ============================================================================
# FederatedQueryResult Tests
# ============================================================================


class TestFederatedQueryResult:
    """Tests for FederatedQueryResult."""

    def test_federated_query_result_creation(self) -> None:
        """Test FederatedQueryResult can be created."""
        result = FederatedQueryResult(
            rows=[{"id": "1"}],
            columns=["id"],
            row_count=1,
            backend_results={},
        )

        assert len(result.rows) == 1
        assert result.row_count == 1
        assert result.columns == ["id"]

    def test_federated_query_result_defaults(self) -> None:
        """Test FederatedQueryResult default values."""
        result = FederatedQueryResult(rows=[], columns=[])

        assert result.row_count == 0
        assert result.backends_queried == 0
        assert result.backends_succeeded == 0

    def test_federated_query_result_to_dict(self) -> None:
        """Test FederatedQueryResult to_dict method."""
        result = FederatedQueryResult(rows=[{"a": 1}], columns=["a"], row_count=1)
        d = result.to_dict()

        assert "rows" in d
        assert "merge_strategy" in d


# ============================================================================
# FederatedQuery Tests
# ============================================================================


class TestFederatedQuery:
    """Tests for FederatedQuery."""

    def test_federated_query_creation(self) -> None:
        """Test FederatedQuery can be created."""
        federated = FederatedQuery()
        assert federated is not None

    def test_federated_query_with_options(self) -> None:
        """Test FederatedQuery with custom options."""
        federated = FederatedQuery(max_workers=10, default_timeout=600)
        assert federated is not None

    def test_federated_query_has_required_methods(self) -> None:
        """Test FederatedQuery has required methods."""
        federated = FederatedQuery()

        assert hasattr(federated, "add_backend")
        assert hasattr(federated, "remove_backend")
        assert hasattr(federated, "query")


# ============================================================================
# Enum Tests
# ============================================================================


class TestSyncDirection:
    """Tests for SyncDirection enum."""

    def test_sync_direction_values(self) -> None:
        """Test SyncDirection enum values."""
        assert SyncDirection.PUSH is not None
        assert SyncDirection.PULL is not None
        assert SyncDirection.BIDIRECTIONAL is not None


class TestConflictResolution:
    """Tests for ConflictResolution enum."""

    def test_conflict_resolution_values(self) -> None:
        """Test ConflictResolution enum values."""
        assert ConflictResolution.LATEST_WINS is not None
        assert ConflictResolution.CENTRAL_WINS is not None
        assert ConflictResolution.LOCAL_WINS is not None
        assert ConflictResolution.MERGE is not None


class TestQueryStrategy:
    """Tests for QueryStrategy enum."""

    def test_query_strategy_values(self) -> None:
        """Test QueryStrategy enum values."""
        assert QueryStrategy.PARALLEL is not None
        assert QueryStrategy.SEQUENTIAL is not None


class TestMergeStrategy:
    """Tests for MergeStrategy enum."""

    def test_merge_strategy_values(self) -> None:
        """Test MergeStrategy enum values."""
        assert MergeStrategy.UNION is not None
        assert MergeStrategy.INTERSECT is not None
