"""
Integration tests for multi-cloud sync functionality.

Tests cover:
- Cross-cloud findings aggregation
- Sync to central storage
- Federated queries across backends
- Conflict resolution
"""

from __future__ import annotations

from datetime import datetime, timezone
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
    NETWORK_EXPOSURE_INTERNAL,
)
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


@pytest.fixture
def aws_findings() -> FindingCollection:
    """Create sample AWS findings."""
    return FindingCollection([
        Finding(
            id="aws-finding-001",
            asset_id="arn:aws:s3:::bucket-1",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            title="S3 Bucket Encryption Disabled",
            description="AWS S3 bucket lacks encryption.",
            rule_id="aws-s3-encryption",
            first_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
            last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
        ),
        Finding(
            id="aws-finding-002",
            asset_id="arn:aws:ec2:us-east-1:123456789012:instance/i-12345",
            finding_type=FindingType.VULNERABILITY,
            severity=Severity.CRITICAL,
            status=FindingStatus.OPEN,
            title="Critical CVE Found",
            description="Critical vulnerability in EC2 instance.",
            cve_id="CVE-2024-0001",
            first_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
            last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
        ),
    ])


@pytest.fixture
def gcp_findings() -> FindingCollection:
    """Create sample GCP findings."""
    return FindingCollection([
        Finding(
            id="gcp-finding-001",
            asset_id="projects/my-project/buckets/gcs-bucket-1",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            title="GCS Bucket Public Access",
            description="GCP Cloud Storage bucket has public access.",
            rule_id="gcp-storage-public",
            first_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
            last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
        ),
    ])


@pytest.fixture
def azure_findings() -> FindingCollection:
    """Create sample Azure findings."""
    return FindingCollection([
        Finding(
            id="azure-finding-001",
            asset_id="/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.MEDIUM,
            status=FindingStatus.OPEN,
            title="Storage Account HTTPS Only",
            description="Azure Storage Account does not enforce HTTPS.",
            rule_id="azure-storage-https",
            first_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
            last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
        ),
    ])


class TestFindingsAggregator:
    """Test findings aggregation across clouds."""

    def test_aggregator_creation(self):
        """Test FindingsAggregator can be created."""
        aggregator = FindingsAggregator()
        assert aggregator is not None

    def test_add_cloud_account(self):
        """Test adding cloud accounts."""
        aggregator = FindingsAggregator()

        account = CloudAccount(
            id="123456789012",
            provider="aws",
            name="Production AWS",
        )
        aggregator.add_account(account)

        # Check that account was added (using internal _accounts dict)
        assert "123456789012" in aggregator._accounts

    def test_aggregate_findings_from_multiple_clouds(
        self, aws_findings, gcp_findings, azure_findings
    ):
        """Test aggregating findings from multiple clouds."""
        aggregator = FindingsAggregator()

        # Add accounts (CloudAccount uses id, provider, name)
        aggregator.add_account(CloudAccount(id="123456789012", provider="aws", name="AWS Prod"))
        aggregator.add_account(CloudAccount(id="my-project", provider="gcp", name="GCP Prod"))
        aggregator.add_account(CloudAccount(id="xxx-subscription", provider="azure", name="Azure Prod"))

        # Add findings
        aggregator.add_findings("123456789012", aws_findings)
        aggregator.add_findings("my-project", gcp_findings)
        aggregator.add_findings("xxx-subscription", azure_findings)

        # Aggregate returns tuple (FindingCollection, AggregationResult)
        findings_collection, result = aggregator.aggregate()

        assert isinstance(result, AggregationResult)
        assert result.total_findings == 4
        # Use findings_by_provider instead of findings_by_cloud
        assert result.findings_by_provider["aws"] == 2
        assert result.findings_by_provider["gcp"] == 1
        assert result.findings_by_provider["azure"] == 1

    def test_normalize_findings(self, aws_findings):
        """Test findings are normalized to common format."""
        aggregator = FindingsAggregator()
        aggregator.add_account(CloudAccount(id="123456789012", provider="aws", name="AWS"))
        aggregator.add_findings("123456789012", aws_findings)

        # Aggregate returns (FindingCollection, AggregationResult)
        findings_collection, result = aggregator.aggregate()

        # Findings collection should contain the findings
        assert len(findings_collection) >= 1

    def test_deduplicate_findings(self):
        """Test duplicate findings are deduplicated."""
        aggregator = FindingsAggregator()
        aggregator.add_account(CloudAccount(id="123456789012", provider="aws", name="AWS"))

        # Add same finding twice (simulating duplicate scans)
        finding = Finding(
            id="duplicate-finding",
            asset_id="arn:aws:s3:::bucket",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            title="Duplicate Finding",
            description="This is duplicated.",
            first_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
            last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
        )

        aggregator.add_findings("123456789012", FindingCollection([finding]))
        aggregator.add_findings("123456789012", FindingCollection([finding]))

        # Aggregate returns (FindingCollection, AggregationResult)
        findings_collection, result = aggregator.aggregate()

        # Should deduplicate - unique_findings should be 1
        assert result.unique_findings == 1


class TestCrossCloudSync:
    """Test cross-cloud sync functionality."""

    def test_sync_config_creation(self):
        """Test SyncConfig can be created."""
        config = SyncConfig(
            central_bucket="stance-central-findings",
            central_prefix="aggregated",
            sync_direction=SyncDirection.BIDIRECTIONAL,
            conflict_resolution=ConflictResolution.LATEST_WINS,
        )

        assert config.central_bucket == "stance-central-findings"
        assert config.sync_direction == SyncDirection.BIDIRECTIONAL

    def test_sync_direction_values(self):
        """Test sync direction enum values."""
        assert SyncDirection.PUSH is not None
        assert SyncDirection.PULL is not None
        assert SyncDirection.BIDIRECTIONAL is not None

    def test_conflict_resolution_values(self):
        """Test conflict resolution enum values."""
        assert ConflictResolution.LATEST_WINS is not None
        assert ConflictResolution.CENTRAL_WINS is not None
        assert ConflictResolution.LOCAL_WINS is not None
        assert ConflictResolution.MERGE is not None

    def test_cross_cloud_sync_creation(self):
        """Test CrossCloudSync can be created."""
        config = SyncConfig(
            central_bucket="test-bucket",
            central_prefix="test",
            sync_direction=SyncDirection.PUSH,
        )
        mock_storage = MagicMock()

        sync = CrossCloudSync(config=config, storage=mock_storage)
        assert sync is not None

    def test_sync_add_local_findings(self, aws_findings):
        """Test adding local findings for sync."""
        config = SyncConfig(
            central_bucket="test-bucket",
            central_prefix="test",
            sync_direction=SyncDirection.PUSH,
        )
        mock_storage = MagicMock()

        sync = CrossCloudSync(config=config, storage=mock_storage)

        # Add local findings
        sync.add_local_findings(aws_findings, account_id="123456789012", provider="aws")

        # Verify findings were added
        assert len(sync._local_findings) == 2


class TestFederatedQuery:
    """Test federated query functionality."""

    def test_federated_query_creation(self):
        """Test FederatedQuery can be created."""
        query = FederatedQuery()
        assert query is not None

    def test_add_backend(self):
        """Test adding query backends."""
        query = FederatedQuery()

        mock_engine = MagicMock()
        backend = BackendConfig(
            name="aws-athena",
            engine=mock_engine,
            provider="aws",
        )
        query.add_backend(backend)

        # Use list_backends() method
        assert len(query.list_backends()) == 1

    def test_query_single_backend(self):
        """Test querying a single backend."""
        from stance.query.base import QueryResult

        query = FederatedQuery()

        mock_engine = MagicMock()
        mock_engine.is_connected.return_value = True
        mock_engine.execute_query.return_value = QueryResult(
            rows=[{"id": "finding-1", "severity": "high"}],
            columns=["id", "severity"],
            row_count=1,
        )

        backend = BackendConfig(
            name="aws-athena",
            engine=mock_engine,
            provider="aws",
        )
        query.add_backend(backend)

        result = query.query(
            "SELECT * FROM findings WHERE severity = 'high'",
            backends=["aws-athena"],
        )

        assert isinstance(result, FederatedQueryResult)

    def test_query_multiple_backends(self):
        """Test querying multiple backends and merging results."""
        from stance.query.base import QueryResult

        query = FederatedQuery()

        # AWS backend
        aws_engine = MagicMock()
        aws_engine.is_connected.return_value = True
        aws_engine.execute_query.return_value = QueryResult(
            rows=[{"id": "aws-1", "severity": "high", "cloud": "aws"}],
            columns=["id", "severity", "cloud"],
            row_count=1,
        )
        query.add_backend(BackendConfig(name="aws", engine=aws_engine, provider="aws"))

        # GCP backend
        gcp_engine = MagicMock()
        gcp_engine.is_connected.return_value = True
        gcp_engine.execute_query.return_value = QueryResult(
            rows=[{"id": "gcp-1", "severity": "high", "cloud": "gcp"}],
            columns=["id", "severity", "cloud"],
            row_count=1,
        )
        query.add_backend(BackendConfig(name="gcp", engine=gcp_engine, provider="gcp"))

        result = query.query(
            "SELECT * FROM findings",
            backends=["aws", "gcp"],
        )

        # Results should be merged
        assert result.row_count >= 2

    def test_query_strategy_parallel(self):
        """Test parallel query strategy."""
        from stance.query.base import QueryResult

        # FederatedQuery doesn't take strategy as __init__ param, pass it to query()
        query = FederatedQuery()

        mock_engine = MagicMock()
        mock_engine.is_connected.return_value = True
        mock_engine.execute_query.return_value = QueryResult(
            rows=[], columns=[], row_count=0
        )

        query.add_backend(BackendConfig(name="backend-1", engine=mock_engine, provider="aws"))
        query.add_backend(BackendConfig(name="backend-2", engine=mock_engine, provider="gcp"))

        result = query.query("SELECT * FROM findings", strategy=QueryStrategy.PARALLEL)

        # Both backends should be queried
        assert mock_engine.execute_query.call_count == 2

    def test_merge_strategy_union(self):
        """Test union merge strategy."""
        from stance.query.base import QueryResult

        # merge_strategy passed to query(), not __init__
        query = FederatedQuery()

        # Two backends with overlapping results
        engine1 = MagicMock()
        engine1.is_connected.return_value = True
        engine1.execute_query.return_value = QueryResult(
            rows=[{"id": "1"}, {"id": "2"}],
            columns=["id"],
            row_count=2,
        )

        engine2 = MagicMock()
        engine2.is_connected.return_value = True
        engine2.execute_query.return_value = QueryResult(
            rows=[{"id": "2"}, {"id": "3"}],
            columns=["id"],
            row_count=2,
        )

        query.add_backend(BackendConfig(name="b1", engine=engine1, provider="aws"))
        query.add_backend(BackendConfig(name="b2", engine=engine2, provider="gcp"))

        result = query.query("SELECT * FROM findings", merge_strategy=MergeStrategy.UNION)

        # Union should combine all results
        assert result.row_count >= 2


class TestAggregationResult:
    """Test AggregationResult structure."""

    def test_aggregation_result_creation(self):
        """Test AggregationResult can be created."""
        result = AggregationResult(
            total_findings=10,
            unique_findings=8,
            duplicates_removed=2,
            findings_by_provider={"aws": 5, "gcp": 3, "azure": 2},
            findings_by_severity={"critical": 2, "high": 4, "medium": 3, "low": 1},
            findings_by_account={"123": 5, "456": 3, "789": 2},
        )

        assert result.total_findings == 10
        assert result.findings_by_provider["aws"] == 5

    def test_aggregation_result_to_dict(self):
        """Test AggregationResult serialization."""
        result = AggregationResult(
            total_findings=5,
            unique_findings=5,
            duplicates_removed=0,
            findings_by_provider={"aws": 5},
            findings_by_severity={"high": 5},
            findings_by_account={"123": 5},
        )

        data = result.to_dict()

        assert "total_findings" in data
        assert data["total_findings"] == 5


class TestSyncResult:
    """Test SyncResult structure."""

    def test_sync_result_creation(self):
        """Test SyncResult can be created."""
        result = SyncResult(
            records_synced=100,
            conflicts_resolved=5,
            errors=[],
            duration_seconds=2.5,
        )

        assert result.records_synced == 100
        assert result.conflicts_resolved == 5

    def test_sync_result_with_errors(self):
        """Test SyncResult with errors."""
        result = SyncResult(
            records_synced=50,
            conflicts_resolved=0,
            errors=["Connection timeout", "Permission denied"],
            duration_seconds=10.0,
        )

        assert len(result.errors) == 2


class TestNormalizedFinding:
    """Test NormalizedFinding structure."""

    def test_normalized_finding_creation(self):
        """Test NormalizedFinding can be created."""
        # First create a Finding to use as the original
        original = Finding(
            id="aws-finding-001",
            asset_id="arn:aws:s3:::bucket",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            title="Test Finding",
            description="Test description",
            rule_id="aws-s3-001",
            first_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
            last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
        )

        # NormalizedFinding wraps the original Finding
        nf = NormalizedFinding(
            original=original,
            normalized_key="abc123",
            provider="aws",
            account_id="123456789012",
            canonical_resource_type="storage_bucket",
            canonical_rule_id="storage-encryption",
        )

        assert nf.provider == "aws"
        assert nf.original.severity == Severity.HIGH


class TestEndToEndMultiCloud:
    """Test complete multi-cloud workflow."""

    def test_full_aggregation_workflow(
        self, aws_findings, gcp_findings, azure_findings
    ):
        """Test complete aggregation workflow."""
        # Create aggregator
        aggregator = FindingsAggregator()

        # Add accounts (CloudAccount uses id, provider, name)
        aggregator.add_account(CloudAccount(id="aws-123", provider="aws", name="AWS Production"))
        aggregator.add_account(CloudAccount(id="gcp-project", provider="gcp", name="GCP Production"))
        aggregator.add_account(CloudAccount(id="azure-sub", provider="azure", name="Azure Production"))

        # Add findings from each cloud
        aggregator.add_findings("aws-123", aws_findings)
        aggregator.add_findings("gcp-project", gcp_findings)
        aggregator.add_findings("azure-sub", azure_findings)

        # Aggregate returns (FindingCollection, AggregationResult)
        findings_collection, result = aggregator.aggregate()

        # Verify results
        assert result.total_findings == 4
        assert len(result.findings_by_provider) == 3
        assert len(findings_collection) == 4

        # Check severity breakdown (uses string keys)
        assert "critical" in result.findings_by_severity
        assert "high" in result.findings_by_severity
        assert "medium" in result.findings_by_severity
