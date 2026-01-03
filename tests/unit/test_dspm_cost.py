"""
Tests for DSPM Cost Analysis module.

Tests the cost analysis functionality including cold data detection,
storage cost estimation, and cloud-specific analyzers.
"""

import pytest
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch, PropertyMock


# =============================================================================
# Tests for FindingType Enum
# =============================================================================


class TestFindingType:
    """Tests for FindingType enum."""

    def test_finding_type_values(self):
        """Test that all finding types have correct values."""
        from stance.dspm.cost.base import FindingType

        assert FindingType.COLD_DATA.value == "cold_data"
        assert FindingType.ARCHIVE_CANDIDATE.value == "archive_candidate"
        assert FindingType.DELETE_CANDIDATE.value == "delete_candidate"
        assert FindingType.INEFFICIENT_STORAGE_CLASS.value == "inefficient_storage_class"
        assert FindingType.LARGE_OBJECT.value == "large_object"

    def test_finding_type_count(self):
        """Test that we have expected number of finding types."""
        from stance.dspm.cost.base import FindingType

        assert len(FindingType) == 5


# =============================================================================
# Tests for StorageTier Enum
# =============================================================================


class TestStorageTier:
    """Tests for StorageTier enum."""

    def test_s3_tiers(self):
        """Test S3 storage tiers."""
        from stance.dspm.cost.base import StorageTier

        assert StorageTier.S3_STANDARD.value == "s3_standard"
        assert StorageTier.S3_GLACIER_DEEP_ARCHIVE.value == "s3_glacier_deep_archive"

    def test_gcs_tiers(self):
        """Test GCS storage tiers."""
        from stance.dspm.cost.base import StorageTier

        assert StorageTier.GCS_STANDARD.value == "gcs_standard"
        assert StorageTier.GCS_ARCHIVE.value == "gcs_archive"

    def test_azure_tiers(self):
        """Test Azure storage tiers."""
        from stance.dspm.cost.base import StorageTier

        assert StorageTier.AZURE_HOT.value == "azure_hot"
        assert StorageTier.AZURE_ARCHIVE.value == "azure_archive"


# =============================================================================
# Tests for Storage Cost Constants
# =============================================================================


class TestStorageCosts:
    """Tests for storage cost constants."""

    def test_costs_exist_for_all_tiers(self):
        """Test that costs are defined for all storage tiers."""
        from stance.dspm.cost.base import StorageTier, STORAGE_COSTS_PER_GB_MONTH

        for tier in StorageTier:
            assert tier in STORAGE_COSTS_PER_GB_MONTH
            assert STORAGE_COSTS_PER_GB_MONTH[tier] >= Decimal("0")

    def test_cheaper_tiers_cost_less(self):
        """Test that archive tiers cost less than standard tiers."""
        from stance.dspm.cost.base import StorageTier, STORAGE_COSTS_PER_GB_MONTH

        # S3
        assert (
            STORAGE_COSTS_PER_GB_MONTH[StorageTier.S3_GLACIER_DEEP_ARCHIVE]
            < STORAGE_COSTS_PER_GB_MONTH[StorageTier.S3_STANDARD]
        )

        # GCS
        assert (
            STORAGE_COSTS_PER_GB_MONTH[StorageTier.GCS_ARCHIVE]
            < STORAGE_COSTS_PER_GB_MONTH[StorageTier.GCS_STANDARD]
        )

        # Azure
        assert (
            STORAGE_COSTS_PER_GB_MONTH[StorageTier.AZURE_ARCHIVE]
            < STORAGE_COSTS_PER_GB_MONTH[StorageTier.AZURE_HOT]
        )


# =============================================================================
# Tests for CostAnalysisConfig
# =============================================================================


class TestCostAnalysisConfig:
    """Tests for CostAnalysisConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        from stance.dspm.cost.base import CostAnalysisConfig

        config = CostAnalysisConfig()
        assert config.cold_data_days == 90
        assert config.archive_candidate_days == 180
        assert config.delete_candidate_days == 365
        assert config.min_object_size_bytes == 1024
        assert config.include_storage_class_analysis is True
        assert config.cost_currency == "USD"
        assert config.sample_size is None

    def test_custom_values(self):
        """Test custom configuration values."""
        from stance.dspm.cost.base import CostAnalysisConfig

        config = CostAnalysisConfig(
            cold_data_days=60,
            archive_candidate_days=120,
            delete_candidate_days=180,
            min_object_size_bytes=4096,
            sample_size=1000,
        )
        assert config.cold_data_days == 60
        assert config.archive_candidate_days == 120
        assert config.delete_candidate_days == 180
        assert config.min_object_size_bytes == 4096
        assert config.sample_size == 1000


# =============================================================================
# Tests for StorageMetrics
# =============================================================================


class TestStorageMetrics:
    """Tests for StorageMetrics dataclass."""

    def test_default_values(self):
        """Test default metrics values."""
        from stance.dspm.cost.base import StorageMetrics, StorageTier

        metrics = StorageMetrics(bucket_name="test-bucket")
        assert metrics.bucket_name == "test-bucket"
        assert metrics.total_size_bytes == 0
        assert metrics.total_objects == 0
        assert metrics.storage_tier == StorageTier.UNKNOWN
        assert metrics.monthly_cost_estimate == Decimal("0")

    def test_to_dict(self):
        """Test metrics serialization."""
        from stance.dspm.cost.base import StorageMetrics, StorageTier

        metrics = StorageMetrics(
            bucket_name="test-bucket",
            total_size_bytes=1024 * 1024 * 1024,  # 1GB
            total_objects=100,
            storage_tier=StorageTier.S3_STANDARD,
            monthly_cost_estimate=Decimal("0.023"),
        )
        data = metrics.to_dict()

        assert data["bucket_name"] == "test-bucket"
        assert data["total_size_bytes"] == 1024 * 1024 * 1024
        assert data["total_size_gb"] == 1.0
        assert data["total_objects"] == 100
        assert data["storage_tier"] == "s3_standard"
        assert data["monthly_cost_estimate"] == 0.023


# =============================================================================
# Tests for ObjectAccessInfo
# =============================================================================


class TestObjectAccessInfo:
    """Tests for ObjectAccessInfo dataclass."""

    def test_creation(self):
        """Test object access info creation."""
        from stance.dspm.cost.base import ObjectAccessInfo

        now = datetime.now(timezone.utc)
        info = ObjectAccessInfo(
            object_key="path/to/file.txt",
            size_bytes=1024 * 1024,
            storage_class="STANDARD",
            last_modified=now,
            days_since_access=90,
            days_since_modified=90,
        )

        assert info.object_key == "path/to/file.txt"
        assert info.size_bytes == 1024 * 1024
        assert info.storage_class == "STANDARD"
        assert info.days_since_access == 90

    def test_to_dict(self):
        """Test serialization."""
        from stance.dspm.cost.base import ObjectAccessInfo

        now = datetime.now(timezone.utc)
        info = ObjectAccessInfo(
            object_key="test.txt",
            size_bytes=1024 * 1024,
            last_modified=now,
            days_since_access=45,
        )
        data = info.to_dict()

        assert data["object_key"] == "test.txt"
        assert data["size_bytes"] == 1024 * 1024
        assert data["size_mb"] == 1.0
        assert data["days_since_access"] == 45


# =============================================================================
# Tests for ColdDataFinding
# =============================================================================


class TestColdDataFinding:
    """Tests for ColdDataFinding dataclass."""

    def test_creation(self):
        """Test finding creation."""
        from stance.dspm.cost.base import ColdDataFinding, FindingType, StorageTier

        finding = ColdDataFinding(
            finding_id="test-001",
            finding_type=FindingType.COLD_DATA,
            severity="medium",
            title="Cold data detected",
            description="Found cold data",
            bucket_name="test-bucket",
            size_bytes=1024 * 1024 * 1024,
            current_cost_monthly=Decimal("0.023"),
            potential_savings_monthly=Decimal("0.015"),
            recommended_tier=StorageTier.S3_STANDARD_IA,
            days_since_access=100,
        )

        assert finding.finding_id == "test-001"
        assert finding.finding_type == FindingType.COLD_DATA
        assert finding.severity == "medium"
        assert finding.size_bytes == 1024 * 1024 * 1024
        assert finding.potential_savings_monthly == Decimal("0.015")

    def test_to_dict(self):
        """Test finding serialization."""
        from stance.dspm.cost.base import ColdDataFinding, FindingType, StorageTier

        finding = ColdDataFinding(
            finding_id="test-001",
            finding_type=FindingType.ARCHIVE_CANDIDATE,
            severity="high",
            title="Archive candidate",
            description="Data should be archived",
            bucket_name="test-bucket",
            size_bytes=10 * 1024 * 1024 * 1024,  # 10GB
            recommended_tier=StorageTier.S3_GLACIER_FLEXIBLE,
        )
        data = finding.to_dict()

        assert data["finding_id"] == "test-001"
        assert data["finding_type"] == "archive_candidate"
        assert data["severity"] == "high"
        assert data["size_gb"] == pytest.approx(10.0, rel=0.01)
        assert data["recommended_tier"] == "s3_glacier_flexible"


# =============================================================================
# Tests for CostAnalysisResult
# =============================================================================


class TestCostAnalysisResult:
    """Tests for CostAnalysisResult dataclass."""

    def test_default_values(self):
        """Test default result values."""
        from stance.dspm.cost.base import CostAnalysisResult, CostAnalysisConfig

        config = CostAnalysisConfig()
        result = CostAnalysisResult(
            analysis_id="test-123",
            bucket_name="test-bucket",
            config=config,
            started_at=datetime.now(timezone.utc),
        )

        assert result.analysis_id == "test-123"
        assert result.bucket_name == "test-bucket"
        assert result.findings == []
        assert result.total_size_bytes == 0
        assert result.cold_data_size_bytes == 0
        assert result.has_findings is False

    def test_has_findings(self):
        """Test has_findings property."""
        from stance.dspm.cost.base import (
            CostAnalysisResult,
            CostAnalysisConfig,
            ColdDataFinding,
            FindingType,
        )

        config = CostAnalysisConfig()
        result = CostAnalysisResult(
            analysis_id="test",
            bucket_name="bucket",
            config=config,
            started_at=datetime.now(timezone.utc),
        )

        assert result.has_findings is False

        result.findings.append(
            ColdDataFinding(
                finding_id="f1",
                finding_type=FindingType.COLD_DATA,
                severity="low",
                title="Cold",
                description="Cold data",
                bucket_name="bucket",
            )
        )

        assert result.has_findings is True

    def test_findings_by_type(self):
        """Test findings_by_type property."""
        from stance.dspm.cost.base import (
            CostAnalysisResult,
            CostAnalysisConfig,
            ColdDataFinding,
            FindingType,
        )

        config = CostAnalysisConfig()
        result = CostAnalysisResult(
            analysis_id="test",
            bucket_name="bucket",
            config=config,
            started_at=datetime.now(timezone.utc),
        )

        result.findings = [
            ColdDataFinding(
                finding_id="f1",
                finding_type=FindingType.COLD_DATA,
                severity="low",
                title="Cold 1",
                description="",
                bucket_name="bucket",
            ),
            ColdDataFinding(
                finding_id="f2",
                finding_type=FindingType.COLD_DATA,
                severity="medium",
                title="Cold 2",
                description="",
                bucket_name="bucket",
            ),
            ColdDataFinding(
                finding_id="f3",
                finding_type=FindingType.DELETE_CANDIDATE,
                severity="high",
                title="Delete",
                description="",
                bucket_name="bucket",
            ),
        ]

        by_type = result.findings_by_type
        assert by_type["cold_data"] == 2
        assert by_type["delete_candidate"] == 1

    def test_cold_data_percentage(self):
        """Test cold_data_percentage property."""
        from stance.dspm.cost.base import CostAnalysisResult, CostAnalysisConfig

        config = CostAnalysisConfig()
        result = CostAnalysisResult(
            analysis_id="test",
            bucket_name="bucket",
            config=config,
            started_at=datetime.now(timezone.utc),
            total_size_bytes=100 * 1024 * 1024,
            cold_data_size_bytes=25 * 1024 * 1024,
        )

        assert result.cold_data_percentage == 25.0

    def test_cold_data_percentage_zero_total(self):
        """Test cold_data_percentage with zero total size."""
        from stance.dspm.cost.base import CostAnalysisResult, CostAnalysisConfig

        config = CostAnalysisConfig()
        result = CostAnalysisResult(
            analysis_id="test",
            bucket_name="bucket",
            config=config,
            started_at=datetime.now(timezone.utc),
        )

        assert result.cold_data_percentage == 0.0

    def test_to_dict(self):
        """Test result serialization."""
        from stance.dspm.cost.base import CostAnalysisResult, CostAnalysisConfig

        config = CostAnalysisConfig(cold_data_days=60)
        now = datetime.now(timezone.utc)
        result = CostAnalysisResult(
            analysis_id="test-123",
            bucket_name="my-bucket",
            config=config,
            started_at=now,
            completed_at=now + timedelta(seconds=5),
            total_size_bytes=1024 * 1024 * 1024,
            cold_data_size_bytes=256 * 1024 * 1024,
            objects_analyzed=1000,
        )
        data = result.to_dict()

        assert data["analysis_id"] == "test-123"
        assert data["bucket_name"] == "my-bucket"
        assert data["config"]["cold_data_days"] == 60
        assert data["total_size_gb"] == 1.0
        assert data["cold_data_percentage"] == 25.0
        assert data["objects_analyzed"] == 1000


# =============================================================================
# Tests for BaseCostAnalyzer
# =============================================================================


class TestBaseCostAnalyzer:
    """Tests for BaseCostAnalyzer abstract base class."""

    def test_calculate_cost(self):
        """Test cost calculation."""
        from stance.dspm.cost.base import (
            BaseCostAnalyzer,
            CostAnalysisConfig,
            StorageTier,
        )

        # Create a concrete implementation for testing
        class TestAnalyzer(BaseCostAnalyzer):
            def analyze_bucket(self, bucket_name):
                pass

            def get_storage_metrics(self, bucket_name):
                pass

            def get_object_access_info(self, bucket_name, object_key):
                pass

            def list_objects_with_access_info(self, bucket_name, prefix=""):
                pass

        analyzer = TestAnalyzer()

        # 1 GB at S3 standard rate
        cost = analyzer._calculate_cost(1024**3, StorageTier.S3_STANDARD)
        assert cost == pytest.approx(Decimal("0.023"), rel=0.01)

        # 1 GB at Glacier Deep Archive rate
        cost = analyzer._calculate_cost(1024**3, StorageTier.S3_GLACIER_DEEP_ARCHIVE)
        assert cost == pytest.approx(Decimal("0.00099"), rel=0.01)

    def test_get_recommended_tier_s3(self):
        """Test S3 tier recommendations."""
        from stance.dspm.cost.base import BaseCostAnalyzer, StorageTier

        class TestAnalyzer(BaseCostAnalyzer):
            def analyze_bucket(self, bucket_name):
                pass

            def get_storage_metrics(self, bucket_name):
                pass

            def get_object_access_info(self, bucket_name, object_key):
                pass

            def list_objects_with_access_info(self, bucket_name, prefix=""):
                pass

        analyzer = TestAnalyzer()

        # 90 days - recommend IA
        tier = analyzer._get_recommended_tier(StorageTier.S3_STANDARD, 90)
        assert tier == StorageTier.S3_STANDARD_IA

        # 180 days - recommend Glacier Flexible
        tier = analyzer._get_recommended_tier(StorageTier.S3_STANDARD, 180)
        assert tier == StorageTier.S3_GLACIER_FLEXIBLE

        # 365 days - recommend Deep Archive
        tier = analyzer._get_recommended_tier(StorageTier.S3_STANDARD, 365)
        assert tier == StorageTier.S3_GLACIER_DEEP_ARCHIVE

    def test_get_recommended_tier_already_cold(self):
        """Test no recommendation when already on cold tier."""
        from stance.dspm.cost.base import BaseCostAnalyzer, StorageTier

        class TestAnalyzer(BaseCostAnalyzer):
            def analyze_bucket(self, bucket_name):
                pass

            def get_storage_metrics(self, bucket_name):
                pass

            def get_object_access_info(self, bucket_name, object_key):
                pass

            def list_objects_with_access_info(self, bucket_name, prefix=""):
                pass

        analyzer = TestAnalyzer()

        # Already on Deep Archive - no recommendation
        tier = analyzer._get_recommended_tier(StorageTier.S3_GLACIER_DEEP_ARCHIVE, 365)
        assert tier is None

    def test_tier_rank(self):
        """Test tier ranking for comparison."""
        from stance.dspm.cost.base import BaseCostAnalyzer, StorageTier

        class TestAnalyzer(BaseCostAnalyzer):
            def analyze_bucket(self, bucket_name):
                pass

            def get_storage_metrics(self, bucket_name):
                pass

            def get_object_access_info(self, bucket_name, object_key):
                pass

            def list_objects_with_access_info(self, bucket_name, prefix=""):
                pass

        analyzer = TestAnalyzer()

        # Standard should be ranked lower than archive
        assert analyzer._tier_rank(StorageTier.S3_STANDARD) < analyzer._tier_rank(
            StorageTier.S3_GLACIER_DEEP_ARCHIVE
        )
        assert analyzer._tier_rank(StorageTier.GCS_STANDARD) < analyzer._tier_rank(
            StorageTier.GCS_ARCHIVE
        )
        assert analyzer._tier_rank(StorageTier.AZURE_HOT) < analyzer._tier_rank(
            StorageTier.AZURE_ARCHIVE
        )

    def test_get_severity_for_cold_data(self):
        """Test severity determination for cold data."""
        from stance.dspm.cost.base import BaseCostAnalyzer

        class TestAnalyzer(BaseCostAnalyzer):
            def analyze_bucket(self, bucket_name):
                pass

            def get_storage_metrics(self, bucket_name):
                pass

            def get_object_access_info(self, bucket_name, object_key):
                pass

            def list_objects_with_access_info(self, bucket_name, prefix=""):
                pass

        analyzer = TestAnalyzer()

        # Large and very old = critical
        assert analyzer._get_severity_for_cold_data(365, 100 * 1024**3) == "critical"

        # 365 days, 10GB = high
        assert analyzer._get_severity_for_cold_data(365, 10 * 1024**3) == "high"

        # 180 days, 10GB = high
        assert analyzer._get_severity_for_cold_data(180, 10 * 1024**3) == "high"

        # 180 days, 1GB = medium
        assert analyzer._get_severity_for_cold_data(180, 1 * 1024**3) == "medium"

        # 90 days = low
        assert analyzer._get_severity_for_cold_data(90, 1 * 1024**3) == "low"

        # Less than 90 days = info
        assert analyzer._get_severity_for_cold_data(30, 1 * 1024**3) == "info"

    def test_generate_findings(self):
        """Test finding generation from objects."""
        from stance.dspm.cost.base import (
            BaseCostAnalyzer,
            ObjectAccessInfo,
            StorageTier,
            FindingType,
        )

        class TestAnalyzer(BaseCostAnalyzer):
            def analyze_bucket(self, bucket_name):
                pass

            def get_storage_metrics(self, bucket_name):
                pass

            def get_object_access_info(self, bucket_name, object_key):
                pass

            def list_objects_with_access_info(self, bucket_name, prefix=""):
                pass

        analyzer = TestAnalyzer()

        objects = [
            # Cold data (90-180 days)
            ObjectAccessInfo(
                object_key="cold1.txt",
                size_bytes=1024 * 1024 * 100,
                days_since_access=100,
            ),
            # Archive candidate (180-365 days)
            ObjectAccessInfo(
                object_key="archive1.txt",
                size_bytes=1024 * 1024 * 200,
                days_since_access=200,
            ),
            # Delete candidate (365+ days)
            ObjectAccessInfo(
                object_key="delete1.txt",
                size_bytes=1024 * 1024 * 300,
                days_since_access=400,
            ),
            # Fresh data (should not generate finding)
            ObjectAccessInfo(
                object_key="fresh.txt",
                size_bytes=1024 * 1024 * 50,
                days_since_access=30,
            ),
        ]

        findings = analyzer._generate_findings(
            "test-bucket", objects, StorageTier.S3_STANDARD
        )

        assert len(findings) == 3

        types = [f.finding_type for f in findings]
        assert FindingType.DELETE_CANDIDATE in types
        assert FindingType.ARCHIVE_CANDIDATE in types
        assert FindingType.COLD_DATA in types


# =============================================================================
# Tests for S3CostAnalyzer
# =============================================================================


class TestS3CostAnalyzer:
    """Tests for S3CostAnalyzer."""

    @patch("stance.dspm.cost.s3_cost.BOTO3_AVAILABLE", True)
    @patch("stance.dspm.cost.s3_cost.boto3")
    def test_initialization(self, mock_boto3):
        """Test analyzer initialization."""
        from stance.dspm.cost.s3_cost import S3CostAnalyzer

        mock_session = MagicMock()
        mock_boto3.Session.return_value = mock_session

        analyzer = S3CostAnalyzer()

        assert analyzer.cloud_provider == "aws"
        mock_session.client.assert_called()

    @patch("stance.dspm.cost.s3_cost.BOTO3_AVAILABLE", False)
    def test_initialization_without_boto3(self):
        """Test that initialization fails without boto3."""
        from stance.dspm.cost.s3_cost import S3CostAnalyzer

        with pytest.raises(ImportError) as exc_info:
            S3CostAnalyzer()

        assert "boto3 is required" in str(exc_info.value)

    @patch("stance.dspm.cost.s3_cost.BOTO3_AVAILABLE", True)
    @patch("stance.dspm.cost.s3_cost.boto3")
    def test_analyze_bucket_strips_prefix(self, mock_boto3):
        """Test that s3:// prefix is stripped."""
        from stance.dspm.cost.s3_cost import S3CostAnalyzer

        mock_session = MagicMock()
        mock_boto3.Session.return_value = mock_session
        mock_s3 = MagicMock()
        mock_session.client.return_value = mock_s3

        # Mock paginator to return empty
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = []
        mock_s3.get_paginator.return_value = mock_paginator

        analyzer = S3CostAnalyzer()
        result = analyzer.analyze_bucket("s3://my-bucket/prefix")

        assert result.bucket_name == "my-bucket"

    @patch("stance.dspm.cost.s3_cost.BOTO3_AVAILABLE", True)
    @patch("stance.dspm.cost.s3_cost.boto3")
    def test_get_storage_metrics(self, mock_boto3):
        """Test storage metrics retrieval."""
        from stance.dspm.cost.s3_cost import S3CostAnalyzer

        mock_session = MagicMock()
        mock_boto3.Session.return_value = mock_session
        mock_s3 = MagicMock()
        mock_session.client.return_value = mock_s3

        # Mock paginator
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Contents": [
                    {"Key": "file1.txt", "Size": 1024, "StorageClass": "STANDARD"},
                    {"Key": "file2.txt", "Size": 2048, "StorageClass": "STANDARD"},
                    {"Key": "file3.txt", "Size": 1024, "StorageClass": "GLACIER"},
                ]
            }
        ]
        mock_s3.get_paginator.return_value = mock_paginator

        analyzer = S3CostAnalyzer()
        metrics = analyzer.get_storage_metrics("test-bucket")

        assert metrics.bucket_name == "test-bucket"
        assert metrics.total_size_bytes == 4096
        assert metrics.total_objects == 3
        assert "STANDARD" in metrics.size_by_tier
        assert "GLACIER" in metrics.size_by_tier

    @patch("stance.dspm.cost.s3_cost.BOTO3_AVAILABLE", True)
    @patch("stance.dspm.cost.s3_cost.boto3")
    def test_list_objects_with_access_info(self, mock_boto3):
        """Test listing objects with access info."""
        from stance.dspm.cost.s3_cost import S3CostAnalyzer
        from stance.dspm.cost.base import CostAnalysisConfig

        mock_session = MagicMock()
        mock_boto3.Session.return_value = mock_session
        mock_s3 = MagicMock()
        mock_session.client.return_value = mock_s3

        now = datetime.now(timezone.utc)
        old_time = now - timedelta(days=100)

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Contents": [
                    {
                        "Key": "old-file.txt",
                        "Size": 10240,
                        "StorageClass": "STANDARD",
                        "LastModified": old_time,
                    },
                    {
                        "Key": "tiny-file.txt",
                        "Size": 100,  # Below minimum
                        "StorageClass": "STANDARD",
                        "LastModified": now,
                    },
                ]
            }
        ]
        mock_s3.get_paginator.return_value = mock_paginator

        config = CostAnalysisConfig(min_object_size_bytes=1024)
        analyzer = S3CostAnalyzer(config=config)

        objects = list(analyzer.list_objects_with_access_info("test-bucket"))

        # Should only have the larger file
        assert len(objects) == 1
        assert objects[0].object_key == "old-file.txt"
        assert objects[0].days_since_access == 100

    @patch("stance.dspm.cost.s3_cost.BOTO3_AVAILABLE", True)
    @patch("stance.dspm.cost.s3_cost.boto3")
    def test_get_bucket_lifecycle_rules(self, mock_boto3):
        """Test getting lifecycle rules."""
        from stance.dspm.cost.s3_cost import S3CostAnalyzer

        mock_session = MagicMock()
        mock_boto3.Session.return_value = mock_session
        mock_s3 = MagicMock()
        mock_session.client.return_value = mock_s3

        mock_s3.get_bucket_lifecycle_configuration.return_value = {
            "Rules": [
                {"ID": "rule1", "Status": "Enabled"},
                {"ID": "rule2", "Status": "Disabled"},
            ]
        }

        analyzer = S3CostAnalyzer()
        rules = analyzer.get_bucket_lifecycle_rules("test-bucket")

        assert len(rules) == 2
        assert rules[0]["ID"] == "rule1"


# =============================================================================
# Tests for GCSCostAnalyzer
# =============================================================================


class TestGCSCostAnalyzer:
    """Tests for GCSCostAnalyzer."""

    @patch("stance.dspm.cost.gcs_cost.GCP_AVAILABLE", True)
    @patch("stance.dspm.cost.gcs_cost.storage")
    def test_initialization(self, mock_storage):
        """Test analyzer initialization."""
        from stance.dspm.cost.gcs_cost import GCSCostAnalyzer

        analyzer = GCSCostAnalyzer(project="test-project")

        assert analyzer.cloud_provider == "gcp"
        mock_storage.Client.assert_called_once()

    @patch("stance.dspm.cost.gcs_cost.GCP_AVAILABLE", False)
    def test_initialization_without_gcp_libs(self):
        """Test that initialization fails without GCP libraries."""
        from stance.dspm.cost.gcs_cost import GCSCostAnalyzer

        with pytest.raises(ImportError) as exc_info:
            GCSCostAnalyzer()

        assert "google-cloud-storage is required" in str(exc_info.value)

    @patch("stance.dspm.cost.gcs_cost.GCP_AVAILABLE", True)
    @patch("stance.dspm.cost.gcs_cost.storage")
    def test_analyze_bucket_strips_prefix(self, mock_storage):
        """Test that gs:// prefix is stripped."""
        from stance.dspm.cost.gcs_cost import GCSCostAnalyzer

        mock_client = MagicMock()
        mock_storage.Client.return_value = mock_client

        mock_bucket = MagicMock()
        mock_bucket.list_blobs.return_value = []
        mock_client.bucket.return_value = mock_bucket
        mock_client.get_bucket.return_value = mock_bucket
        mock_bucket.storage_class = "STANDARD"

        analyzer = GCSCostAnalyzer(project="test-project")
        result = analyzer.analyze_bucket("gs://my-bucket/prefix")

        assert result.bucket_name == "my-bucket"

    @patch("stance.dspm.cost.gcs_cost.GCP_AVAILABLE", True)
    @patch("stance.dspm.cost.gcs_cost.storage")
    def test_get_storage_metrics(self, mock_storage):
        """Test storage metrics retrieval."""
        from stance.dspm.cost.gcs_cost import GCSCostAnalyzer

        mock_client = MagicMock()
        mock_storage.Client.return_value = mock_client

        mock_blob1 = MagicMock()
        mock_blob1.size = 1024
        mock_blob1.storage_class = "STANDARD"

        mock_blob2 = MagicMock()
        mock_blob2.size = 2048
        mock_blob2.storage_class = "NEARLINE"

        mock_bucket = MagicMock()
        mock_bucket.list_blobs.return_value = [mock_blob1, mock_blob2]
        mock_client.bucket.return_value = mock_bucket

        analyzer = GCSCostAnalyzer(project="test-project")
        metrics = analyzer.get_storage_metrics("test-bucket")

        assert metrics.bucket_name == "test-bucket"
        assert metrics.total_size_bytes == 3072
        assert metrics.total_objects == 2
        assert "STANDARD" in metrics.size_by_tier
        assert "NEARLINE" in metrics.size_by_tier


# =============================================================================
# Tests for AzureCostAnalyzer
# =============================================================================


class TestAzureCostAnalyzer:
    """Tests for AzureCostAnalyzer."""

    @patch("stance.dspm.cost.azure_cost.AZURE_AVAILABLE", True)
    @patch("stance.dspm.cost.azure_cost.BlobServiceClient")
    def test_initialization_with_connection_string(self, mock_blob_service):
        """Test analyzer initialization with connection string."""
        from stance.dspm.cost.azure_cost import AzureCostAnalyzer

        analyzer = AzureCostAnalyzer(
            connection_string="DefaultEndpointsProtocol=https;AccountName=test"
        )

        assert analyzer.cloud_provider == "azure"
        mock_blob_service.from_connection_string.assert_called_once()

    @patch("stance.dspm.cost.azure_cost.AZURE_AVAILABLE", True)
    @patch("stance.dspm.cost.azure_cost.BlobServiceClient")
    @patch("stance.dspm.cost.azure_cost.DefaultAzureCredential")
    def test_initialization_with_account_url(
        self, mock_credential, mock_blob_service
    ):
        """Test analyzer initialization with account URL."""
        from stance.dspm.cost.azure_cost import AzureCostAnalyzer

        analyzer = AzureCostAnalyzer(
            account_url="https://testaccount.blob.core.windows.net"
        )

        assert analyzer.cloud_provider == "azure"
        mock_blob_service.assert_called_once()

    @patch("stance.dspm.cost.azure_cost.AZURE_AVAILABLE", True)
    def test_initialization_without_credentials(self):
        """Test that initialization fails without credentials."""
        from stance.dspm.cost.azure_cost import AzureCostAnalyzer

        with pytest.raises(ValueError) as exc_info:
            AzureCostAnalyzer()

        assert "Either connection_string or account_url must be provided" in str(
            exc_info.value
        )

    @patch("stance.dspm.cost.azure_cost.AZURE_AVAILABLE", False)
    def test_initialization_without_azure_libs(self):
        """Test that initialization fails without Azure libraries."""
        from stance.dspm.cost.azure_cost import AzureCostAnalyzer

        with pytest.raises(ImportError) as exc_info:
            AzureCostAnalyzer(connection_string="test")

        assert "azure-storage-blob is required" in str(exc_info.value)

    @patch("stance.dspm.cost.azure_cost.AZURE_AVAILABLE", True)
    @patch("stance.dspm.cost.azure_cost.BlobServiceClient")
    def test_analyze_bucket_strips_prefix(self, mock_blob_service):
        """Test that azure:// prefix is stripped."""
        from stance.dspm.cost.azure_cost import AzureCostAnalyzer

        mock_client = MagicMock()
        mock_blob_service.from_connection_string.return_value = mock_client

        mock_container = MagicMock()
        mock_container.list_blobs.return_value = []
        mock_client.get_container_client.return_value = mock_container

        analyzer = AzureCostAnalyzer(connection_string="test")
        result = analyzer.analyze_bucket("azure://my-container/prefix")

        assert result.bucket_name == "my-container"

    @patch("stance.dspm.cost.azure_cost.AZURE_AVAILABLE", True)
    @patch("stance.dspm.cost.azure_cost.BlobServiceClient")
    def test_get_storage_metrics(self, mock_blob_service):
        """Test storage metrics retrieval."""
        from stance.dspm.cost.azure_cost import AzureCostAnalyzer

        mock_client = MagicMock()
        mock_blob_service.from_connection_string.return_value = mock_client

        mock_blob1 = MagicMock()
        mock_blob1.size = 1024
        mock_blob1.blob_tier = "Hot"

        mock_blob2 = MagicMock()
        mock_blob2.size = 2048
        mock_blob2.blob_tier = "Cool"

        mock_container = MagicMock()
        mock_container.list_blobs.return_value = [mock_blob1, mock_blob2]
        mock_client.get_container_client.return_value = mock_container

        analyzer = AzureCostAnalyzer(connection_string="test")
        metrics = analyzer.get_storage_metrics("test-container")

        assert metrics.bucket_name == "test-container"
        assert metrics.total_size_bytes == 3072
        assert metrics.total_objects == 2
        assert "Hot" in metrics.size_by_tier
        assert "Cool" in metrics.size_by_tier


# =============================================================================
# Integration Tests
# =============================================================================


class TestCostAnalysisIntegration:
    """Integration tests for cost analysis module."""

    def test_module_imports(self):
        """Test that all exports are importable."""
        from stance.dspm.cost import (
            CostAnalysisConfig,
            StorageMetrics,
            ObjectAccessInfo,
            ColdDataFinding,
            CostAnalysisResult,
            FindingType,
            StorageTier,
            BaseCostAnalyzer,
            S3CostAnalyzer,
            GCSCostAnalyzer,
            AzureCostAnalyzer,
        )

        assert CostAnalysisConfig is not None
        assert StorageMetrics is not None
        assert ObjectAccessInfo is not None
        assert ColdDataFinding is not None
        assert CostAnalysisResult is not None
        assert FindingType is not None
        assert StorageTier is not None
        assert BaseCostAnalyzer is not None
        assert S3CostAnalyzer is not None
        assert GCSCostAnalyzer is not None
        assert AzureCostAnalyzer is not None

    def test_cost_savings_calculation(self):
        """Test end-to-end cost savings calculation."""
        from stance.dspm.cost.base import (
            BaseCostAnalyzer,
            CostAnalysisConfig,
            ObjectAccessInfo,
            StorageTier,
        )

        class TestAnalyzer(BaseCostAnalyzer):
            def analyze_bucket(self, bucket_name):
                pass

            def get_storage_metrics(self, bucket_name):
                pass

            def get_object_access_info(self, bucket_name, object_key):
                pass

            def list_objects_with_access_info(self, bucket_name, prefix=""):
                pass

        config = CostAnalysisConfig(
            cold_data_days=90,
            archive_candidate_days=180,
            delete_candidate_days=365,
        )
        analyzer = TestAnalyzer(config=config)

        # 100 GB of data not accessed in 200 days
        objects = [
            ObjectAccessInfo(
                object_key=f"file{i}.txt",
                size_bytes=1024 * 1024 * 1024,  # 1 GB each
                days_since_access=200,
            )
            for i in range(100)
        ]

        findings = analyzer._generate_findings(
            "test-bucket", objects, StorageTier.S3_STANDARD
        )

        # Should have archive candidate finding
        archive_findings = [
            f for f in findings if f.finding_type.value == "archive_candidate"
        ]
        assert len(archive_findings) == 1

        # Check savings is calculated
        assert archive_findings[0].potential_savings_monthly > 0
        assert archive_findings[0].size_bytes == 100 * 1024 * 1024 * 1024

    def test_severity_escalation(self):
        """Test that severity escalates with data age and size."""
        from stance.dspm.cost.base import (
            BaseCostAnalyzer,
            CostAnalysisConfig,
            ObjectAccessInfo,
            StorageTier,
        )

        class TestAnalyzer(BaseCostAnalyzer):
            def analyze_bucket(self, bucket_name):
                pass

            def get_storage_metrics(self, bucket_name):
                pass

            def get_object_access_info(self, bucket_name, object_key):
                pass

            def list_objects_with_access_info(self, bucket_name, prefix=""):
                pass

        analyzer = TestAnalyzer()

        # Small and not very old - low severity
        severity1 = analyzer._get_severity_for_cold_data(90, 1 * 1024**3)
        assert severity1 == "low"

        # Large and old - high severity
        severity2 = analyzer._get_severity_for_cold_data(365, 10 * 1024**3)
        assert severity2 == "high"

        # Very large and very old - critical
        severity3 = analyzer._get_severity_for_cold_data(365, 100 * 1024**3)
        assert severity3 == "critical"
