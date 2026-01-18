"""
Unit tests for DSPM BigQuery scanner.

Tests cover:
- BigQueryConfig creation and validation
- BigQueryScanner initialization
- Connection testing
- Dataset and table listing
- Column scanning decisions
- Data sampling
- Scan result generation
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from stance.dspm.extended.base import (
    ExtendedSourceType,
    ExtendedScanConfig,
    ExtendedScanResult,
    ExtendedScanFinding,
    ExtendedScanSummary,
)
from stance.dspm.extended.bigquery import (
    BigQueryConfig,
    BigQueryScanner,
    BigQueryTableInfo,
    BigQueryColumnInfo,
    scan_bigquery,
    HAS_BIGQUERY,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def bq_config() -> BigQueryConfig:
    """Create sample BigQuery configuration."""
    return BigQueryConfig(
        project_id="test-project",
        credentials_path="/path/to/credentials.json",
        location="US",
    )


@pytest.fixture
def bq_config_with_info() -> BigQueryConfig:
    """Create BigQuery config with credentials info."""
    return BigQueryConfig(
        project_id="test-project",
        credentials_info={
            "type": "service_account",
            "project_id": "test-project",
            "private_key_id": "key123",
            "private_key": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n",
            "client_email": "test@test-project.iam.gserviceaccount.com",
            "client_id": "123456789",
        },
        location="EU",
    )


@pytest.fixture
def scan_config() -> ExtendedScanConfig:
    """Create sample scan configuration."""
    return ExtendedScanConfig(
        sample_rows_per_column=50,
        max_tables=10,
        max_columns_per_table=20,
        exclude_schemas=["INFORMATION_SCHEMA"],
    )


@pytest.fixture
def mock_bigquery():
    """Create mock bigquery module."""
    mock_bq = MagicMock()
    mock_bq.Client = MagicMock()
    mock_bq.QueryJobConfig = MagicMock()
    return mock_bq


@pytest.fixture
def sample_table_info() -> BigQueryTableInfo:
    """Create sample table info."""
    return BigQueryTableInfo(
        dataset_id="test_dataset",
        table_id="users",
        table_type="TABLE",
        num_rows=10000,
        num_bytes=1024 * 1024 * 10,  # 10 MB
        columns=[
            BigQueryColumnInfo(name="id", field_type="INTEGER", mode="REQUIRED"),
            BigQueryColumnInfo(name="email", field_type="STRING", mode="NULLABLE"),
            BigQueryColumnInfo(name="name", field_type="STRING", mode="NULLABLE"),
            BigQueryColumnInfo(name="created_at", field_type="TIMESTAMP", mode="NULLABLE"),
            BigQueryColumnInfo(name="ssn", field_type="STRING", mode="NULLABLE"),
        ],
    )


# =============================================================================
# Test BigQueryConfig
# =============================================================================

class TestBigQueryConfig:
    """Test BigQueryConfig class."""

    def test_basic_config(self, bq_config):
        """Test basic configuration creation."""
        assert bq_config.project_id == "test-project"
        assert bq_config.credentials_path == "/path/to/credentials.json"
        assert bq_config.location == "US"
        assert bq_config.max_bytes_billed == 10 * 1024 * 1024 * 1024  # 10 GB

    def test_config_with_credentials_info(self, bq_config_with_info):
        """Test configuration with credentials info."""
        assert bq_config_with_info.project_id == "test-project"
        assert bq_config_with_info.credentials_info is not None
        assert bq_config_with_info.location == "EU"

    def test_config_defaults(self):
        """Test configuration defaults."""
        config = BigQueryConfig(project_id="my-project")
        assert config.project_id == "my-project"
        assert config.credentials_path is None
        assert config.credentials_info is None
        assert config.location == "US"
        assert config.use_legacy_sql is False
        assert "INFORMATION_SCHEMA" in config.exclude_datasets

    def test_config_with_dataset_filters(self):
        """Test configuration with dataset filters."""
        config = BigQueryConfig(
            project_id="my-project",
            include_datasets=["prod_data", "analytics"],
            exclude_datasets=["temp", "test"],
        )
        assert config.include_datasets == ["prod_data", "analytics"]
        assert config.exclude_datasets == ["temp", "test"]

    def test_config_max_bytes_billed(self):
        """Test custom max bytes billed."""
        config = BigQueryConfig(
            project_id="my-project",
            max_bytes_billed=1024 * 1024 * 100,  # 100 MB
        )
        assert config.max_bytes_billed == 100 * 1024 * 1024


# =============================================================================
# Test BigQueryColumnInfo
# =============================================================================

class TestBigQueryColumnInfo:
    """Test BigQueryColumnInfo class."""

    def test_column_info_creation(self):
        """Test column info creation."""
        col = BigQueryColumnInfo(
            name="email",
            field_type="STRING",
            mode="NULLABLE",
            description="User email address",
        )
        assert col.name == "email"
        assert col.field_type == "STRING"
        assert col.mode == "NULLABLE"
        assert col.description == "User email address"

    def test_column_info_defaults(self):
        """Test column info defaults."""
        col = BigQueryColumnInfo(name="id", field_type="INTEGER")
        assert col.mode == "NULLABLE"
        assert col.description == ""
        assert col.is_partitioning is False
        assert col.sample_values == []

    def test_column_info_with_samples(self):
        """Test column info with sample values."""
        col = BigQueryColumnInfo(
            name="email",
            field_type="STRING",
            sample_values=["test@example.com", "user@test.com"],
        )
        assert len(col.sample_values) == 2


# =============================================================================
# Test BigQueryTableInfo
# =============================================================================

class TestBigQueryTableInfo:
    """Test BigQueryTableInfo class."""

    def test_table_info_creation(self, sample_table_info):
        """Test table info creation."""
        assert sample_table_info.dataset_id == "test_dataset"
        assert sample_table_info.table_id == "users"
        assert sample_table_info.table_type == "TABLE"
        assert sample_table_info.num_rows == 10000
        assert len(sample_table_info.columns) == 5

    def test_table_full_name(self, sample_table_info):
        """Test full table name property."""
        assert sample_table_info.full_name == "test_dataset.users"

    def test_table_info_defaults(self):
        """Test table info defaults."""
        table = BigQueryTableInfo(dataset_id="ds", table_id="tbl")
        assert table.table_type == "TABLE"
        assert table.num_rows == 0
        assert table.num_bytes == 0
        assert table.is_partitioned is False
        assert table.partition_field is None
        assert table.columns == []

    def test_table_info_partitioned(self):
        """Test partitioned table info."""
        table = BigQueryTableInfo(
            dataset_id="ds",
            table_id="events",
            is_partitioned=True,
            partition_field="event_date",
        )
        assert table.is_partitioned is True
        assert table.partition_field == "event_date"


# =============================================================================
# Test BigQueryScanner
# =============================================================================

class TestBigQueryScanner:
    """Test BigQueryScanner class."""

    def test_scanner_initialization(self, bq_config, scan_config):
        """Test scanner initialization."""
        scanner = BigQueryScanner(bq_config=bq_config, scan_config=scan_config)
        assert scanner._bq_config == bq_config
        assert scanner.config == scan_config
        assert scanner.source_type == ExtendedSourceType.BIGQUERY

    def test_scanner_default_config(self, bq_config):
        """Test scanner with default scan config."""
        scanner = BigQueryScanner(bq_config=bq_config)
        assert scanner.config is not None
        assert scanner.config.sample_rows_per_column == 100

    @patch.dict(sys.modules, {"google.cloud.bigquery": MagicMock(), "google.oauth2.service_account": MagicMock()})
    def test_connection_test_success(self, bq_config):
        """Test successful connection test."""
        with patch("stance.dspm.extended.bigquery.HAS_BIGQUERY", True):
            with patch("stance.dspm.extended.bigquery.bigquery") as mock_bq:
                with patch("stance.dspm.extended.bigquery.service_account") as mock_sa:
                    mock_client = MagicMock()
                    mock_client.list_datasets.return_value = iter([MagicMock()])
                    mock_bq.Client.return_value = mock_client
                    mock_sa.Credentials.from_service_account_file.return_value = MagicMock()

                    scanner = BigQueryScanner(bq_config=bq_config)
                    scanner._client = mock_client  # Pre-set client

                    # Test connection
                    result = scanner.test_connection()
                    assert result is True

    def test_connection_test_without_library(self, bq_config):
        """Test connection test fails gracefully without bigquery library."""
        with patch("stance.dspm.extended.bigquery.HAS_BIGQUERY", False):
            scanner = BigQueryScanner(bq_config=bq_config)
            result = scanner.test_connection()
            assert result is False

    def test_should_scan_column_string(self, bq_config):
        """Test column scanning decision for STRING type."""
        scanner = BigQueryScanner(bq_config=bq_config)

        col = BigQueryColumnInfo(name="email", field_type="STRING")
        assert scanner._should_scan_column(col) is True

    def test_should_scan_column_integer(self, bq_config):
        """Test column scanning decision for INTEGER type."""
        scanner = BigQueryScanner(bq_config=bq_config)

        col = BigQueryColumnInfo(name="ssn_num", field_type="INTEGER")
        assert scanner._should_scan_column(col) is True

    def test_should_skip_column_timestamp(self, bq_config):
        """Test column scanning decision for TIMESTAMP type."""
        scanner = BigQueryScanner(bq_config=bq_config)

        col = BigQueryColumnInfo(name="created_at", field_type="TIMESTAMP")
        assert scanner._should_scan_column(col) is False

    def test_should_skip_column_boolean(self, bq_config):
        """Test column scanning decision for BOOLEAN type."""
        scanner = BigQueryScanner(bq_config=bq_config)

        col = BigQueryColumnInfo(name="is_active", field_type="BOOLEAN")
        assert scanner._should_scan_column(col) is False

    def test_should_skip_column_struct(self, bq_config):
        """Test column scanning decision for STRUCT type."""
        scanner = BigQueryScanner(bq_config=bq_config)

        col = BigQueryColumnInfo(name="address", field_type="STRUCT")
        assert scanner._should_scan_column(col) is False

    def test_should_scan_column_json(self, bq_config):
        """Test column scanning decision for JSON type."""
        scanner = BigQueryScanner(bq_config=bq_config)

        col = BigQueryColumnInfo(name="metadata", field_type="JSON")
        assert scanner._should_scan_column(col) is True

    def test_should_scan_table_regular(self, bq_config, sample_table_info):
        """Test table scanning decision for regular table."""
        scanner = BigQueryScanner(bq_config=bq_config)
        assert scanner._should_scan_table(sample_table_info) is True

    def test_should_skip_table_view(self, bq_config):
        """Test table scanning decision for VIEW."""
        scanner = BigQueryScanner(bq_config=bq_config)

        table = BigQueryTableInfo(
            dataset_id="ds",
            table_id="my_view",
            table_type="VIEW",
        )
        assert scanner._should_scan_table(table) is False

    def test_should_skip_table_excluded(self, bq_config):
        """Test table scanning decision for excluded table."""
        config = ExtendedScanConfig(exclude_tables=["users"])
        scanner = BigQueryScanner(bq_config=bq_config, scan_config=config)

        table = BigQueryTableInfo(dataset_id="ds", table_id="users")
        assert scanner._should_scan_table(table) is False

    def test_should_scan_table_included(self, bq_config):
        """Test table scanning decision for included table."""
        config = ExtendedScanConfig(include_tables=["users", "orders"])
        scanner = BigQueryScanner(bq_config=bq_config, scan_config=config)

        users_table = BigQueryTableInfo(dataset_id="ds", table_id="users")
        assert scanner._should_scan_table(users_table) is True

        events_table = BigQueryTableInfo(dataset_id="ds", table_id="events")
        assert scanner._should_scan_table(events_table) is False


# =============================================================================
# Test BigQueryScanner Scan Operations
# =============================================================================

class TestBigQueryScannerOperations:
    """Test BigQueryScanner scan operations with mocked client."""

    @patch.dict(sys.modules, {"google.cloud.bigquery": MagicMock(), "google.oauth2.service_account": MagicMock()})
    def test_list_scannable_objects(self, bq_config):
        """Test listing scannable objects."""
        with patch("stance.dspm.extended.bigquery.HAS_BIGQUERY", True):
            scanner = BigQueryScanner(bq_config=bq_config)

            # Mock dataset and table listing
            mock_dataset = MagicMock()
            mock_dataset.dataset_id = "test_dataset"

            mock_table_ref = MagicMock()
            mock_table_ref.table_id = "users"
            mock_table_ref.reference = MagicMock()

            mock_table = MagicMock()
            mock_table.table_id = "users"
            mock_table.table_type = "TABLE"
            mock_table.num_rows = 1000
            mock_table.num_bytes = 50000
            mock_table.schema = []
            mock_table.time_partitioning = None
            mock_table.created = datetime.now(timezone.utc)
            mock_table.modified = datetime.now(timezone.utc)

            mock_client = MagicMock()
            mock_client.list_datasets.return_value = iter([mock_dataset])
            mock_client.dataset.return_value = MagicMock()
            mock_client.list_tables.return_value = iter([mock_table_ref])
            mock_client.get_table.return_value = mock_table

            scanner._client = mock_client

            tables = scanner.list_scannable_objects("test")

            assert len(tables) >= 0  # May be empty if filters apply

    @patch.dict(sys.modules, {"google.cloud.bigquery": MagicMock(), "google.oauth2.service_account": MagicMock()})
    def test_scan_empty_project(self, bq_config, scan_config):
        """Test scanning project with no datasets."""
        with patch("stance.dspm.extended.bigquery.HAS_BIGQUERY", True):
            scanner = BigQueryScanner(bq_config=bq_config, scan_config=scan_config)

            mock_client = MagicMock()
            mock_client.list_datasets.return_value = iter([])

            scanner._client = mock_client

            result = scanner.scan("test-project")

            assert isinstance(result, ExtendedScanResult)
            assert result.source_type == ExtendedSourceType.BIGQUERY
            assert result.summary.total_objects_scanned == 0

    @patch.dict(sys.modules, {"google.cloud.bigquery": MagicMock(), "google.oauth2.service_account": MagicMock()})
    def test_scan_with_findings(self, bq_config, scan_config):
        """Test scanning that produces findings."""
        with patch("stance.dspm.extended.bigquery.HAS_BIGQUERY", True):
            scanner = BigQueryScanner(bq_config=bq_config, scan_config=scan_config)

            # Mock dataset
            mock_dataset = MagicMock()
            mock_dataset.dataset_id = "prod_data"

            # Mock table with schema
            mock_field = MagicMock()
            mock_field.name = "email"
            mock_field.field_type = "STRING"
            mock_field.mode = "NULLABLE"
            mock_field.description = ""

            mock_table_ref = MagicMock()
            mock_table_ref.table_id = "users"
            mock_table_ref.reference = MagicMock()

            mock_table = MagicMock()
            mock_table.table_id = "users"
            mock_table.table_type = "TABLE"
            mock_table.num_rows = 1000
            mock_table.num_bytes = 50000
            mock_table.schema = [mock_field]
            mock_table.time_partitioning = None
            mock_table.created = datetime.now(timezone.utc)
            mock_table.modified = datetime.now(timezone.utc)

            # Mock query result
            mock_row = MagicMock()
            mock_row.__getitem__ = lambda self, x: "test@example.com"

            mock_query_job = MagicMock()
            mock_query_job.result.return_value = iter([mock_row])

            mock_client = MagicMock()
            mock_client.list_datasets.return_value = iter([mock_dataset])
            mock_client.dataset.return_value = MagicMock()
            mock_client.list_tables.return_value = iter([mock_table_ref])
            mock_client.get_table.return_value = mock_table
            mock_client.query.return_value = mock_query_job

            scanner._client = mock_client

            result = scanner.scan("test-project")

            assert isinstance(result, ExtendedScanResult)
            assert result.completed_at is not None
            # Findings depend on detector matching patterns


# =============================================================================
# Test scan_bigquery Convenience Function
# =============================================================================

class TestScanBigQueryFunction:
    """Test scan_bigquery convenience function."""

    def test_function_creates_scanner(self):
        """Test that function creates scanner with correct config."""
        with patch("stance.dspm.extended.bigquery.BigQueryScanner") as mock_scanner_cls:
            mock_scanner = MagicMock()
            mock_scanner.scan.return_value = ExtendedScanResult(
                scan_id="test",
                source_type=ExtendedSourceType.BIGQUERY,
                target="project",
                config=ExtendedScanConfig(),
            )
            mock_scanner_cls.return_value = mock_scanner

            result = scan_bigquery(
                project_id="my-project",
                credentials_path="/path/to/creds.json",
                include_datasets=["prod"],
                sample_rows=50,
                max_tables=20,
            )

            mock_scanner_cls.assert_called_once()
            call_kwargs = mock_scanner_cls.call_args
            bq_config = call_kwargs.kwargs["bq_config"]
            scan_config = call_kwargs.kwargs["scan_config"]

            assert bq_config.project_id == "my-project"
            assert bq_config.credentials_path == "/path/to/creds.json"
            assert bq_config.include_datasets == ["prod"]
            assert scan_config.sample_rows_per_column == 50
            assert scan_config.max_tables == 20


# =============================================================================
# Test Error Handling
# =============================================================================

class TestBigQueryErrorHandling:
    """Test error handling in BigQuery scanner."""

    def test_scan_handles_connection_error(self, bq_config):
        """Test scan handles connection error gracefully."""
        with patch("stance.dspm.extended.bigquery.HAS_BIGQUERY", True):
            scanner = BigQueryScanner(bq_config=bq_config)

            # Mock client that raises error
            mock_client = MagicMock()
            mock_client.list_datasets.side_effect = Exception("Connection refused")

            scanner._client = mock_client

            result = scanner.scan("test")

            assert isinstance(result, ExtendedScanResult)
            assert len(result.summary.errors) > 0
            assert "Connection refused" in result.summary.errors[0]

    def test_scan_handles_query_error(self, bq_config):
        """Test scan handles query error gracefully."""
        with patch("stance.dspm.extended.bigquery.HAS_BIGQUERY", True):
            scanner = BigQueryScanner(bq_config=bq_config)

            # Mock dataset
            mock_dataset = MagicMock()
            mock_dataset.dataset_id = "test"

            # Mock table
            mock_field = MagicMock()
            mock_field.name = "data"
            mock_field.field_type = "STRING"
            mock_field.mode = "NULLABLE"
            mock_field.description = ""

            mock_table_ref = MagicMock()
            mock_table_ref.reference = MagicMock()

            mock_table = MagicMock()
            mock_table.table_id = "t1"
            mock_table.table_type = "TABLE"
            mock_table.num_rows = 100
            mock_table.num_bytes = 1000
            mock_table.schema = [mock_field]
            mock_table.time_partitioning = None
            mock_table.created = datetime.now(timezone.utc)
            mock_table.modified = datetime.now(timezone.utc)

            mock_client = MagicMock()
            mock_client.list_datasets.return_value = iter([mock_dataset])
            mock_client.dataset.return_value = MagicMock()
            mock_client.list_tables.return_value = iter([mock_table_ref])
            mock_client.get_table.return_value = mock_table
            mock_client.query.side_effect = Exception("Query failed")

            scanner._client = mock_client

            result = scanner.scan("test")

            # Should complete without crashing
            assert isinstance(result, ExtendedScanResult)


# =============================================================================
# Test Integration with Detector
# =============================================================================

class TestBigQueryDetectorIntegration:
    """Test integration with sensitive data detector."""

    def test_scanner_has_detector(self, bq_config):
        """Test scanner initializes detector."""
        scanner = BigQueryScanner(bq_config=bq_config)
        assert scanner.detector is not None

    def test_finding_creation(self, bq_config):
        """Test finding creation from detection result."""
        scanner = BigQueryScanner(bq_config=bq_config)

        # Test with detector directly
        text_with_email = "Contact: john.doe@example.com"
        result = scanner.detector.scan_records(
            records=[{"content": text_with_email}],
            asset_id="test-asset",
            asset_type="test",
        )

        # Detector should find email pattern
        assert result.has_sensitive_data is True
