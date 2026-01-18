"""
Unit tests for DSPM Redshift scanner.

Tests cover:
- RedshiftConfig creation and validation
- RedshiftScanner initialization
- Connection testing
- Schema and table listing
- Column scanning decisions
- Data sampling
- Scan result generation
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from stance.dspm.extended.base import (
    ExtendedSourceType,
    ExtendedScanConfig,
    ExtendedScanResult,
    ExtendedScanFinding,
    ExtendedScanSummary,
)
from stance.dspm.extended.redshift import (
    RedshiftConfig,
    RedshiftScanner,
    RedshiftTableInfo,
    RedshiftColumnInfo,
    scan_redshift,
    HAS_PSYCOPG2,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def rs_config() -> RedshiftConfig:
    """Create sample Redshift configuration."""
    return RedshiftConfig(
        host="my-cluster.123456789012.us-east-1.redshift.amazonaws.com",
        port=5439,
        database="analytics",
        user="admin",
        password="secret123",
    )


@pytest.fixture
def rs_config_with_ssl() -> RedshiftConfig:
    """Create Redshift config with SSL settings."""
    return RedshiftConfig(
        host="my-cluster.123456789012.us-east-1.redshift.amazonaws.com",
        port=5439,
        database="analytics",
        user="admin",
        password="secret123",
        ssl_mode="verify-full",
        ssl_ca="/path/to/ca-bundle.crt",
    )


@pytest.fixture
def scan_config() -> ExtendedScanConfig:
    """Create sample scan configuration."""
    return ExtendedScanConfig(
        sample_rows_per_column=50,
        max_tables=10,
        max_columns_per_table=20,
    )


@pytest.fixture
def sample_table_info() -> RedshiftTableInfo:
    """Create sample table info."""
    return RedshiftTableInfo(
        schema="public",
        name="users",
        table_type="TABLE",
        diststyle="KEY",
        sortkey=["created_at"],
        row_count=100000,
        size_mb=50.5,
        columns=[
            RedshiftColumnInfo(name="id", data_type="integer", is_distkey=True),
            RedshiftColumnInfo(name="email", data_type="varchar", max_length=255),
            RedshiftColumnInfo(name="name", data_type="varchar", max_length=100),
            RedshiftColumnInfo(name="created_at", data_type="timestamp"),
            RedshiftColumnInfo(name="ssn", data_type="varchar", max_length=11),
        ],
    )


# =============================================================================
# Test RedshiftConfig
# =============================================================================

class TestRedshiftConfig:
    """Test RedshiftConfig class."""

    def test_basic_config(self, rs_config):
        """Test basic configuration creation."""
        assert rs_config.host == "my-cluster.123456789012.us-east-1.redshift.amazonaws.com"
        assert rs_config.port == 5439
        assert rs_config.database == "analytics"
        assert rs_config.user == "admin"
        assert rs_config.password == "secret123"

    def test_config_defaults(self):
        """Test configuration defaults."""
        config = RedshiftConfig(
            host="cluster.redshift.amazonaws.com",
            database="db",
            user="user",
            password="pass",
        )
        assert config.port == 5439
        assert config.ssl_mode == "require"
        assert config.ssl_ca is None
        assert config.connect_timeout == 30
        assert "information_schema" in config.exclude_schemas
        assert "pg_catalog" in config.exclude_schemas

    def test_config_with_ssl(self, rs_config_with_ssl):
        """Test configuration with SSL settings."""
        assert rs_config_with_ssl.ssl_mode == "verify-full"
        assert rs_config_with_ssl.ssl_ca == "/path/to/ca-bundle.crt"

    def test_connection_string(self, rs_config):
        """Test connection string generation."""
        conn_str = rs_config.connection_string
        assert "host=" in conn_str
        assert "port=5439" in conn_str
        assert "dbname=analytics" in conn_str
        assert "user=admin" in conn_str
        assert "sslmode=require" in conn_str

    def test_connection_string_with_ssl_ca(self, rs_config_with_ssl):
        """Test connection string with SSL CA."""
        conn_str = rs_config_with_ssl.connection_string
        assert "sslrootcert=/path/to/ca-bundle.crt" in conn_str

    def test_config_schema_filters(self):
        """Test configuration with schema filters."""
        config = RedshiftConfig(
            host="host",
            database="db",
            user="user",
            password="pass",
            include_schemas=["public", "analytics"],
            exclude_schemas=["temp"],
        )
        assert config.include_schemas == ["public", "analytics"]
        assert config.exclude_schemas == ["temp"]


# =============================================================================
# Test RedshiftColumnInfo
# =============================================================================

class TestRedshiftColumnInfo:
    """Test RedshiftColumnInfo class."""

    def test_column_info_creation(self):
        """Test column info creation."""
        col = RedshiftColumnInfo(
            name="email",
            data_type="varchar",
            max_length=255,
            is_nullable=True,
        )
        assert col.name == "email"
        assert col.data_type == "varchar"
        assert col.max_length == 255
        assert col.is_nullable is True

    def test_column_info_defaults(self):
        """Test column info defaults."""
        col = RedshiftColumnInfo(name="id", data_type="integer")
        assert col.max_length is None
        assert col.is_nullable is True
        assert col.is_distkey is False
        assert col.is_sortkey is False
        assert col.encoding == "none"
        assert col.sample_values == []

    def test_column_info_distkey(self):
        """Test column info with distkey."""
        col = RedshiftColumnInfo(
            name="user_id",
            data_type="integer",
            is_distkey=True,
        )
        assert col.is_distkey is True

    def test_column_info_sortkey(self):
        """Test column info with sortkey."""
        col = RedshiftColumnInfo(
            name="created_at",
            data_type="timestamp",
            is_sortkey=True,
        )
        assert col.is_sortkey is True


# =============================================================================
# Test RedshiftTableInfo
# =============================================================================

class TestRedshiftTableInfo:
    """Test RedshiftTableInfo class."""

    def test_table_info_creation(self, sample_table_info):
        """Test table info creation."""
        assert sample_table_info.schema == "public"
        assert sample_table_info.name == "users"
        assert sample_table_info.table_type == "TABLE"
        assert sample_table_info.diststyle == "KEY"
        assert sample_table_info.row_count == 100000
        assert len(sample_table_info.columns) == 5

    def test_table_full_name(self, sample_table_info):
        """Test full table name property."""
        assert sample_table_info.full_name == "public.users"

    def test_table_info_defaults(self):
        """Test table info defaults."""
        table = RedshiftTableInfo(schema="public", name="test")
        assert table.table_type == "TABLE"
        assert table.diststyle == "AUTO"
        assert table.sortkey == []
        assert table.row_count == 0
        assert table.size_mb == 0.0
        assert table.columns == []

    def test_table_info_with_sortkey(self):
        """Test table info with sortkey."""
        table = RedshiftTableInfo(
            schema="public",
            name="events",
            sortkey=["event_date", "event_time"],
        )
        assert len(table.sortkey) == 2


# =============================================================================
# Test RedshiftScanner
# =============================================================================

class TestRedshiftScanner:
    """Test RedshiftScanner class."""

    def test_scanner_initialization(self, rs_config, scan_config):
        """Test scanner initialization."""
        scanner = RedshiftScanner(rs_config=rs_config, scan_config=scan_config)
        assert scanner._rs_config == rs_config
        assert scanner.config == scan_config
        assert scanner.source_type == ExtendedSourceType.REDSHIFT

    def test_scanner_default_config(self, rs_config):
        """Test scanner with default scan config."""
        scanner = RedshiftScanner(rs_config=rs_config)
        assert scanner.config is not None
        assert scanner.config.sample_rows_per_column == 100

    @patch.dict(sys.modules, {"psycopg2": MagicMock()})
    def test_connection_test_success(self, rs_config):
        """Test successful connection test."""
        with patch("stance.dspm.extended.redshift.HAS_PSYCOPG2", True):
            with patch("stance.dspm.extended.redshift.psycopg2") as mock_psycopg2:
                mock_conn = MagicMock()
                mock_cursor = MagicMock()
                mock_cursor.fetchone.return_value = (1,)
                mock_conn.cursor.return_value = mock_cursor
                mock_psycopg2.connect.return_value = mock_conn

                scanner = RedshiftScanner(rs_config=rs_config)
                result = scanner.test_connection()

                assert result is True

    @patch.dict(sys.modules, {"psycopg2": MagicMock()})
    def test_connection_test_failure(self, rs_config):
        """Test failed connection test."""
        with patch("stance.dspm.extended.redshift.HAS_PSYCOPG2", True):
            with patch("stance.dspm.extended.redshift.psycopg2") as mock_psycopg2:
                mock_psycopg2.connect.side_effect = Exception("Connection refused")

                scanner = RedshiftScanner(rs_config=rs_config)
                result = scanner.test_connection()

                assert result is False

    def test_connection_test_without_library(self, rs_config):
        """Test connection test fails gracefully without psycopg2."""
        with patch("stance.dspm.extended.redshift.HAS_PSYCOPG2", False):
            scanner = RedshiftScanner(rs_config=rs_config)
            result = scanner.test_connection()
            assert result is False

    def test_should_scan_column_varchar(self, rs_config):
        """Test column scanning decision for VARCHAR type."""
        scanner = RedshiftScanner(rs_config=rs_config)

        col = RedshiftColumnInfo(name="email", data_type="varchar", max_length=255)
        assert scanner._should_scan_column(col) is True

    def test_should_scan_column_integer(self, rs_config):
        """Test column scanning decision for INTEGER type."""
        scanner = RedshiftScanner(rs_config=rs_config)

        col = RedshiftColumnInfo(name="ssn_num", data_type="integer")
        assert scanner._should_scan_column(col) is True

    def test_should_skip_column_timestamp(self, rs_config):
        """Test column scanning decision for TIMESTAMP type."""
        scanner = RedshiftScanner(rs_config=rs_config)

        col = RedshiftColumnInfo(name="created_at", data_type="timestamp")
        assert scanner._should_scan_column(col) is False

    def test_should_skip_column_boolean(self, rs_config):
        """Test column scanning decision for BOOLEAN type."""
        scanner = RedshiftScanner(rs_config=rs_config)

        col = RedshiftColumnInfo(name="is_active", data_type="boolean")
        assert scanner._should_scan_column(col) is False

    def test_should_skip_column_geometry(self, rs_config):
        """Test column scanning decision for GEOMETRY type."""
        scanner = RedshiftScanner(rs_config=rs_config)

        col = RedshiftColumnInfo(name="location", data_type="geometry")
        assert scanner._should_scan_column(col) is False

    def test_should_scan_column_super(self, rs_config):
        """Test column scanning decision for SUPER type."""
        scanner = RedshiftScanner(rs_config=rs_config)

        col = RedshiftColumnInfo(name="json_data", data_type="super")
        assert scanner._should_scan_column(col) is True

    def test_should_scan_table_regular(self, rs_config, sample_table_info):
        """Test table scanning decision for regular table."""
        scanner = RedshiftScanner(rs_config=rs_config)
        assert scanner._should_scan_table(sample_table_info) is True

    def test_should_skip_table_view(self, rs_config):
        """Test table scanning decision for VIEW."""
        scanner = RedshiftScanner(rs_config=rs_config)

        table = RedshiftTableInfo(
            schema="public",
            name="user_view",
            table_type="VIEW",
        )
        assert scanner._should_scan_table(table) is False

    def test_should_skip_table_excluded(self, rs_config):
        """Test table scanning decision for excluded table."""
        config = ExtendedScanConfig(exclude_tables=["users"])
        scanner = RedshiftScanner(rs_config=rs_config, scan_config=config)

        table = RedshiftTableInfo(schema="public", name="users")
        assert scanner._should_scan_table(table) is False

    def test_should_scan_table_included(self, rs_config):
        """Test table scanning decision for included table."""
        config = ExtendedScanConfig(include_tables=["users", "orders"])
        scanner = RedshiftScanner(rs_config=rs_config, scan_config=config)

        users_table = RedshiftTableInfo(schema="public", name="users")
        assert scanner._should_scan_table(users_table) is True

        events_table = RedshiftTableInfo(schema="public", name="events")
        assert scanner._should_scan_table(events_table) is False


# =============================================================================
# Test RedshiftScanner Scan Operations
# =============================================================================

class TestRedshiftScannerOperations:
    """Test RedshiftScanner scan operations with mocked connection."""

    @patch.dict(sys.modules, {"psycopg2": MagicMock()})
    def test_list_scannable_objects(self, rs_config):
        """Test listing scannable objects."""
        with patch("stance.dspm.extended.redshift.HAS_PSYCOPG2", True):
            with patch("stance.dspm.extended.redshift.psycopg2") as mock_psycopg2:
                mock_conn = MagicMock()
                mock_cursor = MagicMock()

                # Mock schema listing
                mock_cursor.fetchall.side_effect = [
                    [("public",)],  # Schemas
                    [("public", "users", "TABLE", "KEY", "id", 1000, 10.0)],  # Tables
                    [("email", "varchar", 255, "YES", False, False)],  # Columns
                ]

                mock_conn.cursor.return_value = mock_cursor
                mock_psycopg2.connect.return_value = mock_conn

                scanner = RedshiftScanner(rs_config=rs_config)
                tables = scanner.list_scannable_objects("test")

                assert isinstance(tables, list)

    @patch.dict(sys.modules, {"psycopg2": MagicMock()})
    def test_scan_empty_database(self, rs_config, scan_config):
        """Test scanning database with no tables."""
        with patch("stance.dspm.extended.redshift.HAS_PSYCOPG2", True):
            with patch("stance.dspm.extended.redshift.psycopg2") as mock_psycopg2:
                mock_conn = MagicMock()
                mock_cursor = MagicMock()
                mock_cursor.fetchall.return_value = []  # No schemas
                mock_conn.cursor.return_value = mock_cursor
                mock_psycopg2.connect.return_value = mock_conn

                scanner = RedshiftScanner(rs_config=rs_config, scan_config=scan_config)
                result = scanner.scan("test")

                assert isinstance(result, ExtendedScanResult)
                assert result.source_type == ExtendedSourceType.REDSHIFT
                assert result.summary.total_objects_scanned == 0

    @patch.dict(sys.modules, {"psycopg2": MagicMock()})
    def test_scan_with_data(self, rs_config, scan_config):
        """Test scanning that samples data."""
        with patch("stance.dspm.extended.redshift.HAS_PSYCOPG2", True):
            with patch("stance.dspm.extended.redshift.psycopg2") as mock_psycopg2:
                mock_conn = MagicMock()
                mock_cursor = MagicMock()

                # Set up cursor to return different results for different queries
                call_count = [0]

                def fetchall_side_effect():
                    call_count[0] += 1
                    if call_count[0] == 1:
                        return [("public",)]  # Schemas
                    elif call_count[0] == 2:
                        return [("public", "users", "BASE TABLE", "KEY", "id", 1000, 10.0)]  # Tables
                    elif call_count[0] == 3:
                        return [("email", "varchar", 255, "YES", False, False)]  # Columns
                    elif call_count[0] == 4:
                        return [("test@example.com",)]  # Sample data
                    return []

                mock_cursor.fetchall = fetchall_side_effect
                mock_conn.cursor.return_value = mock_cursor
                mock_psycopg2.connect.return_value = mock_conn

                scanner = RedshiftScanner(rs_config=rs_config, scan_config=scan_config)
                result = scanner.scan("test")

                assert isinstance(result, ExtendedScanResult)
                assert result.completed_at is not None


# =============================================================================
# Test scan_redshift Convenience Function
# =============================================================================

class TestScanRedshiftFunction:
    """Test scan_redshift convenience function."""

    def test_function_creates_scanner(self):
        """Test that function creates scanner with correct config."""
        with patch("stance.dspm.extended.redshift.RedshiftScanner") as mock_scanner_cls:
            mock_scanner = MagicMock()
            mock_scanner.scan.return_value = ExtendedScanResult(
                scan_id="test",
                source_type=ExtendedSourceType.REDSHIFT,
                target="host/db",
                config=ExtendedScanConfig(),
            )
            mock_scanner_cls.return_value = mock_scanner

            result = scan_redshift(
                host="my-cluster.redshift.amazonaws.com",
                database="analytics",
                user="admin",
                password="secret",
                port=5439,
                include_schemas=["public"],
                sample_rows=50,
                max_tables=20,
            )

            mock_scanner_cls.assert_called_once()
            call_kwargs = mock_scanner_cls.call_args
            rs_config = call_kwargs.kwargs["rs_config"]
            scan_config = call_kwargs.kwargs["scan_config"]

            assert rs_config.host == "my-cluster.redshift.amazonaws.com"
            assert rs_config.database == "analytics"
            assert rs_config.user == "admin"
            assert rs_config.include_schemas == ["public"]
            assert scan_config.sample_rows_per_column == 50
            assert scan_config.max_tables == 20


# =============================================================================
# Test Error Handling
# =============================================================================

class TestRedshiftErrorHandling:
    """Test error handling in Redshift scanner."""

    @patch.dict(sys.modules, {"psycopg2": MagicMock()})
    def test_scan_handles_connection_error(self, rs_config):
        """Test scan handles connection error gracefully."""
        with patch("stance.dspm.extended.redshift.HAS_PSYCOPG2", True):
            with patch("stance.dspm.extended.redshift.psycopg2") as mock_psycopg2:
                mock_psycopg2.connect.side_effect = Exception("Connection refused")

                scanner = RedshiftScanner(rs_config=rs_config)
                result = scanner.scan("test")

                assert isinstance(result, ExtendedScanResult)
                assert len(result.summary.errors) > 0
                assert "Connection refused" in result.summary.errors[0]

    @patch.dict(sys.modules, {"psycopg2": MagicMock()})
    def test_scan_handles_query_error(self, rs_config):
        """Test scan handles query error gracefully."""
        with patch("stance.dspm.extended.redshift.HAS_PSYCOPG2", True):
            with patch("stance.dspm.extended.redshift.psycopg2") as mock_psycopg2:
                mock_conn = MagicMock()
                mock_cursor = MagicMock()

                # First call succeeds (list schemas), second fails
                mock_cursor.fetchall.side_effect = [
                    [("public",)],  # Schemas
                    Exception("Query failed"),  # Tables query fails
                ]

                mock_conn.cursor.return_value = mock_cursor
                mock_psycopg2.connect.return_value = mock_conn

                scanner = RedshiftScanner(rs_config=rs_config)
                result = scanner.scan("test")

                # Should complete without crashing
                assert isinstance(result, ExtendedScanResult)

    def test_sample_column_handles_error(self, rs_config):
        """Test column sampling handles errors."""
        scanner = RedshiftScanner(rs_config=rs_config)

        mock_cursor = MagicMock()
        mock_cursor.execute.side_effect = Exception("Permission denied")

        values = scanner._sample_column(mock_cursor, "public", "users", "email")

        # Should return empty list on error
        assert values == []


# =============================================================================
# Test Integration with Detector
# =============================================================================

class TestRedshiftDetectorIntegration:
    """Test integration with sensitive data detector."""

    def test_scanner_has_detector(self, rs_config):
        """Test scanner initializes detector."""
        scanner = RedshiftScanner(rs_config=rs_config)
        assert scanner.detector is not None

    def test_finding_creation(self, rs_config):
        """Test finding creation from detection result."""
        scanner = RedshiftScanner(rs_config=rs_config)

        # Test with detector directly - use correct SSN format
        text_with_email = "Contact: john.doe@example.com"
        result = scanner.detector.scan_records(
            records=[{"content": text_with_email}],
            asset_id="test-asset",
            asset_type="test",
        )

        # Detector should find email pattern
        assert result.has_sensitive_data is True

    def test_detector_finds_email(self, rs_config):
        """Test detector finds email addresses."""
        scanner = RedshiftScanner(rs_config=rs_config)

        text = "Contact: john.doe@example.com"
        result = scanner.detector.scan_records(
            records=[{"content": text}],
            asset_id="test-asset",
            asset_type="test",
        )

        assert result.has_sensitive_data is True

    def test_detector_finds_credit_card(self, rs_config):
        """Test detector finds credit card numbers (no dashes)."""
        scanner = RedshiftScanner(rs_config=rs_config)

        # Visa pattern expects digits without dashes
        text = "Card: 4111111111111111"
        result = scanner.detector.scan_records(
            records=[{"content": text}],
            asset_id="test-asset",
            asset_type="test",
        )

        assert result.has_sensitive_data is True


# =============================================================================
# Test Redshift-Specific Features
# =============================================================================

class TestRedshiftSpecificFeatures:
    """Test Redshift-specific features."""

    def test_distkey_column_info(self, rs_config):
        """Test distribution key column information."""
        col = RedshiftColumnInfo(
            name="user_id",
            data_type="integer",
            is_distkey=True,
        )
        assert col.is_distkey is True

    def test_sortkey_table_info(self, sample_table_info):
        """Test sort key in table information."""
        assert sample_table_info.sortkey == ["created_at"]

    def test_diststyle_table_info(self, sample_table_info):
        """Test distribution style in table information."""
        assert sample_table_info.diststyle == "KEY"

    def test_table_size_info(self, sample_table_info):
        """Test table size information."""
        assert sample_table_info.size_mb == 50.5
        assert sample_table_info.row_count == 100000
