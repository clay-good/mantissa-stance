"""
Unit tests for DSPM database scanners.
"""

import sys
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, PropertyMock

from stance.dspm.extended.databases import (
    DatabaseType,
    DatabaseConfig,
    DatabaseScanner,
    TableInfo,
    ColumnInfo,
    scan_database,
)
from stance.dspm.extended.base import (
    ExtendedSourceType,
    ExtendedScanConfig,
    ExtendedScanResult,
)
from stance.dspm.scanners.base import FindingSeverity


class TestDatabaseType:
    """Tests for DatabaseType enum."""

    def test_database_types_exist(self):
        """Test all expected database types exist."""
        assert DatabaseType.POSTGRESQL.value == "postgresql"
        assert DatabaseType.MYSQL.value == "mysql"
        assert DatabaseType.MSSQL.value == "mssql"
        assert DatabaseType.ORACLE.value == "oracle"
        assert DatabaseType.MARIADB.value == "mariadb"


class TestDatabaseConfig:
    """Tests for DatabaseConfig."""

    def test_basic_config(self):
        """Test basic configuration."""
        config = DatabaseConfig(
            host="localhost",
            port=5432,
            database="mydb",
            user="admin",
            password="secret",
        )

        assert config.host == "localhost"
        assert config.port == 5432
        assert config.database == "mydb"
        assert config.user == "admin"
        assert config.password == "secret"
        assert config.db_type == DatabaseType.POSTGRESQL

    def test_mysql_config(self):
        """Test MySQL configuration."""
        config = DatabaseConfig(
            host="mysql.example.com",
            port=3306,
            database="mydb",
            user="root",
            password="secret",
            db_type=DatabaseType.MYSQL,
        )

        assert config.db_type == DatabaseType.MYSQL
        assert config.port == 3306

    def test_ssl_config(self):
        """Test SSL configuration."""
        config = DatabaseConfig(
            host="secure.example.com",
            port=5432,
            database="mydb",
            user="admin",
            password="secret",
            ssl_mode="verify-full",
            ssl_ca="/path/to/ca.pem",
        )

        assert config.ssl_mode == "verify-full"
        assert config.ssl_ca == "/path/to/ca.pem"

    def test_port_default(self):
        """Test port defaults for different database types."""
        pg_config = DatabaseConfig(
            host="localhost",
            port=5432,
            database="db",
            user="user",
            password="pass",
            db_type=DatabaseType.POSTGRESQL,
        )
        assert pg_config.port_default == 5432

        mysql_config = DatabaseConfig(
            host="localhost",
            port=3306,
            database="db",
            user="user",
            password="pass",
            db_type=DatabaseType.MYSQL,
        )
        assert mysql_config.port_default == 3306

        mssql_config = DatabaseConfig(
            host="localhost",
            port=1433,
            database="db",
            user="user",
            password="pass",
            db_type=DatabaseType.MSSQL,
        )
        assert mssql_config.port_default == 1433


class TestColumnInfo:
    """Tests for ColumnInfo."""

    def test_column_creation(self):
        """Test column info creation."""
        column = ColumnInfo(
            name="email",
            data_type="varchar",
            is_nullable=False,
            max_length=255,
        )

        assert column.name == "email"
        assert column.data_type == "varchar"
        assert column.is_nullable is False
        assert column.max_length == 255

    def test_column_defaults(self):
        """Test column default values."""
        column = ColumnInfo(
            name="id",
            data_type="integer",
        )

        assert column.is_nullable is True
        assert column.max_length is None
        assert column.is_primary_key is False
        assert column.sample_values == []


class TestTableInfo:
    """Tests for TableInfo."""

    def test_table_creation(self):
        """Test table info creation."""
        columns = [
            ColumnInfo(name="id", data_type="integer"),
            ColumnInfo(name="name", data_type="varchar"),
        ]

        table = TableInfo(
            schema="public",
            name="users",
            table_type="TABLE",
            row_count=1000,
            columns=columns,
        )

        assert table.schema == "public"
        assert table.name == "users"
        assert table.table_type == "TABLE"
        assert len(table.columns) == 2

    def test_table_full_name(self):
        """Test full name property."""
        table = TableInfo(
            schema="analytics",
            name="events",
        )

        assert table.full_name == "analytics.events"


class TestDatabaseScanner:
    """Tests for DatabaseScanner base class."""

    def test_scannable_types(self):
        """Test that expected types are scannable."""
        assert "varchar" in DatabaseScanner.SCANNABLE_TYPES
        assert "text" in DatabaseScanner.SCANNABLE_TYPES
        assert "char" in DatabaseScanner.SCANNABLE_TYPES
        assert "integer" in DatabaseScanner.SCANNABLE_TYPES

    def test_skip_types(self):
        """Test that expected types are skipped."""
        assert "bytea" in DatabaseScanner.SKIP_TYPES
        assert "binary" in DatabaseScanner.SKIP_TYPES
        assert "timestamp" in DatabaseScanner.SKIP_TYPES
        assert "boolean" in DatabaseScanner.SKIP_TYPES


class TestRDSScannerWithMocks:
    """Tests for RDSScanner with proper mocking."""

    def test_postgresql_scanner_initialization(self):
        """Test PostgreSQL scanner initialization."""
        mock_psycopg2 = MagicMock()
        with patch.dict(sys.modules, {"psycopg2": mock_psycopg2}):
            # Re-import to pick up mock
            from stance.dspm.extended.databases import RDSScanner

            config = DatabaseConfig(
                host="localhost",
                port=5432,
                database="mydb",
                user="admin",
                password="secret",
                db_type=DatabaseType.POSTGRESQL,
            )

            scanner = RDSScanner(config)

            assert scanner.source_type == ExtendedSourceType.RDS
            assert scanner._db_config == config

    def test_test_connection_success(self):
        """Test successful connection test."""
        mock_psycopg2 = MagicMock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (1,)
        mock_conn.cursor.return_value = mock_cursor
        mock_psycopg2.connect.return_value = mock_conn

        with patch.dict(sys.modules, {"psycopg2": mock_psycopg2}):
            from stance.dspm.extended.databases import RDSScanner

            config = DatabaseConfig(
                host="localhost",
                port=5432,
                database="mydb",
                user="admin",
                password="secret",
            )
            scanner = RDSScanner(config)
            scanner._driver = mock_psycopg2

            result = scanner.test_connection()

            assert result is True

    def test_test_connection_failure(self):
        """Test failed connection test."""
        mock_psycopg2 = MagicMock()
        mock_psycopg2.connect.side_effect = Exception("Connection refused")

        with patch.dict(sys.modules, {"psycopg2": mock_psycopg2}):
            from stance.dspm.extended.databases import RDSScanner

            config = DatabaseConfig(
                host="localhost",
                port=5432,
                database="mydb",
                user="admin",
                password="secret",
            )
            scanner = RDSScanner(config)
            scanner._driver = mock_psycopg2

            result = scanner.test_connection()

            assert result is False

    def test_should_scan_column_text_types(self):
        """Test column scanning decisions for text types."""
        mock_psycopg2 = MagicMock()

        with patch.dict(sys.modules, {"psycopg2": mock_psycopg2}):
            from stance.dspm.extended.databases import RDSScanner

            config = DatabaseConfig(
                host="localhost",
                port=5432,
                database="mydb",
                user="admin",
                password="secret",
            )
            scanner = RDSScanner(config)

            # Text types should be scanned
            assert scanner._should_scan_column(
                ColumnInfo(name="test", data_type="varchar")
            ) is True
            assert scanner._should_scan_column(
                ColumnInfo(name="test", data_type="text")
            ) is True
            assert scanner._should_scan_column(
                ColumnInfo(name="test", data_type="character varying")
            ) is True

    def test_should_scan_column_skip_types(self):
        """Test column scanning decisions for skip types."""
        mock_psycopg2 = MagicMock()

        with patch.dict(sys.modules, {"psycopg2": mock_psycopg2}):
            from stance.dspm.extended.databases import RDSScanner

            config = DatabaseConfig(
                host="localhost",
                port=5432,
                database="mydb",
                user="admin",
                password="secret",
            )
            scanner = RDSScanner(config)

            # Binary and timestamp types should be skipped
            assert scanner._should_scan_column(
                ColumnInfo(name="test", data_type="bytea")
            ) is False
            assert scanner._should_scan_column(
                ColumnInfo(name="test", data_type="timestamp")
            ) is False
            assert scanner._should_scan_column(
                ColumnInfo(name="test", data_type="boolean")
            ) is False

    def test_should_scan_table_with_filters(self):
        """Test table scanning decisions with filters."""
        mock_psycopg2 = MagicMock()

        with patch.dict(sys.modules, {"psycopg2": mock_psycopg2}):
            from stance.dspm.extended.databases import RDSScanner

            scan_config = ExtendedScanConfig(
                include_tables=["users", "orders"],
                exclude_tables=["temp_data"],
            )
            config = DatabaseConfig(
                host="localhost",
                port=5432,
                database="mydb",
                user="admin",
                password="secret",
            )
            scanner = RDSScanner(config, scan_config)

            # Included tables
            assert scanner._should_scan_table(
                TableInfo(schema="public", name="users")
            ) is True
            assert scanner._should_scan_table(
                TableInfo(schema="public", name="orders")
            ) is True

            # Not included
            assert scanner._should_scan_table(
                TableInfo(schema="public", name="products")
            ) is False

            # Excluded
            assert scanner._should_scan_table(
                TableInfo(schema="public", name="temp_data")
            ) is False

    def test_scan_returns_result(self):
        """Test that scan returns a result."""
        mock_psycopg2 = MagicMock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = []
        mock_conn.cursor.return_value = mock_cursor
        mock_psycopg2.connect.return_value = mock_conn

        with patch.dict(sys.modules, {"psycopg2": mock_psycopg2}):
            from stance.dspm.extended.databases import RDSScanner

            config = DatabaseConfig(
                host="localhost",
                port=5432,
                database="mydb",
                user="admin",
                password="secret",
            )
            scanner = RDSScanner(config)
            scanner._driver = mock_psycopg2

            result = scanner.scan("mydb")

            assert isinstance(result, ExtendedScanResult)
            assert result.source_type == ExtendedSourceType.RDS
            assert result.completed_at is not None


class TestCloudSQLScannerWithMocks:
    """Tests for CloudSQLScanner with proper mocking."""

    def test_cloud_sql_scanner_initialization(self):
        """Test Cloud SQL scanner initialization."""
        mock_psycopg2 = MagicMock()

        with patch.dict(sys.modules, {"psycopg2": mock_psycopg2}):
            from stance.dspm.extended.databases import CloudSQLScanner

            config = DatabaseConfig(
                host="10.0.0.1",
                port=5432,
                database="mydb",
                user="postgres",
                password="secret",
                db_type=DatabaseType.POSTGRESQL,
            )

            scanner = CloudSQLScanner(config)

            assert scanner.source_type == ExtendedSourceType.CLOUD_SQL

    def test_cloud_sql_test_connection(self):
        """Test Cloud SQL connection test."""
        mock_psycopg2 = MagicMock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (1,)
        mock_conn.cursor.return_value = mock_cursor
        mock_psycopg2.connect.return_value = mock_conn

        with patch.dict(sys.modules, {"psycopg2": mock_psycopg2}):
            from stance.dspm.extended.databases import CloudSQLScanner

            config = DatabaseConfig(
                host="10.0.0.1",
                port=5432,
                database="mydb",
                user="postgres",
                password="secret",
            )
            scanner = CloudSQLScanner(config)
            scanner._driver = mock_psycopg2

            result = scanner.test_connection()

            assert result is True

    def test_cloud_sql_scan(self):
        """Test Cloud SQL scan."""
        mock_psycopg2 = MagicMock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = []
        mock_conn.cursor.return_value = mock_cursor
        mock_psycopg2.connect.return_value = mock_conn

        with patch.dict(sys.modules, {"psycopg2": mock_psycopg2}):
            from stance.dspm.extended.databases import CloudSQLScanner

            config = DatabaseConfig(
                host="10.0.0.1",
                port=5432,
                database="mydb",
                user="postgres",
                password="secret",
            )
            scanner = CloudSQLScanner(config)
            scanner._driver = mock_psycopg2

            result = scanner.scan("mydb")

            assert isinstance(result, ExtendedScanResult)
            assert result.source_type == ExtendedSourceType.CLOUD_SQL


class TestAzureSQLScannerWithMocks:
    """Tests for AzureSQLScanner with proper mocking."""

    def test_azure_sql_scanner_initialization(self):
        """Test Azure SQL scanner initialization."""
        mock_pyodbc = MagicMock()

        with patch.dict(sys.modules, {"pyodbc": mock_pyodbc}):
            from stance.dspm.extended.databases import AzureSQLScanner

            config = DatabaseConfig(
                host="myserver.database.windows.net",
                port=1433,
                database="mydb",
                user="admin",
                password="secret",
                db_type=DatabaseType.MSSQL,
            )

            scanner = AzureSQLScanner(config)

            assert scanner.source_type == ExtendedSourceType.AZURE_SQL

    def test_azure_sql_connection_string(self):
        """Test Azure SQL connection string format."""
        mock_pyodbc = MagicMock()

        with patch.dict(sys.modules, {"pyodbc": mock_pyodbc}):
            from stance.dspm.extended.databases import AzureSQLScanner

            config = DatabaseConfig(
                host="myserver.database.windows.net",
                port=1433,
                database="mydb",
                user="admin",
                password="secret",
            )

            scanner = AzureSQLScanner(config)
            scanner._driver = mock_pyodbc
            scanner._get_connection()

            # Verify connection was called with proper string
            call_args = mock_pyodbc.connect.call_args[0][0]
            assert "myserver.database.windows.net" in call_args
            assert "mydb" in call_args
            assert "Encrypt=yes" in call_args

    def test_azure_sql_test_connection(self):
        """Test Azure SQL connection test."""
        mock_pyodbc = MagicMock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (1,)
        mock_conn.cursor.return_value = mock_cursor
        mock_pyodbc.connect.return_value = mock_conn

        with patch.dict(sys.modules, {"pyodbc": mock_pyodbc}):
            from stance.dspm.extended.databases import AzureSQLScanner

            config = DatabaseConfig(
                host="myserver.database.windows.net",
                port=1433,
                database="mydb",
                user="admin",
                password="secret",
            )
            scanner = AzureSQLScanner(config)
            scanner._driver = mock_pyodbc

            result = scanner.test_connection()

            assert result is True

    def test_azure_sql_scan(self):
        """Test Azure SQL scan."""
        mock_pyodbc = MagicMock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = []
        mock_conn.cursor.return_value = mock_cursor
        mock_pyodbc.connect.return_value = mock_conn

        with patch.dict(sys.modules, {"pyodbc": mock_pyodbc}):
            from stance.dspm.extended.databases import AzureSQLScanner

            config = DatabaseConfig(
                host="myserver.database.windows.net",
                port=1433,
                database="mydb",
                user="admin",
                password="secret",
            )
            scanner = AzureSQLScanner(config)
            scanner._driver = mock_pyodbc

            result = scanner.scan("mydb")

            assert isinstance(result, ExtendedScanResult)
            assert result.source_type == ExtendedSourceType.AZURE_SQL


class TestScanDatabaseConvenience:
    """Tests for scan_database convenience function."""

    def test_scan_postgresql(self):
        """Test scanning PostgreSQL database."""
        with patch("stance.dspm.extended.databases.RDSScanner") as mock_rds_scanner:
            mock_scanner = MagicMock()
            mock_result = MagicMock(spec=ExtendedScanResult)
            mock_scanner.scan.return_value = mock_result
            mock_rds_scanner.return_value = mock_scanner

            config = DatabaseConfig(
                host="localhost",
                port=5432,
                database="mydb",
                user="admin",
                password="secret",
                db_type=DatabaseType.POSTGRESQL,
            )

            result = scan_database(config)

            mock_rds_scanner.assert_called_once()
            assert result == mock_result

    def test_scan_mysql(self):
        """Test scanning MySQL database."""
        with patch("stance.dspm.extended.databases.RDSScanner") as mock_rds_scanner:
            mock_scanner = MagicMock()
            mock_result = MagicMock(spec=ExtendedScanResult)
            mock_scanner.scan.return_value = mock_result
            mock_rds_scanner.return_value = mock_scanner

            config = DatabaseConfig(
                host="localhost",
                port=3306,
                database="mydb",
                user="root",
                password="secret",
                db_type=DatabaseType.MYSQL,
            )

            result = scan_database(config)

            mock_rds_scanner.assert_called_once()
            assert result == mock_result

    def test_scan_mssql(self):
        """Test scanning MSSQL database."""
        with patch("stance.dspm.extended.databases.AzureSQLScanner") as mock_azure_scanner:
            mock_scanner = MagicMock()
            mock_result = MagicMock(spec=ExtendedScanResult)
            mock_scanner.scan.return_value = mock_result
            mock_azure_scanner.return_value = mock_scanner

            config = DatabaseConfig(
                host="localhost",
                port=1433,
                database="mydb",
                user="sa",
                password="secret",
                db_type=DatabaseType.MSSQL,
            )

            result = scan_database(config)

            mock_azure_scanner.assert_called_once()
            assert result == mock_result

    def test_scan_unsupported_type(self):
        """Test scanning unsupported database type."""
        config = DatabaseConfig(
            host="localhost",
            port=1521,
            database="mydb",
            user="admin",
            password="secret",
            db_type=DatabaseType.ORACLE,
        )

        with pytest.raises(ValueError, match="Unsupported database type"):
            scan_database(config)


class TestDatabaseColumnSampling:
    """Tests for column sampling."""

    def test_sample_column_postgresql(self):
        """Test column sampling for PostgreSQL."""
        mock_psycopg2 = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [
            ("value1",),
            ("value2",),
            ("value3",),
        ]

        with patch.dict(sys.modules, {"psycopg2": mock_psycopg2}):
            from stance.dspm.extended.databases import RDSScanner

            config = DatabaseConfig(
                host="localhost",
                port=5432,
                database="mydb",
                user="admin",
                password="secret",
            )
            scanner = RDSScanner(config)

            values = scanner._sample_column(mock_cursor, "public", "users", "email")

            assert values == ["value1", "value2", "value3"]
            # Verify query format
            call_args = mock_cursor.execute.call_args[0][0]
            assert '"email"' in call_args
            assert '"public"."users"' in call_args

    def test_sample_column_mssql(self):
        """Test column sampling for MSSQL."""
        mock_pyodbc = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [
            ("value1",),
            ("value2",),
        ]
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_pyodbc.connect.return_value = mock_conn

        with patch.dict(sys.modules, {"pyodbc": mock_pyodbc}):
            from stance.dspm.extended.databases import AzureSQLScanner

            config = DatabaseConfig(
                host="localhost",
                port=1433,
                database="mydb",
                user="sa",
                password="secret",
            )
            scanner = AzureSQLScanner(config)

            values = scanner._sample_column(mock_cursor, "dbo", "users", "email")

            assert values == ["value1", "value2"]
            # Verify MSSQL-specific query format (TOP instead of LIMIT)
            call_args = mock_cursor.execute.call_args[0][0]
            assert "TOP" in call_args
            assert "[email]" in call_args

    def test_sample_column_handles_error(self):
        """Test that column sampling handles errors gracefully."""
        mock_psycopg2 = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.execute.side_effect = Exception("Query failed")

        with patch.dict(sys.modules, {"psycopg2": mock_psycopg2}):
            from stance.dspm.extended.databases import RDSScanner

            config = DatabaseConfig(
                host="localhost",
                port=5432,
                database="mydb",
                user="admin",
                password="secret",
            )
            scanner = RDSScanner(config)

            values = scanner._sample_column(mock_cursor, "public", "users", "email")

            assert values == []
