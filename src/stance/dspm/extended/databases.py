"""
Database Scanners for DSPM.

Scans relational databases (RDS, Cloud SQL, Azure SQL) to detect
sensitive data using read-only column sampling queries.
"""

from __future__ import annotations

import logging
import uuid
from abc import abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterator

from stance.dspm.extended.base import (
    BaseExtendedScanner,
    ExtendedSourceType,
    ExtendedScanConfig,
    ExtendedScanResult,
    ExtendedScanFinding,
    ExtendedScanSummary,
)
from stance.dspm.scanners.base import FindingSeverity

logger = logging.getLogger(__name__)


class DatabaseType(Enum):
    """Supported database types."""

    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    MARIADB = "mariadb"


@dataclass
class DatabaseConfig:
    """
    Configuration for database connection.

    Attributes:
        host: Database host
        port: Database port
        database: Database name
        user: Username
        password: Password
        db_type: Database type
        ssl_mode: SSL mode (disable, require, verify-ca, verify-full)
        ssl_ca: Path to CA certificate
        connect_timeout: Connection timeout in seconds
    """

    host: str
    port: int
    database: str
    user: str
    password: str
    db_type: DatabaseType = DatabaseType.POSTGRESQL
    ssl_mode: str = "prefer"
    ssl_ca: str | None = None
    connect_timeout: int = 30

    @property
    def port_default(self) -> int:
        """Get default port for database type."""
        defaults = {
            DatabaseType.POSTGRESQL: 5432,
            DatabaseType.MYSQL: 3306,
            DatabaseType.MSSQL: 1433,
            DatabaseType.ORACLE: 1521,
            DatabaseType.MARIADB: 3306,
        }
        return defaults.get(self.db_type, 5432)


@dataclass
class ColumnInfo:
    """
    Information about a database column.

    Attributes:
        name: Column name
        data_type: Column data type
        is_nullable: Whether column allows nulls
        max_length: Maximum length for string columns
        is_primary_key: Whether column is part of primary key
        sample_values: Sampled values from column
    """

    name: str
    data_type: str
    is_nullable: bool = True
    max_length: int | None = None
    is_primary_key: bool = False
    sample_values: list[Any] = field(default_factory=list)


@dataclass
class TableInfo:
    """
    Information about a database table.

    Attributes:
        schema: Schema name
        name: Table name
        table_type: Type (TABLE, VIEW)
        row_count: Approximate row count
        columns: List of columns
    """

    schema: str
    name: str
    table_type: str = "TABLE"
    row_count: int = 0
    columns: list[ColumnInfo] = field(default_factory=list)

    @property
    def full_name(self) -> str:
        """Get fully qualified table name."""
        return f"{self.schema}.{self.name}"


class DatabaseScanner(BaseExtendedScanner):
    """
    Base database scanner for sensitive data detection.

    Samples data from database tables and columns to identify
    PII, PCI, PHI, and other sensitive data patterns.

    All operations are read-only using SELECT queries with LIMIT.
    """

    source_type = ExtendedSourceType.RDS

    # Data types that should be scanned for sensitive data
    SCANNABLE_TYPES = {
        # PostgreSQL / MySQL / MariaDB
        "varchar", "char", "text", "name", "bpchar",
        "character varying", "character",
        "json", "jsonb", "xml",
        "integer", "int", "bigint", "smallint", "numeric", "decimal",
        "float", "double", "real", "double precision",
        # MSSQL
        "nvarchar", "nchar", "ntext",
        "varchar", "char", "text",
        "int", "bigint", "smallint", "tinyint",
        "money", "smallmoney",
    }

    # Data types to skip
    SKIP_TYPES = {
        "bytea", "binary", "varbinary", "image", "blob",
        "date", "time", "timestamp", "timestamptz", "datetime", "datetime2",
        "boolean", "bool", "bit",
        "uuid", "uniqueidentifier",
        "geometry", "geography", "point", "polygon",
    }

    def __init__(
        self,
        db_config: DatabaseConfig,
        scan_config: ExtendedScanConfig | None = None,
    ):
        """
        Initialize database scanner.

        Args:
            db_config: Database connection configuration
            scan_config: Optional scan configuration
        """
        super().__init__(scan_config)
        self._db_config = db_config
        self._connection: Any = None

    @abstractmethod
    def _get_connection(self) -> Any:
        """Get database connection."""
        pass

    @abstractmethod
    def _close_connection(self) -> None:
        """Close database connection."""
        pass

    @abstractmethod
    def _list_schemas(self) -> list[str]:
        """List schemas in the database."""
        pass

    @abstractmethod
    def _list_tables(self, schema: str) -> Iterator[TableInfo]:
        """List tables in a schema."""
        pass

    @abstractmethod
    def _get_table_columns(self, schema: str, table: str) -> list[ColumnInfo]:
        """Get columns for a table."""
        pass

    @abstractmethod
    def _sample_column(
        self, cursor: Any, schema: str, table: str, column: str
    ) -> list[Any]:
        """Sample values from a column."""
        pass

    def test_connection(self) -> bool:
        """
        Test connection to the database.

        Returns:
            True if connection successful
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            cursor.close()
            return True
        except Exception as e:
            logger.error(f"Database connection test failed: {type(e).__name__}: {e}")
            return False
        finally:
            self._close_connection()

    def scan(self, target: str) -> ExtendedScanResult:
        """
        Scan a database for sensitive data.

        Args:
            target: Database identifier (used for logging)

        Returns:
            Scan result with findings and summary
        """
        scan_id = str(uuid.uuid4())[:8]
        started_at = datetime.now(timezone.utc)

        logger.info(
            f"Starting database scan: {self._db_config.host}/{self._db_config.database}, "
            f"scan_id={scan_id}"
        )

        result = ExtendedScanResult(
            scan_id=scan_id,
            source_type=self.source_type,
            target=target or f"{self._db_config.host}/{self._db_config.database}",
            config=self._config,
            started_at=started_at,
        )

        summary = ExtendedScanSummary()
        findings: list[ExtendedScanFinding] = []

        try:
            conn = self._get_connection()
            tables_scanned = 0

            # Get schemas to scan
            schemas = self._list_schemas()

            for schema in schemas:
                # Check schema filters
                if schema.lower() in [s.lower() for s in self._config.exclude_schemas]:
                    continue
                if self._config.include_schemas:
                    if schema.lower() not in [s.lower() for s in self._config.include_schemas]:
                        continue

                # Get tables in schema
                for table in self._list_tables(schema):
                    if tables_scanned >= self._config.max_tables:
                        logger.info(f"Reached max tables limit: {self._config.max_tables}")
                        break

                    # Check table filters
                    if not self._should_scan_table(table):
                        summary.total_objects_skipped += 1
                        continue

                    # Scan the table
                    table_findings = self._scan_table(conn, table)
                    findings.extend(table_findings)

                    tables_scanned += 1
                    summary.total_objects_scanned += 1
                    summary.total_rows_sampled += (
                        self._config.sample_rows_per_column * len(table.columns)
                    )

                    # Update counts
                    for finding in table_findings:
                        summary.total_findings += 1
                        sev = finding.severity.value
                        summary.findings_by_severity[sev] = (
                            summary.findings_by_severity.get(sev, 0) + 1
                        )
                        for cat in finding.categories:
                            cat_val = cat.value
                            summary.findings_by_category[cat_val] = (
                                summary.findings_by_category.get(cat_val, 0) + 1
                            )

                if tables_scanned >= self._config.max_tables:
                    break

        except Exception as e:
            error_msg = f"Database error: {type(e).__name__}: {str(e)}"
            summary.errors.append(error_msg)
            logger.error(error_msg)
        finally:
            self._close_connection()

        # Finalize result
        completed_at = datetime.now(timezone.utc)
        summary.scan_duration_seconds = (completed_at - started_at).total_seconds()

        result.findings = findings
        result.summary = summary
        result.completed_at = completed_at

        logger.info(
            f"Database scan complete: {summary.total_objects_scanned} tables, "
            f"{summary.total_findings} findings, "
            f"{summary.scan_duration_seconds:.2f}s"
        )

        return result

    def list_scannable_objects(self, target: str) -> list[dict[str, Any]]:
        """
        List tables that can be scanned.

        Args:
            target: Database identifier (unused, for interface compliance)

        Returns:
            List of table metadata dictionaries
        """
        tables: list[dict[str, Any]] = []

        try:
            self._get_connection()
            schemas = self._list_schemas()

            for schema in schemas:
                if schema.lower() in [s.lower() for s in self._config.exclude_schemas]:
                    continue

                for table in self._list_tables(schema):
                    tables.append({
                        "schema": table.schema,
                        "name": table.name,
                        "full_name": table.full_name,
                        "table_type": table.table_type,
                        "row_count": table.row_count,
                        "column_count": len(table.columns),
                    })

        finally:
            self._close_connection()

        return tables

    def _should_scan_table(self, table: TableInfo) -> bool:
        """Check if table should be scanned."""
        if table.name.lower() in [t.lower() for t in self._config.exclude_tables]:
            return False

        if self._config.include_tables:
            if table.name.lower() not in [t.lower() for t in self._config.include_tables]:
                return False

        return True

    def _should_scan_column(self, column: ColumnInfo) -> bool:
        """Check if column should be scanned."""
        col_type = column.data_type.lower()

        # Skip known non-text types
        if col_type in self.SKIP_TYPES:
            return False

        # Scan known text types
        if col_type in self.SCANNABLE_TYPES:
            return True

        # Check for partial matches
        if any(t in col_type for t in ["char", "text", "varchar", "string"]):
            return True

        return False

    def _scan_table(
        self, conn: Any, table: TableInfo
    ) -> list[ExtendedScanFinding]:
        """
        Scan a table for sensitive data.

        Args:
            conn: Database connection
            table: Table information

        Returns:
            List of findings for the table
        """
        findings: list[ExtendedScanFinding] = []
        cursor = conn.cursor()

        try:
            # Get columns and filter to scannable
            columns = self._get_table_columns(table.schema, table.name)
            scannable_columns = [
                c for c in columns if self._should_scan_column(c)
            ][:self._config.max_columns_per_table]

            if not scannable_columns:
                return findings

            for column in scannable_columns:
                # Sample data from column
                sample_values = self._sample_column(
                    cursor, table.schema, table.name, column.name
                )

                if not sample_values:
                    continue

                # Convert to text for scanning
                text_content = "\n".join(
                    str(v) for v in sample_values if v is not None
                )

                if not text_content.strip():
                    continue

                # Scan for sensitive data
                detection_result = self._detector.scan_records(
                    records=[{"content": text_content}],
                    asset_id=f"{self.source_type.value}://{table.full_name}.{column.name}",
                    asset_type="database_column",
                    sample_size=1,
                )

                # Create finding
                finding = self._create_finding_from_detection(
                    source_location=f"{self.source_type.value}://{self._db_config.host}/{self._db_config.database}/{table.full_name}",
                    object_type="column",
                    object_name=f"{table.name}.{column.name}",
                    detection_result=detection_result,
                    metadata={
                        "host": self._db_config.host,
                        "database": self._db_config.database,
                        "schema": table.schema,
                        "table": table.name,
                        "column": column.name,
                        "data_type": column.data_type,
                        "sample_size": len(sample_values),
                    },
                )

                if finding:
                    findings.append(finding)

        except Exception as e:
            logger.warning(f"Error scanning table {table.full_name}: {e}")
        finally:
            cursor.close()

        return findings


class RDSScanner(DatabaseScanner):
    """
    AWS RDS database scanner.

    Supports PostgreSQL and MySQL databases on AWS RDS.
    """

    source_type = ExtendedSourceType.RDS

    def __init__(
        self,
        db_config: DatabaseConfig,
        scan_config: ExtendedScanConfig | None = None,
    ):
        """
        Initialize RDS scanner.

        Args:
            db_config: Database connection configuration
            scan_config: Optional scan configuration
        """
        super().__init__(db_config, scan_config)

        # Import appropriate driver
        if db_config.db_type == DatabaseType.POSTGRESQL:
            try:
                import psycopg2
                self._driver = psycopg2
                self._driver_name = "psycopg2"
            except ImportError:
                raise ImportError(
                    "psycopg2 is required for PostgreSQL. "
                    "Install with: pip install psycopg2-binary"
                )
        elif db_config.db_type in (DatabaseType.MYSQL, DatabaseType.MARIADB):
            try:
                import mysql.connector
                self._driver = mysql.connector
                self._driver_name = "mysql.connector"
            except ImportError:
                raise ImportError(
                    "mysql-connector-python is required for MySQL. "
                    "Install with: pip install mysql-connector-python"
                )
        else:
            raise ValueError(f"Unsupported database type: {db_config.db_type}")

    def _get_connection(self) -> Any:
        """Get database connection."""
        if self._connection is None:
            if self._db_config.db_type == DatabaseType.POSTGRESQL:
                self._connection = self._driver.connect(
                    host=self._db_config.host,
                    port=self._db_config.port,
                    database=self._db_config.database,
                    user=self._db_config.user,
                    password=self._db_config.password,
                    connect_timeout=self._db_config.connect_timeout,
                )
            else:
                self._connection = self._driver.connect(
                    host=self._db_config.host,
                    port=self._db_config.port,
                    database=self._db_config.database,
                    user=self._db_config.user,
                    password=self._db_config.password,
                    connection_timeout=self._db_config.connect_timeout,
                )
        return self._connection

    def _close_connection(self) -> None:
        """Close database connection."""
        if self._connection:
            self._connection.close()
            self._connection = None

    def _list_schemas(self) -> list[str]:
        """List schemas in the database."""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            if self._db_config.db_type == DatabaseType.POSTGRESQL:
                cursor.execute("""
                    SELECT schema_name
                    FROM information_schema.schemata
                    WHERE schema_name NOT IN ('pg_catalog', 'information_schema')
                    ORDER BY schema_name
                """)
            else:
                # MySQL doesn't have schemas like PostgreSQL, use databases
                cursor.execute("""
                    SELECT SCHEMA_NAME
                    FROM information_schema.SCHEMATA
                    WHERE SCHEMA_NAME NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys')
                    ORDER BY SCHEMA_NAME
                """)

            return [row[0] for row in cursor.fetchall()]
        finally:
            cursor.close()

    def _list_tables(self, schema: str) -> Iterator[TableInfo]:
        """List tables in a schema."""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            if self._db_config.db_type == DatabaseType.POSTGRESQL:
                cursor.execute("""
                    SELECT table_name, table_type
                    FROM information_schema.tables
                    WHERE table_schema = %s
                    AND table_type IN ('BASE TABLE', 'VIEW')
                    ORDER BY table_name
                """, (schema,))
            else:
                cursor.execute("""
                    SELECT table_name, table_type
                    FROM information_schema.tables
                    WHERE table_schema = %s
                    AND table_type IN ('BASE TABLE', 'VIEW')
                    ORDER BY table_name
                """, (schema,))

            for row in cursor.fetchall():
                table_name = row[0]
                table_type = row[1]

                columns = self._get_table_columns(schema, table_name)

                yield TableInfo(
                    schema=schema,
                    name=table_name,
                    table_type=table_type,
                    columns=columns,
                )
        finally:
            cursor.close()

    def _get_table_columns(self, schema: str, table: str) -> list[ColumnInfo]:
        """Get columns for a table."""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            if self._db_config.db_type == DatabaseType.POSTGRESQL:
                cursor.execute("""
                    SELECT column_name, data_type, is_nullable, character_maximum_length
                    FROM information_schema.columns
                    WHERE table_schema = %s AND table_name = %s
                    ORDER BY ordinal_position
                """, (schema, table))
            else:
                cursor.execute("""
                    SELECT column_name, data_type, is_nullable, character_maximum_length
                    FROM information_schema.columns
                    WHERE table_schema = %s AND table_name = %s
                    ORDER BY ordinal_position
                """, (schema, table))

            columns = []
            for row in cursor.fetchall():
                columns.append(ColumnInfo(
                    name=row[0],
                    data_type=row[1],
                    is_nullable=row[2] == "YES",
                    max_length=row[3],
                ))

            return columns
        finally:
            cursor.close()

    def _sample_column(
        self, cursor: Any, schema: str, table: str, column: str
    ) -> list[Any]:
        """Sample values from a column."""
        try:
            if self._db_config.db_type == DatabaseType.POSTGRESQL:
                query = f"""
                    SELECT "{column}"
                    FROM "{schema}"."{table}"
                    WHERE "{column}" IS NOT NULL
                    LIMIT {self._config.sample_rows_per_column}
                """
            else:
                query = f"""
                    SELECT `{column}`
                    FROM `{schema}`.`{table}`
                    WHERE `{column}` IS NOT NULL
                    LIMIT {self._config.sample_rows_per_column}
                """

            cursor.execute(query)
            return [row[0] for row in cursor.fetchall()]

        except Exception as e:
            logger.debug(f"Error sampling column {column}: {e}")
            return []


class CloudSQLScanner(DatabaseScanner):
    """
    Google Cloud SQL database scanner.

    Supports PostgreSQL and MySQL databases on Cloud SQL.
    Uses the same implementation as RDSScanner.
    """

    source_type = ExtendedSourceType.CLOUD_SQL

    def __init__(
        self,
        db_config: DatabaseConfig,
        scan_config: ExtendedScanConfig | None = None,
    ):
        """
        Initialize Cloud SQL scanner.

        Args:
            db_config: Database connection configuration
            scan_config: Optional scan configuration
        """
        # Reuse RDS scanner implementation
        super().__init__(db_config, scan_config)

        if db_config.db_type == DatabaseType.POSTGRESQL:
            try:
                import psycopg2
                self._driver = psycopg2
            except ImportError:
                raise ImportError(
                    "psycopg2 is required for PostgreSQL. "
                    "Install with: pip install psycopg2-binary"
                )
        elif db_config.db_type in (DatabaseType.MYSQL, DatabaseType.MARIADB):
            try:
                import mysql.connector
                self._driver = mysql.connector
            except ImportError:
                raise ImportError(
                    "mysql-connector-python is required for MySQL. "
                    "Install with: pip install mysql-connector-python"
                )
        else:
            raise ValueError(f"Unsupported database type: {db_config.db_type}")

    def _get_connection(self) -> Any:
        """Get database connection."""
        if self._connection is None:
            if self._db_config.db_type == DatabaseType.POSTGRESQL:
                self._connection = self._driver.connect(
                    host=self._db_config.host,
                    port=self._db_config.port,
                    database=self._db_config.database,
                    user=self._db_config.user,
                    password=self._db_config.password,
                    connect_timeout=self._db_config.connect_timeout,
                )
            else:
                self._connection = self._driver.connect(
                    host=self._db_config.host,
                    port=self._db_config.port,
                    database=self._db_config.database,
                    user=self._db_config.user,
                    password=self._db_config.password,
                    connection_timeout=self._db_config.connect_timeout,
                )
        return self._connection

    def _close_connection(self) -> None:
        """Close database connection."""
        if self._connection:
            self._connection.close()
            self._connection = None

    def _list_schemas(self) -> list[str]:
        """List schemas in the database."""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            if self._db_config.db_type == DatabaseType.POSTGRESQL:
                cursor.execute("""
                    SELECT schema_name
                    FROM information_schema.schemata
                    WHERE schema_name NOT IN ('pg_catalog', 'information_schema')
                    ORDER BY schema_name
                """)
            else:
                cursor.execute("""
                    SELECT SCHEMA_NAME
                    FROM information_schema.SCHEMATA
                    WHERE SCHEMA_NAME NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys')
                    ORDER BY SCHEMA_NAME
                """)

            return [row[0] for row in cursor.fetchall()]
        finally:
            cursor.close()

    def _list_tables(self, schema: str) -> Iterator[TableInfo]:
        """List tables in a schema."""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT table_name, table_type
                FROM information_schema.tables
                WHERE table_schema = %s
                AND table_type IN ('BASE TABLE', 'VIEW')
                ORDER BY table_name
            """, (schema,))

            for row in cursor.fetchall():
                columns = self._get_table_columns(schema, row[0])
                yield TableInfo(
                    schema=schema,
                    name=row[0],
                    table_type=row[1],
                    columns=columns,
                )
        finally:
            cursor.close()

    def _get_table_columns(self, schema: str, table: str) -> list[ColumnInfo]:
        """Get columns for a table."""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT column_name, data_type, is_nullable, character_maximum_length
                FROM information_schema.columns
                WHERE table_schema = %s AND table_name = %s
                ORDER BY ordinal_position
            """, (schema, table))

            return [
                ColumnInfo(
                    name=row[0],
                    data_type=row[1],
                    is_nullable=row[2] == "YES",
                    max_length=row[3],
                )
                for row in cursor.fetchall()
            ]
        finally:
            cursor.close()

    def _sample_column(
        self, cursor: Any, schema: str, table: str, column: str
    ) -> list[Any]:
        """Sample values from a column."""
        try:
            if self._db_config.db_type == DatabaseType.POSTGRESQL:
                query = f"""
                    SELECT "{column}"
                    FROM "{schema}"."{table}"
                    WHERE "{column}" IS NOT NULL
                    LIMIT {self._config.sample_rows_per_column}
                """
            else:
                query = f"""
                    SELECT `{column}`
                    FROM `{schema}`.`{table}`
                    WHERE `{column}` IS NOT NULL
                    LIMIT {self._config.sample_rows_per_column}
                """

            cursor.execute(query)
            return [row[0] for row in cursor.fetchall()]
        except Exception as e:
            logger.debug(f"Error sampling column {column}: {e}")
            return []


class AzureSQLScanner(DatabaseScanner):
    """
    Azure SQL Database scanner.

    Supports Azure SQL Database and Azure SQL Managed Instance.
    """

    source_type = ExtendedSourceType.AZURE_SQL

    def __init__(
        self,
        db_config: DatabaseConfig,
        scan_config: ExtendedScanConfig | None = None,
    ):
        """
        Initialize Azure SQL scanner.

        Args:
            db_config: Database connection configuration
            scan_config: Optional scan configuration
        """
        super().__init__(db_config, scan_config)

        # Force MSSQL type for Azure SQL
        self._db_config.db_type = DatabaseType.MSSQL

        try:
            import pyodbc
            self._driver = pyodbc
        except ImportError:
            raise ImportError(
                "pyodbc is required for Azure SQL. "
                "Install with: pip install pyodbc"
            )

    def _get_connection(self) -> Any:
        """Get database connection."""
        if self._connection is None:
            connection_string = (
                f"DRIVER={{ODBC Driver 18 for SQL Server}};"
                f"SERVER={self._db_config.host},{self._db_config.port};"
                f"DATABASE={self._db_config.database};"
                f"UID={self._db_config.user};"
                f"PWD={self._db_config.password};"
                f"Encrypt=yes;TrustServerCertificate=no;"
                f"Connection Timeout={self._db_config.connect_timeout}"
            )
            self._connection = self._driver.connect(connection_string)
        return self._connection

    def _close_connection(self) -> None:
        """Close database connection."""
        if self._connection:
            self._connection.close()
            self._connection = None

    def _list_schemas(self) -> list[str]:
        """List schemas in the database."""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT SCHEMA_NAME
                FROM INFORMATION_SCHEMA.SCHEMATA
                WHERE SCHEMA_NAME NOT IN ('sys', 'INFORMATION_SCHEMA', 'guest', 'db_owner', 'db_accessadmin', 'db_securityadmin', 'db_ddladmin', 'db_backupoperator', 'db_datareader', 'db_datawriter', 'db_denydatareader', 'db_denydatawriter')
                ORDER BY SCHEMA_NAME
            """)
            return [row[0] for row in cursor.fetchall()]
        finally:
            cursor.close()

    def _list_tables(self, schema: str) -> Iterator[TableInfo]:
        """List tables in a schema."""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT TABLE_NAME, TABLE_TYPE
                FROM INFORMATION_SCHEMA.TABLES
                WHERE TABLE_SCHEMA = ?
                AND TABLE_TYPE IN ('BASE TABLE', 'VIEW')
                ORDER BY TABLE_NAME
            """, (schema,))

            for row in cursor.fetchall():
                columns = self._get_table_columns(schema, row[0])
                yield TableInfo(
                    schema=schema,
                    name=row[0],
                    table_type=row[1],
                    columns=columns,
                )
        finally:
            cursor.close()

    def _get_table_columns(self, schema: str, table: str) -> list[ColumnInfo]:
        """Get columns for a table."""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, CHARACTER_MAXIMUM_LENGTH
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
                ORDER BY ORDINAL_POSITION
            """, (schema, table))

            return [
                ColumnInfo(
                    name=row[0],
                    data_type=row[1],
                    is_nullable=row[2] == "YES",
                    max_length=row[3],
                )
                for row in cursor.fetchall()
            ]
        finally:
            cursor.close()

    def _sample_column(
        self, cursor: Any, schema: str, table: str, column: str
    ) -> list[Any]:
        """Sample values from a column."""
        try:
            query = f"""
                SELECT TOP {self._config.sample_rows_per_column} [{column}]
                FROM [{schema}].[{table}]
                WHERE [{column}] IS NOT NULL
            """
            cursor.execute(query)
            return [row[0] for row in cursor.fetchall()]
        except Exception as e:
            logger.debug(f"Error sampling column {column}: {e}")
            return []


def scan_database(
    db_config: DatabaseConfig,
    scan_config: ExtendedScanConfig | None = None,
) -> ExtendedScanResult:
    """
    Convenience function to scan a database.

    Automatically selects the appropriate scanner based on database type.

    Args:
        db_config: Database connection configuration
        scan_config: Optional scan configuration

    Returns:
        Scan result with findings
    """
    if db_config.db_type in (DatabaseType.POSTGRESQL, DatabaseType.MYSQL, DatabaseType.MARIADB):
        scanner = RDSScanner(db_config, scan_config)
    elif db_config.db_type == DatabaseType.MSSQL:
        scanner = AzureSQLScanner(db_config, scan_config)
    else:
        raise ValueError(f"Unsupported database type: {db_config.db_type}")

    return scanner.scan(f"{db_config.host}/{db_config.database}")
