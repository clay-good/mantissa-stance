"""
Snowflake Data Scanner for DSPM.

Scans Snowflake data warehouses to detect sensitive data using
read-only column sampling queries.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
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

# Import snowflake connector optionally
try:
    import snowflake.connector
    from snowflake.connector import SnowflakeConnection
    from snowflake.connector.errors import Error as SnowflakeError

    SNOWFLAKE_AVAILABLE = True
except ImportError:
    SNOWFLAKE_AVAILABLE = False
    snowflake = None  # type: ignore
    SnowflakeConnection = Any  # type: ignore
    SnowflakeError = Exception  # type: ignore


@dataclass
class SnowflakeConfig:
    """
    Configuration for Snowflake connection.

    Attributes:
        account: Snowflake account identifier
        user: Username for authentication
        password: Password (use key_path for key-pair auth)
        warehouse: Warehouse to use for queries
        database: Default database
        schema: Default schema
        role: Role to use
        key_path: Path to private key file (for key-pair auth)
        key_passphrase: Passphrase for private key
        authenticator: Authentication method (snowflake, externalbrowser, etc.)
    """

    account: str
    user: str
    password: str | None = None
    warehouse: str = "COMPUTE_WH"
    database: str | None = None
    schema: str | None = None
    role: str | None = None
    key_path: str | None = None
    key_passphrase: str | None = None
    authenticator: str = "snowflake"

    def to_connection_params(self) -> dict[str, Any]:
        """Convert to snowflake connector parameters."""
        params: dict[str, Any] = {
            "account": self.account,
            "user": self.user,
            "warehouse": self.warehouse,
            "authenticator": self.authenticator,
        }

        if self.password:
            params["password"] = self.password
        if self.database:
            params["database"] = self.database
        if self.schema:
            params["schema"] = self.schema
        if self.role:
            params["role"] = self.role

        # Handle key-pair authentication
        if self.key_path:
            params["private_key_path"] = self.key_path
            if self.key_passphrase:
                params["private_key_file_pwd"] = self.key_passphrase

        return params


@dataclass
class SnowflakeColumnInfo:
    """
    Information about a Snowflake column.

    Attributes:
        name: Column name
        data_type: Column data type
        is_nullable: Whether column allows nulls
        comment: Column comment
        sample_values: Sampled values from column
    """

    name: str
    data_type: str
    is_nullable: bool = True
    comment: str | None = None
    sample_values: list[Any] = field(default_factory=list)


@dataclass
class SnowflakeTableInfo:
    """
    Information about a Snowflake table.

    Attributes:
        database: Database name
        schema: Schema name
        name: Table name
        table_type: Type (TABLE, VIEW, etc.)
        row_count: Approximate row count
        bytes: Table size in bytes
        columns: List of columns
        comment: Table comment
    """

    database: str
    schema: str
    name: str
    table_type: str = "TABLE"
    row_count: int = 0
    bytes: int = 0
    columns: list[SnowflakeColumnInfo] = field(default_factory=list)
    comment: str | None = None

    @property
    def full_name(self) -> str:
        """Get fully qualified table name."""
        return f"{self.database}.{self.schema}.{self.name}"


class SnowflakeScanner(BaseExtendedScanner):
    """
    Snowflake data warehouse scanner for sensitive data detection.

    Samples data from Snowflake tables and columns to identify
    PII, PCI, PHI, and other sensitive data patterns.

    All operations are read-only using SELECT queries with LIMIT.
    """

    source_type = ExtendedSourceType.SNOWFLAKE

    # Data types that should be scanned for sensitive data
    SCANNABLE_TYPES = {
        "VARCHAR", "CHAR", "STRING", "TEXT",
        "VARIANT", "OBJECT", "ARRAY",
        "NUMBER", "FLOAT", "DOUBLE", "DECIMAL",
    }

    # Data types to skip (binary, timestamps, etc.)
    SKIP_TYPES = {
        "BINARY", "VARBINARY",
        "DATE", "TIME", "TIMESTAMP", "TIMESTAMP_LTZ", "TIMESTAMP_NTZ", "TIMESTAMP_TZ",
        "BOOLEAN",
        "GEOGRAPHY", "GEOMETRY",
    }

    def __init__(
        self,
        snowflake_config: SnowflakeConfig,
        scan_config: ExtendedScanConfig | None = None,
    ):
        """
        Initialize Snowflake scanner.

        Args:
            snowflake_config: Snowflake connection configuration
            scan_config: Optional scan configuration
        """
        super().__init__(scan_config)

        if not SNOWFLAKE_AVAILABLE:
            raise ImportError(
                "snowflake-connector-python is required. "
                "Install with: pip install snowflake-connector-python"
            )

        self._sf_config = snowflake_config
        self._connection: SnowflakeConnection | None = None

    def _get_connection(self) -> SnowflakeConnection:
        """Get or create Snowflake connection."""
        if self._connection is None or self._connection.is_closed():
            self._connection = snowflake.connector.connect(
                **self._sf_config.to_connection_params()
            )
        return self._connection

    def _close_connection(self) -> None:
        """Close Snowflake connection."""
        if self._connection and not self._connection.is_closed():
            self._connection.close()
            self._connection = None

    def test_connection(self) -> bool:
        """
        Test connection to Snowflake.

        Returns:
            True if connection successful
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT CURRENT_VERSION()")
            cursor.fetchone()
            cursor.close()
            return True
        except SnowflakeError as e:
            logger.error(f"Snowflake connection test failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Connection test failed: {type(e).__name__}: {e}")
            return False

    def scan(self, target: str) -> ExtendedScanResult:
        """
        Scan a Snowflake database for sensitive data.

        Args:
            target: Database name to scan

        Returns:
            Scan result with findings and summary
        """
        scan_id = str(uuid.uuid4())[:8]
        started_at = datetime.now(timezone.utc)

        logger.info(f"Starting Snowflake scan: database={target}, scan_id={scan_id}")

        result = ExtendedScanResult(
            scan_id=scan_id,
            source_type=self.source_type,
            target=target,
            config=self._config,
            started_at=started_at,
        )

        summary = ExtendedScanSummary()
        findings: list[ExtendedScanFinding] = []

        try:
            conn = self._get_connection()

            # Get tables to scan
            tables = list(self._list_tables(conn, target))
            tables_scanned = 0

            for table in tables:
                if tables_scanned >= self._config.max_tables:
                    logger.info(f"Reached max tables limit: {self._config.max_tables}")
                    break

                # Check schema filters
                if not self._should_scan_table(table):
                    summary.total_objects_skipped += 1
                    continue

                # Scan the table
                table_findings = self._scan_table(conn, table)
                findings.extend(table_findings)

                tables_scanned += 1
                summary.total_objects_scanned += 1
                summary.total_rows_sampled += self._config.sample_rows_per_column * len(table.columns)

                # Update severity and category counts
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

        except SnowflakeError as e:
            error_msg = f"Snowflake error: {str(e)}"
            summary.errors.append(error_msg)
            logger.error(error_msg)
        except Exception as e:
            error_msg = f"Scan error: {type(e).__name__}: {str(e)}"
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
            f"Snowflake scan complete: {summary.total_objects_scanned} tables, "
            f"{summary.total_findings} findings, "
            f"{summary.scan_duration_seconds:.2f}s"
        )

        return result

    def list_scannable_objects(self, target: str) -> list[dict[str, Any]]:
        """
        List tables that can be scanned in the database.

        Args:
            target: Database name

        Returns:
            List of table metadata dictionaries
        """
        try:
            conn = self._get_connection()
            tables = list(self._list_tables(conn, target))
            return [
                {
                    "database": t.database,
                    "schema": t.schema,
                    "name": t.name,
                    "full_name": t.full_name,
                    "table_type": t.table_type,
                    "row_count": t.row_count,
                    "bytes": t.bytes,
                    "column_count": len(t.columns),
                }
                for t in tables
            ]
        finally:
            self._close_connection()

    def _list_tables(
        self, conn: SnowflakeConnection, database: str
    ) -> Iterator[SnowflakeTableInfo]:
        """
        List tables in a database.

        Args:
            conn: Snowflake connection
            database: Database name

        Yields:
            SnowflakeTableInfo for each table
        """
        cursor = conn.cursor()

        try:
            # Get all schemas in the database
            cursor.execute(f"SHOW SCHEMAS IN DATABASE {database}")
            schemas = [row[1] for row in cursor.fetchall()]

            for schema in schemas:
                # Skip excluded schemas
                if schema.lower() in [s.lower() for s in self._config.exclude_schemas]:
                    continue

                # Check include filter
                if self._config.include_schemas:
                    if schema.lower() not in [s.lower() for s in self._config.include_schemas]:
                        continue

                # Get tables in schema
                cursor.execute(f"SHOW TABLES IN {database}.{schema}")
                tables = cursor.fetchall()

                for row in tables:
                    table_name = row[1]
                    table_type = row[4] if len(row) > 4 else "TABLE"
                    row_count = row[5] if len(row) > 5 else 0
                    table_bytes = row[6] if len(row) > 6 else 0
                    comment = row[7] if len(row) > 7 else None

                    # Get columns for the table
                    columns = list(self._get_table_columns(conn, database, schema, table_name))

                    yield SnowflakeTableInfo(
                        database=database,
                        schema=schema,
                        name=table_name,
                        table_type=table_type,
                        row_count=row_count,
                        bytes=table_bytes,
                        columns=columns,
                        comment=comment,
                    )

        finally:
            cursor.close()

    def _get_table_columns(
        self,
        conn: SnowflakeConnection,
        database: str,
        schema: str,
        table: str,
    ) -> Iterator[SnowflakeColumnInfo]:
        """
        Get columns for a table.

        Args:
            conn: Snowflake connection
            database: Database name
            schema: Schema name
            table: Table name

        Yields:
            SnowflakeColumnInfo for each column
        """
        cursor = conn.cursor()

        try:
            cursor.execute(f"DESCRIBE TABLE {database}.{schema}.{table}")
            columns = cursor.fetchall()

            for row in columns:
                col_name = row[0]
                col_type = row[1].upper().split("(")[0]  # Remove size spec
                is_nullable = row[3] == "Y" if len(row) > 3 else True
                comment = row[8] if len(row) > 8 else None

                yield SnowflakeColumnInfo(
                    name=col_name,
                    data_type=col_type,
                    is_nullable=is_nullable,
                    comment=comment,
                )

        finally:
            cursor.close()

    def _should_scan_table(self, table: SnowflakeTableInfo) -> bool:
        """Check if table should be scanned based on filters."""
        # Check exclude tables
        if table.name.lower() in [t.lower() for t in self._config.exclude_tables]:
            return False

        # Check include tables
        if self._config.include_tables:
            if table.name.lower() not in [t.lower() for t in self._config.include_tables]:
                return False

        return True

    def _should_scan_column(self, column: SnowflakeColumnInfo) -> bool:
        """Check if column should be scanned based on data type."""
        # Skip known non-text types
        if column.data_type in self.SKIP_TYPES:
            return False

        # Scan known text types
        if column.data_type in self.SCANNABLE_TYPES:
            return True

        # Default: scan if it looks like text
        return "CHAR" in column.data_type or "TEXT" in column.data_type

    def _scan_table(
        self, conn: SnowflakeConnection, table: SnowflakeTableInfo
    ) -> list[ExtendedScanFinding]:
        """
        Scan a table for sensitive data.

        Args:
            conn: Snowflake connection
            table: Table information

        Returns:
            List of findings for the table
        """
        findings: list[ExtendedScanFinding] = []
        cursor = conn.cursor()

        try:
            # Filter to scannable columns
            scannable_columns = [
                c for c in table.columns if self._should_scan_column(c)
            ][:self._config.max_columns_per_table]

            if not scannable_columns:
                return findings

            for column in scannable_columns:
                # Sample data from column
                sample_values = self._sample_column(
                    cursor, table, column
                )

                if not sample_values:
                    continue

                # Convert to text for scanning
                text_content = "\n".join(str(v) for v in sample_values if v is not None)

                if not text_content.strip():
                    continue

                # Scan for sensitive data
                detection_result = self._detector.scan_records(
                    records=[{"content": text_content}],
                    asset_id=f"snowflake://{table.full_name}.{column.name}",
                    asset_type="snowflake_column",
                    sample_size=1,
                )

                # Create finding if sensitive data found
                finding = self._create_finding_from_detection(
                    source_location=f"snowflake://{table.full_name}",
                    object_type="column",
                    object_name=f"{table.name}.{column.name}",
                    detection_result=detection_result,
                    metadata={
                        "database": table.database,
                        "schema": table.schema,
                        "table": table.name,
                        "column": column.name,
                        "data_type": column.data_type,
                        "table_row_count": table.row_count,
                        "sample_size": len(sample_values),
                    },
                )

                if finding:
                    findings.append(finding)

        except SnowflakeError as e:
            logger.warning(f"Error scanning table {table.full_name}: {e}")
        finally:
            cursor.close()

        return findings

    def _sample_column(
        self,
        cursor: Any,
        table: SnowflakeTableInfo,
        column: SnowflakeColumnInfo,
    ) -> list[Any]:
        """
        Sample values from a column.

        Args:
            cursor: Database cursor
            table: Table information
            column: Column information

        Returns:
            List of sampled values
        """
        try:
            # Use SAMPLE for random sampling, with LIMIT as fallback
            query = f"""
                SELECT "{column.name}"
                FROM {table.full_name}
                WHERE "{column.name}" IS NOT NULL
                LIMIT {self._config.sample_rows_per_column}
            """

            cursor.execute(query)
            rows = cursor.fetchall()
            return [row[0] for row in rows]

        except SnowflakeError as e:
            logger.debug(f"Error sampling column {column.name}: {e}")
            return []

    def scan_table(self, database: str, schema: str, table_name: str) -> ExtendedScanResult:
        """
        Scan a specific table for sensitive data.

        Args:
            database: Database name
            schema: Schema name
            table_name: Table name

        Returns:
            Scan result with findings
        """
        scan_id = str(uuid.uuid4())[:8]
        started_at = datetime.now(timezone.utc)

        result = ExtendedScanResult(
            scan_id=scan_id,
            source_type=self.source_type,
            target=f"{database}.{schema}.{table_name}",
            config=self._config,
            started_at=started_at,
        )

        summary = ExtendedScanSummary()
        findings: list[ExtendedScanFinding] = []

        try:
            conn = self._get_connection()

            # Get table info
            columns = list(self._get_table_columns(conn, database, schema, table_name))
            table = SnowflakeTableInfo(
                database=database,
                schema=schema,
                name=table_name,
                columns=columns,
            )

            # Scan the table
            findings = self._scan_table(conn, table)
            summary.total_objects_scanned = 1
            summary.total_rows_sampled = self._config.sample_rows_per_column * len(columns)

            # Update counts
            for finding in findings:
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

        except SnowflakeError as e:
            summary.errors.append(f"Snowflake error: {str(e)}")
        finally:
            self._close_connection()

        completed_at = datetime.now(timezone.utc)
        summary.scan_duration_seconds = (completed_at - started_at).total_seconds()

        result.findings = findings
        result.summary = summary
        result.completed_at = completed_at

        return result


def scan_snowflake(
    snowflake_config: SnowflakeConfig,
    database: str,
    scan_config: ExtendedScanConfig | None = None,
) -> ExtendedScanResult:
    """
    Convenience function to scan a Snowflake database.

    Args:
        snowflake_config: Snowflake connection configuration
        database: Database name to scan
        scan_config: Optional scan configuration

    Returns:
        Scan result with findings
    """
    scanner = SnowflakeScanner(snowflake_config, scan_config)
    return scanner.scan(database)
