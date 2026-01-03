"""
Base query engine for Mantissa Stance.

Provides abstract interface for cloud-native query engines (Athena, BigQuery, Synapse).
All implementations are read-only and support only SELECT queries.
"""

from __future__ import annotations

import re
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class QueryResult:
    """
    Result from a query execution.

    Attributes:
        rows: List of result rows as dictionaries
        columns: List of column names
        row_count: Number of rows returned
        bytes_scanned: Bytes scanned (for cost tracking)
        execution_time_ms: Query execution time in milliseconds
        query_id: Unique identifier for the query execution
        metadata: Additional provider-specific metadata
    """

    rows: list[dict[str, Any]]
    columns: list[str]
    row_count: int
    bytes_scanned: int = 0
    execution_time_ms: int = 0
    query_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_list(self) -> list[dict[str, Any]]:
        """Return rows as list of dictionaries."""
        return self.rows

    def to_dict(self) -> dict[str, Any]:
        """Return full result as dictionary."""
        return {
            "rows": self.rows,
            "columns": self.columns,
            "row_count": self.row_count,
            "bytes_scanned": self.bytes_scanned,
            "execution_time_ms": self.execution_time_ms,
            "query_id": self.query_id,
            "metadata": self.metadata,
        }


@dataclass
class TableSchema:
    """
    Schema information for a table.

    Attributes:
        table_name: Name of the table
        columns: List of column definitions
        description: Table description
        row_count: Estimated row count (if available)
        size_bytes: Estimated size in bytes (if available)
    """

    table_name: str
    columns: list[dict[str, Any]]
    description: str = ""
    row_count: int | None = None
    size_bytes: int | None = None

    def get_column_names(self) -> list[str]:
        """Get list of column names."""
        return [col.get("name", "") for col in self.columns]

    def get_column_types(self) -> dict[str, str]:
        """Get mapping of column names to types."""
        return {col.get("name", ""): col.get("type", "") for col in self.columns}


@dataclass
class CostEstimate:
    """
    Estimated cost for a query.

    Attributes:
        estimated_bytes: Estimated bytes to be scanned
        estimated_cost_usd: Estimated cost in USD
        warnings: List of warnings about the query
    """

    estimated_bytes: int = 0
    estimated_cost_usd: float = 0.0
    warnings: list[str] = field(default_factory=list)


class QueryValidationError(Exception):
    """Raised when a query fails validation."""

    pass


class QueryExecutionError(Exception):
    """Raised when a query fails execution."""

    pass


class QueryEngine(ABC):
    """
    Abstract base class for cloud-native query engines.

    All implementations must be read-only and support only SELECT queries.
    This provides a unified interface for querying assets and findings
    stored in cloud-native data warehouses.
    """

    # SQL keywords that are forbidden (write operations)
    FORBIDDEN_KEYWORDS = [
        "INSERT",
        "UPDATE",
        "DELETE",
        "DROP",
        "CREATE",
        "ALTER",
        "TRUNCATE",
        "REPLACE",
        "MERGE",
        "GRANT",
        "REVOKE",
        "EXECUTE",
        "EXEC",
    ]

    # Pattern to detect SQL comments that might hide malicious code
    COMMENT_PATTERN = re.compile(r"(--|/\*|\*/|#)")

    def __init__(self) -> None:
        """Initialize the query engine."""
        self._connected = False

    @property
    @abstractmethod
    def engine_name(self) -> str:
        """Return the name of this query engine."""
        pass

    @property
    @abstractmethod
    def provider(self) -> str:
        """Return the cloud provider (aws, gcp, azure)."""
        pass

    @abstractmethod
    def connect(self) -> None:
        """
        Establish connection to the query engine.

        Raises:
            QueryExecutionError: If connection fails
        """
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """Close connection to the query engine."""
        pass

    @abstractmethod
    def execute_query(
        self,
        sql: str,
        parameters: dict[str, Any] | None = None,
        timeout_seconds: int = 300,
    ) -> QueryResult:
        """
        Execute a SQL query and return results.

        Args:
            sql: SQL query to execute (must be SELECT only)
            parameters: Optional query parameters for parameterized queries
            timeout_seconds: Maximum time to wait for query completion

        Returns:
            QueryResult with rows and metadata

        Raises:
            QueryValidationError: If query is not valid (e.g., not SELECT)
            QueryExecutionError: If query execution fails
        """
        pass

    @abstractmethod
    def get_table_schema(self, table_name: str) -> TableSchema:
        """
        Get schema information for a table.

        Args:
            table_name: Name of the table

        Returns:
            TableSchema with column definitions

        Raises:
            QueryExecutionError: If table does not exist
        """
        pass

    @abstractmethod
    def list_tables(self) -> list[str]:
        """
        List all available tables.

        Returns:
            List of table names
        """
        pass

    @abstractmethod
    def estimate_cost(self, sql: str) -> CostEstimate:
        """
        Estimate the cost of a query before execution.

        Args:
            sql: SQL query to estimate

        Returns:
            CostEstimate with bytes and cost estimation
        """
        pass

    def validate_query(self, sql: str) -> list[str]:
        """
        Validate that a query is safe to execute.

        Checks:
        - Query starts with SELECT
        - No forbidden keywords (INSERT, UPDATE, DELETE, etc.)
        - No SQL comments that could hide malicious code
        - No multiple statements (semicolons)

        Args:
            sql: SQL query to validate

        Returns:
            List of validation errors (empty if valid)
        """
        errors: list[str] = []
        sql_upper = sql.upper().strip()

        # Must start with SELECT or WITH (for CTEs)
        if not sql_upper.startswith("SELECT") and not sql_upper.startswith("WITH"):
            errors.append("Query must start with SELECT or WITH")

        # Check for forbidden keywords
        for keyword in self.FORBIDDEN_KEYWORDS:
            # Use word boundary to avoid false positives
            pattern = rf"\b{keyword}\b"
            if re.search(pattern, sql_upper):
                errors.append(f"Forbidden keyword detected: {keyword}")

        # Check for SQL comments
        if self.COMMENT_PATTERN.search(sql):
            errors.append("SQL comments are not allowed")

        # Check for multiple statements
        # Remove string literals first to avoid false positives
        sql_no_strings = re.sub(r"'[^']*'", "", sql)
        sql_no_strings = re.sub(r'"[^"]*"', "", sql_no_strings)
        if ";" in sql_no_strings:
            errors.append("Multiple statements are not allowed")

        return errors

    def execute_safe(
        self,
        sql: str,
        parameters: dict[str, Any] | None = None,
        timeout_seconds: int = 300,
    ) -> QueryResult:
        """
        Execute a query with validation.

        This is the recommended method for executing queries as it
        validates the query before execution.

        Args:
            sql: SQL query to execute
            parameters: Optional query parameters
            timeout_seconds: Maximum time to wait

        Returns:
            QueryResult with rows and metadata

        Raises:
            QueryValidationError: If query fails validation
            QueryExecutionError: If query execution fails
        """
        errors = self.validate_query(sql)
        if errors:
            raise QueryValidationError(f"Query validation failed: {'; '.join(errors)}")

        return self.execute_query(sql, parameters, timeout_seconds)

    def is_connected(self) -> bool:
        """Check if the engine is connected."""
        return self._connected

    def __enter__(self) -> "QueryEngine":
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        self.disconnect()


# Common table schemas for Stance data
ASSETS_SCHEMA = TableSchema(
    table_name="assets",
    description="Cloud resource inventory from all collectors",
    columns=[
        {"name": "id", "type": "STRING", "description": "Unique resource identifier (ARN/ID)"},
        {"name": "cloud_provider", "type": "STRING", "description": "Cloud provider (aws, gcp, azure)"},
        {"name": "account_id", "type": "STRING", "description": "Cloud account/project/subscription ID"},
        {"name": "region", "type": "STRING", "description": "Geographic region"},
        {"name": "resource_type", "type": "STRING", "description": "Resource type (e.g., aws_s3_bucket)"},
        {"name": "name", "type": "STRING", "description": "Resource name"},
        {"name": "tags", "type": "JSON", "description": "Resource tags as JSON"},
        {"name": "network_exposure", "type": "STRING", "description": "Network exposure level"},
        {"name": "created_at", "type": "TIMESTAMP", "description": "Resource creation time"},
        {"name": "last_seen", "type": "TIMESTAMP", "description": "Last scan time"},
        {"name": "raw_config", "type": "JSON", "description": "Full resource configuration"},
        {"name": "snapshot_id", "type": "STRING", "description": "Scan snapshot identifier"},
    ],
)

FINDINGS_SCHEMA = TableSchema(
    table_name="findings",
    description="Security findings from policy evaluations and security services",
    columns=[
        {"name": "id", "type": "STRING", "description": "Unique finding identifier"},
        {"name": "asset_id", "type": "STRING", "description": "Related asset ID"},
        {"name": "finding_type", "type": "STRING", "description": "Finding type (misconfiguration, vulnerability)"},
        {"name": "severity", "type": "STRING", "description": "Severity level (critical, high, medium, low, info)"},
        {"name": "status", "type": "STRING", "description": "Finding status (open, resolved, suppressed)"},
        {"name": "title", "type": "STRING", "description": "Finding title"},
        {"name": "description", "type": "STRING", "description": "Detailed description"},
        {"name": "rule_id", "type": "STRING", "description": "Policy rule identifier"},
        {"name": "cve_id", "type": "STRING", "description": "CVE identifier (for vulnerabilities)"},
        {"name": "cvss_score", "type": "FLOAT", "description": "CVSS score (for vulnerabilities)"},
        {"name": "compliance_frameworks", "type": "JSON", "description": "Compliance framework mappings"},
        {"name": "remediation_guidance", "type": "STRING", "description": "Remediation steps"},
        {"name": "first_seen", "type": "TIMESTAMP", "description": "First detection time"},
        {"name": "last_seen", "type": "TIMESTAMP", "description": "Last seen time"},
        {"name": "snapshot_id", "type": "STRING", "description": "Scan snapshot identifier"},
    ],
)


def get_common_schemas() -> dict[str, TableSchema]:
    """Get common table schemas for Stance data."""
    return {
        "assets": ASSETS_SCHEMA,
        "findings": FINDINGS_SCHEMA,
    }
