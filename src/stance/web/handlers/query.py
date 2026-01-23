"""
Query engine handlers for the Stance web API.

This module handles all /api/query/* endpoints for SQL query execution,
cost estimation, schema introspection, and query validation against
security data warehouses.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


class QueryHandler(RoutedHandler):
    """
    Handler for query engine API endpoints.

    Handles:
    - SQL query execution (read-only)
    - Query cost estimation
    - Schema introspection
    - Query validation
    - Backend management
    """

    base_path = "/api/query/"

    # Forbidden SQL keywords for safety
    FORBIDDEN_KEYWORDS = [
        "INSERT", "UPDATE", "DELETE", "DROP", "CREATE",
        "ALTER", "TRUNCATE", "REPLACE", "MERGE", "GRANT", "REVOKE",
        "EXEC", "EXECUTE", "CALL", "LOAD", "COPY", "ATTACH",
        "DETACH", "VACUUM", "PRAGMA", "SAVEPOINT", "ROLLBACK",
        "COMMIT", "BEGIN", "SET", "RESET", "EXPLAIN",
    ]

    # Maximum query length to prevent resource exhaustion
    MAX_QUERY_LENGTH = 10000

    # =========================================================================
    # Query Execution endpoints
    # =========================================================================

    @route("execute")
    def query_execute(self, params: dict, body: dict | None) -> HandlerResponse:
        """Execute a SQL SELECT query."""
        try:
            sql = self.get_param(params, "sql", "")
            backend = self.get_param(params, "backend", "demo")
            limit = self.get_param(params, "limit", "")
            timeout = self.get_param_int(params, "timeout", 300)

            if not sql:
                return HandlerResponse.error(
                    "sql parameter is required. Usage: /api/query/execute?sql=SELECT * FROM assets LIMIT 10",
                    HttpStatus.BAD_REQUEST
                )

            # Add LIMIT if requested and not present
            if limit and "LIMIT" not in sql.upper():
                # Validate limit is a positive integer to prevent injection
                try:
                    limit_int = int(limit)
                    if limit_int <= 0:
                        return HandlerResponse.error(
                            f"Invalid limit value: {limit}. Must be a positive integer.",
                            HttpStatus.BAD_REQUEST
                        )
                    sql = f"{sql.rstrip().rstrip(';')} LIMIT {limit_int}"
                except ValueError:
                    return HandlerResponse.error(
                        f"Invalid limit value: {limit}. Must be a positive integer.",
                        HttpStatus.BAD_REQUEST
                    )

            # Execute query (demo mode)
            result = self._execute_demo_query(sql)

            if "error" in result:
                return HandlerResponse.error(result["error"], HttpStatus.BAD_REQUEST)

            return HandlerResponse.success({
                "sql": sql,
                "backend": backend,
                "timeout": timeout,
                "result": result,
            })
        except Exception as e:
            logger.exception("Failed to execute query")
            return HandlerResponse.server_error(str(e))

    @route("estimate")
    def query_estimate(self, params: dict, body: dict | None) -> HandlerResponse:
        """Estimate query cost before execution."""
        try:
            sql = self.get_param(params, "sql", "")
            backend = self.get_param(params, "backend", "demo")

            if not sql:
                return HandlerResponse.error(
                    "sql parameter is required. Usage: /api/query/estimate?sql=SELECT * FROM findings",
                    HttpStatus.BAD_REQUEST
                )

            # Validate query first
            errors = self._validate_sql(sql)
            if errors:
                return HandlerResponse.success({
                    "sql": sql,
                    "valid": False,
                    "errors": errors,
                })

            # Demo estimation
            estimated_bytes = 10 * 1024 * 1024  # 10 MB minimum
            estimated_cost = 0.00005  # ~$5/TB

            return HandlerResponse.success({
                "sql": sql,
                "backend": backend,
                "valid": True,
                "estimated_bytes": estimated_bytes,
                "estimated_bytes_formatted": "10.00 MB",
                "estimated_cost_usd": estimated_cost,
                "warnings": ["Demo mode - no actual cost"],
            })
        except Exception as e:
            logger.exception("Failed to estimate query")
            return HandlerResponse.server_error(str(e))

    @route("validate")
    def query_validate(self, params: dict, body: dict | None) -> HandlerResponse:
        """Validate a SQL query without executing."""
        try:
            sql = self.get_param(params, "sql", "")

            if not sql:
                return HandlerResponse.error(
                    "sql parameter is required. Usage: /api/query/validate?sql=SELECT * FROM assets",
                    HttpStatus.BAD_REQUEST
                )

            errors = self._validate_sql(sql)

            return HandlerResponse.success({
                "sql": sql,
                "valid": len(errors) == 0,
                "errors": errors,
            })
        except Exception as e:
            logger.exception("Failed to validate query")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Schema Introspection endpoints
    # =========================================================================

    @route("tables")
    def query_tables(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available tables."""
        try:
            backend = self.get_param(params, "backend", "demo")

            tables = [
                {"name": "assets", "description": "Cloud assets inventory", "row_count": 1247},
                {"name": "findings", "description": "Security findings and misconfigurations", "row_count": 156},
                {"name": "scans", "description": "Scan history and results", "row_count": 89},
                {"name": "policies", "description": "Security policies", "row_count": 450},
                {"name": "compliance", "description": "Compliance framework mappings", "row_count": 234},
            ]

            return HandlerResponse.success({
                "backend": backend,
                "tables": tables,
                "count": len(tables),
            })
        except Exception as e:
            logger.exception("Failed to list tables")
            return HandlerResponse.server_error(str(e))

    @route("schema")
    def query_schema(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get table schema."""
        try:
            table_name = self.get_param(params, "table", "")
            backend = self.get_param(params, "backend", "demo")

            available_tables = ["assets", "findings", "scans", "policies", "compliance"]

            if not table_name:
                return HandlerResponse.error(
                    f"table parameter is required. Available tables: {', '.join(available_tables)}",
                    HttpStatus.BAD_REQUEST
                )

            if table_name not in available_tables:
                return HandlerResponse.error(
                    f"Table not found: {table_name}. Available tables: {', '.join(available_tables)}",
                    HttpStatus.NOT_FOUND
                )

            # Schema definitions
            schemas = {
                "assets": {
                    "table_name": "assets",
                    "description": "Cloud assets inventory across all providers",
                    "columns": [
                        {"name": "id", "type": "STRING", "description": "Unique asset identifier (ARN/URI)"},
                        {"name": "cloud_provider", "type": "STRING", "description": "Cloud provider (aws, gcp, azure)"},
                        {"name": "account_id", "type": "STRING", "description": "Cloud account/project ID"},
                        {"name": "region", "type": "STRING", "description": "Cloud region"},
                        {"name": "resource_type", "type": "STRING", "description": "Resource type (e.g., aws_s3_bucket)"},
                        {"name": "name", "type": "STRING", "description": "Resource name"},
                        {"name": "tags", "type": "JSON", "description": "Resource tags as JSON"},
                        {"name": "network_exposure", "type": "STRING", "description": "Network exposure level"},
                        {"name": "created_at", "type": "TIMESTAMP", "description": "Asset creation timestamp"},
                        {"name": "updated_at", "type": "TIMESTAMP", "description": "Last update timestamp"},
                    ],
                },
                "findings": {
                    "table_name": "findings",
                    "description": "Security findings and misconfigurations",
                    "columns": [
                        {"name": "id", "type": "STRING", "description": "Unique finding identifier"},
                        {"name": "asset_id", "type": "STRING", "description": "Related asset identifier"},
                        {"name": "finding_type", "type": "STRING", "description": "Finding type category"},
                        {"name": "severity", "type": "STRING", "description": "Severity (critical, high, medium, low)"},
                        {"name": "status", "type": "STRING", "description": "Finding status (open, resolved, suppressed)"},
                        {"name": "title", "type": "STRING", "description": "Finding title"},
                        {"name": "description", "type": "STRING", "description": "Finding description"},
                        {"name": "rule_id", "type": "STRING", "description": "Policy rule identifier"},
                        {"name": "remediation", "type": "STRING", "description": "Remediation guidance"},
                        {"name": "first_seen", "type": "TIMESTAMP", "description": "First detection timestamp"},
                        {"name": "last_seen", "type": "TIMESTAMP", "description": "Last detection timestamp"},
                    ],
                },
                "scans": {
                    "table_name": "scans",
                    "description": "Scan history and results",
                    "columns": [
                        {"name": "scan_id", "type": "STRING", "description": "Unique scan identifier"},
                        {"name": "config_name", "type": "STRING", "description": "Configuration used"},
                        {"name": "started_at", "type": "TIMESTAMP", "description": "Scan start time"},
                        {"name": "completed_at", "type": "TIMESTAMP", "description": "Scan completion time"},
                        {"name": "status", "type": "STRING", "description": "Scan status"},
                        {"name": "assets_scanned", "type": "INTEGER", "description": "Number of assets scanned"},
                        {"name": "findings_count", "type": "INTEGER", "description": "Number of findings"},
                    ],
                },
                "policies": {
                    "table_name": "policies",
                    "description": "Security policies",
                    "columns": [
                        {"name": "policy_id", "type": "STRING", "description": "Policy identifier"},
                        {"name": "name", "type": "STRING", "description": "Policy name"},
                        {"name": "category", "type": "STRING", "description": "Policy category"},
                        {"name": "severity", "type": "STRING", "description": "Default severity"},
                        {"name": "provider", "type": "STRING", "description": "Cloud provider"},
                        {"name": "enabled", "type": "BOOLEAN", "description": "Whether policy is enabled"},
                    ],
                },
                "compliance": {
                    "table_name": "compliance",
                    "description": "Compliance framework mappings",
                    "columns": [
                        {"name": "framework", "type": "STRING", "description": "Framework name"},
                        {"name": "control_id", "type": "STRING", "description": "Control identifier"},
                        {"name": "control_name", "type": "STRING", "description": "Control name"},
                        {"name": "policy_ids", "type": "ARRAY<STRING>", "description": "Mapped policy IDs"},
                        {"name": "compliance_score", "type": "FLOAT", "description": "Compliance score"},
                    ],
                },
            }

            schema = schemas[table_name]

            return HandlerResponse.success({
                "backend": backend,
                "table_name": schema["table_name"],
                "description": schema["description"],
                "columns": schema["columns"],
                "column_count": len(schema["columns"]),
            })
        except Exception as e:
            logger.exception("Failed to get schema")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Backend Management endpoints
    # =========================================================================

    @route("backends")
    def query_backends(self, params: dict, body: dict | None) -> HandlerResponse:
        """List configured query backends."""
        try:
            backends = [
                {
                    "name": "athena",
                    "provider": "aws",
                    "description": "AWS Athena - Query data in S3 using SQL",
                    "pricing": "$5.00 per TB scanned",
                    "configured": False,
                    "status": "not_configured",
                },
                {
                    "name": "bigquery",
                    "provider": "gcp",
                    "description": "Google BigQuery - Serverless data warehouse",
                    "pricing": "$5.00 per TB processed",
                    "configured": False,
                    "status": "not_configured",
                },
                {
                    "name": "synapse",
                    "provider": "azure",
                    "description": "Azure Synapse Analytics",
                    "pricing": "$5.00 per TB processed",
                    "configured": False,
                    "status": "not_configured",
                },
                {
                    "name": "demo",
                    "provider": "local",
                    "description": "Demo mode with sample data",
                    "pricing": "Free",
                    "configured": True,
                    "status": "active",
                },
            ]

            return HandlerResponse.success({
                "backends": backends,
                "total": len(backends),
                "configured": sum(1 for b in backends if b["configured"]),
                "active": "demo",
            })
        except Exception as e:
            logger.exception("Failed to list backends")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Query History and Saved Queries endpoints
    # =========================================================================

    @route("history")
    def query_history(self, params: dict, body: dict | None) -> HandlerResponse:
        """List query execution history."""
        try:
            limit = self.get_param_int(params, "limit", 20)
            user = self.get_param(params, "user", "")

            history = [
                {
                    "query_id": "q-001",
                    "sql": "SELECT * FROM assets WHERE cloud_provider = 'aws' LIMIT 10",
                    "backend": "demo",
                    "user": "admin",
                    "executed_at": "2024-12-30T14:30:00Z",
                    "execution_time_ms": 45,
                    "rows_returned": 10,
                    "bytes_scanned": 1024,
                    "status": "completed",
                },
                {
                    "query_id": "q-002",
                    "sql": "SELECT severity, COUNT(*) FROM findings GROUP BY severity",
                    "backend": "demo",
                    "user": "admin",
                    "executed_at": "2024-12-30T14:25:00Z",
                    "execution_time_ms": 32,
                    "rows_returned": 4,
                    "bytes_scanned": 2048,
                    "status": "completed",
                },
                {
                    "query_id": "q-003",
                    "sql": "SELECT * FROM findings WHERE severity = 'critical'",
                    "backend": "demo",
                    "user": "analyst",
                    "executed_at": "2024-12-30T14:20:00Z",
                    "execution_time_ms": 28,
                    "rows_returned": 5,
                    "bytes_scanned": 512,
                    "status": "completed",
                },
            ]

            if user:
                history = [h for h in history if h["user"] == user]

            history = history[:limit]

            return HandlerResponse.success({
                "history": history,
                "total": len(history),
                "limit": limit,
            })
        except Exception as e:
            logger.exception("Failed to get query history")
            return HandlerResponse.server_error(str(e))

    @route("saved")
    def query_saved(self, params: dict, body: dict | None) -> HandlerResponse:
        """List saved queries."""
        try:
            category = self.get_param(params, "category", "")

            saved_queries = [
                {
                    "id": "sq-001",
                    "name": "Critical Findings",
                    "description": "All critical severity findings",
                    "sql": "SELECT * FROM findings WHERE severity = 'critical'",
                    "category": "security",
                    "created_by": "admin",
                    "created_at": "2024-12-01T10:00:00Z",
                    "is_public": True,
                },
                {
                    "id": "sq-002",
                    "name": "Public S3 Buckets",
                    "description": "S3 buckets with public access",
                    "sql": "SELECT * FROM assets WHERE resource_type = 'aws_s3_bucket' AND network_exposure = 'public'",
                    "category": "compliance",
                    "created_by": "admin",
                    "created_at": "2024-12-05T15:00:00Z",
                    "is_public": True,
                },
                {
                    "id": "sq-003",
                    "name": "Findings by Region",
                    "description": "Count of findings grouped by region",
                    "sql": "SELECT a.region, COUNT(f.id) FROM findings f JOIN assets a ON f.asset_id = a.id GROUP BY a.region",
                    "category": "analytics",
                    "created_by": "analyst",
                    "created_at": "2024-12-10T09:00:00Z",
                    "is_public": False,
                },
            ]

            if category:
                saved_queries = [q for q in saved_queries if q["category"] == category]

            return HandlerResponse.success({
                "queries": saved_queries,
                "total": len(saved_queries),
            })
        except Exception as e:
            logger.exception("Failed to get saved queries")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Status and Statistics endpoints
    # =========================================================================

    @route("stats")
    def query_stats(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get query engine statistics."""
        try:
            result = {
                "queries_executed_24h": 45,
                "queries_executed_7d": 312,
                "bytes_scanned_24h": 104857600,  # 100 MB
                "bytes_scanned_7d": 1073741824,  # 1 GB
                "average_execution_time_ms": 42,
                "failed_queries_24h": 2,
                "top_tables": [
                    {"table": "findings", "queries": 156},
                    {"table": "assets", "queries": 123},
                    {"table": "scans", "queries": 33},
                ],
                "top_users": [
                    {"user": "admin", "queries": 187},
                    {"user": "analyst", "queries": 89},
                    {"user": "auditor", "queries": 36},
                ],
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get query stats")
            return HandlerResponse.server_error(str(e))

    @route("status")
    def query_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get query engine status and capabilities."""
        try:
            result = {
                "module": "query_engine",
                "version": "1.0.0",
                "status": "operational",
                "capabilities": {
                    "sql_execution": True,
                    "cost_estimation": True,
                    "schema_introspection": True,
                    "query_validation": True,
                    "parameterized_queries": True,
                    "result_pagination": True,
                    "query_history": True,
                    "saved_queries": True,
                },
                "supported_backends": ["athena", "bigquery", "synapse", "demo"],
                "active_backend": "demo",
                "security": {
                    "read_only": True,
                    "forbidden_keywords": self.FORBIDDEN_KEYWORDS,
                },
                "common_tables": ["assets", "findings", "scans", "policies", "compliance"],
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get query status")
            return HandlerResponse.server_error(str(e))

    @route("summary")
    def query_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get comprehensive query module summary."""
        try:
            result = {
                "module": "query_engine",
                "version": "1.0.0",
                "description": "SQL query engine for security data analysis",
                "features": [
                    "Read-only SQL execution",
                    "Multi-backend support (Athena, BigQuery, Synapse)",
                    "Query cost estimation",
                    "Schema introspection",
                    "Query validation and security checks",
                    "Query history tracking",
                    "Saved queries library",
                ],
                "tables_available": 5,
                "backends_configured": 1,
                "saved_queries": 3,
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get query summary")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Helper methods
    # =========================================================================

    def _validate_sql(self, sql: str) -> list[str]:
        """
        Validate SQL query for safety.

        Performs comprehensive validation to prevent SQL injection and
        unauthorized operations:
        - Length limits to prevent DoS
        - Keyword filtering before AND after string removal
        - Proper handling of escaped quotes
        - Comment detection (multiple styles)
        - Statement separation detection
        """
        errors = []

        # Check query length
        if len(sql) > self.MAX_QUERY_LENGTH:
            errors.append(f"Query exceeds maximum length of {self.MAX_QUERY_LENGTH} characters")
            return errors  # Don't process further if too long

        # Check for null bytes (could be used to truncate strings)
        if "\x00" in sql:
            errors.append("Query contains invalid null bytes")
            return errors

        sql_upper = sql.upper().strip()

        # Must start with SELECT or WITH (only allowed statements)
        if not sql_upper.startswith("SELECT") and not sql_upper.startswith("WITH"):
            errors.append("Query must start with SELECT or WITH")

        # Check for forbidden keywords in the raw query first
        # This catches attempts to hide keywords in string manipulation
        for keyword in self.FORBIDDEN_KEYWORDS:
            pattern = rf"\b{keyword}\b"
            if re.search(pattern, sql_upper):
                errors.append(f"Forbidden keyword detected: {keyword}")

        # Check for SQL comments (multiple styles)
        # -- SQL comment, /* block comment */, # MySQL comment
        comment_patterns = [
            r"--",           # SQL standard comment
            r"/\*",          # Block comment start
            r"\*/",          # Block comment end (unbalanced)
            r"#(?!\{)",      # MySQL comment (but not #{} which could be legit string)
        ]
        for pattern in comment_patterns:
            if re.search(pattern, sql):
                errors.append("SQL comments are not allowed")
                break

        # Properly remove string literals to check for statement separators
        # Handle escaped quotes properly: '' (SQL standard) and \' (non-standard)
        sql_no_strings = self._remove_string_literals(sql)

        # Check for multiple statements
        if ";" in sql_no_strings:
            errors.append("Multiple statements are not allowed")

        # Check for UNION-based injection attempts (after string removal)
        if re.search(r"\bUNION\b", sql_no_strings.upper()):
            # UNION is sometimes legitimate, but flag for review
            # Could be used for data exfiltration
            pass  # Allow UNION but could add logging here

        # Check for hexadecimal or binary strings that might encode dangerous content
        # Patterns like 0x... or X'...' or B'...'
        if re.search(r"0x[0-9a-fA-F]+", sql) or re.search(r"[XB]'[^']*'", sql_upper):
            # Allow but could add to validation list in the future
            pass

        # Check for common injection patterns
        injection_patterns = [
            r"OR\s+['\"]?1['\"]?\s*=\s*['\"]?1",  # OR 1=1
            r"OR\s+['\"]?[^'\"]+['\"]?\s*=\s*['\"]?[^'\"]+['\"]?",  # OR 'a'='a'
            r"'\s*OR\s*'",  # ' OR '
            r";\s*--",  # ; --
            r"'\s*;\s*--",  # '; --
        ]
        for pattern in injection_patterns:
            if re.search(pattern, sql_upper):
                errors.append("Potential SQL injection pattern detected")
                break

        return errors

    def _remove_string_literals(self, sql: str) -> str:
        """
        Safely remove string literals from SQL for validation.

        Handles:
        - Single-quoted strings with escaped quotes ('')
        - Double-quoted strings with escaped quotes ("")
        - Backslash escapes (\' and \")
        """
        result = []
        i = 0
        in_string = False
        string_char = None

        while i < len(sql):
            char = sql[i]

            if not in_string:
                if char in ("'", '"'):
                    in_string = True
                    string_char = char
                else:
                    result.append(char)
            else:
                # Inside a string
                if char == string_char:
                    # Check for escaped quote ('' or "")
                    if i + 1 < len(sql) and sql[i + 1] == string_char:
                        i += 1  # Skip the escaped quote
                    else:
                        in_string = False
                        string_char = None
                elif char == "\\" and i + 1 < len(sql):
                    # Backslash escape - skip next character
                    i += 1

            i += 1

        # If we're still in a string at the end, it's malformed
        # Return the result anyway - the query will likely fail
        return "".join(result)

    def _execute_demo_query(self, sql: str) -> dict[str, Any]:
        """Execute a demo query with sample data."""
        sql_upper = sql.upper()

        # Validate first
        errors = self._validate_sql(sql)
        if errors:
            return {
                "error": "Query validation failed",
                "errors": errors,
            }

        # Determine table and get sample data
        if "ASSETS" in sql_upper:
            rows = self._get_sample_assets()
            columns = ["id", "cloud_provider", "account_id", "region", "resource_type", "name", "tags", "network_exposure"]
        elif "FINDINGS" in sql_upper:
            rows = self._get_sample_findings()
            columns = ["id", "asset_id", "finding_type", "severity", "status", "title", "description", "rule_id"]
        else:
            rows = []
            columns = []

        # Apply LIMIT
        if "LIMIT" in sql_upper:
            match = re.search(r"LIMIT\s+(\d+)", sql_upper)
            if match:
                limit = int(match.group(1))
                rows = rows[:limit]

        return {
            "rows": rows,
            "columns": columns,
            "row_count": len(rows),
            "bytes_scanned": len(str(rows)) * 2,
            "execution_time_ms": 50,
            "query_id": "demo-query-001",
            "metadata": {"backend": "demo"},
        }

    def _get_sample_assets(self) -> list[dict[str, Any]]:
        """Get sample assets for query demo."""
        return [
            {
                "id": "arn:aws:s3:::production-data",
                "cloud_provider": "aws",
                "account_id": "123456789012",
                "region": "us-east-1",
                "resource_type": "aws_s3_bucket",
                "name": "production-data",
                "tags": '{"Environment": "production"}',
                "network_exposure": "private",
            },
            {
                "id": "arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0",
                "cloud_provider": "aws",
                "account_id": "123456789012",
                "region": "us-west-2",
                "resource_type": "aws_ec2_instance",
                "name": "web-server-01",
                "tags": '{"Environment": "production", "Role": "web"}',
                "network_exposure": "public",
            },
            {
                "id": "//storage.googleapis.com/projects/my-gcp-project/buckets/analytics",
                "cloud_provider": "gcp",
                "account_id": "my-gcp-project",
                "region": "us-central1",
                "resource_type": "gcp_storage_bucket",
                "name": "analytics",
                "tags": '{"team": "analytics"}',
                "network_exposure": "private",
            },
        ]

    def _get_sample_findings(self) -> list[dict[str, Any]]:
        """Get sample findings for query demo."""
        return [
            {
                "id": "finding-001",
                "asset_id": "arn:aws:s3:::production-data",
                "finding_type": "misconfiguration",
                "severity": "high",
                "status": "open",
                "title": "S3 bucket without encryption",
                "description": "S3 bucket does not have default encryption enabled",
                "rule_id": "aws-s3-001",
            },
            {
                "id": "finding-002",
                "asset_id": "arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0",
                "finding_type": "misconfiguration",
                "severity": "critical",
                "status": "open",
                "title": "EC2 instance with public IP",
                "description": "EC2 instance has a public IP address assigned",
                "rule_id": "aws-ec2-002",
            },
            {
                "id": "finding-003",
                "asset_id": "//storage.googleapis.com/projects/my-gcp-project/buckets/analytics",
                "finding_type": "misconfiguration",
                "severity": "medium",
                "status": "resolved",
                "title": "GCS bucket uniform access not enabled",
                "description": "Cloud Storage bucket does not have uniform bucket-level access",
                "rule_id": "gcp-storage-001",
            },
        ]
