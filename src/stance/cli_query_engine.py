"""
CLI commands for query engine operations.

Provides CLI access to the query module for:
- Executing SQL queries on cloud data warehouses (Athena, BigQuery, Synapse)
- Cost estimation before query execution
- Table schema introspection
- Listing available tables
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from stance.query import (
    QueryEngine,
    QueryResult,
    TableSchema,
    CostEstimate,
    QueryExecutionError,
    QueryValidationError,
    AthenaQueryEngine,
    BigQueryEngine,
    SynapseQueryEngine,
    get_query_engine,
    get_common_schemas,
    ASSETS_SCHEMA,
    FINDINGS_SCHEMA,
)


def cmd_sql(args: argparse.Namespace) -> int:
    """Handle sql subcommands."""
    if not hasattr(args, "sql_command") or args.sql_command is None:
        print("Usage: stance sql <command>")
        print("")
        print("Commands:")
        print("  execute     Execute a SQL SELECT query")
        print("  estimate    Estimate query cost before execution")
        print("  tables      List available tables")
        print("  schema      Show table schema")
        print("  validate    Validate a query without executing")
        print("  backends    List configured query backends")
        print("  status      Show query engine status")
        return 0

    command = args.sql_command

    if command == "execute":
        return _cmd_execute(args)
    elif command == "estimate":
        return _cmd_estimate(args)
    elif command == "tables":
        return _cmd_tables(args)
    elif command == "schema":
        return _cmd_schema(args)
    elif command == "validate":
        return _cmd_validate(args)
    elif command == "backends":
        return _cmd_backends(args)
    elif command == "status":
        return _cmd_status(args)
    else:
        print(f"Unknown command: {command}")
        return 1


def _cmd_execute(args: argparse.Namespace) -> int:
    """Execute a SQL SELECT query."""
    output_format = getattr(args, "format", "table")
    sql = getattr(args, "sql", None)
    backend = getattr(args, "backend", "demo")
    timeout = getattr(args, "timeout", 300)
    limit = getattr(args, "limit", None)
    dry_run = getattr(args, "dry_run", False)

    if not sql:
        print("Error: --sql is required")
        print("Usage: stance sql execute --sql 'SELECT * FROM assets LIMIT 10'")
        return 1

    # Add LIMIT if requested and not already present
    if limit and "LIMIT" not in sql.upper():
        sql = f"{sql.rstrip().rstrip(';')} LIMIT {limit}"

    # Get query engine
    engine = _get_engine(backend, args)

    if dry_run:
        # Just validate and estimate
        errors = engine.validate_query(sql)
        if errors:
            if output_format == "json":
                print(json.dumps({"valid": False, "errors": errors}, indent=2))
            else:
                print("\nQuery Validation Failed")
                print("=" * 50)
                for error in errors:
                    print(f"  - {error}")
            return 1

        estimate = engine.estimate_cost(sql)
        if output_format == "json":
            output = {
                "dry_run": True,
                "valid": True,
                "sql": sql,
                "backend": backend,
                "estimate": {
                    "bytes": estimate.estimated_bytes,
                    "cost_usd": estimate.estimated_cost_usd,
                    "warnings": estimate.warnings,
                },
            }
            print(json.dumps(output, indent=2))
        else:
            print("\nQuery Preview (Dry Run)")
            print("=" * 60)
            print(f"\n  SQL:      {sql[:50]}{'...' if len(sql) > 50 else ''}")
            print(f"  Backend:  {backend}")
            print(f"  Valid:    Yes")
            print(f"\n  Estimated Cost:")
            print(f"    Bytes:  {_format_bytes(estimate.estimated_bytes)}")
            print(f"    Cost:   ${estimate.estimated_cost_usd:.6f} USD")
            if estimate.warnings:
                print(f"\n  Warnings:")
                for w in estimate.warnings[:3]:
                    print(f"    - {w[:60]}")
        return 0

    # Execute query
    if backend == "demo":
        # Demo mode with sample data
        result = _execute_demo_query(sql)
    else:
        try:
            engine.connect()
            result = engine.execute_safe(sql, timeout_seconds=timeout)
            engine.disconnect()
        except QueryValidationError as e:
            print(f"Query validation failed: {e}")
            return 1
        except QueryExecutionError as e:
            print(f"Query execution failed: {e}")
            return 1

    if output_format == "json":
        print(json.dumps(result.to_dict(), indent=2, default=str))
    elif output_format == "csv":
        _print_csv(result)
    else:
        _print_table_result(result)

    return 0


def _cmd_estimate(args: argparse.Namespace) -> int:
    """Estimate query cost before execution."""
    output_format = getattr(args, "format", "table")
    sql = getattr(args, "sql", None)
    backend = getattr(args, "backend", "demo")

    if not sql:
        print("Error: --sql is required")
        print("Usage: stance sql estimate --sql 'SELECT * FROM findings'")
        return 1

    # Validate first
    engine = _get_engine(backend, args)
    errors = engine.validate_query(sql)

    if errors:
        if output_format == "json":
            print(json.dumps({"valid": False, "errors": errors}, indent=2))
        else:
            print("\nQuery Validation Failed")
            print("=" * 50)
            for error in errors:
                print(f"  - {error}")
        return 1

    # Get estimate
    estimate = engine.estimate_cost(sql)

    if output_format == "json":
        output = {
            "sql": sql,
            "backend": backend,
            "estimated_bytes": estimate.estimated_bytes,
            "estimated_cost_usd": estimate.estimated_cost_usd,
            "warnings": estimate.warnings,
        }
        print(json.dumps(output, indent=2))
    else:
        print("\nQuery Cost Estimate")
        print("=" * 60)
        print(f"\n  SQL:      {sql[:50]}{'...' if len(sql) > 50 else ''}")
        print(f"  Backend:  {backend}")
        print(f"\n  Estimate:")
        print(f"    Bytes to Scan:  {_format_bytes(estimate.estimated_bytes)}")
        print(f"    Estimated Cost: ${estimate.estimated_cost_usd:.6f} USD")
        if estimate.warnings:
            print(f"\n  Warnings:")
            for w in estimate.warnings:
                print(f"    - {w[:70]}")

    return 0


def _cmd_tables(args: argparse.Namespace) -> int:
    """List available tables."""
    output_format = getattr(args, "format", "table")
    backend = getattr(args, "backend", "demo")

    if backend == "demo":
        # Demo mode with common schemas
        tables = list(get_common_schemas().keys())
    else:
        engine = _get_engine(backend, args)
        try:
            engine.connect()
            tables = engine.list_tables()
            engine.disconnect()
        except QueryExecutionError as e:
            print(f"Failed to list tables: {e}")
            return 1

    if output_format == "json":
        print(json.dumps({"tables": tables, "count": len(tables)}, indent=2))
    else:
        print("\nAvailable Tables")
        print("=" * 50)
        if not tables:
            print("  No tables found.")
        else:
            for table in tables:
                print(f"  - {table}")
            print(f"\nTotal: {len(tables)} tables")

    return 0


def _cmd_schema(args: argparse.Namespace) -> int:
    """Show table schema."""
    output_format = getattr(args, "format", "table")
    table_name = getattr(args, "table", None)
    backend = getattr(args, "backend", "demo")

    if not table_name:
        print("Error: --table is required")
        print("Usage: stance sql schema --table assets")
        return 1

    if backend == "demo":
        # Demo mode with common schemas
        schemas = get_common_schemas()
        if table_name not in schemas:
            print(f"Table not found: {table_name}")
            print(f"Available tables: {', '.join(schemas.keys())}")
            return 1
        schema = schemas[table_name]
    else:
        engine = _get_engine(backend, args)
        try:
            engine.connect()
            schema = engine.get_table_schema(table_name)
            engine.disconnect()
        except QueryExecutionError as e:
            print(f"Failed to get schema: {e}")
            return 1

    if output_format == "json":
        output = {
            "table_name": schema.table_name,
            "description": schema.description,
            "columns": schema.columns,
            "column_count": len(schema.columns),
        }
        if schema.row_count is not None:
            output["row_count"] = schema.row_count
        if schema.size_bytes is not None:
            output["size_bytes"] = schema.size_bytes
        print(json.dumps(output, indent=2))
    else:
        _print_table_schema(schema)

    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    """Validate a query without executing."""
    output_format = getattr(args, "format", "table")
    sql = getattr(args, "sql", None)
    backend = getattr(args, "backend", "demo")

    if not sql:
        print("Error: --sql is required")
        print("Usage: stance sql validate --sql 'SELECT * FROM assets'")
        return 1

    engine = _get_engine(backend, args)
    errors = engine.validate_query(sql)

    if output_format == "json":
        output = {
            "sql": sql,
            "valid": len(errors) == 0,
            "errors": errors,
        }
        print(json.dumps(output, indent=2))
    else:
        print("\nQuery Validation")
        print("=" * 50)
        print(f"\n  SQL: {sql[:50]}{'...' if len(sql) > 50 else ''}")
        if errors:
            print(f"\n  Valid: No")
            print(f"\n  Errors:")
            for error in errors:
                print(f"    - {error}")
        else:
            print(f"\n  Valid: Yes")
            print(f"\n  The query is safe to execute.")

    return 0 if not errors else 1


def _cmd_backends(args: argparse.Namespace) -> int:
    """List configured query backends."""
    output_format = getattr(args, "format", "table")

    backends = [
        {
            "name": "athena",
            "provider": "aws",
            "description": "AWS Athena - Query data in S3 using SQL",
            "pricing": "$5.00 per TB scanned",
            "configured": False,
        },
        {
            "name": "bigquery",
            "provider": "gcp",
            "description": "Google BigQuery - Serverless data warehouse",
            "pricing": "$5.00 per TB processed (first 1TB free/month)",
            "configured": False,
        },
        {
            "name": "synapse",
            "provider": "azure",
            "description": "Azure Synapse Analytics - Unified analytics",
            "pricing": "$5.00 per TB processed (serverless)",
            "configured": False,
        },
        {
            "name": "demo",
            "provider": "local",
            "description": "Demo mode with sample data",
            "pricing": "Free",
            "configured": True,
        },
    ]

    if output_format == "json":
        print(json.dumps(backends, indent=2))
    else:
        print("\nQuery Backends")
        print("=" * 70)
        print(f"\n{'Name':<12} {'Provider':<10} {'Configured':<12} {'Description':<35}")
        print("-" * 70)
        for b in backends:
            configured = "Yes" if b["configured"] else "No"
            desc = b["description"][:32] + "..." if len(b["description"]) > 35 else b["description"]
            print(f"{b['name']:<12} {b['provider']:<10} {configured:<12} {desc:<35}")
        print(f"\nNote: Use --backend <name> to select a backend for queries.")

    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    """Show query engine status."""
    output_format = getattr(args, "format", "table")

    status = {
        "module": "query_engine",
        "version": "1.0.0",
        "capabilities": {
            "sql_execution": True,
            "cost_estimation": True,
            "schema_introspection": True,
            "query_validation": True,
            "parameterized_queries": True,
            "result_pagination": True,
        },
        "supported_backends": {
            "athena": {
                "provider": "aws",
                "features": ["cost_tracking", "workgroups", "query_history"],
            },
            "bigquery": {
                "provider": "gcp",
                "features": ["cost_tracking", "query_cache", "dry_run"],
            },
            "synapse": {
                "provider": "azure",
                "features": ["serverless", "external_tables"],
            },
        },
        "security": {
            "read_only": True,
            "forbidden_keywords": [
                "INSERT", "UPDATE", "DELETE", "DROP", "CREATE",
                "ALTER", "TRUNCATE", "GRANT", "REVOKE"
            ],
            "comment_blocking": True,
            "multi_statement_blocking": True,
        },
        "common_tables": ["assets", "findings"],
    }

    if output_format == "json":
        print(json.dumps(status, indent=2))
    else:
        print("\nQuery Engine Status")
        print("=" * 60)
        print(f"\n  Module:  {status['module']}")
        print(f"  Version: {status['version']}")

        print("\n  Capabilities:")
        for cap, enabled in status["capabilities"].items():
            indicator = "[x]" if enabled else "[ ]"
            cap_name = cap.replace("_", " ").title()
            print(f"    {indicator} {cap_name}")

        print("\n  Supported Backends:")
        for name, info in status["supported_backends"].items():
            print(f"    - {name} ({info['provider'].upper()})")

        print("\n  Security Features:")
        print(f"    - Read-only queries only (SELECT/WITH)")
        print(f"    - {len(status['security']['forbidden_keywords'])} forbidden keywords blocked")
        print(f"    - SQL comments blocked")
        print(f"    - Multiple statements blocked")

        print(f"\n  Common Tables: {', '.join(status['common_tables'])}")

    return 0


def _get_engine(backend: str, args: argparse.Namespace) -> QueryEngine:
    """Get query engine for the specified backend."""
    backend = backend.lower()

    if backend == "demo":
        # Return a demo engine that uses sample data
        return _DemoQueryEngine()

    elif backend == "athena":
        database = getattr(args, "database", "default")
        workgroup = getattr(args, "workgroup", "primary")
        region = getattr(args, "region", "us-east-1")
        output_location = getattr(args, "output_location", None)
        return AthenaQueryEngine(
            database=database,
            workgroup=workgroup,
            region=region,
            output_location=output_location,
        )

    elif backend == "bigquery":
        project_id = getattr(args, "project_id", None)
        dataset_id = getattr(args, "dataset_id", None)
        if not project_id or not dataset_id:
            raise ValueError("--project-id and --dataset-id are required for BigQuery")
        return BigQueryEngine(
            project_id=project_id,
            dataset_id=dataset_id,
        )

    elif backend == "synapse":
        server = getattr(args, "server", None)
        database = getattr(args, "database", None)
        if not server or not database:
            raise ValueError("--server and --database are required for Synapse")
        return SynapseQueryEngine(
            server=server,
            database=database,
        )

    else:
        raise ValueError(f"Unknown backend: {backend}")


class _DemoQueryEngine(QueryEngine):
    """Demo query engine for testing without cloud backends."""

    @property
    def engine_name(self) -> str:
        return "demo"

    @property
    def provider(self) -> str:
        return "local"

    def connect(self) -> None:
        self._connected = True

    def disconnect(self) -> None:
        self._connected = False

    def execute_query(
        self,
        sql: str,
        parameters: dict[str, Any] | None = None,
        timeout_seconds: int = 300,
    ) -> QueryResult:
        errors = self.validate_query(sql)
        if errors:
            raise QueryValidationError(f"Query validation failed: {'; '.join(errors)}")
        return _execute_demo_query(sql)

    def get_table_schema(self, table_name: str) -> TableSchema:
        schemas = get_common_schemas()
        if table_name not in schemas:
            raise QueryExecutionError(f"Table not found: {table_name}")
        return schemas[table_name]

    def list_tables(self) -> list[str]:
        return list(get_common_schemas().keys())

    def estimate_cost(self, sql: str) -> CostEstimate:
        return CostEstimate(
            estimated_bytes=0,
            estimated_cost_usd=0.0,
            warnings=["Demo mode - no actual cost"],
        )


def _execute_demo_query(sql: str) -> QueryResult:
    """Execute a demo query with sample data."""
    sql_upper = sql.upper()

    # Determine which table is being queried
    if "ASSETS" in sql_upper:
        rows = _get_sample_assets()
        columns = ASSETS_SCHEMA.get_column_names()
    elif "FINDINGS" in sql_upper:
        rows = _get_sample_findings()
        columns = FINDINGS_SCHEMA.get_column_names()
    else:
        rows = []
        columns = []

    # Apply LIMIT if present
    if "LIMIT" in sql_upper:
        try:
            limit_idx = sql_upper.index("LIMIT")
            limit_str = sql[limit_idx + 5:].strip().split()[0]
            limit = int(limit_str)
            rows = rows[:limit]
        except (ValueError, IndexError):
            pass

    return QueryResult(
        rows=rows,
        columns=columns,
        row_count=len(rows),
        bytes_scanned=len(str(rows)) * 2,
        execution_time_ms=50,
        query_id="demo-query-001",
        metadata={"backend": "demo", "note": "Sample data for demonstration"},
    )


def _get_sample_assets() -> list[dict[str, Any]]:
    """Get sample assets for demo mode."""
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
            "created_at": "2024-01-15T10:00:00Z",
            "last_seen": "2025-12-28T12:00:00Z",
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
            "created_at": "2024-02-01T08:30:00Z",
            "last_seen": "2025-12-28T12:00:00Z",
        },
        {
            "id": "//storage.googleapis.com/projects/my-gcp-project/buckets/analytics-data",
            "cloud_provider": "gcp",
            "account_id": "my-gcp-project",
            "region": "us-central1",
            "resource_type": "gcp_storage_bucket",
            "name": "analytics-data",
            "tags": '{"team": "analytics"}',
            "network_exposure": "private",
            "created_at": "2024-03-10T14:00:00Z",
            "last_seen": "2025-12-28T12:00:00Z",
        },
    ]


def _get_sample_findings() -> list[dict[str, Any]]:
    """Get sample findings for demo mode."""
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
            "cve_id": None,
            "cvss_score": None,
            "compliance_frameworks": '["CIS AWS 2.1.1", "PCI-DSS 3.4"]',
            "remediation_guidance": "Enable default encryption using AWS KMS",
            "first_seen": "2025-12-20T10:00:00Z",
            "last_seen": "2025-12-28T12:00:00Z",
        },
        {
            "id": "finding-002",
            "asset_id": "arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0",
            "finding_type": "misconfiguration",
            "severity": "critical",
            "status": "open",
            "title": "EC2 instance with public IP and open SSH",
            "description": "EC2 instance is publicly accessible with SSH port 22 open to 0.0.0.0/0",
            "rule_id": "aws-ec2-002",
            "cve_id": None,
            "cvss_score": None,
            "compliance_frameworks": '["CIS AWS 4.1", "NIST 800-53 SC-7"]',
            "remediation_guidance": "Restrict SSH access to specific IP ranges",
            "first_seen": "2025-12-15T08:00:00Z",
            "last_seen": "2025-12-28T12:00:00Z",
        },
        {
            "id": "finding-003",
            "asset_id": "//storage.googleapis.com/projects/my-gcp-project/buckets/analytics-data",
            "finding_type": "vulnerability",
            "severity": "medium",
            "status": "open",
            "title": "GCS bucket with uniform access disabled",
            "description": "Cloud Storage bucket uses legacy ACLs instead of uniform bucket-level access",
            "rule_id": "gcp-storage-001",
            "cve_id": None,
            "cvss_score": None,
            "compliance_frameworks": '["CIS GCP 5.1"]',
            "remediation_guidance": "Enable uniform bucket-level access",
            "first_seen": "2025-12-22T16:00:00Z",
            "last_seen": "2025-12-28T12:00:00Z",
        },
    ]


def _print_table_result(result: QueryResult) -> None:
    """Print query result in table format."""
    print(f"\nQuery Results")
    print("=" * 70)

    if not result.rows:
        print("  No rows returned.")
        return

    # Get column widths
    widths = {}
    for col in result.columns:
        widths[col] = len(col)
        for row in result.rows:
            val = str(row.get(col, ""))[:30]
            widths[col] = max(widths[col], len(val))

    # Print header
    header = "  ".join(f"{col:<{widths[col]}}" for col in result.columns[:6])
    print(f"\n{header}")
    print("-" * len(header))

    # Print rows (max 20)
    for row in result.rows[:20]:
        row_str = "  ".join(
            f"{str(row.get(col, ''))[:widths[col]]:<{widths[col]}}"
            for col in result.columns[:6]
        )
        print(row_str)

    if len(result.rows) > 20:
        print(f"... and {len(result.rows) - 20} more rows")

    print(f"\nRows: {result.row_count}  |  Bytes scanned: {_format_bytes(result.bytes_scanned)}  |  Time: {result.execution_time_ms}ms")


def _print_csv(result: QueryResult) -> None:
    """Print query result in CSV format."""
    import csv
    import sys

    writer = csv.DictWriter(sys.stdout, fieldnames=result.columns)
    writer.writeheader()
    writer.writerows(result.rows)


def _print_table_schema(schema: TableSchema) -> None:
    """Print table schema in table format."""
    print(f"\nTable: {schema.table_name}")
    print("=" * 70)
    if schema.description:
        print(f"\n  Description: {schema.description}")

    print(f"\n  {'Column':<25} {'Type':<15} {'Description':<30}")
    print("  " + "-" * 70)
    for col in schema.columns:
        name = col.get("name", "")[:22]
        col_type = col.get("type", "")[:12]
        desc = col.get("description", "")[:27]
        partition = " (partition)" if col.get("is_partition") else ""
        print(f"  {name:<25} {col_type:<15} {desc}{partition}")

    print(f"\n  Total columns: {len(schema.columns)}")


def _format_bytes(bytes_val: int) -> str:
    """Format bytes to human readable string."""
    if bytes_val < 1024:
        return f"{bytes_val} B"
    elif bytes_val < 1024 * 1024:
        return f"{bytes_val / 1024:.1f} KB"
    elif bytes_val < 1024 * 1024 * 1024:
        return f"{bytes_val / 1024 / 1024:.1f} MB"
    elif bytes_val < 1024 * 1024 * 1024 * 1024:
        return f"{bytes_val / 1024 / 1024 / 1024:.2f} GB"
    else:
        return f"{bytes_val / 1024 / 1024 / 1024 / 1024:.2f} TB"


def add_sql_parser(subparsers: argparse._SubParsersAction) -> None:
    """Add sql command parser."""
    sql_parser = subparsers.add_parser(
        "sql",
        help="Execute SQL queries on cloud data warehouses",
        description="Execute SQL SELECT queries on Athena, BigQuery, or Synapse. "
        "Provides cost estimation, schema introspection, and query validation.",
    )

    sql_subparsers = sql_parser.add_subparsers(
        dest="sql_command",
        metavar="<command>",
    )

    # execute command
    execute_parser = sql_subparsers.add_parser(
        "execute",
        help="Execute a SQL SELECT query",
    )
    execute_parser.add_argument(
        "--sql",
        required=True,
        help="SQL query to execute (SELECT only)",
    )
    execute_parser.add_argument(
        "--backend",
        choices=["demo", "athena", "bigquery", "synapse"],
        default="demo",
        help="Query backend to use (default: demo)",
    )
    execute_parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Query timeout in seconds (default: 300)",
    )
    execute_parser.add_argument(
        "--limit",
        type=int,
        help="Limit number of rows returned",
    )
    execute_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and estimate cost without executing",
    )
    execute_parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    # Backend-specific options
    execute_parser.add_argument("--database", help="Database name (Athena/Synapse)")
    execute_parser.add_argument("--workgroup", help="Athena workgroup name")
    execute_parser.add_argument("--region", help="AWS region for Athena")
    execute_parser.add_argument("--output-location", help="S3 location for Athena results")
    execute_parser.add_argument("--project-id", help="GCP project ID for BigQuery")
    execute_parser.add_argument("--dataset-id", help="BigQuery dataset ID")
    execute_parser.add_argument("--server", help="Azure Synapse server")

    # estimate command
    estimate_parser = sql_subparsers.add_parser(
        "estimate",
        help="Estimate query cost before execution",
    )
    estimate_parser.add_argument(
        "--sql",
        required=True,
        help="SQL query to estimate",
    )
    estimate_parser.add_argument(
        "--backend",
        choices=["demo", "athena", "bigquery", "synapse"],
        default="demo",
        help="Query backend (default: demo)",
    )
    estimate_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # tables command
    tables_parser = sql_subparsers.add_parser(
        "tables",
        help="List available tables",
    )
    tables_parser.add_argument(
        "--backend",
        choices=["demo", "athena", "bigquery", "synapse"],
        default="demo",
        help="Query backend (default: demo)",
    )
    tables_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # schema command
    schema_parser = sql_subparsers.add_parser(
        "schema",
        help="Show table schema",
    )
    schema_parser.add_argument(
        "--table",
        required=True,
        help="Table name to show schema for",
    )
    schema_parser.add_argument(
        "--backend",
        choices=["demo", "athena", "bigquery", "synapse"],
        default="demo",
        help="Query backend (default: demo)",
    )
    schema_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # validate command
    validate_parser = sql_subparsers.add_parser(
        "validate",
        help="Validate a query without executing",
    )
    validate_parser.add_argument(
        "--sql",
        required=True,
        help="SQL query to validate",
    )
    validate_parser.add_argument(
        "--backend",
        choices=["demo", "athena", "bigquery", "synapse"],
        default="demo",
        help="Query backend (default: demo)",
    )
    validate_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # backends command
    backends_parser = sql_subparsers.add_parser(
        "backends",
        help="List configured query backends",
    )
    backends_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # status command
    status_parser = sql_subparsers.add_parser(
        "status",
        help="Show query engine status and capabilities",
    )
    status_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )
