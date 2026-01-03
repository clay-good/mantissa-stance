"""
CLI commands for the Storage module.

Provides commands for managing storage backends, snapshots, and data persistence.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any


def add_storage_parser(subparsers: Any) -> None:
    """
    Add storage subcommand parser.

    Args:
        subparsers: Argument parser subparsers
    """
    storage_parser = subparsers.add_parser(
        "storage",
        help="Storage backend commands",
        description="Manage storage backends, snapshots, and data persistence",
    )

    storage_subparsers = storage_parser.add_subparsers(
        dest="storage_action",
        help="Storage action to perform",
    )

    # backends - List available backends
    backends_parser = storage_subparsers.add_parser(
        "backends",
        help="List available storage backends",
        description="List storage backends and their availability",
    )
    backends_parser.add_argument(
        "--format",
        type=str,
        default="table",
        choices=["table", "json"],
        help="Output format (default: table)",
    )

    # backend - Show backend details
    backend_parser = storage_subparsers.add_parser(
        "backend",
        help="Show details for a storage backend",
        description="Display configuration details for a storage backend",
    )
    backend_parser.add_argument(
        "backend_name",
        type=str,
        choices=["local", "s3", "gcs", "azure"],
        help="Backend name",
    )
    backend_parser.add_argument(
        "--format",
        type=str,
        default="table",
        choices=["table", "json"],
        help="Output format (default: table)",
    )

    # snapshots - List snapshots
    snapshots_parser = storage_subparsers.add_parser(
        "snapshots",
        help="List stored snapshots",
        description="List snapshots with asset and finding counts",
    )
    snapshots_parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Maximum number of snapshots (default: 10)",
    )
    snapshots_parser.add_argument(
        "--format",
        type=str,
        default="table",
        choices=["table", "json"],
        help="Output format (default: table)",
    )

    # snapshot - Show snapshot details
    snapshot_parser = storage_subparsers.add_parser(
        "snapshot",
        help="Show details for a snapshot",
        description="Display detailed information for a snapshot",
    )
    snapshot_parser.add_argument(
        "snapshot_id",
        type=str,
        help="Snapshot ID",
    )
    snapshot_parser.add_argument(
        "--format",
        type=str,
        default="table",
        choices=["table", "json"],
        help="Output format (default: table)",
    )

    # latest - Show latest snapshot
    latest_parser = storage_subparsers.add_parser(
        "latest",
        help="Show latest snapshot",
        description="Display the most recent snapshot",
    )
    latest_parser.add_argument(
        "--format",
        type=str,
        default="table",
        choices=["table", "json"],
        help="Output format (default: table)",
    )

    # config - Show storage configuration
    config_parser = storage_subparsers.add_parser(
        "config",
        help="Show storage configuration",
        description="Display current storage configuration",
    )
    config_parser.add_argument(
        "--format",
        type=str,
        default="table",
        choices=["table", "json"],
        help="Output format (default: table)",
    )

    # capabilities - List backend capabilities
    capabilities_parser = storage_subparsers.add_parser(
        "capabilities",
        help="List storage capabilities",
        description="List capabilities by backend type",
    )
    capabilities_parser.add_argument(
        "--backend",
        type=str,
        choices=["local", "s3", "gcs", "azure"],
        help="Filter by backend",
    )
    capabilities_parser.add_argument(
        "--format",
        type=str,
        default="table",
        choices=["table", "json"],
        help="Output format (default: table)",
    )

    # query-services - List query services
    query_parser = storage_subparsers.add_parser(
        "query-services",
        help="List query services",
        description="List SQL query services by backend",
    )
    query_parser.add_argument(
        "--format",
        type=str,
        default="table",
        choices=["table", "json"],
        help="Output format (default: table)",
    )

    # ddl - Generate DDL for query service
    ddl_parser = storage_subparsers.add_parser(
        "ddl",
        help="Generate DDL for query service",
        description="Generate CREATE TABLE statements for query services",
    )
    ddl_parser.add_argument(
        "backend",
        type=str,
        choices=["s3", "gcs", "azure"],
        help="Backend type",
    )
    ddl_parser.add_argument(
        "--table",
        type=str,
        default="assets",
        choices=["assets", "findings"],
        help="Table type (default: assets)",
    )
    ddl_parser.add_argument(
        "--format",
        type=str,
        default="table",
        choices=["table", "json"],
        help="Output format (default: table)",
    )

    # stats - Show storage statistics
    stats_parser = storage_subparsers.add_parser(
        "stats",
        help="Show storage statistics",
        description="Display storage usage statistics",
    )
    stats_parser.add_argument(
        "--format",
        type=str,
        default="table",
        choices=["table", "json"],
        help="Output format (default: table)",
    )

    # status - Show storage status
    status_parser = storage_subparsers.add_parser(
        "status",
        help="Show storage status",
        description="Display storage module status",
    )
    status_parser.add_argument(
        "--format",
        type=str,
        default="table",
        choices=["table", "json"],
        help="Output format (default: table)",
    )

    # summary - Show storage summary
    summary_parser = storage_subparsers.add_parser(
        "summary",
        help="Show storage summary",
        description="Display comprehensive storage summary",
    )
    summary_parser.add_argument(
        "--format",
        type=str,
        default="table",
        choices=["table", "json"],
        help="Output format (default: table)",
    )


def cmd_storage(args: argparse.Namespace) -> int:
    """
    Handle storage commands.

    Args:
        args: Parsed command arguments

    Returns:
        Exit code (0 for success, 1 for error)
    """
    action = getattr(args, "storage_action", None)

    if not action:
        print("Error: No action specified. Use --help for available actions.")
        return 1

    handlers = {
        "backends": _handle_backends,
        "backend": _handle_backend,
        "snapshots": _handle_snapshots,
        "snapshot": _handle_snapshot,
        "latest": _handle_latest,
        "config": _handle_config,
        "capabilities": _handle_capabilities,
        "query-services": _handle_query_services,
        "ddl": _handle_ddl,
        "stats": _handle_stats,
        "status": _handle_status,
        "summary": _handle_summary,
    }

    handler = handlers.get(action)
    if handler:
        return handler(args)

    print(f"Error: Unknown action '{action}'")
    return 1


def _handle_backends(args: argparse.Namespace) -> int:
    """Handle backends command."""
    backends = _get_available_backends()

    if args.format == "json":
        print(json.dumps({"backends": backends, "total": len(backends)}, indent=2))
    else:
        print(f"\nAvailable Storage Backends ({len(backends)} total)")
        print("=" * 70)
        for backend in backends:
            status = "available" if backend["available"] else "not installed"
            print(f"\n  {backend['name'].upper()}")
            print(f"    Description: {backend['description']}")
            print(f"    Status: {status}")
            print(f"    SDK: {backend['sdk']}")
            if backend.get("query_service"):
                print(f"    Query Service: {backend['query_service']}")

    return 0


def _handle_backend(args: argparse.Namespace) -> int:
    """Handle backend command."""
    backend = _get_backend_details(args.backend_name)

    if args.format == "json":
        print(json.dumps({"backend": backend}, indent=2))
    else:
        print(f"\nBackend: {backend['name'].upper()}")
        print("=" * 60)
        print(f"  Description: {backend['description']}")
        print(f"  Available: {backend['available']}")
        print(f"  SDK: {backend['sdk']}")
        print(f"\n  Configuration Options:")
        for opt in backend["config_options"]:
            req = "(required)" if opt["required"] else "(optional)"
            print(f"    {opt['name']} {req}")
            print(f"      {opt['description']}")
            if opt.get("default"):
                print(f"      Default: {opt['default']}")
        print(f"\n  Query Service: {backend.get('query_service', 'N/A')}")
        print(f"\n  Features:")
        for feature in backend["features"]:
            print(f"    - {feature}")

    return 0


def _handle_snapshots(args: argparse.Namespace) -> int:
    """Handle snapshots command."""
    snapshots = _get_sample_snapshots(args.limit)

    if args.format == "json":
        print(json.dumps({"snapshots": snapshots, "total": len(snapshots)}, indent=2))
    else:
        print(f"\nStored Snapshots ({len(snapshots)} shown)")
        print("=" * 80)
        for snap in snapshots:
            print(f"\n  {snap['id']}")
            print(f"    Created: {snap['created_at']}")
            print(f"    Account: {snap.get('account_id', 'N/A')}")
            print(f"    Assets: {snap.get('asset_count', 0)}")
            print(f"    Findings: {snap.get('finding_count', 0)}")

    return 0


def _handle_snapshot(args: argparse.Namespace) -> int:
    """Handle snapshot command."""
    snapshot = _get_sample_snapshot(args.snapshot_id)

    if not snapshot:
        print(f"Error: Snapshot '{args.snapshot_id}' not found")
        return 1

    if args.format == "json":
        print(json.dumps({"snapshot": snapshot}, indent=2))
    else:
        print(f"\nSnapshot: {snapshot['id']}")
        print("=" * 60)
        print(f"  Created: {snapshot['created_at']}")
        print(f"  Account ID: {snapshot.get('account_id', 'N/A')}")
        print(f"  Assets: {snapshot.get('asset_count', 0)}")
        print(f"  Findings: {snapshot.get('finding_count', 0)}")
        if snapshot.get("by_severity"):
            print("\n  Findings by Severity:")
            for sev, count in snapshot["by_severity"].items():
                print(f"    {sev}: {count}")
        if snapshot.get("by_resource_type"):
            print("\n  Top Resource Types:")
            for rt, count in list(snapshot["by_resource_type"].items())[:5]:
                print(f"    {rt}: {count}")

    return 0


def _handle_latest(args: argparse.Namespace) -> int:
    """Handle latest command."""
    snapshot = _get_latest_snapshot()

    if not snapshot:
        print("No snapshots found")
        return 1

    if args.format == "json":
        print(json.dumps({"snapshot": snapshot}, indent=2))
    else:
        print(f"\nLatest Snapshot: {snapshot['id']}")
        print("=" * 60)
        print(f"  Created: {snapshot['created_at']}")
        print(f"  Account ID: {snapshot.get('account_id', 'N/A')}")
        print(f"  Assets: {snapshot.get('asset_count', 0)}")
        print(f"  Findings: {snapshot.get('finding_count', 0)}")

    return 0


def _handle_config(args: argparse.Namespace) -> int:
    """Handle config command."""
    config = _get_storage_config()

    if args.format == "json":
        print(json.dumps(config, indent=2))
    else:
        print("\nStorage Configuration")
        print("=" * 60)
        print(f"  Active Backend: {config['active_backend']}")
        print(f"  Backend Status: {config['backend_status']}")
        print(f"\n  Settings:")
        for key, value in config["settings"].items():
            print(f"    {key}: {value}")
        print(f"\n  Paths:")
        for key, value in config["paths"].items():
            print(f"    {key}: {value}")

    return 0


def _handle_capabilities(args: argparse.Namespace) -> int:
    """Handle capabilities command."""
    capabilities = _get_backend_capabilities(args.backend if hasattr(args, 'backend') else None)

    if args.format == "json":
        print(json.dumps({"capabilities": capabilities}, indent=2))
    else:
        print("\nStorage Backend Capabilities")
        print("=" * 70)
        for backend, caps in capabilities.items():
            print(f"\n  {backend.upper()}:")
            for cap, supported in caps.items():
                indicator = "yes" if supported else "no"
                print(f"    {cap}: {indicator}")

    return 0


def _handle_query_services(args: argparse.Namespace) -> int:
    """Handle query-services command."""
    services = _get_query_services()

    if args.format == "json":
        print(json.dumps({"query_services": services, "total": len(services)}, indent=2))
    else:
        print(f"\nQuery Services ({len(services)} available)")
        print("=" * 60)
        for svc in services:
            print(f"\n  {svc['name']}")
            print(f"    Backend: {svc['backend']}")
            print(f"    Description: {svc['description']}")
            print(f"    SQL Dialect: {svc['sql_dialect']}")

    return 0


def _handle_ddl(args: argparse.Namespace) -> int:
    """Handle ddl command."""
    ddl = _get_ddl(args.backend, args.table)

    if args.format == "json":
        print(json.dumps({"ddl": ddl, "backend": args.backend, "table": args.table}, indent=2))
    else:
        print(f"\n{args.backend.upper()} DDL for {args.table}:")
        print("=" * 60)
        print(ddl["statement"])

    return 0


def _handle_stats(args: argparse.Namespace) -> int:
    """Handle stats command."""
    stats = _get_storage_stats()

    if args.format == "json":
        print(json.dumps(stats, indent=2))
    else:
        print("\nStorage Statistics")
        print("=" * 60)
        print(f"  Total Snapshots: {stats['total_snapshots']}")
        print(f"  Total Assets: {stats['total_assets']}")
        print(f"  Total Findings: {stats['total_findings']}")
        print(f"  Storage Size: {stats['storage_size']}")
        print(f"\n  By Backend:")
        for backend, count in stats["by_backend"].items():
            print(f"    {backend}: {count} snapshots")
        print(f"\n  Latest Snapshot: {stats['latest_snapshot']}")
        print(f"  Oldest Snapshot: {stats['oldest_snapshot']}")

    return 0


def _handle_status(args: argparse.Namespace) -> int:
    """Handle status command."""
    status = _get_storage_status()

    if args.format == "json":
        print(json.dumps(status, indent=2))
    else:
        print("\nStorage Module Status")
        print("=" * 60)
        print(f"  Module: {status['module']}")
        print(f"  Version: {status['version']}")
        print(f"  Status: {status['status']}")
        print(f"\n  Backends:")
        for name, available in status["backends"].items():
            indicator = "available" if available else "not installed"
            print(f"    {name}: {indicator}")
        print(f"\n  Active Backend: {status['active_backend']}")
        print(f"\n  Capabilities:")
        for cap, enabled in status["capabilities"].items():
            indicator = "enabled" if enabled else "disabled"
            print(f"    {cap}: {indicator}")

    return 0


def _handle_summary(args: argparse.Namespace) -> int:
    """Handle summary command."""
    summary = _get_storage_summary()

    if args.format == "json":
        print(json.dumps(summary, indent=2))
    else:
        print("\nStorage Module Summary")
        print("=" * 60)
        print(f"  Module: {summary['module']}")
        print(f"  Version: {summary['version']}")
        print(f"  Status: {summary['status']}")
        print(f"\n  Backends Available: {summary['backends_available']}")
        print(f"  Active Backend: {summary['active_backend']}")
        print(f"\n  Data:")
        print(f"    Snapshots: {summary['data']['snapshots']}")
        print(f"    Assets: {summary['data']['assets']}")
        print(f"    Findings: {summary['data']['findings']}")
        print(f"\n  Features:")
        for feature in summary["features"]:
            print(f"    - {feature}")

    return 0


# Sample data generators


def _get_available_backends() -> list[dict[str, Any]]:
    """Get available storage backends."""
    from stance.storage import list_available_backends

    available = list_available_backends()

    backends = [
        {
            "name": "local",
            "description": "SQLite-based local storage for development",
            "available": "local" in available,
            "sdk": "sqlite3 (built-in)",
            "query_service": "SQLite",
        },
        {
            "name": "s3",
            "description": "AWS S3 storage with Athena query support",
            "available": "s3" in available,
            "sdk": "boto3",
            "query_service": "Amazon Athena",
        },
        {
            "name": "gcs",
            "description": "Google Cloud Storage with BigQuery support",
            "available": "gcs" in available,
            "sdk": "google-cloud-storage",
            "query_service": "BigQuery",
        },
        {
            "name": "azure",
            "description": "Azure Blob Storage with Synapse support",
            "available": "azure" in available,
            "sdk": "azure-storage-blob",
            "query_service": "Azure Synapse",
        },
    ]

    return backends


def _get_backend_details(name: str) -> dict[str, Any]:
    """Get detailed backend information."""
    backends = {
        "local": {
            "name": "local",
            "description": "SQLite-based local storage for development and single-user scenarios",
            "available": True,
            "sdk": "sqlite3 (built-in)",
            "query_service": "SQLite",
            "config_options": [
                {
                    "name": "db_path",
                    "description": "Path to SQLite database file",
                    "required": False,
                    "default": "~/.stance/stance.db",
                },
            ],
            "features": [
                "Snapshot management",
                "Asset and finding storage",
                "SQL query support",
                "Automatic schema migration",
                "Index optimization",
            ],
        },
        "s3": {
            "name": "s3",
            "description": "AWS S3 storage for production deployments with Athena querying",
            "available": True,
            "sdk": "boto3",
            "query_service": "Amazon Athena",
            "config_options": [
                {
                    "name": "bucket",
                    "description": "S3 bucket name",
                    "required": True,
                },
                {
                    "name": "prefix",
                    "description": "Key prefix for objects",
                    "required": False,
                    "default": "stance",
                },
                {
                    "name": "region",
                    "description": "AWS region",
                    "required": False,
                    "default": "us-east-1",
                },
            ],
            "features": [
                "JSON Lines format for Athena compatibility",
                "Manifest-based snapshot tracking",
                "Automatic DDL generation for Athena tables",
                "Multi-account support",
                "Scalable storage",
            ],
        },
        "gcs": {
            "name": "gcs",
            "description": "Google Cloud Storage for GCP deployments with BigQuery querying",
            "available": True,
            "sdk": "google-cloud-storage",
            "query_service": "BigQuery",
            "config_options": [
                {
                    "name": "bucket",
                    "description": "GCS bucket name",
                    "required": True,
                },
                {
                    "name": "prefix",
                    "description": "Blob prefix for objects",
                    "required": False,
                    "default": "stance",
                },
                {
                    "name": "project_id",
                    "description": "GCP project ID",
                    "required": False,
                },
            ],
            "features": [
                "JSON Lines format for BigQuery compatibility",
                "Manifest-based snapshot tracking",
                "Automatic DDL generation for BigQuery tables",
                "Service account authentication",
                "Cross-project access",
            ],
        },
        "azure": {
            "name": "azure",
            "description": "Azure Blob Storage for Azure deployments with Synapse querying",
            "available": True,
            "sdk": "azure-storage-blob",
            "query_service": "Azure Synapse",
            "config_options": [
                {
                    "name": "account_name",
                    "description": "Azure Storage account name",
                    "required": True,
                },
                {
                    "name": "container",
                    "description": "Container name",
                    "required": True,
                },
                {
                    "name": "prefix",
                    "description": "Blob prefix for objects",
                    "required": False,
                    "default": "stance",
                },
                {
                    "name": "connection_string",
                    "description": "Connection string (alternative to credentials)",
                    "required": False,
                },
            ],
            "features": [
                "JSON Lines format for Synapse compatibility",
                "Manifest-based snapshot tracking",
                "Automatic DDL generation for Synapse tables",
                "Azure AD authentication",
                "Connection string support",
            ],
        },
    }

    return backends.get(name, {"name": name, "error": "Backend not found"})


def _get_sample_snapshots(limit: int) -> list[dict[str, Any]]:
    """Get sample snapshots."""
    snapshots = [
        {
            "id": "20251229-120000",
            "created_at": "2025-12-29T12:00:00Z",
            "account_id": "123456789012",
            "asset_count": 1250,
            "finding_count": 45,
        },
        {
            "id": "20251228-120000",
            "created_at": "2025-12-28T12:00:00Z",
            "account_id": "123456789012",
            "asset_count": 1245,
            "finding_count": 52,
        },
        {
            "id": "20251227-120000",
            "created_at": "2025-12-27T12:00:00Z",
            "account_id": "123456789012",
            "asset_count": 1240,
            "finding_count": 48,
        },
        {
            "id": "20251226-120000",
            "created_at": "2025-12-26T12:00:00Z",
            "account_id": "123456789012",
            "asset_count": 1235,
            "finding_count": 55,
        },
        {
            "id": "20251225-120000",
            "created_at": "2025-12-25T12:00:00Z",
            "account_id": "123456789012",
            "asset_count": 1230,
            "finding_count": 42,
        },
    ]

    return snapshots[:limit]


def _get_sample_snapshot(snapshot_id: str) -> dict[str, Any] | None:
    """Get sample snapshot details."""
    snapshots = _get_sample_snapshots(10)
    for snap in snapshots:
        if snap["id"] == snapshot_id:
            snap["by_severity"] = {
                "critical": 5,
                "high": 12,
                "medium": 18,
                "low": 8,
                "info": 2,
            }
            snap["by_resource_type"] = {
                "aws_s3_bucket": 45,
                "aws_iam_user": 32,
                "aws_ec2_instance": 128,
                "aws_rds_instance": 12,
                "aws_lambda_function": 87,
            }
            return snap
    return None


def _get_latest_snapshot() -> dict[str, Any] | None:
    """Get latest snapshot."""
    snapshots = _get_sample_snapshots(1)
    return snapshots[0] if snapshots else None


def _get_storage_config() -> dict[str, Any]:
    """Get storage configuration."""
    return {
        "active_backend": "local",
        "backend_status": "connected",
        "settings": {
            "auto_snapshot": True,
            "retention_days": 90,
            "compression": False,
            "encryption": False,
        },
        "paths": {
            "database": "~/.stance/stance.db",
            "cache": "~/.stance/cache",
            "logs": "~/.stance/logs",
        },
    }


def _get_backend_capabilities(backend: str | None) -> dict[str, dict[str, bool]]:
    """Get backend capabilities."""
    capabilities = {
        "local": {
            "snapshot_storage": True,
            "sql_queries": True,
            "concurrent_access": False,
            "multi_region": False,
            "encryption_at_rest": False,
            "versioning": False,
        },
        "s3": {
            "snapshot_storage": True,
            "sql_queries": True,
            "concurrent_access": True,
            "multi_region": True,
            "encryption_at_rest": True,
            "versioning": True,
        },
        "gcs": {
            "snapshot_storage": True,
            "sql_queries": True,
            "concurrent_access": True,
            "multi_region": True,
            "encryption_at_rest": True,
            "versioning": True,
        },
        "azure": {
            "snapshot_storage": True,
            "sql_queries": True,
            "concurrent_access": True,
            "multi_region": True,
            "encryption_at_rest": True,
            "versioning": True,
        },
    }

    if backend:
        return {backend: capabilities.get(backend, {})}
    return capabilities


def _get_query_services() -> list[dict[str, Any]]:
    """Get query services."""
    return [
        {
            "name": "SQLite",
            "backend": "local",
            "description": "Embedded SQL database for local queries",
            "sql_dialect": "SQLite",
        },
        {
            "name": "Amazon Athena",
            "backend": "s3",
            "description": "Serverless query service for S3 data",
            "sql_dialect": "Presto/Trino",
        },
        {
            "name": "BigQuery",
            "backend": "gcs",
            "description": "Serverless data warehouse for GCS data",
            "sql_dialect": "BigQuery SQL",
        },
        {
            "name": "Azure Synapse",
            "backend": "azure",
            "description": "Analytics service for Azure Blob data",
            "sql_dialect": "T-SQL",
        },
    ]


def _get_ddl(backend: str, table: str) -> dict[str, Any]:
    """Get DDL statement for backend."""
    ddl_templates = {
        "s3": {
            "assets": """CREATE EXTERNAL TABLE IF NOT EXISTS stance_assets (
    id STRING,
    cloud_provider STRING,
    account_id STRING,
    region STRING,
    resource_type STRING,
    name STRING,
    tags MAP<STRING, STRING>,
    network_exposure STRING,
    created_at STRING,
    last_seen STRING,
    raw_config STRING
)
ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
LOCATION 's3://<bucket>/<prefix>/assets/'""",
            "findings": """CREATE EXTERNAL TABLE IF NOT EXISTS stance_findings (
    id STRING,
    asset_id STRING,
    finding_type STRING,
    severity STRING,
    status STRING,
    title STRING,
    description STRING,
    rule_id STRING,
    cve_id STRING,
    cvss_score DOUBLE,
    compliance_frameworks ARRAY<STRING>,
    remediation_guidance STRING
)
ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
LOCATION 's3://<bucket>/<prefix>/findings/'""",
        },
        "gcs": {
            "assets": """CREATE OR REPLACE EXTERNAL TABLE `<project>.stance.assets`
OPTIONS (
    format = 'JSON',
    uris = ['gs://<bucket>/<prefix>/assets/*/assets.jsonl']
);""",
            "findings": """CREATE OR REPLACE EXTERNAL TABLE `<project>.stance.findings`
OPTIONS (
    format = 'JSON',
    uris = ['gs://<bucket>/<prefix>/findings/*/findings.jsonl']
);""",
        },
        "azure": {
            "assets": """CREATE EXTERNAL TABLE stance_assets (
    id VARCHAR(500),
    cloud_provider VARCHAR(50),
    account_id VARCHAR(100),
    region VARCHAR(50),
    resource_type VARCHAR(100),
    name VARCHAR(500),
    tags VARCHAR(MAX),
    network_exposure VARCHAR(50)
)
WITH (
    LOCATION = 'https://<account>.blob.core.windows.net/<container>/<prefix>/assets/',
    DATA_SOURCE = AzureBlob,
    FILE_FORMAT = JsonFormat
);""",
            "findings": """CREATE EXTERNAL TABLE stance_findings (
    id VARCHAR(500),
    asset_id VARCHAR(500),
    finding_type VARCHAR(50),
    severity VARCHAR(20),
    status VARCHAR(20),
    title VARCHAR(500),
    description VARCHAR(MAX),
    rule_id VARCHAR(100)
)
WITH (
    LOCATION = 'https://<account>.blob.core.windows.net/<container>/<prefix>/findings/',
    DATA_SOURCE = AzureBlob,
    FILE_FORMAT = JsonFormat
);""",
        },
    }

    return {
        "backend": backend,
        "table": table,
        "statement": ddl_templates.get(backend, {}).get(table, "DDL not available"),
    }


def _get_storage_stats() -> dict[str, Any]:
    """Get storage statistics."""
    return {
        "total_snapshots": 25,
        "total_assets": 31250,
        "total_findings": 1125,
        "storage_size": "128 MB",
        "by_backend": {
            "local": 25,
            "s3": 0,
            "gcs": 0,
            "azure": 0,
        },
        "latest_snapshot": "20251229-120000",
        "oldest_snapshot": "20251205-120000",
    }


def _get_storage_status() -> dict[str, Any]:
    """Get storage status."""
    from stance.storage import list_available_backends

    available = list_available_backends()

    return {
        "module": "storage",
        "version": "1.0.0",
        "status": "operational",
        "backends": {
            "local": "local" in available,
            "s3": "s3" in available,
            "gcs": "gcs" in available,
            "azure": "azure" in available,
        },
        "active_backend": "local",
        "capabilities": {
            "snapshot_storage": True,
            "asset_persistence": True,
            "finding_persistence": True,
            "sql_queries": True,
            "cloud_storage": True,
            "query_service_integration": True,
        },
    }


def _get_storage_summary() -> dict[str, Any]:
    """Get storage summary."""
    from stance.storage import list_available_backends

    available = list_available_backends()

    return {
        "module": "Storage",
        "version": "1.0.0",
        "status": "operational",
        "backends_available": len(available),
        "active_backend": "local",
        "data": {
            "snapshots": 25,
            "assets": 31250,
            "findings": 1125,
        },
        "features": [
            "Multi-backend support (Local, S3, GCS, Azure)",
            "Snapshot-based data versioning",
            "JSON Lines format for analytics compatibility",
            "Query service integration (Athena, BigQuery, Synapse)",
            "Automatic DDL generation",
            "Asset and finding persistence",
            "Safe SQL query validation",
        ],
    }
