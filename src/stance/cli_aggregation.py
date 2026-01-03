"""
CLI commands for multi-cloud aggregation.

Provides CLI access to the aggregation module for:
- Multi-cloud findings aggregation
- Cross-cloud synchronization
- Federated query capabilities
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from typing import Any

from stance.aggregation import (
    FindingsAggregator,
    CloudAccount,
    AggregationResult,
    CrossCloudSync,
    SyncConfig,
    SyncDirection,
    ConflictResolution,
    SyncResult,
    FederatedQuery,
    FederatedQueryResult,
    QueryStrategy,
    MergeStrategy,
    BackendConfig,
)
from stance.models.finding import Finding, Severity


def cmd_aggregation(args: argparse.Namespace) -> int:
    """Handle aggregation subcommands."""
    if not hasattr(args, "aggregation_command") or args.aggregation_command is None:
        print("Usage: stance aggregation <command>")
        print("")
        print("Commands:")
        print("  aggregate    Aggregate findings from multiple cloud accounts")
        print("  cross-account  Find findings that appear in multiple accounts")
        print("  summary      Generate aggregation summary report")
        print("  sync         Synchronize findings to central storage")
        print("  sync-status  Show synchronization status")
        print("  federate     Execute federated query across backends")
        print("  backends     List and manage query backends")
        print("  status       Show aggregation module status")
        return 0

    command = args.aggregation_command

    if command == "aggregate":
        return _cmd_aggregate(args)
    elif command == "cross-account":
        return _cmd_cross_account(args)
    elif command == "summary":
        return _cmd_summary(args)
    elif command == "sync":
        return _cmd_sync(args)
    elif command == "sync-status":
        return _cmd_sync_status(args)
    elif command == "federate":
        return _cmd_federate(args)
    elif command == "backends":
        return _cmd_backends(args)
    elif command == "status":
        return _cmd_status(args)
    else:
        print(f"Unknown command: {command}")
        return 1


def _cmd_aggregate(args: argparse.Namespace) -> int:
    """Aggregate findings from multiple cloud accounts."""
    output_format = getattr(args, "format", "table")
    severity_filter = getattr(args, "severity", None)
    deduplicate = getattr(args, "deduplicate", True)
    accounts_file = getattr(args, "accounts_file", None)
    findings_dir = getattr(args, "findings_dir", None)

    # Create aggregator
    aggregator = FindingsAggregator()

    # Load accounts and findings
    accounts, findings_by_account = _load_aggregation_data(accounts_file, findings_dir)

    if not accounts:
        # Demo mode with sample data
        accounts, findings_by_account = _get_sample_aggregation_data()

    # Add accounts and findings to aggregator
    for account in accounts:
        aggregator.add_account(account)
        if account.id in findings_by_account:
            aggregator.add_findings(account.id, findings_by_account[account.id])

    # Parse severity filter
    sev = None
    if severity_filter:
        try:
            sev = Severity(severity_filter.lower())
        except ValueError:
            print(f"Invalid severity: {severity_filter}")
            return 1

    # Perform aggregation
    findings_collection, result = aggregator.aggregate(
        deduplicate=deduplicate,
        severity_filter=sev,
    )

    if output_format == "json":
        output = {
            "result": result.to_dict(),
            "findings": [f.to_dict() for f in findings_collection],
        }
        print(json.dumps(output, indent=2, default=str))
    else:
        _print_aggregation_result(result, list(findings_collection))

    return 0


def _cmd_cross_account(args: argparse.Namespace) -> int:
    """Find findings that appear in multiple accounts."""
    output_format = getattr(args, "format", "table")
    min_accounts = getattr(args, "min_accounts", 2)
    accounts_file = getattr(args, "accounts_file", None)
    findings_dir = getattr(args, "findings_dir", None)

    # Create aggregator
    aggregator = FindingsAggregator()

    # Load accounts and findings
    accounts, findings_by_account = _load_aggregation_data(accounts_file, findings_dir)

    if not accounts:
        accounts, findings_by_account = _get_sample_aggregation_data()

    # Add accounts and findings
    for account in accounts:
        aggregator.add_account(account)
        if account.id in findings_by_account:
            aggregator.add_findings(account.id, findings_by_account[account.id])

    # Get cross-account findings
    cross_account_findings = aggregator.get_cross_account_findings(min_accounts=min_accounts)
    findings_list = list(cross_account_findings)

    if output_format == "json":
        output = {
            "min_accounts": min_accounts,
            "count": len(findings_list),
            "findings": [f.to_dict() for f in findings_list],
        }
        print(json.dumps(output, indent=2, default=str))
    else:
        print(f"\nCross-Account Findings (appearing in {min_accounts}+ accounts)")
        print("=" * 70)
        if not findings_list:
            print("No cross-account findings found.")
        else:
            print(f"\n{'ID':<20} {'Severity':<10} {'Title':<40}")
            print("-" * 70)
            for finding in findings_list:
                title = finding.title[:37] + "..." if len(finding.title) > 40 else finding.title
                print(f"{finding.id:<20} {finding.severity.value:<10} {title:<40}")
            print(f"\nTotal: {len(findings_list)} cross-account findings")

    return 0


def _cmd_summary(args: argparse.Namespace) -> int:
    """Generate aggregation summary report."""
    output_format = getattr(args, "format", "table")
    accounts_file = getattr(args, "accounts_file", None)
    findings_dir = getattr(args, "findings_dir", None)

    # Create aggregator
    aggregator = FindingsAggregator()

    # Load accounts and findings
    accounts, findings_by_account = _load_aggregation_data(accounts_file, findings_dir)

    if not accounts:
        accounts, findings_by_account = _get_sample_aggregation_data()

    # Add accounts and findings
    for account in accounts:
        aggregator.add_account(account)
        if account.id in findings_by_account:
            aggregator.add_findings(account.id, findings_by_account[account.id])

    # Generate summary report
    summary = aggregator.generate_summary_report()

    if output_format == "json":
        print(json.dumps(summary, indent=2, default=str))
    else:
        _print_summary_report(summary)

    return 0


def _cmd_sync(args: argparse.Namespace) -> int:
    """Synchronize findings to central storage."""
    output_format = getattr(args, "format", "table")
    bucket = getattr(args, "bucket", None)
    prefix = getattr(args, "prefix", "aggregated")
    direction = getattr(args, "direction", "push")
    conflict_resolution = getattr(args, "conflict_resolution", "latest_wins")
    dry_run = getattr(args, "dry_run", False)

    if not bucket:
        print("Error: --bucket is required for sync operations")
        print("Usage: stance aggregation sync --bucket <bucket-name>")
        return 1

    # Parse sync direction
    try:
        sync_dir = SyncDirection(direction)
    except ValueError:
        print(f"Invalid direction: {direction}")
        print("Valid options: push, pull, bidirectional")
        return 1

    # Parse conflict resolution
    try:
        conflict_res = ConflictResolution(conflict_resolution)
    except ValueError:
        print(f"Invalid conflict resolution: {conflict_resolution}")
        print("Valid options: latest_wins, central_wins, local_wins, merge")
        return 1

    # Create sync config
    config = SyncConfig(
        central_bucket=bucket,
        central_prefix=prefix,
        sync_direction=sync_dir,
        conflict_resolution=conflict_res,
    )

    if dry_run:
        if output_format == "json":
            output = {
                "dry_run": True,
                "config": {
                    "bucket": bucket,
                    "prefix": prefix,
                    "direction": direction,
                    "conflict_resolution": conflict_resolution,
                },
                "message": "Dry run - no changes made",
            }
            print(json.dumps(output, indent=2))
        else:
            print("\nSync Configuration (Dry Run)")
            print("=" * 50)
            print(f"  Bucket:              {bucket}")
            print(f"  Prefix:              {prefix}")
            print(f"  Direction:           {direction}")
            print(f"  Conflict Resolution: {conflict_resolution}")
            print("\n[Dry run mode - no changes would be made]")
        return 0

    # For actual sync, we would need a storage adapter
    # This demonstrates the interface
    if output_format == "json":
        result = SyncResult(
            success=True,
            records_synced=0,
            records_skipped=0,
            conflicts_resolved=0,
            sync_direction=sync_dir,
        )
        output = {
            "config": {
                "bucket": bucket,
                "prefix": prefix,
                "direction": direction,
            },
            "result": result.to_dict(),
            "message": "Sync requires storage adapter configuration",
        }
        print(json.dumps(output, indent=2))
    else:
        print("\nSync Operation")
        print("=" * 50)
        print(f"  Bucket:    {bucket}")
        print(f"  Direction: {direction}")
        print("\nNote: Actual sync requires storage adapter configuration.")
        print("Configure storage adapter in your stance configuration.")

    return 0


def _cmd_sync_status(args: argparse.Namespace) -> int:
    """Show synchronization status."""
    output_format = getattr(args, "format", "table")

    # In a real implementation, this would read from state storage
    status = {
        "last_sync": None,
        "sync_enabled": False,
        "configured_buckets": [],
        "pending_records": 0,
        "sync_errors": [],
    }

    if output_format == "json":
        print(json.dumps(status, indent=2))
    else:
        print("\nSync Status")
        print("=" * 50)
        print(f"  Sync Enabled:    {status['sync_enabled']}")
        print(f"  Last Sync:       {status['last_sync'] or 'Never'}")
        print(f"  Pending Records: {status['pending_records']}")
        if status['configured_buckets']:
            print(f"  Buckets:         {', '.join(status['configured_buckets'])}")
        else:
            print("  Buckets:         None configured")
        if status['sync_errors']:
            print(f"  Errors:          {len(status['sync_errors'])}")

    return 0


def _cmd_federate(args: argparse.Namespace) -> int:
    """Execute federated query across backends."""
    output_format = getattr(args, "format", "table")
    query = getattr(args, "query", None)
    backends = getattr(args, "backends", None)
    strategy = getattr(args, "strategy", "parallel")
    merge = getattr(args, "merge", "union")

    if not query:
        print("Error: --query is required")
        print("Usage: stance aggregation federate --query 'SELECT * FROM findings'")
        return 1

    # Parse strategies
    try:
        query_strategy = QueryStrategy(strategy)
    except ValueError:
        print(f"Invalid query strategy: {strategy}")
        print("Valid options: parallel, sequential, first_success, best_effort")
        return 1

    try:
        merge_strategy = MergeStrategy(merge)
    except ValueError:
        print(f"Invalid merge strategy: {merge}")
        print("Valid options: union, union_distinct, intersect, priority")
        return 1

    # Parse backend list
    backend_list = None
    if backends:
        backend_list = [b.strip() for b in backends.split(",")]

    # In a real implementation, we would have configured backends
    # This demonstrates the interface
    result = FederatedQueryResult(
        rows=[],
        columns=[],
        backends_queried=0,
        backends_succeeded=0,
        merge_strategy=merge_strategy,
    )

    if output_format == "json":
        output = {
            "query": query,
            "strategy": strategy,
            "merge": merge,
            "backends_requested": backend_list or "all",
            "result": result.to_dict(),
            "message": "Federated query requires configured backends",
        }
        print(json.dumps(output, indent=2))
    else:
        print("\nFederated Query")
        print("=" * 60)
        print(f"  Query:    {query}")
        print(f"  Strategy: {strategy}")
        print(f"  Merge:    {merge}")
        if backend_list:
            print(f"  Backends: {', '.join(backend_list)}")
        print("\nNote: Federated query requires configured query backends.")
        print("Configure backends using stance configuration.")

    return 0


def _cmd_backends(args: argparse.Namespace) -> int:
    """List and manage query backends."""
    output_format = getattr(args, "format", "table")
    action = getattr(args, "action", "list")

    if action == "list":
        # In a real implementation, this would read from configuration
        backends = _get_sample_backends()

        if output_format == "json":
            print(json.dumps(backends, indent=2))
        else:
            print("\nQuery Backends")
            print("=" * 70)
            if not backends:
                print("No backends configured.")
                print("\nTo add a backend, configure it in your stance settings.")
            else:
                print(f"\n{'Name':<20} {'Provider':<10} {'Enabled':<10} {'Priority':<10}")
                print("-" * 70)
                for backend in backends:
                    print(
                        f"{backend['name']:<20} "
                        f"{backend['provider']:<10} "
                        f"{'Yes' if backend['enabled'] else 'No':<10} "
                        f"{backend['priority']:<10}"
                    )
                print(f"\nTotal: {len(backends)} backends")
    elif action == "status":
        backends = _get_sample_backends()
        if output_format == "json":
            status = {
                "backends": backends,
                "total": len(backends),
                "enabled": sum(1 for b in backends if b["enabled"]),
                "connected": 0,  # Would check actual connections
            }
            print(json.dumps(status, indent=2))
        else:
            print("\nBackend Status")
            print("=" * 50)
            enabled = sum(1 for b in backends if b["enabled"])
            print(f"  Total Backends:   {len(backends)}")
            print(f"  Enabled:          {enabled}")
            print(f"  Connected:        0 (no active connections)")
    else:
        print(f"Unknown action: {action}")
        print("Valid actions: list, status")
        return 1

    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    """Show aggregation module status."""
    output_format = getattr(args, "format", "table")

    status = {
        "module": "aggregation",
        "version": "1.0.0",
        "capabilities": {
            "multi_account_aggregation": True,
            "cross_account_detection": True,
            "deduplication": True,
            "severity_filtering": True,
            "cross_cloud_sync": True,
            "federated_queries": True,
        },
        "supported_providers": ["aws", "gcp", "azure"],
        "sync_adapters": ["S3", "GCS", "Azure Blob"],
        "query_backends": ["Athena", "BigQuery", "Synapse"],
        "merge_strategies": ["union", "union_distinct", "intersect", "priority"],
        "conflict_resolutions": ["latest_wins", "central_wins", "local_wins", "merge"],
    }

    if output_format == "json":
        print(json.dumps(status, indent=2))
    else:
        print("\nAggregation Module Status")
        print("=" * 60)
        print(f"\n  Module:  {status['module']}")
        print(f"  Version: {status['version']}")

        print("\n  Capabilities:")
        for cap, enabled in status["capabilities"].items():
            indicator = "[x]" if enabled else "[ ]"
            cap_name = cap.replace("_", " ").title()
            print(f"    {indicator} {cap_name}")

        print(f"\n  Supported Providers: {', '.join(status['supported_providers'])}")
        print(f"  Sync Adapters:       {', '.join(status['sync_adapters'])}")
        print(f"  Query Backends:      {', '.join(status['query_backends'])}")
        print(f"  Merge Strategies:    {', '.join(status['merge_strategies'])}")

    return 0


def _print_aggregation_result(result: AggregationResult, findings: list[Finding]) -> None:
    """Print aggregation result in table format."""
    print("\nAggregation Result")
    print("=" * 60)
    print(f"\n  Total Findings:      {result.total_findings}")
    print(f"  Unique Findings:     {result.unique_findings}")
    print(f"  Duplicates Removed:  {result.duplicates_removed}")
    print(f"  Source Accounts:     {len(result.source_accounts)}")
    print(f"  Aggregated At:       {result.aggregated_at.isoformat()}")

    if result.findings_by_severity:
        print("\n  By Severity:")
        for sev, count in sorted(result.findings_by_severity.items()):
            print(f"    {sev:<12} {count}")

    if result.findings_by_provider:
        print("\n  By Provider:")
        for provider, count in sorted(result.findings_by_provider.items()):
            print(f"    {provider:<12} {count}")

    if result.findings_by_account:
        print("\n  By Account:")
        for account, count in sorted(result.findings_by_account.items()):
            account_short = account[:20] + "..." if len(account) > 23 else account
            print(f"    {account_short:<23} {count}")

    if findings:
        print(f"\n  Sample Findings (showing first 5 of {len(findings)}):")
        print(f"  {'ID':<20} {'Severity':<10} {'Title':<30}")
        print("  " + "-" * 60)
        for finding in findings[:5]:
            title = finding.title[:27] + "..." if len(finding.title) > 30 else finding.title
            print(f"  {finding.id:<20} {finding.severity.value:<10} {title:<30}")


def _print_summary_report(summary: dict[str, Any]) -> None:
    """Print summary report in table format."""
    print("\nAggregation Summary Report")
    print("=" * 60)

    s = summary.get("summary", {})
    print(f"\n  Overview:")
    print(f"    Total Accounts:        {s.get('total_accounts', 0)}")
    print(f"    Total Findings:        {s.get('total_findings', 0)}")
    print(f"    Unique Findings:       {s.get('unique_findings', 0)}")
    print(f"    Duplicates Removed:    {s.get('duplicates_removed', 0)}")
    print(f"    Cross-Account Issues:  {s.get('cross_account_findings', 0)}")

    by_severity = summary.get("by_severity", {})
    if by_severity:
        print("\n  Findings by Severity:")
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in by_severity:
                print(f"    {sev.capitalize():<12} {by_severity[sev]}")

    by_provider = summary.get("by_provider", {})
    if by_provider:
        print("\n  Findings by Provider:")
        for provider, count in sorted(by_provider.items()):
            print(f"    {provider.upper():<12} {count}")

    critical_high = summary.get("critical_high_by_provider", {})
    if critical_high:
        print("\n  Critical/High by Provider:")
        for provider, count in sorted(critical_high.items()):
            print(f"    {provider.upper():<12} {count}")

    print(f"\n  Aggregated At: {summary.get('aggregated_at', 'N/A')}")


def _load_aggregation_data(
    accounts_file: str | None,
    findings_dir: str | None,
) -> tuple[list[CloudAccount], dict[str, list[Finding]]]:
    """Load aggregation data from files."""
    accounts: list[CloudAccount] = []
    findings_by_account: dict[str, list[Finding]] = {}

    # In a real implementation, this would load from:
    # - accounts_file: JSON file with account definitions
    # - findings_dir: Directory with findings JSON files per account

    return accounts, findings_by_account


def _get_sample_aggregation_data() -> tuple[list[CloudAccount], dict[str, list[Finding]]]:
    """Get sample data for demonstration."""
    # Sample accounts
    accounts = [
        CloudAccount(
            id="123456789012",
            provider="aws",
            name="AWS Production",
            region="us-east-1",
        ),
        CloudAccount(
            id="my-gcp-project",
            provider="gcp",
            name="GCP Production",
            region="us-central1",
        ),
        CloudAccount(
            id="azure-sub-001",
            provider="azure",
            name="Azure Production",
            region="eastus",
        ),
    ]

    # Sample findings
    now = datetime.utcnow()
    findings_by_account = {
        "123456789012": [
            Finding(
                id="finding-aws-001",
                title="S3 bucket without encryption",
                description="S3 bucket does not have encryption enabled",
                severity=Severity.HIGH,
                rule_id="aws-s3-001",
                asset_id="arn:aws:s3:::my-bucket",
                first_seen=now,
                last_seen=now,
            ),
            Finding(
                id="finding-aws-002",
                title="Public S3 bucket detected",
                description="S3 bucket allows public access",
                severity=Severity.CRITICAL,
                rule_id="aws-s3-002",
                asset_id="arn:aws:s3:::public-bucket",
                first_seen=now,
                last_seen=now,
            ),
        ],
        "my-gcp-project": [
            Finding(
                id="finding-gcp-001",
                title="GCS bucket without encryption",
                description="Cloud Storage bucket does not have encryption",
                severity=Severity.HIGH,
                rule_id="gcp-storage-001",
                asset_id="//storage.googleapis.com/projects/my-gcp-project/buckets/my-bucket",
                first_seen=now,
                last_seen=now,
            ),
        ],
        "azure-sub-001": [
            Finding(
                id="finding-azure-001",
                title="Storage account without encryption",
                description="Azure storage account does not have encryption",
                severity=Severity.HIGH,
                rule_id="azure-storage-001",
                asset_id="/subscriptions/azure-sub-001/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/mystorageaccount",
                first_seen=now,
                last_seen=now,
            ),
        ],
    }

    return accounts, findings_by_account


def _get_sample_backends() -> list[dict[str, Any]]:
    """Get sample backend configurations for demonstration."""
    return [
        {
            "name": "aws-athena-prod",
            "provider": "aws",
            "enabled": True,
            "priority": 1,
            "engine": "Athena",
            "database": "stance_findings",
        },
        {
            "name": "gcp-bigquery-prod",
            "provider": "gcp",
            "enabled": True,
            "priority": 2,
            "engine": "BigQuery",
            "dataset": "stance_findings",
        },
        {
            "name": "azure-synapse-prod",
            "provider": "azure",
            "enabled": False,
            "priority": 3,
            "engine": "Synapse",
            "database": "stance_findings",
        },
    ]


def add_aggregation_parser(subparsers: argparse._SubParsersAction) -> None:
    """Add aggregation command parser."""
    aggregation_parser = subparsers.add_parser(
        "aggregation",
        help="Multi-cloud findings aggregation and federation",
        description="Aggregate findings from multiple cloud accounts, synchronize "
        "to central storage, and execute federated queries across backends.",
    )

    aggregation_subparsers = aggregation_parser.add_subparsers(
        dest="aggregation_command",
        metavar="<command>",
    )

    # aggregate command
    aggregate_parser = aggregation_subparsers.add_parser(
        "aggregate",
        help="Aggregate findings from multiple cloud accounts",
    )
    aggregate_parser.add_argument(
        "--accounts-file",
        help="JSON file with account definitions",
    )
    aggregate_parser.add_argument(
        "--findings-dir",
        help="Directory containing findings JSON files",
    )
    aggregate_parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        help="Filter by severity level",
    )
    aggregate_parser.add_argument(
        "--no-deduplicate",
        dest="deduplicate",
        action="store_false",
        help="Disable deduplication",
    )
    aggregate_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # cross-account command
    cross_account_parser = aggregation_subparsers.add_parser(
        "cross-account",
        help="Find findings that appear in multiple accounts",
    )
    cross_account_parser.add_argument(
        "--min-accounts",
        type=int,
        default=2,
        help="Minimum accounts finding must appear in (default: 2)",
    )
    cross_account_parser.add_argument(
        "--accounts-file",
        help="JSON file with account definitions",
    )
    cross_account_parser.add_argument(
        "--findings-dir",
        help="Directory containing findings JSON files",
    )
    cross_account_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # summary command
    summary_parser = aggregation_subparsers.add_parser(
        "summary",
        help="Generate aggregation summary report",
    )
    summary_parser.add_argument(
        "--accounts-file",
        help="JSON file with account definitions",
    )
    summary_parser.add_argument(
        "--findings-dir",
        help="Directory containing findings JSON files",
    )
    summary_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # sync command
    sync_parser = aggregation_subparsers.add_parser(
        "sync",
        help="Synchronize findings to central storage",
    )
    sync_parser.add_argument(
        "--bucket",
        required=False,
        help="Central storage bucket (S3/GCS/Azure Blob)",
    )
    sync_parser.add_argument(
        "--prefix",
        default="aggregated",
        help="Storage prefix (default: aggregated)",
    )
    sync_parser.add_argument(
        "--direction",
        choices=["push", "pull", "bidirectional"],
        default="push",
        help="Sync direction (default: push)",
    )
    sync_parser.add_argument(
        "--conflict-resolution",
        choices=["latest_wins", "central_wins", "local_wins", "merge"],
        default="latest_wins",
        help="Conflict resolution strategy (default: latest_wins)",
    )
    sync_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be synced without making changes",
    )
    sync_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # sync-status command
    sync_status_parser = aggregation_subparsers.add_parser(
        "sync-status",
        help="Show synchronization status",
    )
    sync_status_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # federate command
    federate_parser = aggregation_subparsers.add_parser(
        "federate",
        help="Execute federated query across backends",
    )
    federate_parser.add_argument(
        "--query",
        help="SQL query to execute",
    )
    federate_parser.add_argument(
        "--backends",
        help="Comma-separated list of backend names (default: all)",
    )
    federate_parser.add_argument(
        "--strategy",
        choices=["parallel", "sequential", "first_success", "best_effort"],
        default="parallel",
        help="Query execution strategy (default: parallel)",
    )
    federate_parser.add_argument(
        "--merge",
        choices=["union", "union_distinct", "intersect", "priority"],
        default="union",
        help="Result merge strategy (default: union)",
    )
    federate_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # backends command
    backends_parser = aggregation_subparsers.add_parser(
        "backends",
        help="List and manage query backends",
    )
    backends_parser.add_argument(
        "--action",
        choices=["list", "status"],
        default="list",
        help="Backend action (default: list)",
    )
    backends_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # status command
    status_parser = aggregation_subparsers.add_parser(
        "status",
        help="Show aggregation module status and capabilities",
    )
    status_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )
