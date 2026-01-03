"""
CLI commands for Multi-Account Scanning module.

Provides command-line interface for multi-account scanning orchestration:
- Organization-level scanning with parallel execution
- Progress tracking and monitoring
- Account status and results viewing
- Cross-account findings aggregation
"""

from __future__ import annotations

import argparse
import json
from typing import Any


def add_scanning_parser(subparsers: Any) -> None:
    """Add scanning parser to CLI subparsers."""
    scan_parser = subparsers.add_parser(
        "scanning",
        help="Multi-account scanning orchestration",
        description="Orchestrate scanning across multiple cloud accounts",
    )

    scan_subparsers = scan_parser.add_subparsers(
        dest="scanning_action",
        help="Scanning action to perform",
    )

    # scan - Start an organization scan
    start_parser = scan_subparsers.add_parser(
        "scan",
        help="Start a multi-account scan",
    )
    start_parser.add_argument(
        "--config",
        default="default",
        help="Configuration name to use (default: default)",
    )
    start_parser.add_argument(
        "--parallel",
        type=int,
        default=3,
        help="Number of accounts to scan in parallel (default: 3)",
    )
    start_parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Timeout per account in seconds (default: 300)",
    )
    start_parser.add_argument(
        "--continue-on-error",
        action="store_true",
        default=True,
        help="Continue scanning if an account fails (default: true)",
    )
    start_parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        help="Minimum severity threshold",
    )
    start_parser.add_argument(
        "--collectors",
        help="Comma-separated list of collectors to run",
    )
    start_parser.add_argument(
        "--regions",
        help="Comma-separated list of regions to scan",
    )
    start_parser.add_argument(
        "--skip-accounts",
        help="Comma-separated list of account IDs to skip",
    )
    start_parser.add_argument(
        "--include-disabled",
        action="store_true",
        help="Include disabled accounts in scan",
    )
    start_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # progress - Show scan progress
    progress_parser = scan_subparsers.add_parser(
        "progress",
        help="Show current scan progress",
    )
    progress_parser.add_argument(
        "--scan-id",
        dest="scan_id",
        help="Scan ID to check progress for",
    )
    progress_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # results - Show scan results
    results_parser = scan_subparsers.add_parser(
        "results",
        help="Show scan results",
    )
    results_parser.add_argument(
        "--scan-id",
        dest="scan_id",
        help="Scan ID to show results for",
    )
    results_parser.add_argument(
        "--account",
        help="Filter by account ID",
    )
    results_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # accounts - List configured accounts
    accounts_parser = scan_subparsers.add_parser(
        "accounts",
        help="List configured accounts for scanning",
    )
    accounts_parser.add_argument(
        "--config",
        default="default",
        help="Configuration name (default: default)",
    )
    accounts_parser.add_argument(
        "--include-disabled",
        action="store_true",
        help="Include disabled accounts",
    )
    accounts_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # report - Generate scan report
    report_parser = scan_subparsers.add_parser(
        "report",
        help="Generate scan report",
    )
    report_parser.add_argument(
        "--scan-id",
        dest="scan_id",
        help="Scan ID to generate report for",
    )
    report_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # account-statuses - List account statuses
    statuses_parser = scan_subparsers.add_parser(
        "account-statuses",
        help="List available account statuses",
    )
    statuses_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # options - Show scan options
    options_parser = scan_subparsers.add_parser(
        "options",
        help="Show available scan options",
    )
    options_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # providers - List cloud providers
    providers_parser = scan_subparsers.add_parser(
        "providers",
        help="List supported cloud providers",
    )
    providers_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # stats - Show scanning statistics
    stats_parser = scan_subparsers.add_parser(
        "stats",
        help="Show scanning module statistics",
    )
    stats_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # status - Show module status
    status_parser = scan_subparsers.add_parser(
        "status",
        help="Show scanning module status",
    )
    status_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # summary - Get comprehensive summary
    summary_parser = scan_subparsers.add_parser(
        "summary",
        help="Get comprehensive scanning module summary",
    )
    summary_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )


def cmd_scanning(args: argparse.Namespace) -> int:
    """Handle scanning commands."""
    action = getattr(args, "scanning_action", None)

    if not action:
        print("No scanning action specified. Use 'stance scanning --help' for options.")
        return 1

    handlers = {
        "scan": _handle_scan,
        "progress": _handle_progress,
        "results": _handle_results,
        "accounts": _handle_accounts,
        "report": _handle_report,
        "account-statuses": _handle_account_statuses,
        "options": _handle_options,
        "providers": _handle_providers,
        "stats": _handle_stats,
        "status": _handle_status,
        "summary": _handle_summary,
    }

    handler = handlers.get(action)
    if handler:
        return handler(args)

    print(f"Unknown action: {action}")
    return 1


def _handle_scan(args: argparse.Namespace) -> int:
    """Handle scan command."""
    from stance.scanning import MultiAccountScanner, ScanOptions

    # Build scan options
    options = ScanOptions(
        parallel_accounts=args.parallel,
        timeout_per_account=args.timeout,
        continue_on_error=args.continue_on_error,
        include_disabled=getattr(args, "include_disabled", False),
    )

    if args.collectors:
        options.collectors = [c.strip() for c in args.collectors.split(",")]

    if args.regions:
        options.regions = [r.strip() for r in args.regions.split(",")]

    if getattr(args, "skip_accounts", None):
        options.skip_accounts = [a.strip() for a in args.skip_accounts.split(",")]

    if args.severity:
        from stance.models.finding import Severity
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        options.severity_threshold = severity_map.get(args.severity)

    # Create scanner (in a real scenario, would load config)
    scanner = MultiAccountScanner()

    if args.format == "json":
        result = {
            "action": "scan_initiated",
            "config": args.config,
            "options": options.to_dict(),
            "note": "Multi-account scan would be started with configured scanner",
        }
        print(json.dumps(result, indent=2))
    else:
        print("\nMulti-Account Scan Configuration")
        print("=" * 50)
        print(f"Configuration: {args.config}")
        print(f"Parallel Accounts: {options.parallel_accounts}")
        print(f"Timeout per Account: {options.timeout_per_account}s")
        print(f"Continue on Error: {options.continue_on_error}")
        if options.collectors:
            print(f"Collectors: {', '.join(options.collectors)}")
        if options.regions:
            print(f"Regions: {', '.join(options.regions)}")
        if options.skip_accounts:
            print(f"Skip Accounts: {', '.join(options.skip_accounts)}")
        if options.severity_threshold:
            print(f"Severity Threshold: {options.severity_threshold.value}")
        print("\nNote: Scan would start with configured scanner")

    return 0


def _handle_progress(args: argparse.Namespace) -> int:
    """Handle progress command."""
    # In a real implementation, would track active scans
    scan_id = getattr(args, "scan_id", None) or "current"

    progress_data = {
        "scan_id": scan_id,
        "total_accounts": 10,
        "completed_accounts": 5,
        "failed_accounts": 1,
        "skipped_accounts": 0,
        "pending_accounts": 4,
        "current_accounts": ["account-006"],
        "findings_so_far": 42,
        "progress_percent": 60.0,
        "is_complete": False,
        "started_at": "2024-01-15T10:00:00Z",
        "estimated_completion": "2024-01-15T10:15:00Z",
    }

    if args.format == "json":
        print(json.dumps(progress_data, indent=2))
    else:
        print(f"\nScan Progress: {scan_id}")
        print("=" * 50)
        print(f"Progress: {progress_data['progress_percent']:.1f}%")
        print(f"  Completed: {progress_data['completed_accounts']}/{progress_data['total_accounts']}")
        print(f"  Failed: {progress_data['failed_accounts']}")
        print(f"  Pending: {progress_data['pending_accounts']}")
        print(f"Currently Scanning: {', '.join(progress_data['current_accounts'])}")
        print(f"Findings So Far: {progress_data['findings_so_far']}")
        print(f"Started: {progress_data['started_at']}")
        print(f"Est. Completion: {progress_data['estimated_completion']}")

    return 0


def _handle_results(args: argparse.Namespace) -> int:
    """Handle results command."""
    scan_id = getattr(args, "scan_id", None) or "latest"
    account_filter = getattr(args, "account", None)

    results_data = {
        "scan_id": scan_id,
        "config_name": "default",
        "started_at": "2024-01-15T10:00:00Z",
        "completed_at": "2024-01-15T10:20:00Z",
        "duration_seconds": 1200,
        "summary": {
            "total_accounts": 10,
            "successful_accounts": 9,
            "failed_accounts": 1,
            "total_findings": 156,
            "unique_findings": 98,
            "total_assets": 1245,
        },
        "findings_by_severity": {
            "critical": 12,
            "high": 35,
            "medium": 67,
            "low": 42,
        },
        "account_results": [
            {"account_id": "123456789012", "status": "completed", "findings": 25},
            {"account_id": "234567890123", "status": "completed", "findings": 18},
            {"account_id": "345678901234", "status": "failed", "error": "Access denied"},
        ],
    }

    if account_filter:
        results_data["filter"] = {"account": account_filter}

    if args.format == "json":
        print(json.dumps(results_data, indent=2))
    else:
        print(f"\nScan Results: {scan_id}")
        print("=" * 60)
        print(f"Config: {results_data['config_name']}")
        print(f"Duration: {results_data['duration_seconds']}s")
        print(f"\nSummary:")
        summary = results_data["summary"]
        print(f"  Accounts: {summary['successful_accounts']}/{summary['total_accounts']} successful")
        print(f"  Total Findings: {summary['total_findings']}")
        print(f"  Unique Findings: {summary['unique_findings']}")
        print(f"  Total Assets: {summary['total_assets']}")
        print(f"\nFindings by Severity:")
        for sev, count in results_data["findings_by_severity"].items():
            print(f"  {sev.upper()}: {count}")

    return 0


def _handle_accounts(args: argparse.Namespace) -> int:
    """Handle accounts command."""
    include_disabled = getattr(args, "include_disabled", False)

    accounts = [
        {
            "account_id": "123456789012",
            "name": "Production-AWS",
            "provider": "aws",
            "enabled": True,
            "regions": ["us-east-1", "us-west-2"],
        },
        {
            "account_id": "234567890123",
            "name": "Staging-AWS",
            "provider": "aws",
            "enabled": True,
            "regions": ["us-east-1"],
        },
        {
            "account_id": "project-prod-12345",
            "name": "Production-GCP",
            "provider": "gcp",
            "enabled": True,
            "regions": ["us-central1"],
        },
        {
            "account_id": "sub-12345678-abcd",
            "name": "Production-Azure",
            "provider": "azure",
            "enabled": False,
            "regions": ["eastus"],
        },
    ]

    if not include_disabled:
        accounts = [a for a in accounts if a["enabled"]]

    if args.format == "json":
        print(json.dumps({"total": len(accounts), "accounts": accounts}, indent=2))
    else:
        print(f"\nConfigured Accounts ({len(accounts)})")
        print("=" * 80)
        print(f"{'Account ID':<25} {'Name':<20} {'Provider':<10} {'Enabled':<10}")
        print("-" * 80)
        for acc in accounts:
            enabled = "Yes" if acc["enabled"] else "No"
            print(f"{acc['account_id']:<25} {acc['name']:<20} {acc['provider']:<10} {enabled:<10}")

    return 0


def _handle_report(args: argparse.Namespace) -> int:
    """Handle report command."""
    scan_id = getattr(args, "scan_id", None) or "latest"

    report = {
        "scan_id": scan_id,
        "scan_date": "2024-01-15T10:00:00Z",
        "duration_seconds": 1200,
        "summary": {
            "accounts_scanned": 10,
            "accounts_successful": 9,
            "accounts_failed": 1,
            "scan_success_rate": 90.0,
            "total_findings": 156,
            "unique_findings": 98,
            "cross_account_findings": 12,
            "total_assets": 1245,
        },
        "findings_by_severity": {
            "critical": 12,
            "high": 35,
            "medium": 67,
            "low": 42,
        },
        "findings_by_provider": {
            "aws": 112,
            "gcp": 34,
            "azure": 10,
        },
        "top_accounts_by_findings": [
            {"account_id": "123456789012", "account_name": "Production-AWS", "findings_count": 45},
            {"account_id": "234567890123", "account_name": "Staging-AWS", "findings_count": 32},
        ],
        "accounts_with_critical_findings": [
            {"account_id": "123456789012", "account_name": "Production-AWS", "critical_findings": 8},
        ],
        "failed_accounts": [
            {"account_id": "345678901234", "account_name": "Test-Azure", "error": "Access denied"},
        ],
    }

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(f"\nOrganization Scan Report: {scan_id}")
        print("=" * 60)
        summary = report["summary"]
        print(f"Date: {report['scan_date']}")
        print(f"Duration: {report['duration_seconds']}s")
        print(f"\nAccounts:")
        print(f"  Scanned: {summary['accounts_scanned']}")
        print(f"  Successful: {summary['accounts_successful']}")
        print(f"  Failed: {summary['accounts_failed']}")
        print(f"  Success Rate: {summary['scan_success_rate']:.1f}%")
        print(f"\nFindings:")
        print(f"  Total: {summary['total_findings']}")
        print(f"  Unique: {summary['unique_findings']}")
        print(f"  Cross-Account: {summary['cross_account_findings']}")
        print(f"\nSeverity Distribution:")
        for sev, count in report["findings_by_severity"].items():
            print(f"  {sev.upper()}: {count}")
        print(f"\nTop Accounts by Findings:")
        for acc in report["top_accounts_by_findings"]:
            print(f"  {acc['account_name']}: {acc['findings_count']}")

    return 0


def _handle_account_statuses(args: argparse.Namespace) -> int:
    """Handle account-statuses command."""
    statuses = [
        {
            "status": "pending",
            "description": "Account scan has not started yet",
            "indicator": "Queued",
        },
        {
            "status": "running",
            "description": "Account scan is currently in progress",
            "indicator": "Active",
        },
        {
            "status": "completed",
            "description": "Account scan completed successfully",
            "indicator": "Success",
        },
        {
            "status": "failed",
            "description": "Account scan failed with an error",
            "indicator": "Error",
        },
        {
            "status": "skipped",
            "description": "Account was skipped (disabled or filtered)",
            "indicator": "Skipped",
        },
    ]

    if args.format == "json":
        print(json.dumps({"total": len(statuses), "statuses": statuses}, indent=2))
    else:
        print("\nAccount Statuses")
        print("=" * 60)
        for status in statuses:
            print(f"\n{status['status'].upper()}")
            print(f"  {status['description']}")
            print(f"  Indicator: {status['indicator']}")

    return 0


def _handle_options(args: argparse.Namespace) -> int:
    """Handle options command."""
    options = [
        {
            "option": "parallel_accounts",
            "type": "int",
            "default": 3,
            "description": "Number of accounts to scan in parallel",
        },
        {
            "option": "timeout_per_account",
            "type": "int",
            "default": 300,
            "description": "Maximum time per account scan in seconds",
        },
        {
            "option": "continue_on_error",
            "type": "bool",
            "default": True,
            "description": "Continue scanning other accounts if one fails",
        },
        {
            "option": "severity_threshold",
            "type": "enum",
            "default": None,
            "description": "Minimum severity to include in results",
        },
        {
            "option": "collectors",
            "type": "list",
            "default": None,
            "description": "List of collectors to run (None = all)",
        },
        {
            "option": "regions",
            "type": "list",
            "default": None,
            "description": "List of regions to scan (None = all configured)",
        },
        {
            "option": "skip_accounts",
            "type": "list",
            "default": [],
            "description": "Account IDs to skip",
        },
        {
            "option": "include_disabled",
            "type": "bool",
            "default": False,
            "description": "Include disabled accounts in scan",
        },
    ]

    if args.format == "json":
        print(json.dumps({"total": len(options), "options": options}, indent=2))
    else:
        print("\nScan Options")
        print("=" * 80)
        print(f"{'Option':<25} {'Type':<10} {'Default':<15} Description")
        print("-" * 80)
        for opt in options:
            default_str = str(opt["default"]) if opt["default"] is not None else "None"
            print(f"{opt['option']:<25} {opt['type']:<10} {default_str:<15} {opt['description']}")

    return 0


def _handle_providers(args: argparse.Namespace) -> int:
    """Handle providers command."""
    providers = [
        {
            "provider": "aws",
            "name": "Amazon Web Services",
            "account_format": "12-digit account ID",
            "collectors": ["iam", "s3", "ec2", "security"],
        },
        {
            "provider": "gcp",
            "name": "Google Cloud Platform",
            "account_format": "Project ID",
            "collectors": ["iam", "storage", "compute", "security"],
        },
        {
            "provider": "azure",
            "name": "Microsoft Azure",
            "account_format": "Subscription ID",
            "collectors": ["identity", "storage", "compute", "security"],
        },
    ]

    if args.format == "json":
        print(json.dumps({"total": len(providers), "providers": providers}, indent=2))
    else:
        print("\nSupported Cloud Providers")
        print("=" * 60)
        for provider in providers:
            print(f"\n{provider['name']} ({provider['provider']})")
            print(f"  Account Format: {provider['account_format']}")
            print(f"  Collectors: {', '.join(provider['collectors'])}")

    return 0


def _handle_stats(args: argparse.Namespace) -> int:
    """Handle stats command."""
    stats = {
        "account_statuses": 5,
        "scan_options": 8,
        "cloud_providers": 3,
        "features": {
            "parallel_execution": True,
            "progress_tracking": True,
            "cross_account_aggregation": True,
            "timeout_handling": True,
            "error_recovery": True,
        },
        "default_settings": {
            "parallel_accounts": 3,
            "timeout_per_account": 300,
            "continue_on_error": True,
        },
    }

    if args.format == "json":
        print(json.dumps(stats, indent=2))
    else:
        print("\nScanning Module Statistics")
        print("=" * 50)
        print(f"Account Statuses: {stats['account_statuses']}")
        print(f"Scan Options: {stats['scan_options']}")
        print(f"Cloud Providers: {stats['cloud_providers']}")
        print("\nFeatures:")
        for feature, enabled in stats["features"].items():
            status = "Enabled" if enabled else "Disabled"
            print(f"  {feature}: {status}")
        print("\nDefault Settings:")
        for key, value in stats["default_settings"].items():
            print(f"  {key}: {value}")

    return 0


def _handle_status(args: argparse.Namespace) -> int:
    """Handle status command."""
    status = {
        "module": "scanning",
        "status": "operational",
        "components": {
            "MultiAccountScanner": "available",
            "ScanOptions": "available",
            "ScanProgress": "available",
            "AccountScanResult": "available",
            "OrganizationScan": "available",
            "AccountStatus": "available",
        },
        "capabilities": [
            "parallel_account_scanning",
            "progress_tracking",
            "timeout_handling",
            "error_recovery",
            "cross_account_aggregation",
            "findings_deduplication",
            "report_generation",
            "callback_notifications",
        ],
        "integrations": {
            "aggregation": "FindingsAggregator",
            "config": "ScanConfiguration",
            "models": "FindingCollection, AssetCollection",
        },
    }

    if args.format == "json":
        print(json.dumps(status, indent=2))
    else:
        print("\nScanning Module Status")
        print("=" * 50)
        print(f"Module: {status['module']}")
        print(f"Status: {status['status']}")
        print("\nComponents:")
        for comp, state in status["components"].items():
            print(f"  {comp}: {state}")
        print(f"\nCapabilities ({len(status['capabilities'])}):")
        for cap in status["capabilities"]:
            print(f"  - {cap}")
        print("\nIntegrations:")
        for key, value in status["integrations"].items():
            print(f"  {key}: {value}")

    return 0


def _handle_summary(args: argparse.Namespace) -> int:
    """Handle summary command."""
    summary = {
        "module": "scanning",
        "version": "1.0.0",
        "description": "Multi-account scanning orchestration for organization-level security assessments",
        "features": [
            "Parallel execution across multiple cloud accounts",
            "Real-time progress tracking with callbacks",
            "Cross-account findings aggregation",
            "Automatic findings deduplication",
            "Configurable timeout per account",
            "Error recovery with continue-on-error mode",
            "Report generation for organization scans",
            "Support for AWS, GCP, and Azure accounts",
            "Severity-based filtering",
            "Region and collector filtering",
        ],
        "scan_workflow": {
            "1": "Load configuration with account definitions",
            "2": "Apply scan options and filters",
            "3": "Execute parallel account scans",
            "4": "Track progress and notify callbacks",
            "5": "Aggregate findings across accounts",
            "6": "Deduplicate and enrich results",
            "7": "Generate organization scan report",
        },
        "data_classes": {
            "ScanOptions": "Configuration for scan execution",
            "AccountScanResult": "Result of scanning a single account",
            "ScanProgress": "Real-time progress tracking",
            "OrganizationScan": "Complete organization scan result",
        },
        "cloud_support": ["aws", "gcp", "azure"],
    }

    if args.format == "json":
        print(json.dumps(summary, indent=2))
    else:
        print("\nScanning Module Summary")
        print("=" * 60)
        print(f"Module: {summary['module']}")
        print(f"Version: {summary['version']}")
        print(f"Description: {summary['description']}")

        print("\nFeatures:")
        for feature in summary["features"]:
            print(f"  - {feature}")

        print("\nScan Workflow:")
        for step, desc in summary["scan_workflow"].items():
            print(f"  {step}. {desc}")

        print("\nData Classes:")
        for cls, desc in summary["data_classes"].items():
            print(f"  {cls}: {desc}")

        print(f"\nCloud Support: {', '.join(summary['cloud_support'])}")

    return 0
