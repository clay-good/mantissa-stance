"""
Mantissa Stance CLI entry point.

This module provides the command-line interface for Stance.
"""

from __future__ import annotations

import argparse
import logging
import sys

from stance import __version__
from stance.cli_commands import (
    cmd_scan,
    cmd_query,
    cmd_report,
    cmd_policies,
    cmd_findings,
    cmd_assets,
    cmd_dashboard,
    cmd_notify,
    cmd_image_scan,
    cmd_iac_scan,
    cmd_secrets_scan,
    cmd_docs_generate,
)
from stance.cli_scheduling import (
    cmd_schedule,
    cmd_history,
    cmd_trends,
)
from stance.cli_shell import cmd_shell
from stance.cli_watch import cmd_watch
from stance.cli_diff import cmd_diff
from stance.cli_dspm import cmd_dspm
from stance.cli_identity import cmd_identity
from stance.cli_exposure import cmd_exposure
from stance.cli_analytics import cmd_analytics
from stance.cli_drift import cmd_drift
from stance.cli_enrich import cmd_enrich
from stance.cli_aggregation import cmd_aggregation, add_aggregation_parser
from stance.cli_query_engine import cmd_sql, add_sql_parser
from stance.cli_plugins import cmd_plugins, add_plugins_parser
from stance.cli_exceptions import cmd_exceptions, add_exceptions_parser
from stance.cli_notifications import cmd_notifications, add_notifications_parser
from stance.cli_alerting import cmd_alerting, add_alerting_parser
from stance.cli_automation import cmd_automation, add_automation_parser
from stance.cli_iac import cmd_iac, add_iac_parser
from stance.cli_engine import cmd_engine, add_engine_parser
from stance.cli_storage import cmd_storage, add_storage_parser
from stance.cli_llm import cmd_llm, add_llm_parser
from stance.cli_detection import cmd_detection, add_detection_parser
from stance.cli_scanner import cmd_scanner, add_scanner_parser
from stance.cli_export import cmd_export, add_export_parser
from stance.cli_reporting import cmd_reporting, add_reporting_parser
from stance.cli_observability import cmd_observability, add_observability_parser
from stance.cli_scanning import cmd_scanning, add_scanning_parser
from stance.cli_state import cmd_state, add_state_parser
from stance.cli_collectors import cmd_collectors, add_collectors_parser
from stance.cli_cloud import cmd_cloud, add_cloud_parser
from stance.cli_config import cmd_config, add_config_parser
from stance.cli_docs import cmd_docs, add_docs_parser
from stance.cli_sbom import cmd_sbom, add_sbom_parser
from stance.cli_api_security import cmd_api_security, add_api_security_parser
from stance.cli_dashboards import cmd_dashboards, add_dashboards_parser
from stance.cli_auth import cmd_auth, add_auth_parser
from stance.cli_ciem import cmd_ciem, add_ciem_parser
from stance.cli_benchmark import cmd_benchmark, add_benchmark_parser


def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="stance",
        description="Mantissa Stance - Cloud Security Posture Management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"stance {__version__}",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (can be repeated)",
    )

    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress non-essential output",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Run posture assessment")
    scan_parser.add_argument(
        "--account-id",
        help="AWS account ID to scan (uses current if not specified)",
    )
    scan_parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region (default: us-east-1)",
    )
    scan_parser.add_argument(
        "--collectors",
        help="Comma-separated list of collectors to run (default: all)",
    )
    scan_parser.add_argument(
        "--output",
        choices=["json", "table", "quiet"],
        default="table",
        help="Output format (default: table)",
    )
    scan_parser.add_argument(
        "--storage",
        choices=["local", "s3"],
        default="local",
        help="Storage backend (default: local)",
    )
    scan_parser.add_argument(
        "--secrets",
        action="store_true",
        help="Enable secrets detection in configurations",
    )
    scan_parser.add_argument(
        "--secrets-only",
        action="store_true",
        help="Only run secrets detection (skip policy evaluation)",
    )

    # query command
    query_parser = subparsers.add_parser("query", help="Natural language query")
    query_parser.add_argument(
        "-q",
        "--question",
        required=True,
        help="Natural language question",
    )
    query_parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Use SQL directly instead of natural language translation",
    )
    query_parser.add_argument(
        "--llm-provider",
        choices=["anthropic", "openai", "gemini"],
        default="anthropic",
        help="LLM provider to use (default: anthropic)",
    )
    query_parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    query_parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum results (default: 100)",
    )

    # report command
    report_parser = subparsers.add_parser("report", help="Generate compliance report")
    report_parser.add_argument(
        "--format",
        choices=["html", "json", "csv"],
        default="html",
        help="Output format (default: html)",
    )
    report_parser.add_argument(
        "--framework",
        choices=["cis-aws", "pci-dss", "soc2", "all"],
        default="all",
        help="Compliance framework (default: all)",
    )
    report_parser.add_argument(
        "-o",
        "--output",
        help="Output file path",
    )

    # policies command
    policies_parser = subparsers.add_parser("policies", help="Manage policies")
    policies_subparsers = policies_parser.add_subparsers(dest="policies_action")

    # policies list
    policies_list_parser = policies_subparsers.add_parser("list", help="List policies")
    policies_list_parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        help="Filter by severity",
    )
    policies_list_parser.add_argument(
        "--framework",
        help="Filter by compliance framework",
    )

    # policies validate
    policies_validate_parser = policies_subparsers.add_parser(
        "validate", help="Validate policy files"
    )

    # policies generate (AI-powered)
    policies_generate_parser = policies_subparsers.add_parser(
        "generate", help="Generate policy from natural language description (AI)"
    )
    policies_generate_parser.add_argument(
        "description",
        help="Natural language description of the policy to generate",
    )
    policies_generate_parser.add_argument(
        "--cloud",
        choices=["aws", "gcp", "azure"],
        default="aws",
        help="Target cloud provider (default: aws)",
    )
    policies_generate_parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        help="Suggested severity level",
    )
    policies_generate_parser.add_argument(
        "--resource-type",
        help="Specific resource type to target",
    )
    policies_generate_parser.add_argument(
        "--framework",
        help="Compliance framework to reference",
    )
    policies_generate_parser.add_argument(
        "--llm-provider",
        choices=["anthropic", "openai", "gemini"],
        default="anthropic",
        help="LLM provider to use (default: anthropic)",
    )
    policies_generate_parser.add_argument(
        "-o", "--output",
        help="Output file path (if not specified, prints to stdout)",
    )
    policies_generate_parser.add_argument(
        "--format",
        choices=["yaml", "json"],
        default="yaml",
        help="Output format (default: yaml)",
    )

    # policies suggest (AI-powered)
    policies_suggest_parser = policies_subparsers.add_parser(
        "suggest", help="Get AI-powered policy suggestions for a resource type"
    )
    policies_suggest_parser.add_argument(
        "resource_type",
        help="Resource type to get suggestions for (e.g., aws_s3_bucket)",
    )
    policies_suggest_parser.add_argument(
        "--count",
        type=int,
        default=5,
        help="Number of suggestions (default: 5)",
    )
    policies_suggest_parser.add_argument(
        "--llm-provider",
        choices=["anthropic", "openai", "gemini"],
        default="anthropic",
        help="LLM provider to use (default: anthropic)",
    )

    # Also keep backwards compatibility with positional action
    policies_parser.add_argument(
        "action",
        nargs="?",
        choices=["list", "validate"],
        help="Action to perform (deprecated: use subcommands instead)",
    )
    policies_parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        help="Filter by severity",
    )
    policies_parser.add_argument(
        "--framework",
        help="Filter by compliance framework",
    )

    # findings command
    findings_parser = subparsers.add_parser("findings", help="View findings")
    findings_subparsers = findings_parser.add_subparsers(dest="findings_action")

    # findings list (default when no subcommand)
    findings_list_parser = findings_subparsers.add_parser("list", help="List findings")
    findings_list_parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        help="Filter by severity",
    )
    findings_list_parser.add_argument(
        "--status",
        choices=["open", "resolved", "suppressed", "false_positive"],
        help="Filter by status",
    )
    findings_list_parser.add_argument(
        "--asset-id",
        help="Filter by asset ID",
    )
    findings_list_parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )

    # findings explain (AI-powered)
    findings_explain_parser = findings_subparsers.add_parser(
        "explain", help="Get AI-powered explanation for a finding"
    )
    findings_explain_parser.add_argument(
        "finding_id",
        help="Finding ID to explain",
    )
    findings_explain_parser.add_argument(
        "--llm-provider",
        choices=["anthropic", "openai", "gemini"],
        default="anthropic",
        help="LLM provider to use (default: anthropic)",
    )
    findings_explain_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    findings_explain_parser.add_argument(
        "--no-remediation",
        action="store_true",
        help="Skip remediation steps in explanation",
    )

    # Also add direct arguments for backwards compatibility
    findings_parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        help="Filter by severity",
    )
    findings_parser.add_argument(
        "--status",
        choices=["open", "resolved", "suppressed", "false_positive"],
        help="Filter by status",
    )
    findings_parser.add_argument(
        "--asset-id",
        help="Filter by asset ID",
    )
    findings_parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )

    # assets command
    assets_parser = subparsers.add_parser("assets", help="View discovered assets")
    assets_parser.add_argument(
        "--type",
        help="Filter by resource type",
    )
    assets_parser.add_argument(
        "--region",
        help="Filter by region",
    )
    assets_parser.add_argument(
        "--exposure",
        choices=["internet_facing", "internal", "isolated"],
        help="Filter by network exposure",
    )
    assets_parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )

    # dashboard command
    dashboard_parser = subparsers.add_parser("dashboard", help="Start web dashboard")
    dashboard_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to (default: 127.0.0.1)",
    )
    dashboard_parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=8080,
        help="Port to listen on (default: 8080)",
    )
    dashboard_parser.add_argument(
        "-o",
        "--open",
        action="store_true",
        help="Open browser automatically",
    )
    dashboard_parser.add_argument(
        "--no-open",
        action="store_true",
        help="Do not open browser",
    )

    # notify command
    notify_parser = subparsers.add_parser("notify", help="Send notifications for findings")
    notify_parser.add_argument(
        "action",
        choices=["send", "test"],
        nargs="?",
        default="send",
        help="Action to perform (default: send)",
    )
    notify_parser.add_argument(
        "--finding-id",
        help="Specific finding ID to notify about",
    )
    notify_parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        help="Send notifications for findings of this severity",
    )
    notify_parser.add_argument(
        "--destination",
        required=True,
        help="Notification destination (slack, pagerduty, email, teams, jira, webhook)",
    )
    notify_parser.add_argument(
        "--webhook-url",
        help="Webhook URL (for slack, teams, or webhook destinations)",
    )
    notify_parser.add_argument(
        "--config",
        help="Path to alerting configuration file",
    )
    notify_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview notification without sending",
    )

    # schedule command
    schedule_parser = subparsers.add_parser("schedule", help="Manage scheduled scans")
    schedule_subparsers = schedule_parser.add_subparsers(dest="schedule_action")

    # schedule list
    schedule_list_parser = schedule_subparsers.add_parser("list", help="List scheduled jobs")
    schedule_list_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # schedule add
    schedule_add_parser = schedule_subparsers.add_parser("add", help="Add a scheduled job")
    schedule_add_parser.add_argument(
        "--name",
        required=True,
        help="Job name",
    )
    schedule_add_parser.add_argument(
        "--schedule",
        required=True,
        help="Schedule expression (cron or rate format)",
    )
    schedule_add_parser.add_argument(
        "--config",
        default="default",
        help="Scan configuration to use (default: default)",
    )

    # schedule remove
    schedule_remove_parser = schedule_subparsers.add_parser("remove", help="Remove a scheduled job")
    schedule_remove_parser.add_argument(
        "job_id",
        help="Job ID to remove",
    )

    # schedule enable
    schedule_enable_parser = schedule_subparsers.add_parser("enable", help="Enable a scheduled job")
    schedule_enable_parser.add_argument(
        "job_id",
        help="Job ID to enable",
    )

    # schedule disable
    schedule_disable_parser = schedule_subparsers.add_parser("disable", help="Disable a scheduled job")
    schedule_disable_parser.add_argument(
        "job_id",
        help="Job ID to disable",
    )

    # schedule run
    schedule_run_parser = schedule_subparsers.add_parser("run", help="Run a job immediately")
    schedule_run_parser.add_argument(
        "job_id",
        help="Job ID to run",
    )

    # schedule status
    schedule_status_parser = schedule_subparsers.add_parser("status", help="Show scheduler status")
    schedule_status_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # history command
    history_parser = subparsers.add_parser("history", help="View scan history")
    history_subparsers = history_parser.add_subparsers(dest="history_action")

    # history list
    history_list_parser = history_subparsers.add_parser("list", help="List scan history")
    history_list_parser.add_argument(
        "--config",
        default="default",
        help="Configuration name (default: default)",
    )
    history_list_parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Number of entries to show (default: 20)",
    )
    history_list_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # history show
    history_show_parser = history_subparsers.add_parser("show", help="Show scan details")
    history_show_parser.add_argument(
        "scan_id",
        help="Scan ID to show",
    )
    history_show_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # history compare
    history_compare_parser = history_subparsers.add_parser("compare", help="Compare two scans")
    history_compare_parser.add_argument(
        "--baseline",
        help="Baseline scan ID",
    )
    history_compare_parser.add_argument(
        "--current",
        help="Current scan ID",
    )
    history_compare_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # history trend
    history_trend_parser = history_subparsers.add_parser("trend", help="Show trend analysis")
    history_trend_parser.add_argument(
        "--days",
        type=int,
        default=7,
        help="Days to analyze (default: 7)",
    )
    history_trend_parser.add_argument(
        "--config",
        default="default",
        help="Configuration name (default: default)",
    )
    history_trend_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # trends command
    trends_parser = subparsers.add_parser("trends", help="Advanced trend analysis")
    trends_subparsers = trends_parser.add_subparsers(dest="trends_action")

    # trends summary
    trends_summary_parser = trends_subparsers.add_parser("summary", help="Show trend summary")
    trends_summary_parser.add_argument(
        "--days",
        type=int,
        default=30,
        help="Days to analyze (default: 30)",
    )
    trends_summary_parser.add_argument(
        "--config",
        default="default",
        help="Configuration name (default: default)",
    )
    trends_summary_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # trends forecast
    trends_forecast_parser = trends_subparsers.add_parser("forecast", help="Show findings forecast")
    trends_forecast_parser.add_argument(
        "--history-days",
        type=int,
        default=30,
        help="Days of history for model (default: 30)",
    )
    trends_forecast_parser.add_argument(
        "--forecast-days",
        type=int,
        default=7,
        help="Days to forecast (default: 7)",
    )
    trends_forecast_parser.add_argument(
        "--config",
        default="default",
        help="Configuration name (default: default)",
    )
    trends_forecast_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # trends velocity
    trends_velocity_parser = trends_subparsers.add_parser("velocity", help="Show findings velocity")
    trends_velocity_parser.add_argument(
        "--days",
        type=int,
        default=7,
        help="Days to analyze (default: 7)",
    )
    trends_velocity_parser.add_argument(
        "--config",
        default="default",
        help="Configuration name (default: default)",
    )
    trends_velocity_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # trends compare
    trends_compare_parser = trends_subparsers.add_parser("compare", help="Compare periods")
    trends_compare_parser.add_argument(
        "--current-days",
        type=int,
        default=7,
        help="Days in current period (default: 7)",
    )
    trends_compare_parser.add_argument(
        "--previous-days",
        type=int,
        default=7,
        help="Days in previous period (default: 7)",
    )
    trends_compare_parser.add_argument(
        "--config",
        default="default",
        help="Configuration name (default: default)",
    )
    trends_compare_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # shell command
    shell_parser = subparsers.add_parser("shell", help="Start interactive shell")
    shell_parser.add_argument(
        "--storage",
        choices=["local", "s3"],
        default="local",
        help="Storage backend (default: local)",
    )
    shell_parser.add_argument(
        "--llm-provider",
        help="LLM provider for natural language queries",
    )

    # watch command
    watch_parser = subparsers.add_parser("watch", help="Continuous monitoring mode")
    watch_parser.add_argument(
        "--interval",
        "-i",
        type=int,
        default=300,
        help="Seconds between scans (default: 300)",
    )
    watch_parser.add_argument(
        "--collectors",
        "-c",
        help="Comma-separated collectors to run",
    )
    watch_parser.add_argument(
        "--count",
        "-n",
        type=int,
        default=0,
        help="Number of iterations (0 = unlimited)",
    )
    watch_parser.add_argument(
        "--notify",
        action="store_true",
        help="Send notifications on changes",
    )
    watch_parser.add_argument(
        "--no-summary",
        action="store_true",
        help="Don't show scan summary",
    )
    watch_parser.add_argument(
        "--no-diff",
        action="store_true",
        help="Don't show changes from previous scan",
    )
    watch_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # diff command
    diff_parser = subparsers.add_parser("diff", help="Compare findings between snapshots")
    diff_parser.add_argument(
        "--baseline",
        "-b",
        required=True,
        help="Baseline snapshot ID",
    )
    diff_parser.add_argument(
        "--current",
        "-c",
        help="Current snapshot ID (default: latest)",
    )
    diff_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )
    diff_parser.add_argument(
        "--show-unchanged",
        action="store_true",
        help="Include unchanged findings in output",
    )
    diff_parser.add_argument(
        "--fail-on-new",
        action="store_true",
        help="Exit with code 1 if new findings exist",
    )

    # version command
    subparsers.add_parser("version", help="Show version information")

    # image-scan command
    image_scan_parser = subparsers.add_parser(
        "image-scan", help="Scan container images for vulnerabilities"
    )
    image_scan_parser.add_argument(
        "images",
        nargs="+",
        help="Container images to scan (e.g., nginx:latest ghcr.io/org/app:v1)",
    )
    image_scan_parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Timeout per image in seconds (default: 300)",
    )
    image_scan_parser.add_argument(
        "--skip-db-update",
        action="store_true",
        help="Skip vulnerability database update",
    )
    image_scan_parser.add_argument(
        "--ignore-unfixed",
        action="store_true",
        help="Only show vulnerabilities with available fixes",
    )
    image_scan_parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low"],
        help="Minimum severity to report",
    )
    image_scan_parser.add_argument(
        "--format",
        choices=["table", "json", "sarif"],
        default="table",
        help="Output format (default: table)",
    )
    image_scan_parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        help="Exit with code 1 if vulnerabilities at or above this severity exist",
    )

    # iac-scan command
    iac_scan_parser = subparsers.add_parser(
        "iac-scan", help="Scan Infrastructure as Code files for security issues"
    )
    iac_scan_parser.add_argument(
        "paths",
        nargs="+",
        help="Files or directories to scan (Terraform, CloudFormation, ARM)",
    )
    iac_scan_parser.add_argument(
        "--format",
        choices=["table", "json", "sarif"],
        default="table",
        help="Output format (default: table)",
    )
    iac_scan_parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        help="Minimum severity to report",
    )
    iac_scan_parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        help="Exit with code 1 if issues at or above this severity exist",
    )
    iac_scan_parser.add_argument(
        "--policy-dir",
        help="Additional directory containing IaC policies",
    )
    iac_scan_parser.add_argument(
        "--skip-secrets",
        action="store_true",
        help="Skip hardcoded secrets detection",
    )
    iac_scan_parser.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        help="Recursively scan directories",
    )
    iac_scan_parser.add_argument(
        "-o",
        "--output",
        help="Output file path",
    )

    # secrets-scan command
    secrets_scan_parser = subparsers.add_parser(
        "secrets-scan", help="Scan files or configurations for hardcoded secrets"
    )
    secrets_scan_parser.add_argument(
        "paths",
        nargs="+",
        help="Files or directories to scan for secrets",
    )
    secrets_scan_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )
    secrets_scan_parser.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        help="Recursively scan directories",
    )
    secrets_scan_parser.add_argument(
        "--min-entropy",
        type=float,
        default=3.5,
        help="Minimum entropy for high-entropy detection (default: 3.5)",
    )
    secrets_scan_parser.add_argument(
        "--exclude",
        help="Comma-separated patterns to exclude (e.g., '*.lock,node_modules')",
    )
    secrets_scan_parser.add_argument(
        "-o",
        "--output",
        help="Output file path",
    )
    secrets_scan_parser.add_argument(
        "--fail-on-secrets",
        action="store_true",
        help="Exit with code 1 if secrets are found",
    )

    # docs-generate command
    docs_parser = subparsers.add_parser(
        "docs-generate",
        help="Generate API and CLI documentation",
    )
    docs_parser.add_argument(
        "--type",
        choices=["all", "api", "cli", "policies"],
        default="all",
        help="Type of documentation to generate (default: all)",
    )
    docs_parser.add_argument(
        "--source-dir",
        default="src/stance",
        help="Source directory for API docs (default: src/stance)",
    )
    docs_parser.add_argument(
        "--output-dir",
        default="docs/generated",
        help="Output directory for generated docs (default: docs/generated)",
    )
    docs_parser.add_argument(
        "--policies-dir",
        default="policies",
        help="Policies directory for policy docs (default: policies)",
    )

    # dspm command (Data Security Posture Management)
    dspm_parser = subparsers.add_parser(
        "dspm", help="Data Security Posture Management commands"
    )
    dspm_subparsers = dspm_parser.add_subparsers(dest="dspm_action")

    # dspm scan
    dspm_scan_parser = dspm_subparsers.add_parser(
        "scan", help="Scan storage for sensitive data"
    )
    dspm_scan_parser.add_argument(
        "target",
        help="Storage target to scan (bucket name or container)",
    )
    dspm_scan_parser.add_argument(
        "--cloud",
        choices=["aws", "gcp", "azure"],
        required=True,
        help="Cloud provider",
    )
    dspm_scan_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )
    dspm_scan_parser.add_argument(
        "--sample-size",
        type=int,
        default=100,
        help="Number of objects to sample (default: 100)",
    )
    dspm_scan_parser.add_argument(
        "--max-file-size",
        type=int,
        default=10485760,
        help="Maximum file size to scan in bytes (default: 10MB)",
    )
    dspm_scan_parser.add_argument(
        "--include",
        help="Comma-separated patterns to include (e.g., '*.csv,*.json')",
    )
    dspm_scan_parser.add_argument(
        "--exclude",
        help="Comma-separated patterns to exclude (e.g., '*.log,*.tmp')",
    )

    # dspm access
    dspm_access_parser = dspm_subparsers.add_parser(
        "access", help="Analyze data access patterns"
    )
    dspm_access_parser.add_argument(
        "target",
        help="Storage target to analyze",
    )
    dspm_access_parser.add_argument(
        "--cloud",
        choices=["aws", "gcp", "azure"],
        required=True,
        help="Cloud provider",
    )
    dspm_access_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )
    dspm_access_parser.add_argument(
        "--stale-days",
        type=int,
        default=90,
        help="Days without access to consider stale (default: 90)",
    )
    dspm_access_parser.add_argument(
        "--lookback-days",
        type=int,
        default=180,
        help="Days to look back for access logs (default: 180)",
    )

    # dspm cost
    dspm_cost_parser = dspm_subparsers.add_parser(
        "cost", help="Analyze storage costs and cold data"
    )
    dspm_cost_parser.add_argument(
        "target",
        help="Storage target to analyze",
    )
    dspm_cost_parser.add_argument(
        "--cloud",
        choices=["aws", "gcp", "azure"],
        required=True,
        help="Cloud provider",
    )
    dspm_cost_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )
    dspm_cost_parser.add_argument(
        "--cold-days",
        type=int,
        default=90,
        help="Days without access to consider cold (default: 90)",
    )
    dspm_cost_parser.add_argument(
        "--archive-days",
        type=int,
        default=180,
        help="Days to recommend archive tier (default: 180)",
    )
    dspm_cost_parser.add_argument(
        "--delete-days",
        type=int,
        default=365,
        help="Days to recommend deletion (default: 365)",
    )

    # dspm classify
    dspm_classify_parser = dspm_subparsers.add_parser(
        "classify", help="Classify sample text for sensitive content"
    )
    dspm_classify_parser.add_argument(
        "--text",
        help="Text to classify",
    )
    dspm_classify_parser.add_argument(
        "--file",
        help="File path to classify",
    )
    dspm_classify_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # identity command (Identity Security)
    identity_parser = subparsers.add_parser(
        "identity", help="Identity Security commands"
    )
    identity_subparsers = identity_parser.add_subparsers(dest="identity_action")

    # identity who-can-access
    identity_wca_parser = identity_subparsers.add_parser(
        "who-can-access", help="Show who can access a resource"
    )
    identity_wca_parser.add_argument(
        "resource",
        help="Resource ID to analyze (bucket, table, file)",
    )
    identity_wca_parser.add_argument(
        "--cloud",
        choices=["aws", "gcp", "azure"],
        required=True,
        help="Cloud provider",
    )
    identity_wca_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )
    identity_wca_parser.add_argument(
        "--include-users",
        action="store_true",
        default=True,
        help="Include user principals",
    )
    identity_wca_parser.add_argument(
        "--include-roles",
        action="store_true",
        default=True,
        help="Include role principals",
    )
    identity_wca_parser.add_argument(
        "--include-groups",
        action="store_true",
        default=True,
        help="Include group principals",
    )
    identity_wca_parser.add_argument(
        "--include-service-accounts",
        action="store_true",
        default=True,
        help="Include service account principals",
    )

    # identity exposure
    identity_exposure_parser = identity_subparsers.add_parser(
        "exposure", help="Analyze principal exposure to sensitive data"
    )
    identity_exposure_parser.add_argument(
        "principal",
        help="Principal ID to analyze (user, role, service account)",
    )
    identity_exposure_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )
    identity_exposure_parser.add_argument(
        "--classification",
        choices=["public", "internal", "confidential", "restricted"],
        help="Filter by data classification level",
    )

    # identity overprivileged
    identity_op_parser = identity_subparsers.add_parser(
        "overprivileged", help="Find over-privileged principals"
    )
    identity_op_parser.add_argument(
        "--cloud",
        choices=["aws", "gcp", "azure"],
        required=True,
        help="Cloud provider",
    )
    identity_op_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )
    identity_op_parser.add_argument(
        "--days",
        type=int,
        default=90,
        help="Days to analyze for activity (default: 90)",
    )

    # exposure command (Exposure Management)
    exposure_parser = subparsers.add_parser(
        "exposure", help="Exposure Management commands"
    )
    exposure_subparsers = exposure_parser.add_subparsers(dest="exposure_action")

    # exposure inventory
    exposure_inv_parser = exposure_subparsers.add_parser(
        "inventory", help="List publicly accessible assets"
    )
    exposure_inv_parser.add_argument(
        "--cloud",
        choices=["aws", "gcp", "azure"],
        help="Filter by cloud provider",
    )
    exposure_inv_parser.add_argument(
        "--region",
        help="Filter by region",
    )
    exposure_inv_parser.add_argument(
        "--type",
        help="Filter by resource type",
    )
    exposure_inv_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # exposure certificates
    exposure_cert_parser = exposure_subparsers.add_parser(
        "certificates", help="Monitor SSL/TLS certificates"
    )
    exposure_cert_parser.add_argument(
        "--cloud",
        choices=["aws", "gcp", "azure"],
        help="Filter by cloud provider",
    )
    exposure_cert_parser.add_argument(
        "--domain",
        help="Filter by domain",
    )
    exposure_cert_parser.add_argument(
        "--expiring-within",
        type=int,
        default=30,
        help="Show certificates expiring within N days (default: 30)",
    )
    exposure_cert_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # exposure dns
    exposure_dns_parser = exposure_subparsers.add_parser(
        "dns", help="Analyze DNS records for issues"
    )
    exposure_dns_parser.add_argument(
        "--zone",
        help="DNS zone to analyze",
    )
    exposure_dns_parser.add_argument(
        "--cloud",
        choices=["aws", "gcp", "azure"],
        help="Filter by cloud provider",
    )
    exposure_dns_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # exposure sensitive
    exposure_sens_parser = exposure_subparsers.add_parser(
        "sensitive", help="Detect sensitive data exposure in public assets"
    )
    exposure_sens_parser.add_argument(
        "--cloud",
        choices=["aws", "gcp", "azure"],
        help="Filter by cloud provider",
    )
    exposure_sens_parser.add_argument(
        "--classification",
        choices=["public", "internal", "confidential", "restricted"],
        help="Filter by data classification",
    )
    exposure_sens_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # analytics command (Vulnerability Analytics)
    analytics_parser = subparsers.add_parser(
        "analytics", help="Vulnerability analytics commands"
    )
    analytics_subparsers = analytics_parser.add_subparsers(dest="analytics_action")

    # analytics attack-paths
    analytics_ap_parser = analytics_subparsers.add_parser(
        "attack-paths", help="Analyze attack paths in the environment"
    )
    analytics_ap_parser.add_argument(
        "--type",
        choices=[
            "internet_to_internal",
            "privilege_escalation",
            "lateral_movement",
            "data_exfiltration",
            "credential_exposure",
            "data_theft",
            "ransomware_spread",
            "crypto_mining",
            "identity_theft",
        ],
        help="Filter by attack path type",
    )
    analytics_ap_parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        help="Minimum severity to include",
    )
    analytics_ap_parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum number of paths to show (default: 20)",
    )
    analytics_ap_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # analytics risk-score
    analytics_rs_parser = analytics_subparsers.add_parser(
        "risk-score", help="Calculate risk scores for assets"
    )
    analytics_rs_parser.add_argument(
        "--asset-id",
        help="Specific asset ID to score",
    )
    analytics_rs_parser.add_argument(
        "--min-score",
        type=float,
        help="Minimum risk score to include",
    )
    analytics_rs_parser.add_argument(
        "--level",
        choices=["critical", "high", "medium", "low", "minimal"],
        help="Filter by risk level",
    )
    analytics_rs_parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum number of assets to show (default: 20)",
    )
    analytics_rs_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # analytics blast-radius
    analytics_br_parser = analytics_subparsers.add_parser(
        "blast-radius", help="Calculate blast radius for findings"
    )
    analytics_br_parser.add_argument(
        "--finding-id",
        help="Specific finding ID to analyze",
    )
    analytics_br_parser.add_argument(
        "--category",
        choices=[
            "data_exposure",
            "service_disruption",
            "credential_compromise",
            "compliance_violation",
            "lateral_movement",
            "privilege_escalation",
        ],
        help="Filter by impact category",
    )
    analytics_br_parser.add_argument(
        "--min-score",
        type=float,
        help="Minimum blast radius score to include",
    )
    analytics_br_parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum number of findings to show (default: 20)",
    )
    analytics_br_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # analytics mitre
    analytics_mitre_parser = analytics_subparsers.add_parser(
        "mitre", help="Map findings to MITRE ATT&CK framework"
    )
    analytics_mitre_parser.add_argument(
        "--finding-id",
        help="Specific finding ID to map",
    )
    analytics_mitre_parser.add_argument(
        "--technique",
        help="Show details for a specific technique ID (e.g., T1078)",
    )
    analytics_mitre_parser.add_argument(
        "--tactic",
        choices=[
            "reconnaissance",
            "resource_development",
            "initial_access",
            "execution",
            "persistence",
            "privilege_escalation",
            "defense_evasion",
            "credential_access",
            "discovery",
            "lateral_movement",
            "collection",
            "exfiltration",
            "impact",
        ],
        help="Filter by MITRE ATT&CK tactic",
    )
    analytics_mitre_parser.add_argument(
        "--coverage",
        action="store_true",
        help="Show ATT&CK coverage summary instead of individual mappings",
    )
    analytics_mitre_parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum number of mappings to show (default: 20)",
    )
    analytics_mitre_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # drift command (Drift Detection)
    drift_parser = subparsers.add_parser(
        "drift", help="Drift detection and baseline management"
    )
    drift_subparsers = drift_parser.add_subparsers(dest="drift_action")

    # drift detect
    drift_detect_parser = drift_subparsers.add_parser(
        "detect", help="Detect configuration drift from baseline"
    )
    drift_detect_parser.add_argument(
        "--baseline",
        help="Baseline ID to compare against (default: active baseline)",
    )
    drift_detect_parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        help="Minimum severity to include",
    )
    drift_detect_parser.add_argument(
        "--type",
        help="Filter by asset type",
    )
    drift_detect_parser.add_argument(
        "--cloud",
        choices=["aws", "gcp", "azure"],
        help="Filter by cloud provider",
    )
    drift_detect_parser.add_argument(
        "--region",
        help="Filter by region",
    )
    drift_detect_parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum number of drift events to show (default: 50)",
    )
    drift_detect_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # drift baseline (with nested subcommands)
    drift_baseline_parser = drift_subparsers.add_parser(
        "baseline", help="Manage configuration baselines"
    )
    drift_baseline_subparsers = drift_baseline_parser.add_subparsers(dest="baseline_action")

    # drift baseline create
    baseline_create_parser = drift_baseline_subparsers.add_parser(
        "create", help="Create a new baseline from current assets"
    )
    baseline_create_parser.add_argument(
        "--name",
        required=True,
        help="Baseline name",
    )
    baseline_create_parser.add_argument(
        "--description",
        default="",
        help="Baseline description",
    )
    baseline_create_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # drift baseline list
    baseline_list_parser = drift_baseline_subparsers.add_parser(
        "list", help="List all baselines"
    )
    baseline_list_parser.add_argument(
        "--status",
        choices=["active", "archived", "draft"],
        help="Filter by status",
    )
    baseline_list_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # drift baseline show
    baseline_show_parser = drift_baseline_subparsers.add_parser(
        "show", help="Show details for a specific baseline"
    )
    baseline_show_parser.add_argument(
        "id",
        help="Baseline ID to show",
    )
    baseline_show_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # drift baseline update
    baseline_update_parser = drift_baseline_subparsers.add_parser(
        "update", help="Update a baseline with current asset configurations"
    )
    baseline_update_parser.add_argument(
        "id",
        help="Baseline ID to update",
    )
    baseline_update_parser.add_argument(
        "--assets",
        help="Comma-separated asset IDs to update (default: all)",
    )
    baseline_update_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # drift baseline archive
    baseline_archive_parser = drift_baseline_subparsers.add_parser(
        "archive", help="Archive a baseline"
    )
    baseline_archive_parser.add_argument(
        "id",
        help="Baseline ID to archive",
    )
    baseline_archive_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # drift baseline delete
    baseline_delete_parser = drift_baseline_subparsers.add_parser(
        "delete", help="Delete a baseline"
    )
    baseline_delete_parser.add_argument(
        "id",
        help="Baseline ID to delete",
    )
    baseline_delete_parser.add_argument(
        "--force",
        action="store_true",
        help="Force deletion without confirmation",
    )
    baseline_delete_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # drift history
    drift_history_parser = drift_subparsers.add_parser(
        "history", help="View change history for a specific asset"
    )
    drift_history_parser.add_argument(
        "--asset-id",
        required=True,
        help="Asset ID to view history for",
    )
    drift_history_parser.add_argument(
        "--days",
        type=int,
        default=30,
        help="Number of days to show (default: 30)",
    )
    drift_history_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # drift changes
    drift_changes_parser = drift_subparsers.add_parser(
        "changes", help="View recent configuration changes"
    )
    drift_changes_parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="Hours to look back (default: 24)",
    )
    drift_changes_parser.add_argument(
        "--type",
        choices=["created", "updated", "deleted", "restored"],
        help="Filter by change type",
    )
    drift_changes_parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum number of changes to show (default: 50)",
    )
    drift_changes_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # drift summary
    drift_summary_parser = drift_subparsers.add_parser(
        "summary", help="Show comprehensive drift detection summary"
    )
    drift_summary_parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="Hours to analyze for recent changes (default: 24)",
    )
    drift_summary_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # enrich command (Data Enrichment)
    enrich_parser = subparsers.add_parser(
        "enrich", help="Enrich findings and assets with threat intelligence"
    )
    enrich_subparsers = enrich_parser.add_subparsers(dest="enrich_action")

    # enrich findings
    enrich_findings_parser = enrich_subparsers.add_parser(
        "findings", help="Enrich findings with threat intelligence and CVE details"
    )
    enrich_findings_parser.add_argument(
        "--finding-id",
        help="Specific finding ID to enrich (shows detailed output)",
    )
    enrich_findings_parser.add_argument(
        "--types",
        help="Comma-separated enrichment types (cve, kev, vuln, threat)",
    )
    enrich_findings_parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum number of findings to enrich (default: 50)",
    )
    enrich_findings_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # enrich assets
    enrich_assets_parser = enrich_subparsers.add_parser(
        "assets", help="Enrich assets with context and IP information"
    )
    enrich_assets_parser.add_argument(
        "--asset-id",
        help="Specific asset ID to enrich (shows detailed output)",
    )
    enrich_assets_parser.add_argument(
        "--types",
        help="Comma-separated enrichment types (ip, geo, cloud, context, tags)",
    )
    enrich_assets_parser.add_argument(
        "--cloud",
        choices=["aws", "gcp", "azure"],
        help="Filter by cloud provider",
    )
    enrich_assets_parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum number of assets to enrich (default: 50)",
    )
    enrich_assets_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # enrich ip
    enrich_ip_parser = enrich_subparsers.add_parser(
        "ip", help="Look up information for a specific IP address"
    )
    enrich_ip_parser.add_argument(
        "ip",
        help="IP address to look up",
    )
    enrich_ip_parser.add_argument(
        "--no-geoip",
        action="store_true",
        help="Disable GeoIP lookup (only show cloud provider)",
    )
    enrich_ip_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # enrich cve
    enrich_cve_parser = enrich_subparsers.add_parser(
        "cve", help="Look up information for a specific CVE"
    )
    enrich_cve_parser.add_argument(
        "cve",
        help="CVE ID to look up (e.g., CVE-2021-44228)",
    )
    enrich_cve_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # enrich kev
    enrich_kev_parser = enrich_subparsers.add_parser(
        "kev", help="Check if CVE is in CISA KEV catalog"
    )
    enrich_kev_parser.add_argument(
        "cve",
        nargs="?",
        help="CVE ID to check (e.g., CVE-2021-44228)",
    )
    enrich_kev_parser.add_argument(
        "--list",
        action="store_true",
        help="List all KEV entries",
    )
    enrich_kev_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # enrich status
    enrich_status_parser = enrich_subparsers.add_parser(
        "status", help="Show enrichment capabilities and availability"
    )
    enrich_status_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # aggregation command (Multi-cloud Aggregation)
    add_aggregation_parser(subparsers)

    # sql command (Query Engine)
    add_sql_parser(subparsers)

    # plugins command (Plugin Management)
    add_plugins_parser(subparsers)

    # exceptions command (Policy Exceptions)
    add_exceptions_parser(subparsers)

    # notifications command (Automation/Notifications)
    add_notifications_parser(subparsers)


    # alerting command (Alert Routing and Notifications)
    add_alerting_parser(subparsers)

    # automation command (Notification Automation and Workflows)
    add_automation_parser(subparsers)

    # iac command (Infrastructure as Code Scanning)
    add_iac_parser(subparsers)

    # engine command (Policy Engine)
    add_engine_parser(subparsers)

    # storage command (Storage Backend Management)
    add_storage_parser(subparsers)

    # llm command (AI-powered features)
    add_llm_parser(subparsers)

    # detection command (Secrets detection)
    add_detection_parser(subparsers)

    # scanner command (Container image scanning)
    add_scanner_parser(subparsers)

    # export command (Report generation and data export)
    add_export_parser(subparsers)

    # reporting command (Trend analysis and security reporting)
    add_reporting_parser(subparsers)

    # observability command (Logging, metrics, and tracing)
    add_observability_parser(subparsers)

    # scanning command (Multi-account scanning orchestration)
    add_scanning_parser(subparsers)

    # state command (State management for scans, checkpoints, findings)
    add_state_parser(subparsers)

    # collectors command (Cloud resource collector management)
    add_collectors_parser(subparsers)

    # cloud command (Cloud provider management)
    add_cloud_parser(subparsers)

    # config command (Configuration management)
    add_config_parser(subparsers)

    # docs command (Documentation management)
    add_docs_parser(subparsers)

    # sbom command (SBOM and supply chain security)
    add_sbom_parser(subparsers)

    # api-security command (API security testing)
    add_api_security_parser(subparsers)

    # dashboards command (Advanced Reporting & Dashboards)
    add_dashboards_parser(subparsers)

    # auth command (API Gateway & Authentication)
    add_auth_parser(subparsers)

    # ciem command (Cloud Infrastructure Entitlement Management)
    add_ciem_parser(subparsers)

    # benchmark command (CIS Benchmarks)
    add_benchmark_parser(subparsers)

    return parser


def main() -> int:
    """Main entry point for the CLI."""
    parser = create_parser()
    args = parser.parse_args()

    # Configure logging based on verbosity
    if hasattr(args, "verbose") and args.verbose:
        level = logging.DEBUG if args.verbose > 1 else logging.INFO
        logging.basicConfig(
            level=level,
            format="%(levelname)s: %(message)s",
        )

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "version":
        print(f"Mantissa Stance version {__version__}")
        return 0

    # Route to command handlers
    command_handlers = {
        "scan": cmd_scan,
        "query": cmd_query,
        "report": cmd_report,
        "policies": cmd_policies,
        "findings": cmd_findings,
        "assets": cmd_assets,
        "dashboard": cmd_dashboard,
        "notify": cmd_notify,
        "schedule": cmd_schedule,
        "history": cmd_history,
        "trends": cmd_trends,
        "shell": cmd_shell,
        "watch": cmd_watch,
        "diff": cmd_diff,
        "image-scan": cmd_image_scan,
        "iac-scan": cmd_iac_scan,
        "secrets-scan": cmd_secrets_scan,
        "docs-generate": cmd_docs_generate,
        "dspm": cmd_dspm,
        "identity": cmd_identity,
        "exposure": cmd_exposure,
        "analytics": cmd_analytics,
        "drift": cmd_drift,
        "enrich": cmd_enrich,
        "aggregation": cmd_aggregation,
        "sql": cmd_sql,
        "plugins": cmd_plugins,
        "exceptions": cmd_exceptions,
        "notifications": cmd_notifications,
        "alerting": cmd_alerting,
        "automation": cmd_automation,
        "iac": cmd_iac,
        "engine": cmd_engine,
        "storage": cmd_storage,
        "llm": cmd_llm,
        "detection": cmd_detection,
        "scanner": cmd_scanner,
        "export": cmd_export,
        "reporting": cmd_reporting,
        "observability": cmd_observability,
        "scanning": cmd_scanning,
        "state": cmd_state,
        "collectors": cmd_collectors,
        "cloud": cmd_cloud,
        "config": cmd_config,
        "docs": cmd_docs,
        "sbom": cmd_sbom,
        "api-security": cmd_api_security,
        "dashboards": cmd_dashboards,
        "auth": cmd_auth,
        "ciem": cmd_ciem,
        "benchmark": cmd_benchmark,
    }

    handler = command_handlers.get(args.command)
    if handler:
        return handler(args)

    print(f"Unknown command: {args.command}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
