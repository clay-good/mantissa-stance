"""
CLI commands for State module.

Provides command-line interface for state management:
- Scan history tracking and viewing
- Checkpoint management for incremental scans
- Finding lifecycle tracking
- State export and import
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta
from typing import Any


def add_state_parser(subparsers: Any) -> None:
    """Add state parser to CLI subparsers."""
    state_parser = subparsers.add_parser(
        "state",
        help="State management for scans, checkpoints, and findings",
        description="Manage scan history, checkpoints, and finding lifecycle",
    )

    state_subparsers = state_parser.add_subparsers(
        dest="state_action",
        help="State action to perform",
    )

    # scans - List scan history
    scans_parser = state_subparsers.add_parser(
        "scans",
        help="List scan history",
    )
    scans_parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum number of scans to show (default: 20)",
    )
    scans_parser.add_argument(
        "--status",
        choices=["pending", "running", "completed", "failed", "cancelled"],
        help="Filter by scan status",
    )
    scans_parser.add_argument(
        "--days",
        type=int,
        help="Show scans from last N days",
    )
    scans_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # scan - Show specific scan details
    scan_parser = state_subparsers.add_parser(
        "scan",
        help="Show details for a specific scan",
    )
    scan_parser.add_argument(
        "scan_id",
        help="Scan ID to show",
    )
    scan_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # checkpoints - List checkpoints
    checkpoints_parser = state_subparsers.add_parser(
        "checkpoints",
        help="List saved checkpoints",
    )
    checkpoints_parser.add_argument(
        "--collector",
        help="Filter by collector name",
    )
    checkpoints_parser.add_argument(
        "--account",
        help="Filter by account ID",
    )
    checkpoints_parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum number of checkpoints to show (default: 50)",
    )
    checkpoints_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # checkpoint - Show specific checkpoint
    checkpoint_parser = state_subparsers.add_parser(
        "checkpoint",
        help="Show checkpoint details",
    )
    checkpoint_parser.add_argument(
        "--collector",
        required=True,
        help="Collector name",
    )
    checkpoint_parser.add_argument(
        "--account",
        required=True,
        help="Account ID",
    )
    checkpoint_parser.add_argument(
        "--region",
        required=True,
        help="Region",
    )
    checkpoint_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # delete-checkpoint - Delete a checkpoint
    del_checkpoint_parser = state_subparsers.add_parser(
        "delete-checkpoint",
        help="Delete a checkpoint",
    )
    del_checkpoint_parser.add_argument(
        "--collector",
        required=True,
        help="Collector name",
    )
    del_checkpoint_parser.add_argument(
        "--account",
        required=True,
        help="Account ID",
    )
    del_checkpoint_parser.add_argument(
        "--region",
        required=True,
        help="Region",
    )
    del_checkpoint_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # findings - List finding states
    findings_parser = state_subparsers.add_parser(
        "findings",
        help="List finding lifecycle states",
    )
    findings_parser.add_argument(
        "--asset-id",
        dest="asset_id",
        help="Filter by asset ID",
    )
    findings_parser.add_argument(
        "--lifecycle",
        choices=["new", "recurring", "resolved", "reopened", "suppressed", "false_positive"],
        help="Filter by lifecycle state",
    )
    findings_parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum number of findings to show (default: 50)",
    )
    findings_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # finding - Show specific finding state
    finding_parser = state_subparsers.add_parser(
        "finding",
        help="Show finding lifecycle details",
    )
    finding_parser.add_argument(
        "finding_id",
        help="Finding ID to show",
    )
    finding_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # suppress - Suppress a finding
    suppress_parser = state_subparsers.add_parser(
        "suppress",
        help="Suppress a finding",
    )
    suppress_parser.add_argument(
        "finding_id",
        help="Finding ID to suppress",
    )
    suppress_parser.add_argument(
        "--by",
        required=True,
        help="User or system performing suppression",
    )
    suppress_parser.add_argument(
        "--reason",
        default="",
        help="Reason for suppression",
    )
    suppress_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # resolve - Resolve a finding
    resolve_parser = state_subparsers.add_parser(
        "resolve",
        help="Mark a finding as resolved",
    )
    resolve_parser.add_argument(
        "finding_id",
        help="Finding ID to resolve",
    )
    resolve_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # scan-statuses - List scan statuses
    scan_statuses_parser = state_subparsers.add_parser(
        "scan-statuses",
        help="List available scan statuses",
    )
    scan_statuses_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # lifecycles - List finding lifecycle states
    lifecycles_parser = state_subparsers.add_parser(
        "lifecycles",
        help="List finding lifecycle states",
    )
    lifecycles_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # backends - List state backends
    backends_parser = state_subparsers.add_parser(
        "backends",
        help="List available state backends",
    )
    backends_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # finding-stats - Show finding statistics
    finding_stats_parser = state_subparsers.add_parser(
        "finding-stats",
        help="Show finding statistics by lifecycle",
    )
    finding_stats_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # stats - Show state statistics
    stats_parser = state_subparsers.add_parser(
        "stats",
        help="Show state module statistics",
    )
    stats_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # status - Show state module status
    status_parser = state_subparsers.add_parser(
        "status",
        help="Show state module status",
    )
    status_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # summary - Get comprehensive state summary
    summary_parser = state_subparsers.add_parser(
        "summary",
        help="Get comprehensive state summary",
    )
    summary_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )


def cmd_state(args: argparse.Namespace) -> int:
    """Handle state commands."""
    action = getattr(args, "state_action", None)

    if not action:
        print("Usage: stance state <action>")
        print("\nAvailable actions:")
        print("  scans            List scan history")
        print("  scan             Show specific scan details")
        print("  checkpoints      List saved checkpoints")
        print("  checkpoint       Show checkpoint details")
        print("  delete-checkpoint  Delete a checkpoint")
        print("  findings         List finding lifecycle states")
        print("  finding          Show finding lifecycle details")
        print("  suppress         Suppress a finding")
        print("  resolve          Mark a finding as resolved")
        print("  scan-statuses    List available scan statuses")
        print("  lifecycles       List finding lifecycle states")
        print("  backends         List available state backends")
        print("  finding-stats    Show finding statistics by lifecycle")
        print("  stats            Show state module statistics")
        print("  status           Show state module status")
        print("  summary          Get comprehensive state summary")
        return 1

    handlers = {
        "scans": _handle_scans,
        "scan": _handle_scan,
        "checkpoints": _handle_checkpoints,
        "checkpoint": _handle_checkpoint,
        "delete-checkpoint": _handle_delete_checkpoint,
        "findings": _handle_findings,
        "finding": _handle_finding,
        "suppress": _handle_suppress,
        "resolve": _handle_resolve,
        "scan-statuses": _handle_scan_statuses,
        "lifecycles": _handle_lifecycles,
        "backends": _handle_backends,
        "finding-stats": _handle_finding_stats,
        "stats": _handle_stats,
        "status": _handle_status,
        "summary": _handle_summary,
    }

    handler = handlers.get(action)
    if handler:
        return handler(args)

    print(f"Unknown state action: {action}")
    return 1


def _handle_scans(args: argparse.Namespace) -> int:
    """Handle scans command."""
    from stance.state import ScanStatus, get_state_manager

    output_format = getattr(args, "format", "table")
    limit = getattr(args, "limit", 20)
    status_filter = getattr(args, "status", None)
    days = getattr(args, "days", None)

    try:
        manager = get_state_manager()

        # Parse status filter
        status = ScanStatus(status_filter) if status_filter else None
        since = datetime.utcnow() - timedelta(days=days) if days else None

        scans = manager.backend.list_scans(limit=limit, status=status, since=since)

        if output_format == "json":
            print(json.dumps([s.to_dict() for s in scans], indent=2, default=str))
        else:
            if not scans:
                print("No scans found")
                return 0

            print(f"\nScan History ({len(scans)} scans)")
            print("=" * 100)
            print(f"{'Scan ID':<20} {'Status':<12} {'Started':<20} {'Duration':<10} {'Assets':<8} {'Findings':<8}")
            print("-" * 100)

            for scan in scans:
                duration = f"{scan.duration_seconds:.1f}s" if scan.duration_seconds else "-"
                started = scan.started_at.strftime("%Y-%m-%d %H:%M:%S")
                print(f"{scan.scan_id:<20} {scan.status.value:<12} {started:<20} {duration:<10} {scan.asset_count:<8} {scan.finding_count:<8}")

        return 0
    except Exception as e:
        print(f"Error listing scans: {e}")
        return 1


def _handle_scan(args: argparse.Namespace) -> int:
    """Handle scan command."""
    from stance.state import get_state_manager

    output_format = getattr(args, "format", "table")
    scan_id = args.scan_id

    try:
        manager = get_state_manager()
        scan = manager.backend.get_scan(scan_id)

        if not scan:
            print(f"Scan not found: {scan_id}")
            return 1

        if output_format == "json":
            print(json.dumps(scan.to_dict(), indent=2, default=str))
        else:
            print(f"\nScan Details: {scan_id}")
            print("=" * 60)
            print(f"Status:       {scan.status.value}")
            print(f"Snapshot ID:  {scan.snapshot_id}")
            print(f"Config:       {scan.config_name}")
            print(f"Account:      {scan.account_id or 'N/A'}")
            print(f"Region:       {scan.region or 'N/A'}")
            print(f"Started:      {scan.started_at.isoformat()}")
            print(f"Completed:    {scan.completed_at.isoformat() if scan.completed_at else 'N/A'}")
            print(f"Duration:     {scan.duration_seconds:.1f}s" if scan.duration_seconds else "Duration:     N/A")
            print(f"Assets:       {scan.asset_count}")
            print(f"Findings:     {scan.finding_count}")
            if scan.collectors:
                print(f"Collectors:   {', '.join(scan.collectors)}")
            if scan.error_message:
                print(f"Error:        {scan.error_message}")
            if scan.metadata:
                print(f"Metadata:     {json.dumps(scan.metadata)}")

        return 0
    except Exception as e:
        print(f"Error getting scan: {e}")
        return 1


def _handle_checkpoints(args: argparse.Namespace) -> int:
    """Handle checkpoints command."""
    output_format = getattr(args, "format", "table")
    collector_filter = getattr(args, "collector", None)
    account_filter = getattr(args, "account", None)

    # Get checkpoints by querying the database directly (not exposed in manager API)
    checkpoints = _get_all_checkpoints()

    # Apply filters
    if collector_filter:
        checkpoints = [c for c in checkpoints if c.get("collector_name") == collector_filter]
    if account_filter:
        checkpoints = [c for c in checkpoints if c.get("account_id") == account_filter]

    if output_format == "json":
        print(json.dumps(checkpoints, indent=2, default=str))
    else:
        if not checkpoints:
            print("No checkpoints found")
            return 0

        print(f"\nCheckpoints ({len(checkpoints)} saved)")
        print("=" * 100)
        print(f"{'Checkpoint ID':<18} {'Collector':<20} {'Account':<15} {'Region':<15} {'Last Scan':<20}")
        print("-" * 100)

        for cp in checkpoints:
            last_scan_time = cp.get("last_scan_time", "")
            if isinstance(last_scan_time, str) and last_scan_time:
                try:
                    dt = datetime.fromisoformat(last_scan_time)
                    last_scan_time = dt.strftime("%Y-%m-%d %H:%M")
                except ValueError:
                    pass
            print(f"{cp.get('checkpoint_id', ''):<18} {cp.get('collector_name', ''):<20} {cp.get('account_id', ''):<15} {cp.get('region', ''):<15} {last_scan_time:<20}")

    return 0


def _get_all_checkpoints() -> list[dict[str, Any]]:
    """Get all checkpoints from the backend."""
    import os
    import sqlite3
    from pathlib import Path

    db_path = os.path.expanduser("~/.stance/state.db")
    if not Path(db_path).exists():
        return []

    checkpoints = []
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM checkpoints ORDER BY last_scan_time DESC")
            for row in cursor.fetchall():
                checkpoints.append({
                    "checkpoint_id": row["checkpoint_id"],
                    "collector_name": row["collector_name"],
                    "account_id": row["account_id"],
                    "region": row["region"],
                    "last_scan_id": row["last_scan_id"],
                    "last_scan_time": row["last_scan_time"],
                    "cursor": row["cursor"],
                    "metadata": json.loads(row["metadata"]) if row["metadata"] else {},
                })
    except Exception:
        pass

    return checkpoints


def _handle_checkpoint(args: argparse.Namespace) -> int:
    """Handle checkpoint command."""
    from stance.state import get_state_manager

    output_format = getattr(args, "format", "table")
    collector = args.collector
    account = args.account
    region = args.region

    try:
        manager = get_state_manager()
        checkpoint = manager.get_checkpoint(collector, account, region)

        if not checkpoint:
            print(f"Checkpoint not found for {collector}/{account}/{region}")
            return 1

        if output_format == "json":
            print(json.dumps(checkpoint.to_dict(), indent=2, default=str))
        else:
            print(f"\nCheckpoint Details")
            print("=" * 60)
            print(f"Checkpoint ID:  {checkpoint.checkpoint_id}")
            print(f"Collector:      {checkpoint.collector_name}")
            print(f"Account:        {checkpoint.account_id}")
            print(f"Region:         {checkpoint.region}")
            print(f"Last Scan ID:   {checkpoint.last_scan_id}")
            print(f"Last Scan Time: {checkpoint.last_scan_time.isoformat()}")
            if checkpoint.cursor:
                print(f"Cursor:         {checkpoint.cursor}")
            if checkpoint.metadata:
                print(f"Metadata:       {json.dumps(checkpoint.metadata)}")

        return 0
    except Exception as e:
        print(f"Error getting checkpoint: {e}")
        return 1


def _handle_delete_checkpoint(args: argparse.Namespace) -> int:
    """Handle delete-checkpoint command."""
    from stance.state import get_state_manager

    output_format = getattr(args, "format", "table")
    collector = args.collector
    account = args.account
    region = args.region

    try:
        manager = get_state_manager()
        deleted = manager.backend.delete_checkpoint(collector, account, region)

        result = {
            "deleted": deleted,
            "collector": collector,
            "account": account,
            "region": region,
        }

        if output_format == "json":
            print(json.dumps(result, indent=2))
        else:
            if deleted:
                print(f"Checkpoint deleted for {collector}/{account}/{region}")
            else:
                print(f"Checkpoint not found for {collector}/{account}/{region}")

        return 0 if deleted else 1
    except Exception as e:
        print(f"Error deleting checkpoint: {e}")
        return 1


def _handle_findings(args: argparse.Namespace) -> int:
    """Handle findings command."""
    from stance.state import FindingLifecycle, get_state_manager

    output_format = getattr(args, "format", "table")
    asset_id = getattr(args, "asset_id", None)
    lifecycle_filter = getattr(args, "lifecycle", None)
    limit = getattr(args, "limit", 50)

    try:
        manager = get_state_manager()

        lifecycle = FindingLifecycle(lifecycle_filter) if lifecycle_filter else None
        findings = manager.backend.list_finding_states(
            asset_id=asset_id,
            lifecycle=lifecycle,
            limit=limit,
        )

        if output_format == "json":
            print(json.dumps([f.to_dict() for f in findings], indent=2, default=str))
        else:
            if not findings:
                print("No findings found")
                return 0

            print(f"\nFinding States ({len(findings)} findings)")
            print("=" * 110)
            print(f"{'Finding ID':<20} {'Lifecycle':<14} {'First Seen':<20} {'Last Seen':<20} {'Scans':<6} {'Rule ID':<20}")
            print("-" * 110)

            for finding in findings:
                first_seen = finding.first_seen.strftime("%Y-%m-%d %H:%M")
                last_seen = finding.last_seen.strftime("%Y-%m-%d %H:%M")
                rule_id = finding.rule_id[:18] + ".." if len(finding.rule_id) > 20 else finding.rule_id
                print(f"{finding.finding_id:<20} {finding.lifecycle.value:<14} {first_seen:<20} {last_seen:<20} {finding.scan_count:<6} {rule_id:<20}")

        return 0
    except Exception as e:
        print(f"Error listing findings: {e}")
        return 1


def _handle_finding(args: argparse.Namespace) -> int:
    """Handle finding command."""
    from stance.state import get_state_manager

    output_format = getattr(args, "format", "table")
    finding_id = args.finding_id

    try:
        manager = get_state_manager()
        state = manager.backend.get_finding_state(finding_id)

        if not state:
            print(f"Finding not found: {finding_id}")
            return 1

        if output_format == "json":
            print(json.dumps(state.to_dict(), indent=2, default=str))
        else:
            print(f"\nFinding State: {finding_id}")
            print("=" * 60)
            print(f"Lifecycle:     {state.lifecycle.value}")
            print(f"Asset ID:      {state.asset_id}")
            print(f"Rule ID:       {state.rule_id}")
            print(f"First Seen:    {state.first_seen.isoformat()}")
            print(f"Last Seen:     {state.last_seen.isoformat()}")
            print(f"Scan Count:    {state.scan_count}")
            if state.resolved_at:
                print(f"Resolved At:   {state.resolved_at.isoformat()}")
            if state.suppressed_by:
                print(f"Suppressed By: {state.suppressed_by}")
                print(f"Suppressed At: {state.suppressed_at.isoformat() if state.suppressed_at else 'N/A'}")
                print(f"Suppression Reason: {state.suppression_reason or 'N/A'}")
            if state.notes:
                print(f"Notes:         {', '.join(state.notes)}")

        return 0
    except Exception as e:
        print(f"Error getting finding: {e}")
        return 1


def _handle_suppress(args: argparse.Namespace) -> int:
    """Handle suppress command."""
    from stance.state import get_state_manager

    output_format = getattr(args, "format", "table")
    finding_id = args.finding_id
    suppressed_by = args.by
    reason = getattr(args, "reason", "")

    try:
        manager = get_state_manager()
        state = manager.suppress_finding(finding_id, suppressed_by, reason)

        if not state:
            print(f"Finding not found: {finding_id}")
            return 1

        result = {
            "suppressed": True,
            "finding_id": finding_id,
            "suppressed_by": suppressed_by,
            "reason": reason,
            "lifecycle": state.lifecycle.value,
        }

        if output_format == "json":
            print(json.dumps(result, indent=2))
        else:
            print(f"Finding {finding_id} suppressed")
            print(f"  Suppressed by: {suppressed_by}")
            if reason:
                print(f"  Reason: {reason}")

        return 0
    except Exception as e:
        print(f"Error suppressing finding: {e}")
        return 1


def _handle_resolve(args: argparse.Namespace) -> int:
    """Handle resolve command."""
    from stance.state import get_state_manager

    output_format = getattr(args, "format", "table")
    finding_id = args.finding_id

    try:
        manager = get_state_manager()
        state = manager.resolve_finding(finding_id)

        if not state:
            print(f"Finding not found: {finding_id}")
            return 1

        result = {
            "resolved": True,
            "finding_id": finding_id,
            "lifecycle": state.lifecycle.value,
            "resolved_at": state.resolved_at.isoformat() if state.resolved_at else None,
        }

        if output_format == "json":
            print(json.dumps(result, indent=2, default=str))
        else:
            print(f"Finding {finding_id} marked as resolved")

        return 0
    except Exception as e:
        print(f"Error resolving finding: {e}")
        return 1


def _handle_scan_statuses(args: argparse.Namespace) -> int:
    """Handle scan-statuses command."""
    from stance.state import ScanStatus

    output_format = getattr(args, "format", "table")

    statuses = [
        {
            "status": ScanStatus.PENDING.value,
            "description": "Scan is queued but not yet started",
            "indicator": "[.]",
        },
        {
            "status": ScanStatus.RUNNING.value,
            "description": "Scan is currently in progress",
            "indicator": "[>]",
        },
        {
            "status": ScanStatus.COMPLETED.value,
            "description": "Scan completed successfully",
            "indicator": "[+]",
        },
        {
            "status": ScanStatus.FAILED.value,
            "description": "Scan failed with error",
            "indicator": "[!]",
        },
        {
            "status": ScanStatus.CANCELLED.value,
            "description": "Scan was cancelled",
            "indicator": "[x]",
        },
    ]

    if output_format == "json":
        print(json.dumps(statuses, indent=2))
    else:
        print("\nScan Statuses")
        print("=" * 70)
        print(f"{'Status':<12} {'Indicator':<12} {'Description':<40}")
        print("-" * 70)
        for s in statuses:
            print(f"{s['status']:<12} {s['indicator']:<12} {s['description']:<40}")

    return 0


def _handle_lifecycles(args: argparse.Namespace) -> int:
    """Handle lifecycles command."""
    from stance.state import FindingLifecycle

    output_format = getattr(args, "format", "table")

    lifecycles = [
        {
            "lifecycle": FindingLifecycle.NEW.value,
            "description": "First time this finding was seen",
            "action": "Investigate and remediate",
        },
        {
            "lifecycle": FindingLifecycle.RECURRING.value,
            "description": "Seen again in subsequent scans",
            "action": "Continue remediation",
        },
        {
            "lifecycle": FindingLifecycle.RESOLVED.value,
            "description": "No longer detected in scans",
            "action": "Verify fix is complete",
        },
        {
            "lifecycle": FindingLifecycle.REOPENED.value,
            "description": "Was resolved but detected again",
            "action": "Investigate regression",
        },
        {
            "lifecycle": FindingLifecycle.SUPPRESSED.value,
            "description": "Manually suppressed by user",
            "action": "Review periodically",
        },
        {
            "lifecycle": FindingLifecycle.FALSE_POSITIVE.value,
            "description": "Marked as not a real issue",
            "action": "Consider policy tuning",
        },
    ]

    if output_format == "json":
        print(json.dumps(lifecycles, indent=2))
    else:
        print("\nFinding Lifecycle States")
        print("=" * 90)
        print(f"{'Lifecycle':<16} {'Description':<35} {'Recommended Action':<35}")
        print("-" * 90)
        for lc in lifecycles:
            print(f"{lc['lifecycle']:<16} {lc['description']:<35} {lc['action']:<35}")

    return 0


def _handle_backends(args: argparse.Namespace) -> int:
    """Handle backends command."""
    output_format = getattr(args, "format", "table")

    backends = [
        {
            "backend": "local",
            "type": "SQLite",
            "description": "Local file-based state storage",
            "available": True,
            "default": True,
            "path": "~/.stance/state.db",
        },
        {
            "backend": "dynamodb",
            "type": "DynamoDB",
            "description": "AWS DynamoDB state storage",
            "available": False,
            "default": False,
            "path": "stance-state table",
        },
        {
            "backend": "firestore",
            "type": "Firestore",
            "description": "GCP Firestore state storage",
            "available": False,
            "default": False,
            "path": "stance-state collection",
        },
        {
            "backend": "cosmosdb",
            "type": "Cosmos DB",
            "description": "Azure Cosmos DB state storage",
            "available": False,
            "default": False,
            "path": "stance-state container",
        },
    ]

    if output_format == "json":
        print(json.dumps(backends, indent=2))
    else:
        print("\nState Backends")
        print("=" * 90)
        print(f"{'Backend':<12} {'Type':<12} {'Available':<10} {'Default':<8} {'Description':<40}")
        print("-" * 90)
        for b in backends:
            available = "Yes" if b["available"] else "No"
            default = "Yes" if b["default"] else "No"
            print(f"{b['backend']:<12} {b['type']:<12} {available:<10} {default:<8} {b['description']:<40}")

    return 0


def _handle_finding_stats(args: argparse.Namespace) -> int:
    """Handle finding-stats command."""
    from stance.state import get_state_manager

    output_format = getattr(args, "format", "table")

    try:
        manager = get_state_manager()
        stats = manager.get_finding_stats()

        if output_format == "json":
            print(json.dumps(stats, indent=2))
        else:
            print("\nFinding Statistics by Lifecycle")
            print("=" * 40)
            total = sum(stats.values())
            for lifecycle, count in stats.items():
                pct = (count / total * 100) if total > 0 else 0
                print(f"{lifecycle:<16} {count:>6} ({pct:>5.1f}%)")
            print("-" * 40)
            print(f"{'Total':<16} {total:>6}")

        return 0
    except Exception as e:
        print(f"Error getting finding stats: {e}")
        return 1


def _handle_stats(args: argparse.Namespace) -> int:
    """Handle stats command."""
    from stance.state import FindingLifecycle, ScanStatus, get_state_manager

    output_format = getattr(args, "format", "table")

    try:
        manager = get_state_manager()

        # Gather statistics
        scans = manager.backend.list_scans(limit=1000)
        finding_stats = manager.get_finding_stats()
        checkpoints = _get_all_checkpoints()

        # Scan statistics
        scan_by_status = {}
        for status in ScanStatus:
            scan_by_status[status.value] = len([s for s in scans if s.status == status])

        stats = {
            "scans": {
                "total": len(scans),
                "by_status": scan_by_status,
            },
            "checkpoints": {
                "total": len(checkpoints),
            },
            "findings": {
                "total": sum(finding_stats.values()),
                "by_lifecycle": finding_stats,
            },
            "backends": {
                "available": 1,
                "active": "local",
            },
            "scan_statuses": len(ScanStatus),
            "lifecycle_states": len(FindingLifecycle),
        }

        if output_format == "json":
            print(json.dumps(stats, indent=2))
        else:
            print("\nState Module Statistics")
            print("=" * 50)

            print("\nScan Records:")
            print(f"  Total:     {stats['scans']['total']}")
            for status, count in stats["scans"]["by_status"].items():
                print(f"  {status:<12} {count}")

            print(f"\nCheckpoints: {stats['checkpoints']['total']}")

            print("\nFinding States:")
            print(f"  Total:     {stats['findings']['total']}")
            for lifecycle, count in stats["findings"]["by_lifecycle"].items():
                print(f"  {lifecycle:<14} {count}")

            print(f"\nBackends:    {stats['backends']['available']} available, '{stats['backends']['active']}' active")
            print(f"Scan Statuses: {stats['scan_statuses']}")
            print(f"Lifecycle States: {stats['lifecycle_states']}")

        return 0
    except Exception as e:
        print(f"Error getting stats: {e}")
        return 1


def _handle_status(args: argparse.Namespace) -> int:
    """Handle status command."""
    import os
    from pathlib import Path

    output_format = getattr(args, "format", "table")

    # Check backend availability
    db_path = os.path.expanduser("~/.stance/state.db")
    db_exists = Path(db_path).exists()

    status = {
        "module": "state",
        "active_backend": "local",
        "backend_path": db_path,
        "backend_exists": db_exists,
        "components": {
            "StateManager": True,
            "LocalStateBackend": True,
            "ScanRecord": True,
            "Checkpoint": True,
            "FindingState": True,
        },
        "capabilities": [
            "scan_tracking",
            "checkpoint_management",
            "finding_lifecycle",
            "state_persistence",
            "incremental_scanning",
        ],
    }

    if output_format == "json":
        print(json.dumps(status, indent=2))
    else:
        print("\nState Module Status")
        print("=" * 50)
        print(f"Module:          {status['module']}")
        print(f"Active Backend:  {status['active_backend']}")
        print(f"Backend Path:    {status['backend_path']}")
        print(f"Backend Exists:  {'Yes' if status['backend_exists'] else 'No'}")

        print("\nComponents:")
        for component, available in status["components"].items():
            indicator = "[+]" if available else "[-]"
            print(f"  {indicator} {component}")

        print("\nCapabilities:")
        for cap in status["capabilities"]:
            print(f"  - {cap}")

    return 0


def _handle_summary(args: argparse.Namespace) -> int:
    """Handle summary command."""
    import os
    from pathlib import Path

    from stance.state import FindingLifecycle, ScanStatus, get_state_manager

    output_format = getattr(args, "format", "table")

    try:
        manager = get_state_manager()
        scans = manager.backend.list_scans(limit=1000)
        finding_stats = manager.get_finding_stats()
        checkpoints = _get_all_checkpoints()

        # Get latest scan
        latest_scan = scans[0] if scans else None

        # Calculate metrics
        completed_scans = [s for s in scans if s.status == ScanStatus.COMPLETED]
        failed_scans = [s for s in scans if s.status == ScanStatus.FAILED]
        total_findings = sum(finding_stats.values())
        active_findings = finding_stats.get("new", 0) + finding_stats.get("recurring", 0) + finding_stats.get("reopened", 0)

        db_path = os.path.expanduser("~/.stance/state.db")
        db_size = Path(db_path).stat().st_size if Path(db_path).exists() else 0

        summary = {
            "overview": {
                "description": "State management for scans, checkpoints, and finding lifecycle",
                "active_backend": "local",
                "database_size_bytes": db_size,
            },
            "scans": {
                "total": len(scans),
                "completed": len(completed_scans),
                "failed": len(failed_scans),
                "success_rate": (len(completed_scans) / len(scans) * 100) if scans else 0,
            },
            "latest_scan": {
                "scan_id": latest_scan.scan_id if latest_scan else None,
                "status": latest_scan.status.value if latest_scan else None,
                "started_at": latest_scan.started_at.isoformat() if latest_scan else None,
                "assets": latest_scan.asset_count if latest_scan else 0,
                "findings": latest_scan.finding_count if latest_scan else 0,
            } if latest_scan else None,
            "checkpoints": {
                "total": len(checkpoints),
            },
            "findings": {
                "total": total_findings,
                "active": active_findings,
                "resolved": finding_stats.get("resolved", 0),
                "suppressed": finding_stats.get("suppressed", 0),
            },
            "features": [
                "Scan history tracking",
                "Checkpoint management for incremental scans",
                "Finding lifecycle tracking (new, recurring, resolved, reopened)",
                "Finding suppression and false positive marking",
                "SQLite-based local persistence",
                "Extensible backend architecture (DynamoDB, Firestore, Cosmos DB planned)",
            ],
        }

        if output_format == "json":
            print(json.dumps(summary, indent=2, default=str))
        else:
            print("\nState Module Summary")
            print("=" * 70)

            print("\nOverview:")
            print(f"  {summary['overview']['description']}")
            print(f"  Active Backend: {summary['overview']['active_backend']}")
            print(f"  Database Size:  {db_size / 1024:.1f} KB")

            print("\nScan History:")
            print(f"  Total Scans:    {summary['scans']['total']}")
            print(f"  Completed:      {summary['scans']['completed']}")
            print(f"  Failed:         {summary['scans']['failed']}")
            print(f"  Success Rate:   {summary['scans']['success_rate']:.1f}%")

            if latest_scan:
                print("\nLatest Scan:")
                print(f"  Scan ID:   {latest_scan.scan_id}")
                print(f"  Status:    {latest_scan.status.value}")
                print(f"  Started:   {latest_scan.started_at.strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"  Assets:    {latest_scan.asset_count}")
                print(f"  Findings:  {latest_scan.finding_count}")

            print(f"\nCheckpoints: {summary['checkpoints']['total']} saved")

            print("\nFinding Lifecycle:")
            print(f"  Total:      {summary['findings']['total']}")
            print(f"  Active:     {summary['findings']['active']}")
            print(f"  Resolved:   {summary['findings']['resolved']}")
            print(f"  Suppressed: {summary['findings']['suppressed']}")

            print("\nFeatures:")
            for feature in summary["features"]:
                print(f"  - {feature}")

        return 0
    except Exception as e:
        print(f"Error getting summary: {e}")
        return 1
