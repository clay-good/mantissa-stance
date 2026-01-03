"""
CLI command handlers for Drift Detection.

Provides commands for:
- Detecting configuration drift from baselines
- Managing baselines (create, list, update, delete)
- Viewing drift history and change tracking
- Generating drift reports
"""

from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


def cmd_drift(args: argparse.Namespace) -> int:
    """
    Route drift subcommands to appropriate handlers.

    Returns:
        Exit code (0 success, 1 error)
    """
    action = getattr(args, "drift_action", None)

    if action is None:
        print("Usage: stance drift <command>")
        print("")
        print("Commands:")
        print("  detect      Detect configuration drift from baseline")
        print("  baseline    Manage baselines (create, list, update, delete)")
        print("  history     View change history for assets")
        print("  changes     View recent configuration changes")
        print("  summary     Show drift detection summary")
        print("")
        print("Run 'stance drift <command> --help' for more information")
        return 0

    handlers = {
        "detect": _cmd_drift_detect,
        "baseline": _cmd_drift_baseline,
        "history": _cmd_drift_history,
        "changes": _cmd_drift_changes,
        "summary": _cmd_drift_summary,
    }

    handler = handlers.get(action)
    if handler:
        return handler(args)

    print(f"Unknown drift command: {action}")
    return 1


def _cmd_drift_detect(args: argparse.Namespace) -> int:
    """
    Detect configuration drift from baseline.

    Compares current asset configurations against the specified
    or active baseline and identifies changes.
    """
    from stance.drift.baseline import BaselineManager
    from stance.drift.drift_detector import DriftDetector, DriftSeverity
    from stance.storage import get_storage

    output_format = getattr(args, "format", "table")
    baseline_id = getattr(args, "baseline", None)
    severity_filter = getattr(args, "severity", None)
    asset_type_filter = getattr(args, "type", None)
    cloud_filter = getattr(args, "cloud", None)
    region_filter = getattr(args, "region", None)
    limit = getattr(args, "limit", 50)

    try:
        # Load assets from storage
        storage = get_storage()
        assets = storage.load_assets()

        if not assets or not assets.assets:
            print("No assets found. Run 'stance scan' first.")
            return 1

        # Initialize drift detector
        manager = BaselineManager()
        detector = DriftDetector(baseline_manager=manager)

        # Detect drift
        if baseline_id:
            print(f"Detecting drift against baseline: {baseline_id}")
        else:
            print("Detecting drift against active baseline...")

        result = detector.detect_drift(assets, baseline_id=baseline_id)

        # Check for baseline not found
        if "error" in result.summary:
            print(f"Error: {result.summary['error']}")
            print("Create a baseline first with: stance drift baseline create --name <name>")
            return 1

        # Filter drift events
        drift_events = result.drift_events

        if severity_filter:
            try:
                filter_sev = DriftSeverity(severity_filter.lower())
                severity_order = {
                    DriftSeverity.CRITICAL: 0,
                    DriftSeverity.HIGH: 1,
                    DriftSeverity.MEDIUM: 2,
                    DriftSeverity.LOW: 3,
                    DriftSeverity.INFO: 4,
                }
                filter_order = severity_order.get(filter_sev, 4)
                drift_events = [
                    e for e in drift_events
                    if severity_order.get(e.severity, 4) <= filter_order
                ]
            except ValueError:
                print(f"Warning: Unknown severity '{severity_filter}'")

        if asset_type_filter:
            drift_events = [
                e for e in drift_events
                if asset_type_filter.lower() in e.asset_type.lower()
            ]

        if cloud_filter:
            drift_events = [
                e for e in drift_events
                if e.cloud_provider.lower() == cloud_filter.lower()
            ]

        if region_filter:
            drift_events = [
                e for e in drift_events
                if e.region.lower() == region_filter.lower()
            ]

        # Limit results
        drift_events = drift_events[:limit]

        # Output results
        if output_format == "json":
            output = {
                "baseline_id": result.baseline_id,
                "detected_at": result.detected_at.isoformat(),
                "assets_checked": result.assets_checked,
                "assets_with_drift": result.assets_with_drift,
                "has_drift": result.summary.get("has_drift", False),
                "drift_by_severity": result.summary.get("drift_by_severity", {}),
                "security_drift_count": result.summary.get("security_drift_count", 0),
                "drift_events": [e.to_dict() for e in drift_events],
            }
            print(json.dumps(output, indent=2, default=str))
        else:
            # Table format
            print("")
            print("Drift Detection Results")
            print("=" * 100)
            print(f"Baseline: {result.baseline_id}")
            print(f"Detected at: {result.detected_at.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Assets checked: {result.assets_checked}")
            print(f"Assets with drift: {result.assets_with_drift}")
            print(f"Security-relevant drift: {result.summary.get('security_drift_count', 0)}")
            print("")

            if not drift_events:
                print("No drift detected. All assets match baseline.")
                return 0

            # Summary by severity
            drift_by_sev = result.summary.get("drift_by_severity", {})
            if drift_by_sev:
                print("Drift by Severity:")
                for sev, count in sorted(drift_by_sev.items()):
                    print(f"  {sev.upper()}: {count}")
                print("")

            # Drift event table
            print(f"{'Asset ID':<40} {'Type':<15} {'Drift Type':<20} {'Severity':<10} {'Changes'}")
            print("-" * 100)

            for event in drift_events:
                asset_short = event.asset_id[:37] + "..." if len(event.asset_id) > 40 else event.asset_id
                type_short = event.asset_type[:12] + "..." if len(event.asset_type) > 15 else event.asset_type
                print(
                    f"{asset_short:<40} "
                    f"{type_short:<15} "
                    f"{event.drift_type.value:<20} "
                    f"{event.severity.value:<10} "
                    f"{len(event.differences)}"
                )

            # Show detailed view for single drift
            if len(drift_events) == 1:
                event = drift_events[0]
                print("")
                print("Drift Details:")
                print(f"  Asset: {event.asset_id}")
                print(f"  Type: {event.asset_type}")
                print(f"  Cloud: {event.cloud_provider}")
                print(f"  Region: {event.region}")
                print(f"  Description: {event.description}")

                if event.differences:
                    print("")
                    print("  Configuration Changes:")
                    for diff in event.differences[:10]:
                        security_tag = " [SECURITY]" if diff.is_security_relevant else ""
                        print(f"    - {diff.path}: {diff.change_type}{security_tag}")
                        print(f"      Was: {diff.baseline_value}")
                        print(f"      Now: {diff.current_value}")

                    if len(event.differences) > 10:
                        print(f"    ... and {len(event.differences) - 10} more changes")

        return 0

    except Exception as e:
        logger.error(f"Drift detection failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_drift_baseline(args: argparse.Namespace) -> int:
    """
    Manage configuration baselines.

    Supports create, list, show, update, archive, and delete operations.
    """
    baseline_action = getattr(args, "baseline_action", "list")

    if baseline_action == "create":
        return _cmd_baseline_create(args)
    elif baseline_action == "list":
        return _cmd_baseline_list(args)
    elif baseline_action == "show":
        return _cmd_baseline_show(args)
    elif baseline_action == "update":
        return _cmd_baseline_update(args)
    elif baseline_action == "archive":
        return _cmd_baseline_archive(args)
    elif baseline_action == "delete":
        return _cmd_baseline_delete(args)
    else:
        # Default to list if no action specified
        return _cmd_baseline_list(args)


def _cmd_baseline_create(args: argparse.Namespace) -> int:
    """Create a new baseline from current assets."""
    from stance.drift.baseline import BaselineManager
    from stance.storage import get_storage

    name = getattr(args, "name", None)
    description = getattr(args, "description", "")
    output_format = getattr(args, "format", "table")

    if not name:
        print("Error: Baseline name is required. Use --name <name>")
        return 1

    try:
        # Load assets
        storage = get_storage()
        assets = storage.load_assets()

        if not assets or not assets.assets:
            print("No assets found. Run 'stance scan' first.")
            return 1

        # Create baseline
        manager = BaselineManager()
        baseline = manager.create_baseline(
            name=name,
            assets=assets,
            description=description,
            created_by="cli",
        )

        if output_format == "json":
            output = {
                "success": True,
                "baseline": {
                    "id": baseline.id,
                    "name": baseline.name,
                    "description": baseline.description,
                    "status": baseline.status.value,
                    "asset_count": baseline.asset_count,
                    "created_at": baseline.created_at.isoformat(),
                }
            }
            print(json.dumps(output, indent=2))
        else:
            print("")
            print("Baseline created successfully!")
            print("=" * 60)
            print(f"  ID: {baseline.id}")
            print(f"  Name: {baseline.name}")
            print(f"  Description: {baseline.description or 'N/A'}")
            print(f"  Status: {baseline.status.value}")
            print(f"  Assets: {baseline.asset_count}")
            print(f"  Created: {baseline.created_at.strftime('%Y-%m-%d %H:%M:%S')}")

        return 0

    except Exception as e:
        logger.error(f"Baseline creation failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_baseline_list(args: argparse.Namespace) -> int:
    """List all baselines."""
    from stance.drift.baseline import BaselineManager, BaselineStatus

    output_format = getattr(args, "format", "table")
    status_filter = getattr(args, "status", None)

    try:
        manager = BaselineManager()
        baselines = manager.list_baselines()

        # Filter by status
        if status_filter:
            try:
                filter_status = BaselineStatus(status_filter.lower())
                baselines = [b for b in baselines if b.status == filter_status]
            except ValueError:
                print(f"Warning: Unknown status '{status_filter}'")

        if output_format == "json":
            output = {
                "total": len(baselines),
                "baselines": [
                    {
                        "id": b.id,
                        "name": b.name,
                        "description": b.description,
                        "status": b.status.value,
                        "asset_count": b.asset_count,
                        "created_at": b.created_at.isoformat(),
                        "updated_at": b.updated_at.isoformat(),
                    }
                    for b in baselines
                ]
            }
            print(json.dumps(output, indent=2))
        else:
            print("")
            print(f"Baselines ({len(baselines)} total)")
            print("=" * 100)

            if not baselines:
                print("No baselines found. Create one with: stance drift baseline create --name <name>")
                return 0

            print(f"{'ID':<35} {'Name':<20} {'Status':<10} {'Assets':<8} {'Created'}")
            print("-" * 100)

            for baseline in baselines:
                id_short = baseline.id[:32] + "..." if len(baseline.id) > 35 else baseline.id
                name_short = baseline.name[:17] + "..." if len(baseline.name) > 20 else baseline.name
                created = baseline.created_at.strftime("%Y-%m-%d %H:%M")
                print(
                    f"{id_short:<35} "
                    f"{name_short:<20} "
                    f"{baseline.status.value:<10} "
                    f"{baseline.asset_count:<8} "
                    f"{created}"
                )

        return 0

    except Exception as e:
        logger.error(f"Baseline listing failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_baseline_show(args: argparse.Namespace) -> int:
    """Show details for a specific baseline."""
    from stance.drift.baseline import BaselineManager

    baseline_id = getattr(args, "id", None)
    output_format = getattr(args, "format", "table")

    if not baseline_id:
        print("Error: Baseline ID is required.")
        return 1

    try:
        manager = BaselineManager()
        baseline = manager.get_baseline(baseline_id)

        if not baseline:
            print(f"Baseline not found: {baseline_id}")
            return 1

        if output_format == "json":
            print(json.dumps(baseline.to_dict(), indent=2, default=str))
        else:
            print("")
            print(f"Baseline: {baseline.name}")
            print("=" * 60)
            print(f"  ID: {baseline.id}")
            print(f"  Description: {baseline.description or 'N/A'}")
            print(f"  Status: {baseline.status.value}")
            print(f"  Assets: {baseline.asset_count}")
            print(f"  Created: {baseline.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"  Updated: {baseline.updated_at.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"  Created by: {baseline.created_by}")

            if baseline.metadata:
                print(f"  Metadata: {json.dumps(baseline.metadata)}")

            # Show asset types summary
            if baseline.asset_baselines:
                print("")
                print("Asset Types:")
                type_counts: dict[str, int] = {}
                for ab in baseline.asset_baselines.values():
                    type_counts[ab.asset_type] = type_counts.get(ab.asset_type, 0) + 1

                for asset_type, count in sorted(type_counts.items(), key=lambda x: -x[1]):
                    print(f"    {asset_type}: {count}")

        return 0

    except Exception as e:
        logger.error(f"Baseline show failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_baseline_update(args: argparse.Namespace) -> int:
    """Update a baseline with current asset configurations."""
    from stance.drift.baseline import BaselineManager
    from stance.storage import get_storage

    baseline_id = getattr(args, "id", None)
    asset_ids = getattr(args, "assets", None)
    output_format = getattr(args, "format", "table")

    if not baseline_id:
        print("Error: Baseline ID is required.")
        return 1

    try:
        # Load assets
        storage = get_storage()
        assets = storage.load_assets()

        if not assets or not assets.assets:
            print("No assets found. Run 'stance scan' first.")
            return 1

        # Parse asset IDs if specified
        asset_id_list = None
        if asset_ids:
            asset_id_list = [a.strip() for a in asset_ids.split(",")]

        # Update baseline
        manager = BaselineManager()
        baseline = manager.update_baseline(
            baseline_id=baseline_id,
            assets=assets,
            asset_ids=asset_id_list,
        )

        if not baseline:
            print(f"Baseline not found: {baseline_id}")
            return 1

        if output_format == "json":
            output = {
                "success": True,
                "baseline": {
                    "id": baseline.id,
                    "name": baseline.name,
                    "asset_count": baseline.asset_count,
                    "updated_at": baseline.updated_at.isoformat(),
                }
            }
            print(json.dumps(output, indent=2))
        else:
            print("")
            print("Baseline updated successfully!")
            print("=" * 60)
            print(f"  ID: {baseline.id}")
            print(f"  Name: {baseline.name}")
            print(f"  Assets: {baseline.asset_count}")
            print(f"  Updated: {baseline.updated_at.strftime('%Y-%m-%d %H:%M:%S')}")

        return 0

    except Exception as e:
        logger.error(f"Baseline update failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_baseline_archive(args: argparse.Namespace) -> int:
    """Archive a baseline."""
    from stance.drift.baseline import BaselineManager

    baseline_id = getattr(args, "id", None)
    output_format = getattr(args, "format", "table")

    if not baseline_id:
        print("Error: Baseline ID is required.")
        return 1

    try:
        manager = BaselineManager()
        success = manager.archive_baseline(baseline_id)

        if not success:
            print(f"Baseline not found: {baseline_id}")
            return 1

        if output_format == "json":
            print(json.dumps({"success": True, "baseline_id": baseline_id}))
        else:
            print(f"Baseline archived: {baseline_id}")

        return 0

    except Exception as e:
        logger.error(f"Baseline archive failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_baseline_delete(args: argparse.Namespace) -> int:
    """Delete a baseline."""
    from stance.drift.baseline import BaselineManager

    baseline_id = getattr(args, "id", None)
    force = getattr(args, "force", False)
    output_format = getattr(args, "format", "table")

    if not baseline_id:
        print("Error: Baseline ID is required.")
        return 1

    if not force:
        print(f"Warning: This will permanently delete baseline '{baseline_id}'")
        print("Use --force to confirm deletion.")
        return 1

    try:
        manager = BaselineManager()
        success = manager.delete_baseline(baseline_id)

        if not success:
            print(f"Baseline not found: {baseline_id}")
            return 1

        if output_format == "json":
            print(json.dumps({"success": True, "baseline_id": baseline_id}))
        else:
            print(f"Baseline deleted: {baseline_id}")

        return 0

    except Exception as e:
        logger.error(f"Baseline delete failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_drift_history(args: argparse.Namespace) -> int:
    """
    View change history for a specific asset.

    Shows the timeline of configuration changes including
    what changed, when, and by whom.
    """
    from stance.drift.change_tracker import ChangeTracker

    asset_id = getattr(args, "asset_id", None)
    days = getattr(args, "days", 30)
    output_format = getattr(args, "format", "table")

    if not asset_id:
        print("Error: Asset ID is required. Use --asset-id <id>")
        return 1

    try:
        tracker = ChangeTracker()
        history = tracker.get_asset_history(asset_id)

        if not history:
            print(f"No history found for asset: {asset_id}")
            return 0

        timeline = tracker.get_change_timeline(asset_id, days=days)

        if output_format == "json":
            output = {
                "asset_id": history.asset_id,
                "asset_type": history.asset_type,
                "cloud_provider": history.cloud_provider,
                "first_seen": history.first_seen.isoformat() if history.first_seen else None,
                "last_seen": history.last_seen.isoformat() if history.last_seen else None,
                "total_changes": len(history.events),
                "timeline": timeline,
            }
            print(json.dumps(output, indent=2, default=str))
        else:
            print("")
            print(f"Change History for Asset: {asset_id}")
            print("=" * 100)
            print(f"  Type: {history.asset_type}")
            print(f"  Cloud: {history.cloud_provider}")
            print(f"  First seen: {history.first_seen.strftime('%Y-%m-%d %H:%M:%S') if history.first_seen else 'N/A'}")
            print(f"  Last seen: {history.last_seen.strftime('%Y-%m-%d %H:%M:%S') if history.last_seen else 'N/A'}")
            print(f"  Total changes: {len(history.events)}")
            print("")

            if not timeline:
                print(f"No changes in the last {days} days.")
                return 0

            print(f"Timeline (last {days} days):")
            print("-" * 100)

            for entry in timeline:
                ts = entry["timestamp"][:19].replace("T", " ")
                change_type = entry["change_type"].upper()
                source = entry.get("source", "unknown")
                attributed = entry.get("attributed_to", "unknown")

                print(f"  [{ts}] {change_type}")
                print(f"    Source: {source}, By: {attributed}")

                changed_paths = entry.get("changed_paths", [])
                if changed_paths:
                    for path in changed_paths[:5]:
                        print(f"    - {path}")
                    if len(changed_paths) > 5:
                        print(f"    ... and {len(changed_paths) - 5} more")

                print("")

        return 0

    except Exception as e:
        logger.error(f"History retrieval failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_drift_changes(args: argparse.Namespace) -> int:
    """
    View recent configuration changes across all assets.

    Shows a summary of recent changes with attribution
    and change source information.
    """
    from stance.drift.change_tracker import ChangeTracker, ChangeType

    hours = getattr(args, "hours", 24)
    change_type_filter = getattr(args, "type", None)
    limit = getattr(args, "limit", 50)
    output_format = getattr(args, "format", "table")

    try:
        tracker = ChangeTracker()

        # Get summary
        summary = tracker.get_change_summary(hours=hours)

        # Get recent changes
        change_type = None
        if change_type_filter:
            try:
                change_type = ChangeType(change_type_filter.lower())
            except ValueError:
                print(f"Warning: Unknown change type '{change_type_filter}'")

        changes = tracker.get_recent_changes(limit=limit, change_type=change_type)

        if output_format == "json":
            output = {
                "period_hours": hours,
                "summary": summary,
                "changes": [c.to_dict() for c in changes],
            }
            print(json.dumps(output, indent=2, default=str))
        else:
            print("")
            print(f"Recent Changes (last {hours} hours)")
            print("=" * 100)
            print(f"  Total changes: {summary['total_changes']}")
            print(f"  Unique assets: {summary['unique_assets_changed']}")
            print(f"  Created: {summary['created']}")
            print(f"  Updated: {summary['updated']}")
            print(f"  Deleted: {summary['deleted']}")
            print("")

            if not changes:
                print("No changes found in the specified period.")
                return 0

            # Most active assets
            if summary.get("most_active_assets"):
                print("Most Active Assets:")
                for asset in summary["most_active_assets"][:5]:
                    print(f"    {asset['asset_id']}: {asset['change_count']} changes")
                print("")

            # Recent changes table
            print(f"{'Timestamp':<20} {'Asset ID':<35} {'Type':<10} {'Source'}")
            print("-" * 100)

            for change in changes:
                ts = change.detected_at.strftime("%Y-%m-%d %H:%M:%S")
                asset_short = change.asset_id[:32] + "..." if len(change.asset_id) > 35 else change.asset_id
                print(
                    f"{ts:<20} "
                    f"{asset_short:<35} "
                    f"{change.change_type.value:<10} "
                    f"{change.source}"
                )

        return 0

    except Exception as e:
        logger.error(f"Changes retrieval failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_drift_summary(args: argparse.Namespace) -> int:
    """
    Show comprehensive drift detection summary.

    Provides an overview of drift status, baselines,
    and recent changes.
    """
    from stance.drift.baseline import BaselineManager
    from stance.drift.drift_detector import DriftDetector
    from stance.drift.change_tracker import ChangeTracker
    from stance.storage import get_storage

    output_format = getattr(args, "format", "table")
    change_hours = getattr(args, "hours", 24)

    try:
        # Load assets
        storage = get_storage()
        assets = storage.load_assets()

        if not assets or not assets.assets:
            print("No assets found. Run 'stance scan' first.")
            return 1

        # Get baseline info
        manager = BaselineManager()
        baselines = manager.list_baselines()
        active_baseline = manager.get_active_baseline()

        # Get drift status
        drift_result = None
        if active_baseline:
            detector = DriftDetector(baseline_manager=manager)
            drift_result = detector.detect_drift(assets)

        # Get change summary
        tracker = ChangeTracker()
        change_summary = tracker.get_change_summary(hours=change_hours)

        if output_format == "json":
            output = {
                "assets": {
                    "total": len(list(assets.assets)),
                },
                "baselines": {
                    "total": len(baselines),
                    "active": active_baseline.id if active_baseline else None,
                    "active_name": active_baseline.name if active_baseline else None,
                },
                "drift": None,
                "changes": change_summary,
            }

            if drift_result:
                output["drift"] = {
                    "has_drift": drift_result.summary.get("has_drift", False),
                    "assets_checked": drift_result.assets_checked,
                    "assets_with_drift": drift_result.assets_with_drift,
                    "drift_by_severity": drift_result.summary.get("drift_by_severity", {}),
                    "security_drift_count": drift_result.summary.get("security_drift_count", 0),
                }

            print(json.dumps(output, indent=2, default=str))
        else:
            print("")
            print("Drift Detection Summary")
            print("=" * 60)

            # Asset overview
            print("")
            print("Assets:")
            print(f"  Total assets: {len(list(assets.assets))}")

            # Baseline overview
            print("")
            print("Baselines:")
            print(f"  Total baselines: {len(baselines)}")
            if active_baseline:
                print(f"  Active baseline: {active_baseline.name} ({active_baseline.id})")
                print(f"  Baseline assets: {active_baseline.asset_count}")
            else:
                print("  Active baseline: None")
                print("  Create one with: stance drift baseline create --name <name>")

            # Drift status
            print("")
            print("Drift Status:")
            if drift_result:
                has_drift = drift_result.summary.get("has_drift", False)
                print(f"  Has drift: {'Yes' if has_drift else 'No'}")
                print(f"  Assets checked: {drift_result.assets_checked}")
                print(f"  Assets with drift: {drift_result.assets_with_drift}")

                drift_by_sev = drift_result.summary.get("drift_by_severity", {})
                if drift_by_sev:
                    print("  By severity:")
                    for sev, count in sorted(drift_by_sev.items()):
                        print(f"    {sev.upper()}: {count}")

                security_count = drift_result.summary.get("security_drift_count", 0)
                if security_count > 0:
                    print(f"  Security-relevant drift: {security_count}")
            else:
                print("  No active baseline for drift detection")

            # Change summary
            print("")
            print(f"Recent Changes (last {change_hours} hours):")
            print(f"  Total changes: {change_summary['total_changes']}")
            print(f"  Unique assets: {change_summary['unique_assets_changed']}")
            print(f"  Created: {change_summary['created']}")
            print(f"  Updated: {change_summary['updated']}")
            print(f"  Deleted: {change_summary['deleted']}")

        return 0

    except Exception as e:
        logger.error(f"Summary generation failed: {e}")
        print(f"Error: {e}")
        return 1
