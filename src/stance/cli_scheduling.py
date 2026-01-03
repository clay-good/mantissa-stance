"""
CLI command handlers for scheduling and automation features.

Implements CLI subcommands for scan scheduling, history viewing,
trend analysis, and notification management.
"""

from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timedelta
from typing import Any

logger = logging.getLogger(__name__)


def cmd_schedule(args: argparse.Namespace) -> int:
    """
    Handle schedule subcommand.

    Manages scheduled scan jobs including listing, adding, removing,
    enabling, and disabling jobs.

    Returns:
        Exit code (0 success, 1 error)
    """
    action = getattr(args, "schedule_action", None) or getattr(args, "action", "list")

    handlers = {
        "list": _schedule_list,
        "add": _schedule_add,
        "remove": _schedule_remove,
        "enable": _schedule_enable,
        "disable": _schedule_disable,
        "run": _schedule_run,
        "status": _schedule_status,
    }

    handler = handlers.get(action)
    if handler:
        return handler(args)

    print(f"Unknown schedule action: {action}")
    return 1


def _schedule_list(args: argparse.Namespace) -> int:
    """List scheduled scan jobs."""
    from stance.scheduling import ScanScheduler

    scheduler = _get_scheduler()
    jobs = scheduler.get_jobs()

    if not jobs:
        print("No scheduled jobs found.")
        return 0

    output_format = getattr(args, "format", "table")

    if output_format == "json":
        job_data = [
            {
                "id": job.id,
                "name": job.name,
                "schedule": str(job.schedule),
                "enabled": job.enabled,
                "last_run": job.last_run.isoformat() if job.last_run else None,
                "next_run": job.next_run.isoformat() if job.next_run else None,
                "run_count": job.run_count,
            }
            for job in jobs
        ]
        print(json.dumps(job_data, indent=2))
    else:
        print(f"{'ID':<20} {'Name':<25} {'Schedule':<20} {'Enabled':<8} {'Last Run':<20}")
        print("-" * 95)
        for job in jobs:
            last_run = job.last_run.strftime("%Y-%m-%d %H:%M") if job.last_run else "Never"
            print(f"{job.id:<20} {job.name:<25} {str(job.schedule):<20} {str(job.enabled):<8} {last_run:<20}")

    return 0


def _schedule_add(args: argparse.Namespace) -> int:
    """Add a new scheduled scan job."""
    from stance.scheduling import ScanScheduler, parse_schedule

    name = getattr(args, "name", None)
    schedule_expr = getattr(args, "schedule", None)
    config_name = getattr(args, "config", "default")

    if not name or not schedule_expr:
        print("Error: --name and --schedule are required")
        return 1

    try:
        schedule = parse_schedule(schedule_expr)
    except ValueError as e:
        print(f"Error: Invalid schedule expression: {e}")
        return 1

    scheduler = _get_scheduler()

    job = scheduler.add_job(
        name=name,
        schedule=schedule,
        config_name=config_name,
    )

    print(f"Created scheduled job: {job.id}")
    print(f"  Name: {job.name}")
    print(f"  Schedule: {job.schedule}")
    print(f"  Next run: {job.next_run}")

    # Save scheduler state
    _save_scheduler(scheduler)

    return 0


def _schedule_remove(args: argparse.Namespace) -> int:
    """Remove a scheduled scan job."""
    job_id = getattr(args, "job_id", None)

    if not job_id:
        print("Error: job_id is required")
        return 1

    scheduler = _get_scheduler()

    if scheduler.remove_job(job_id):
        print(f"Removed job: {job_id}")
        _save_scheduler(scheduler)
        return 0
    else:
        print(f"Job not found: {job_id}")
        return 1


def _schedule_enable(args: argparse.Namespace) -> int:
    """Enable a scheduled scan job."""
    job_id = getattr(args, "job_id", None)

    if not job_id:
        print("Error: job_id is required")
        return 1

    scheduler = _get_scheduler()

    if scheduler.enable_job(job_id):
        job = scheduler.get_job(job_id)
        print(f"Enabled job: {job_id}")
        if job:
            print(f"  Next run: {job.next_run}")
        _save_scheduler(scheduler)
        return 0
    else:
        print(f"Job not found: {job_id}")
        return 1


def _schedule_disable(args: argparse.Namespace) -> int:
    """Disable a scheduled scan job."""
    job_id = getattr(args, "job_id", None)

    if not job_id:
        print("Error: job_id is required")
        return 1

    scheduler = _get_scheduler()

    if scheduler.disable_job(job_id):
        print(f"Disabled job: {job_id}")
        _save_scheduler(scheduler)
        return 0
    else:
        print(f"Job not found: {job_id}")
        return 1


def _schedule_run(args: argparse.Namespace) -> int:
    """Run a scheduled job immediately."""
    job_id = getattr(args, "job_id", None)

    if not job_id:
        print("Error: job_id is required")
        return 1

    scheduler = _get_scheduler()
    job = scheduler.get_job(job_id)

    if not job:
        print(f"Job not found: {job_id}")
        return 1

    print(f"Running job: {job.name} ({job_id})...")

    result = scheduler.run_job_now(job_id)

    if result:
        if result.success:
            print(f"Job completed successfully")
            print(f"  Duration: {result.duration.total_seconds():.1f}s")
            print(f"  Assets scanned: {result.assets_scanned}")
            print(f"  Findings: {result.findings_count}")
        else:
            print(f"Job failed: {result.error}")
            return 1
    else:
        print("Failed to run job")
        return 1

    _save_scheduler(scheduler)
    return 0


def _schedule_status(args: argparse.Namespace) -> int:
    """Show scheduler status."""
    scheduler = _get_scheduler()
    status = scheduler.get_status()

    output_format = getattr(args, "format", "table")

    if output_format == "json":
        print(json.dumps(status, indent=2, default=str))
    else:
        print("Scheduler Status")
        print("-" * 40)
        print(f"  Running: {status.get('running', False)}")
        print(f"  Total jobs: {status.get('total_jobs', 0)}")
        print(f"  Enabled jobs: {status.get('enabled_jobs', 0)}")
        print(f"  Last check: {status.get('last_check', 'Never')}")

    return 0


def cmd_history(args: argparse.Namespace) -> int:
    """
    Handle history subcommand.

    Views scan history and compares scans.

    Returns:
        Exit code (0 success, 1 error)
    """
    action = getattr(args, "history_action", None) or getattr(args, "action", "list")

    handlers = {
        "list": _history_list,
        "show": _history_show,
        "compare": _history_compare,
        "trend": _history_trend,
    }

    handler = handlers.get(action)
    if handler:
        return handler(args)

    print(f"Unknown history action: {action}")
    return 1


def _history_list(args: argparse.Namespace) -> int:
    """List scan history."""
    from stance.scheduling import ScanHistoryManager

    config_name = getattr(args, "config", "default")
    limit = getattr(args, "limit", 20)
    output_format = getattr(args, "format", "table")

    manager = _get_history_manager()
    history = manager.get_history(config_name=config_name, limit=limit)

    if not history:
        print("No scan history found.")
        return 0

    if output_format == "json":
        data = [
            {
                "scan_id": entry.scan_id,
                "timestamp": entry.timestamp.isoformat(),
                "duration_seconds": entry.duration_seconds,
                "assets_scanned": entry.assets_scanned,
                "findings_total": entry.findings_total,
                "findings_by_severity": entry.findings_by_severity,
            }
            for entry in history
        ]
        print(json.dumps(data, indent=2))
    else:
        print(f"{'Scan ID':<25} {'Timestamp':<20} {'Assets':<8} {'Findings':<10} {'Duration':<10}")
        print("-" * 80)
        for entry in history:
            ts = entry.timestamp.strftime("%Y-%m-%d %H:%M")
            duration = f"{entry.duration_seconds:.1f}s" if entry.duration_seconds else "N/A"
            print(f"{entry.scan_id:<25} {ts:<20} {entry.assets_scanned:<8} {entry.findings_total:<10} {duration:<10}")

    return 0


def _history_show(args: argparse.Namespace) -> int:
    """Show details for a specific scan."""
    scan_id = getattr(args, "scan_id", None)

    if not scan_id:
        print("Error: scan_id is required")
        return 1

    manager = _get_history_manager()
    entry = manager.get_entry(scan_id)

    if not entry:
        print(f"Scan not found: {scan_id}")
        return 1

    output_format = getattr(args, "format", "table")

    if output_format == "json":
        data = {
            "scan_id": entry.scan_id,
            "timestamp": entry.timestamp.isoformat(),
            "config_name": entry.config_name,
            "duration_seconds": entry.duration_seconds,
            "assets_scanned": entry.assets_scanned,
            "findings_total": entry.findings_total,
            "findings_by_severity": entry.findings_by_severity,
        }
        print(json.dumps(data, indent=2))
    else:
        print(f"Scan: {entry.scan_id}")
        print("-" * 40)
        print(f"  Timestamp: {entry.timestamp}")
        print(f"  Config: {entry.config_name}")
        print(f"  Duration: {entry.duration_seconds:.1f}s")
        print(f"  Assets scanned: {entry.assets_scanned}")
        print(f"  Total findings: {entry.findings_total}")
        print(f"  By severity:")
        for sev, count in entry.findings_by_severity.items():
            print(f"    {sev}: {count}")

    return 0


def _history_compare(args: argparse.Namespace) -> int:
    """Compare two scans."""
    baseline_id = getattr(args, "baseline", None)
    current_id = getattr(args, "current", None)

    manager = _get_history_manager()

    # If only one ID provided, compare with latest
    if baseline_id and not current_id:
        comparison = manager.compare_with_latest(baseline_id)
    elif baseline_id and current_id:
        comparison = manager.compare_scans(baseline_id, current_id)
    else:
        # Get last two scans
        history = manager.get_history(limit=2)
        if len(history) < 2:
            print("Not enough scans to compare. Need at least 2 scans.")
            return 1
        comparison = manager.compare_scans(history[1].scan_id, history[0].scan_id)

    if not comparison:
        print("Failed to compare scans.")
        return 1

    output_format = getattr(args, "format", "table")

    if output_format == "json":
        data = {
            "baseline_scan_id": comparison.baseline_scan_id,
            "current_scan_id": comparison.current_scan_id,
            "new_findings": len(comparison.new_findings),
            "resolved_findings": len(comparison.resolved_findings),
            "unchanged_findings": len(comparison.unchanged_findings),
            "has_changes": comparison.has_changes,
            "improvement_ratio": comparison.improvement_ratio,
        }
        print(json.dumps(data, indent=2))
    else:
        print(f"Scan Comparison")
        print("-" * 40)
        print(f"  Baseline: {comparison.baseline_scan_id}")
        print(f"  Current: {comparison.current_scan_id}")
        print()
        print(f"  New findings: {len(comparison.new_findings)}")
        print(f"  Resolved findings: {len(comparison.resolved_findings)}")
        print(f"  Unchanged findings: {len(comparison.unchanged_findings)}")
        print()
        if comparison.improvement_ratio > 0:
            print(f"  Status: IMPROVING ({comparison.improvement_ratio:.1%} improvement)")
        elif comparison.improvement_ratio < 0:
            print(f"  Status: DECLINING ({abs(comparison.improvement_ratio):.1%} regression)")
        else:
            print(f"  Status: STABLE")

    return 0


def _history_trend(args: argparse.Namespace) -> int:
    """Show trend analysis."""
    days = getattr(args, "days", 7)
    config_name = getattr(args, "config", "default")

    manager = _get_history_manager()
    trend = manager.get_trend(config_name=config_name, days=days)

    output_format = getattr(args, "format", "table")

    if output_format == "json":
        print(json.dumps(trend, indent=2, default=str))
    else:
        print(f"Trend Analysis ({days} days)")
        print("-" * 40)
        print(f"  Data points: {trend.get('data_points', 0)}")
        print(f"  First scan: {trend.get('first_timestamp', 'N/A')}")
        print(f"  Last scan: {trend.get('last_timestamp', 'N/A')}")

        if "findings_trend" in trend:
            ft = trend["findings_trend"]
            print()
            print(f"  Findings trend:")
            print(f"    Start: {ft.get('start_count', 0)}")
            print(f"    End: {ft.get('end_count', 0)}")
            print(f"    Change: {ft.get('change', 0):+d}")
            print(f"    Direction: {ft.get('direction', 'stable')}")

    return 0


def cmd_trends(args: argparse.Namespace) -> int:
    """
    Handle trends subcommand.

    Provides advanced trend analysis with forecasting.

    Returns:
        Exit code (0 success, 1 error)
    """
    action = getattr(args, "trends_action", None) or getattr(args, "action", "summary")

    handlers = {
        "summary": _trends_summary,
        "forecast": _trends_forecast,
        "velocity": _trends_velocity,
        "compare": _trends_compare,
    }

    handler = handlers.get(action)
    if handler:
        return handler(args)

    print(f"Unknown trends action: {action}")
    return 1


def _trends_summary(args: argparse.Namespace) -> int:
    """Show trend summary."""
    from stance.reporting import TrendAnalyzer

    days = getattr(args, "days", 30)
    config_name = getattr(args, "config", "default")

    analyzer = _get_trend_analyzer()
    report = analyzer.analyze(config_name=config_name, days=days)

    output_format = getattr(args, "format", "table")

    if output_format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(f"Trend Analysis Summary ({days} days)")
        print("=" * 50)
        print()
        print(f"Direction: {report.total_findings.direction.value.upper()}")
        print(f"Scan frequency: {report.scan_frequency:.2f} scans/day")
        print()
        print("Findings Metrics:")
        print(f"  Current: {report.total_findings.current_value:.0f}")
        print(f"  Previous: {report.total_findings.previous_value:.0f}")
        print(f"  Change: {report.total_findings.change:+.0f} ({report.total_findings.change_percent:+.1f}%)")
        print(f"  Average: {report.total_findings.average:.1f}")
        print(f"  Velocity: {report.total_findings.velocity:+.2f}/day")
        print()

        if report.severity_trends:
            print("By Severity:")
            for sev, trend in report.severity_trends.items():
                print(f"  {sev}: {trend.metrics.current_value:.0f} ({trend.metrics.change:+.0f})")
        print()

        if report.recommendations:
            print("Recommendations:")
            for i, rec in enumerate(report.recommendations, 1):
                print(f"  {i}. {rec}")

    return 0


def _trends_forecast(args: argparse.Namespace) -> int:
    """Show findings forecast."""
    history_days = getattr(args, "history_days", 30)
    forecast_days = getattr(args, "forecast_days", 7)
    config_name = getattr(args, "config", "default")

    analyzer = _get_trend_analyzer()
    forecast = analyzer.forecast(
        config_name=config_name,
        days_history=history_days,
        days_forecast=forecast_days,
    )

    output_format = getattr(args, "format", "table")

    if output_format == "json":
        print(json.dumps(forecast, indent=2))
    else:
        if "error" in forecast:
            print(f"Forecast error: {forecast['error']}")
            return 1

        print(f"Findings Forecast")
        print("=" * 50)
        print()
        print(f"Model: {forecast.get('model', 'N/A')}")
        print(f"Data points: {forecast.get('data_points', 0)}")
        print(f"Confidence (R²): {forecast.get('confidence', 0):.2%}")
        print(f"Trend: {forecast.get('trend_direction', 'N/A')}")
        print(f"Slope: {forecast.get('trend_slope', 0):+.4f}/day")
        print()
        print(f"Current findings: {forecast.get('current_findings', 0)}")
        print()
        print("Forecast:")
        for fc in forecast.get("forecasts", []):
            print(f"  Day {fc['day']}: {fc['projected_findings']} findings")

    return 0


def _trends_velocity(args: argparse.Namespace) -> int:
    """Show findings velocity."""
    days = getattr(args, "days", 7)
    config_name = getattr(args, "config", "default")

    analyzer = _get_trend_analyzer()
    velocities = analyzer.get_findings_velocity(config_name=config_name, days=days)

    output_format = getattr(args, "format", "table")

    if output_format == "json":
        print(json.dumps(velocities, indent=2))
    else:
        print(f"Findings Velocity ({days} days)")
        print("=" * 40)
        print()
        for sev, vel in velocities.items():
            direction = "↓" if vel < 0 else "↑" if vel > 0 else "→"
            print(f"  {sev:<12}: {vel:+.2f}/day {direction}")

    return 0


def _trends_compare(args: argparse.Namespace) -> int:
    """Compare periods."""
    current_days = getattr(args, "current_days", 7)
    previous_days = getattr(args, "previous_days", 7)
    config_name = getattr(args, "config", "default")

    analyzer = _get_trend_analyzer()
    comparison = analyzer.compare_periods(
        config_name=config_name,
        current_days=current_days,
        previous_days=previous_days,
    )

    output_format = getattr(args, "format", "table")

    if output_format == "json":
        print(json.dumps(comparison, indent=2, default=str))
    else:
        print(f"Period Comparison")
        print("=" * 50)
        print()

        current = comparison.get("current_period", {})
        previous = comparison.get("previous_period", {})
        comp = comparison.get("comparison", {})

        print(f"Current period: {current.get('days', 0)} days")
        print(f"  Scans: {current.get('stats', {}).get('scans', 0)}")
        print(f"  Avg findings: {current.get('stats', {}).get('avg_findings', 0):.1f}")
        print()

        print(f"Previous period: {previous.get('days', 0)} days")
        print(f"  Scans: {previous.get('stats', {}).get('scans', 0)}")
        print(f"  Avg findings: {previous.get('stats', {}).get('avg_findings', 0):.1f}")
        print()

        change = comp.get("avg_findings_change", 0)
        direction = comp.get("direction", "stable")
        print(f"Change: {change:+.1f}%")
        print(f"Direction: {direction.upper()}")

    return 0


# Helper functions

def _get_scheduler():
    """Get or create scheduler instance."""
    from stance.scheduling import ScanScheduler
    import os

    state_path = os.path.expanduser("~/.stance/scheduler_state.json")
    scheduler = ScanScheduler()

    if os.path.exists(state_path):
        try:
            with open(state_path, "r") as f:
                import json
                state = json.load(f)
                scheduler = ScanScheduler.from_dict(state)
        except Exception as e:
            logger.warning(f"Failed to load scheduler state: {e}")

    return scheduler


def _save_scheduler(scheduler):
    """Save scheduler state."""
    import os

    state_path = os.path.expanduser("~/.stance/scheduler_state.json")
    os.makedirs(os.path.dirname(state_path), exist_ok=True)

    try:
        with open(state_path, "w") as f:
            import json
            json.dump(scheduler.to_dict(), f, indent=2, default=str)
    except Exception as e:
        logger.warning(f"Failed to save scheduler state: {e}")


def _get_history_manager():
    """Get history manager instance."""
    from stance.scheduling import ScanHistoryManager

    return ScanHistoryManager(storage_path="~/.stance/history")


def _get_trend_analyzer():
    """Get trend analyzer instance."""
    from stance.reporting import TrendAnalyzer

    history_manager = _get_history_manager()
    return TrendAnalyzer(history_manager=history_manager)
