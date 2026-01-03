"""
Watch mode for continuous monitoring in Mantissa Stance.

Provides continuous scanning with real-time updates and
notifications when security posture changes.
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

from stance import __version__


@dataclass
class WatchConfig:
    """
    Configuration for watch mode.

    Attributes:
        interval_seconds: Time between scans
        collectors: Specific collectors to run (None = all)
        policies: Specific policies to evaluate (None = all)
        notify_on_change: Send notifications on changes
        show_summary: Display summary after each scan
        show_diff: Display changes from previous scan
        max_iterations: Maximum scans (0 = unlimited)
        quiet: Suppress non-essential output
        output_format: Output format (table/json)
    """

    interval_seconds: int = 300  # 5 minutes default
    collectors: list[str] | None = None
    policies: list[str] | None = None
    notify_on_change: bool = False
    show_summary: bool = True
    show_diff: bool = True
    max_iterations: int = 0
    quiet: bool = False
    output_format: str = "table"


@dataclass
class ScanSnapshot:
    """
    Snapshot of scan results for comparison.

    Attributes:
        timestamp: When the scan was performed
        snapshot_id: Unique identifier for this snapshot
        total_findings: Total number of findings
        findings_by_severity: Findings count by severity
        critical_findings: List of critical finding IDs
        finding_ids: Set of all finding IDs
    """

    timestamp: datetime
    snapshot_id: str
    total_findings: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    critical_findings: list[str] = field(default_factory=list)
    finding_ids: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "snapshot_id": self.snapshot_id,
            "total_findings": self.total_findings,
            "findings_by_severity": self.findings_by_severity,
            "critical_findings": self.critical_findings,
            "finding_count": len(self.finding_ids),
        }


@dataclass
class ScanDelta:
    """
    Changes between two scan snapshots.

    Attributes:
        previous: Previous snapshot
        current: Current snapshot
        new_findings: Count of new findings
        resolved_findings: Count of resolved findings
        new_critical: Count of new critical findings
        severity_changes: Changes by severity
        is_improved: Whether posture improved
        is_degraded: Whether posture degraded
    """

    previous: ScanSnapshot
    current: ScanSnapshot
    new_findings: int = 0
    resolved_findings: int = 0
    new_critical: int = 0
    severity_changes: dict[str, int] = field(default_factory=dict)
    is_improved: bool = False
    is_degraded: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "previous_snapshot": self.previous.snapshot_id,
            "current_snapshot": self.current.snapshot_id,
            "new_findings": self.new_findings,
            "resolved_findings": self.resolved_findings,
            "new_critical": self.new_critical,
            "severity_changes": self.severity_changes,
            "is_improved": self.is_improved,
            "is_degraded": self.is_degraded,
            "net_change": self.new_findings - self.resolved_findings,
        }


class WatchMode:
    """
    Continuous monitoring mode for Stance.

    Runs periodic scans and tracks changes over time,
    providing real-time visibility into security posture.
    """

    def __init__(self, config: WatchConfig | None = None):
        """
        Initialize watch mode.

        Args:
            config: Watch configuration
        """
        self._config = config or WatchConfig()
        self._running = False
        self._stop_event = threading.Event()
        self._iteration = 0
        self._snapshots: list[ScanSnapshot] = []
        self._callbacks: list[Callable[[ScanSnapshot, ScanDelta | None], None]] = []
        self._last_error: str | None = None

    @property
    def config(self) -> WatchConfig:
        """Get watch configuration."""
        return self._config

    @property
    def is_running(self) -> bool:
        """Check if watch mode is running."""
        return self._running

    @property
    def iteration_count(self) -> int:
        """Get current iteration count."""
        return self._iteration

    @property
    def snapshots(self) -> list[ScanSnapshot]:
        """Get all snapshots."""
        return self._snapshots.copy()

    @property
    def last_snapshot(self) -> ScanSnapshot | None:
        """Get most recent snapshot."""
        return self._snapshots[-1] if self._snapshots else None

    def add_callback(
        self,
        callback: Callable[[ScanSnapshot, ScanDelta | None], None],
    ) -> None:
        """
        Add a callback to be called after each scan.

        Args:
            callback: Function receiving snapshot and optional delta
        """
        self._callbacks.append(callback)

    def start(self) -> None:
        """
        Start watch mode.

        Runs continuously until stop() is called or max_iterations reached.
        """
        self._running = True
        self._stop_event.clear()

        # Set up signal handlers
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

        self._print_header()

        try:
            while self._running:
                # Check max iterations before running
                if self._config.max_iterations > 0:
                    if self._iteration >= self._config.max_iterations:
                        self._print_message("Maximum iterations reached.")
                        break

                self._iteration += 1

                # Run scan
                self._run_scan_iteration()

                # Check if stopped
                if not self._running:
                    break

                # Wait for next interval
                if self._config.max_iterations == 0 or self._iteration < self._config.max_iterations:
                    self._wait_for_interval()

        finally:
            self._running = False
            self._print_footer()

    def stop(self) -> None:
        """Stop watch mode."""
        self._running = False
        self._stop_event.set()

    def _handle_signal(self, signum: int, frame: Any) -> None:
        """Handle interrupt signals."""
        self._print_message("\nStopping watch mode...")
        self.stop()

    def _print_header(self) -> None:
        """Print watch mode header."""
        if self._config.quiet:
            return

        print()
        print("=" * 70)
        print(f"  STANCE WATCH MODE - v{__version__}")
        print("=" * 70)
        print(f"  Interval: {self._config.interval_seconds}s")
        if self._config.collectors:
            print(f"  Collectors: {', '.join(self._config.collectors)}")
        if self._config.max_iterations:
            print(f"  Max iterations: {self._config.max_iterations}")
        print("  Press Ctrl+C to stop")
        print("=" * 70)
        print()

    def _print_footer(self) -> None:
        """Print watch mode footer."""
        if self._config.quiet:
            return

        print()
        print("=" * 70)
        print(f"  Watch mode stopped after {self._iteration} iteration(s)")
        if self._snapshots:
            first = self._snapshots[0]
            last = self._snapshots[-1]
            print(f"  First scan: {first.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"  Last scan:  {last.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"  Finding change: {first.total_findings} -> {last.total_findings}")
        print("=" * 70)
        print()

    def _print_message(self, message: str) -> None:
        """Print a message if not quiet."""
        if not self._config.quiet:
            print(message)

    def _run_scan_iteration(self) -> None:
        """Run a single scan iteration."""
        timestamp = datetime.utcnow()
        self._print_message(f"[{timestamp.strftime('%H:%M:%S')}] Scan #{self._iteration} starting...")

        try:
            snapshot = self._perform_scan()
            self._snapshots.append(snapshot)

            # Calculate delta from previous
            delta = None
            if len(self._snapshots) > 1:
                delta = self._calculate_delta(self._snapshots[-2], snapshot)

            # Display results
            self._display_results(snapshot, delta)

            # Notify callbacks
            for callback in self._callbacks:
                try:
                    callback(snapshot, delta)
                except Exception:
                    pass  # Don't let callback errors stop watch mode

            # Send notifications if configured
            if self._config.notify_on_change and delta:
                self._send_notifications(snapshot, delta)

        except Exception as e:
            self._last_error = str(e)
            self._print_message(f"  Error: {e}")

    def _perform_scan(self) -> ScanSnapshot:
        """
        Perform a security scan.

        Returns:
            ScanSnapshot with results
        """
        from stance.storage import get_storage, generate_snapshot_id
        from stance.collectors import run_collection
        from stance.engine import PolicyLoader, PolicyEvaluator
        from stance.models.finding import FindingCollection

        storage = get_storage("local")

        # Run collection
        assets, security_findings, results = run_collection(
            collectors=self._config.collectors,
        )

        # Store assets
        snapshot_id = generate_snapshot_id()
        storage.store_assets(assets, snapshot_id)

        # Evaluate policies
        loader = PolicyLoader()
        policies = loader.load_all()

        # Filter policies if specified
        if self._config.policies:
            policies = [p for p in policies if p.id in self._config.policies]

        evaluator = PolicyEvaluator()
        findings, eval_result = evaluator.evaluate_all(policies, assets)

        # Merge security findings
        findings = findings.merge(security_findings)

        # Store findings
        storage.store_findings(findings, snapshot_id)

        # Build snapshot
        severity_counts = findings.count_by_severity_dict()
        critical_ids = [
            f.id for f in findings
            if f.severity.value == "critical"
        ]

        return ScanSnapshot(
            timestamp=datetime.utcnow(),
            snapshot_id=snapshot_id,
            total_findings=len(findings),
            findings_by_severity=severity_counts,
            critical_findings=critical_ids,
            finding_ids={f.id for f in findings},
        )

    def _calculate_delta(
        self,
        previous: ScanSnapshot,
        current: ScanSnapshot,
    ) -> ScanDelta:
        """
        Calculate delta between two snapshots.

        Args:
            previous: Previous snapshot
            current: Current snapshot

        Returns:
            ScanDelta with changes
        """
        new_ids = current.finding_ids - previous.finding_ids
        resolved_ids = previous.finding_ids - current.finding_ids

        # Severity changes
        severity_changes = {}
        for sev in ["critical", "high", "medium", "low", "info"]:
            prev_count = previous.findings_by_severity.get(sev, 0)
            curr_count = current.findings_by_severity.get(sev, 0)
            change = curr_count - prev_count
            if change != 0:
                severity_changes[sev] = change

        # New critical findings
        new_critical = len(
            set(current.critical_findings) - set(previous.critical_findings)
        )

        # Determine improvement/degradation
        net_change = len(new_ids) - len(resolved_ids)
        is_improved = net_change < 0 or (
            net_change == 0 and severity_changes.get("critical", 0) < 0
        )
        is_degraded = net_change > 0 or new_critical > 0

        return ScanDelta(
            previous=previous,
            current=current,
            new_findings=len(new_ids),
            resolved_findings=len(resolved_ids),
            new_critical=new_critical,
            severity_changes=severity_changes,
            is_improved=is_improved,
            is_degraded=is_degraded,
        )

    def _display_results(
        self,
        snapshot: ScanSnapshot,
        delta: ScanDelta | None,
    ) -> None:
        """Display scan results."""
        if self._config.output_format == "json":
            output = {
                "snapshot": snapshot.to_dict(),
                "delta": delta.to_dict() if delta else None,
            }
            print(json.dumps(output, indent=2))
            return

        if self._config.quiet:
            return

        # Summary
        if self._config.show_summary:
            print(f"  Snapshot: {snapshot.snapshot_id}")
            print(f"  Total findings: {snapshot.total_findings}")
            sev_str = ", ".join(
                f"{sev}:{count}"
                for sev, count in snapshot.findings_by_severity.items()
                if count > 0
            )
            if sev_str:
                print(f"  By severity: {sev_str}")

        # Delta
        if self._config.show_diff and delta:
            status = "IMPROVED" if delta.is_improved else "DEGRADED" if delta.is_degraded else "STABLE"
            status_symbol = "✓" if delta.is_improved else "✗" if delta.is_degraded else "="

            print(f"  Status: {status_symbol} {status}")
            if delta.new_findings:
                print(f"  New findings: +{delta.new_findings}")
            if delta.resolved_findings:
                print(f"  Resolved: -{delta.resolved_findings}")
            if delta.new_critical:
                print(f"  New critical: {delta.new_critical} ⚠️")

        print()

    def _send_notifications(
        self,
        snapshot: ScanSnapshot,
        delta: ScanDelta,
    ) -> None:
        """Send notifications for changes."""
        if not delta.is_degraded:
            return

        # Only notify on degradation
        try:
            from stance.automation import NotificationHandler, NotificationType

            handler = NotificationHandler()

            if delta.new_critical > 0:
                handler._notify(
                    NotificationType.CRITICAL_FINDING,
                    f"Watch mode detected {delta.new_critical} new critical finding(s)",
                    scan_id=snapshot.snapshot_id,
                    details={
                        "new_findings": delta.new_findings,
                        "new_critical": delta.new_critical,
                    },
                )
        except ImportError:
            pass  # Notification module not available

    def _wait_for_interval(self) -> None:
        """Wait for the configured interval."""
        self._print_message(
            f"  Next scan in {self._config.interval_seconds}s (Ctrl+C to stop)"
        )
        self._stop_event.wait(timeout=self._config.interval_seconds)


def cmd_watch(args: argparse.Namespace) -> int:
    """
    Execute watch mode command.

    Args:
        args: Command-line arguments

    Returns:
        Exit code
    """
    # Build configuration
    config = WatchConfig(
        interval_seconds=getattr(args, "interval", 300),
        collectors=getattr(args, "collectors", "").split(",") if getattr(args, "collectors", None) else None,
        notify_on_change=getattr(args, "notify", False),
        show_summary=not getattr(args, "no_summary", False),
        show_diff=not getattr(args, "no_diff", False),
        max_iterations=getattr(args, "count", 0),
        quiet=getattr(args, "quiet", False),
        output_format=getattr(args, "format", "table"),
    )

    watch = WatchMode(config)

    try:
        watch.start()
        return 0
    except KeyboardInterrupt:
        print("\nWatch mode interrupted.")
        return 0
    except Exception as e:
        print(f"Watch mode error: {e}")
        return 1
