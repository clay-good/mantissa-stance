"""
Scan History for Mantissa Stance.

Provides scan history tracking, storage, and comparison capabilities
for analyzing security posture changes over time.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from stance.models.finding import Finding, FindingCollection, Severity


class DiffType(Enum):
    """Types of differences between scans."""

    NEW = "new"  # Finding appeared in latest scan
    RESOLVED = "resolved"  # Finding no longer present
    UNCHANGED = "unchanged"  # Finding present in both
    SEVERITY_CHANGED = "severity_changed"  # Same finding, different severity
    STATUS_CHANGED = "status_changed"  # Same finding, different status


@dataclass
class ScanHistoryEntry:
    """
    A single scan history entry.

    Attributes:
        scan_id: Unique scan identifier
        timestamp: When the scan was performed
        config_name: Configuration used for the scan
        duration_seconds: How long the scan took
        assets_scanned: Number of assets scanned
        findings_total: Total number of findings
        findings_by_severity: Breakdown by severity level
        accounts_scanned: List of accounts scanned
        regions_scanned: List of regions scanned
        collectors_used: List of collectors used
        metadata: Additional scan metadata
    """

    scan_id: str
    timestamp: datetime
    config_name: str = "default"
    duration_seconds: float = 0.0
    assets_scanned: int = 0
    findings_total: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    accounts_scanned: list[str] = field(default_factory=list)
    regions_scanned: list[str] = field(default_factory=list)
    collectors_used: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp.isoformat(),
            "config_name": self.config_name,
            "duration_seconds": self.duration_seconds,
            "assets_scanned": self.assets_scanned,
            "findings_total": self.findings_total,
            "findings_by_severity": self.findings_by_severity,
            "accounts_scanned": self.accounts_scanned,
            "regions_scanned": self.regions_scanned,
            "collectors_used": self.collectors_used,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanHistoryEntry:
        """Create from dictionary."""
        return cls(
            scan_id=data["scan_id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            config_name=data.get("config_name", "default"),
            duration_seconds=data.get("duration_seconds", 0.0),
            assets_scanned=data.get("assets_scanned", 0),
            findings_total=data.get("findings_total", 0),
            findings_by_severity=data.get("findings_by_severity", {}),
            accounts_scanned=data.get("accounts_scanned", []),
            regions_scanned=data.get("regions_scanned", []),
            collectors_used=data.get("collectors_used", []),
            metadata=data.get("metadata", {}),
        )


@dataclass
class ScanDiff:
    """
    Difference for a single finding between scans.

    Attributes:
        finding_id: ID of the finding
        diff_type: Type of difference
        finding: The finding object
        previous_severity: Previous severity (if changed)
        current_severity: Current severity (if changed)
        previous_status: Previous status (if changed)
        current_status: Current status (if changed)
    """

    finding_id: str
    diff_type: DiffType
    finding: Finding | None = None
    previous_severity: Severity | None = None
    current_severity: Severity | None = None
    previous_status: str | None = None
    current_status: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "finding_id": self.finding_id,
            "diff_type": self.diff_type.value,
            "finding": self.finding.to_dict() if self.finding else None,
            "previous_severity": self.previous_severity.value if self.previous_severity else None,
            "current_severity": self.current_severity.value if self.current_severity else None,
            "previous_status": self.previous_status,
            "current_status": self.current_status,
        }


@dataclass
class ScanComparison:
    """
    Comparison between two scans.

    Attributes:
        baseline_scan_id: ID of the baseline (previous) scan
        current_scan_id: ID of the current scan
        baseline_timestamp: When the baseline scan was performed
        current_timestamp: When the current scan was performed
        new_findings: Findings that appeared in current scan
        resolved_findings: Findings that were resolved
        unchanged_findings: Findings present in both
        severity_changes: Findings with severity changes
        status_changes: Findings with status changes
        summary: Summary statistics
    """

    baseline_scan_id: str
    current_scan_id: str
    baseline_timestamp: datetime
    current_timestamp: datetime
    new_findings: list[ScanDiff] = field(default_factory=list)
    resolved_findings: list[ScanDiff] = field(default_factory=list)
    unchanged_findings: list[ScanDiff] = field(default_factory=list)
    severity_changes: list[ScanDiff] = field(default_factory=list)
    status_changes: list[ScanDiff] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    @property
    def total_new(self) -> int:
        """Get count of new findings."""
        return len(self.new_findings)

    @property
    def total_resolved(self) -> int:
        """Get count of resolved findings."""
        return len(self.resolved_findings)

    @property
    def total_unchanged(self) -> int:
        """Get count of unchanged findings."""
        return len(self.unchanged_findings)

    @property
    def has_changes(self) -> bool:
        """Check if there are any changes."""
        return (
            len(self.new_findings) > 0
            or len(self.resolved_findings) > 0
            or len(self.severity_changes) > 0
            or len(self.status_changes) > 0
        )

    @property
    def improvement_ratio(self) -> float:
        """
        Calculate improvement ratio.

        Positive values indicate improvement (more resolved than new).
        Negative values indicate regression (more new than resolved).
        """
        total_changes = self.total_new + self.total_resolved
        if total_changes == 0:
            return 0.0
        return (self.total_resolved - self.total_new) / total_changes

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "baseline_scan_id": self.baseline_scan_id,
            "current_scan_id": self.current_scan_id,
            "baseline_timestamp": self.baseline_timestamp.isoformat(),
            "current_timestamp": self.current_timestamp.isoformat(),
            "new_findings": [d.to_dict() for d in self.new_findings],
            "resolved_findings": [d.to_dict() for d in self.resolved_findings],
            "unchanged_count": len(self.unchanged_findings),
            "severity_changes": [d.to_dict() for d in self.severity_changes],
            "status_changes": [d.to_dict() for d in self.status_changes],
            "summary": {
                "total_new": self.total_new,
                "total_resolved": self.total_resolved,
                "total_unchanged": self.total_unchanged,
                "has_changes": self.has_changes,
                "improvement_ratio": self.improvement_ratio,
                "new_by_severity": self._count_by_severity(self.new_findings),
                "resolved_by_severity": self._count_by_severity(self.resolved_findings),
            },
        }

    def _count_by_severity(self, diffs: list[ScanDiff]) -> dict[str, int]:
        """Count findings by severity."""
        counts: dict[str, int] = {}
        for diff in diffs:
            if diff.finding:
                sev = diff.finding.severity.value
                counts[sev] = counts.get(sev, 0) + 1
        return counts


class ScanHistoryManager:
    """
    Manages scan history and comparisons.

    Provides storage, retrieval, and analysis of historical scan data.
    """

    def __init__(self, storage_path: str = "~/.stance/history"):
        """
        Initialize the history manager.

        Args:
            storage_path: Path to store history data
        """
        self.storage_path = os.path.expanduser(storage_path)
        Path(self.storage_path).mkdir(parents=True, exist_ok=True)
        self._history_file = os.path.join(self.storage_path, "scan_history.json")
        self._findings_dir = os.path.join(self.storage_path, "findings")
        Path(self._findings_dir).mkdir(parents=True, exist_ok=True)

    def record_scan(
        self,
        scan_id: str,
        findings: FindingCollection,
        config_name: str = "default",
        duration_seconds: float = 0.0,
        assets_scanned: int = 0,
        accounts: list[str] | None = None,
        regions: list[str] | None = None,
        collectors: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ScanHistoryEntry:
        """
        Record a completed scan.

        Args:
            scan_id: Unique scan identifier
            findings: Findings from the scan
            config_name: Configuration used
            duration_seconds: Scan duration
            assets_scanned: Number of assets scanned
            accounts: Accounts scanned
            regions: Regions scanned
            collectors: Collectors used
            metadata: Additional metadata

        Returns:
            Created history entry
        """
        # Count findings by severity
        severity_counts = findings.count_by_severity_dict()

        entry = ScanHistoryEntry(
            scan_id=scan_id,
            timestamp=datetime.utcnow(),
            config_name=config_name,
            duration_seconds=duration_seconds,
            assets_scanned=assets_scanned,
            findings_total=len(findings),
            findings_by_severity=severity_counts,
            accounts_scanned=accounts or [],
            regions_scanned=regions or [],
            collectors_used=collectors or [],
            metadata=metadata or {},
        )

        # Save history entry
        self._save_entry(entry)

        # Save findings snapshot
        self._save_findings(scan_id, findings)

        return entry

    def get_history(
        self,
        limit: int | None = None,
        config_name: str | None = None,
        since: datetime | None = None,
    ) -> list[ScanHistoryEntry]:
        """
        Get scan history entries.

        Args:
            limit: Maximum number of entries to return
            config_name: Filter by configuration name
            since: Only include scans after this time

        Returns:
            List of history entries (most recent first)
        """
        entries = self._load_all_entries()

        # Filter by config
        if config_name:
            entries = [e for e in entries if e.config_name == config_name]

        # Filter by time
        if since:
            entries = [e for e in entries if e.timestamp >= since]

        # Sort by timestamp (most recent first)
        entries.sort(key=lambda e: e.timestamp, reverse=True)

        # Apply limit
        if limit:
            entries = entries[:limit]

        return entries

    def get_entry(self, scan_id: str) -> ScanHistoryEntry | None:
        """Get a specific history entry."""
        entries = self._load_all_entries()
        for entry in entries:
            if entry.scan_id == scan_id:
                return entry
        return None

    def get_latest(self, config_name: str = "default") -> ScanHistoryEntry | None:
        """Get the most recent scan for a configuration."""
        entries = self.get_history(limit=1, config_name=config_name)
        return entries[0] if entries else None

    def get_findings(self, scan_id: str) -> FindingCollection | None:
        """Get findings for a specific scan."""
        findings_file = os.path.join(self._findings_dir, f"{scan_id}.json")
        if not os.path.exists(findings_file):
            return None

        with open(findings_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            return FindingCollection.from_list(data)

    def compare_scans(
        self,
        baseline_scan_id: str,
        current_scan_id: str,
    ) -> ScanComparison | None:
        """
        Compare two scans.

        Args:
            baseline_scan_id: ID of the baseline (older) scan
            current_scan_id: ID of the current (newer) scan

        Returns:
            Comparison result, or None if scans not found
        """
        baseline_entry = self.get_entry(baseline_scan_id)
        current_entry = self.get_entry(current_scan_id)

        if not baseline_entry or not current_entry:
            return None

        baseline_findings = self.get_findings(baseline_scan_id)
        current_findings = self.get_findings(current_scan_id)

        if not baseline_findings or not current_findings:
            return None

        return self._compute_comparison(
            baseline_scan_id=baseline_scan_id,
            current_scan_id=current_scan_id,
            baseline_timestamp=baseline_entry.timestamp,
            current_timestamp=current_entry.timestamp,
            baseline_findings=baseline_findings,
            current_findings=current_findings,
        )

    def compare_with_latest(
        self,
        scan_id: str,
        config_name: str = "default",
    ) -> ScanComparison | None:
        """
        Compare a scan with the latest scan.

        Args:
            scan_id: ID of the baseline scan
            config_name: Configuration to compare within

        Returns:
            Comparison result
        """
        latest = self.get_latest(config_name)
        if not latest or latest.scan_id == scan_id:
            return None

        return self.compare_scans(scan_id, latest.scan_id)

    def get_trend(
        self,
        config_name: str = "default",
        days: int = 30,
    ) -> list[dict[str, Any]]:
        """
        Get trend data for the specified period.

        Args:
            config_name: Configuration to analyze
            days: Number of days to include

        Returns:
            List of trend data points
        """
        since = datetime.utcnow() - __import__("datetime").timedelta(days=days)
        entries = self.get_history(config_name=config_name, since=since)

        trend_data = []
        for entry in reversed(entries):  # Chronological order
            trend_data.append({
                "timestamp": entry.timestamp.isoformat(),
                "scan_id": entry.scan_id,
                "findings_total": entry.findings_total,
                "critical": entry.findings_by_severity.get("critical", 0),
                "high": entry.findings_by_severity.get("high", 0),
                "medium": entry.findings_by_severity.get("medium", 0),
                "low": entry.findings_by_severity.get("low", 0),
                "info": entry.findings_by_severity.get("info", 0),
                "assets_scanned": entry.assets_scanned,
            })

        return trend_data

    def cleanup_old_entries(self, retention_days: int = 90) -> int:
        """
        Remove history entries older than retention period.

        Args:
            retention_days: Number of days to retain

        Returns:
            Number of entries removed
        """
        cutoff = datetime.utcnow() - __import__("datetime").timedelta(days=retention_days)
        entries = self._load_all_entries()

        kept = []
        removed = 0

        for entry in entries:
            if entry.timestamp >= cutoff:
                kept.append(entry)
            else:
                # Remove findings file
                findings_file = os.path.join(self._findings_dir, f"{entry.scan_id}.json")
                if os.path.exists(findings_file):
                    os.remove(findings_file)
                removed += 1

        # Save remaining entries
        self._save_all_entries(kept)

        return removed

    def _save_entry(self, entry: ScanHistoryEntry) -> None:
        """Save a history entry."""
        entries = self._load_all_entries()
        entries.append(entry)
        self._save_all_entries(entries)

    def _save_all_entries(self, entries: list[ScanHistoryEntry]) -> None:
        """Save all history entries."""
        data = [e.to_dict() for e in entries]
        with open(self._history_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _load_all_entries(self) -> list[ScanHistoryEntry]:
        """Load all history entries."""
        if not os.path.exists(self._history_file):
            return []

        with open(self._history_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            return [ScanHistoryEntry.from_dict(d) for d in data]

    def _save_findings(self, scan_id: str, findings: FindingCollection) -> None:
        """Save findings for a scan."""
        findings_file = os.path.join(self._findings_dir, f"{scan_id}.json")
        with open(findings_file, "w", encoding="utf-8") as f:
            json.dump(findings.to_list(), f, indent=2)

    def _compute_comparison(
        self,
        baseline_scan_id: str,
        current_scan_id: str,
        baseline_timestamp: datetime,
        current_timestamp: datetime,
        baseline_findings: FindingCollection,
        current_findings: FindingCollection,
    ) -> ScanComparison:
        """Compute comparison between two finding sets."""
        # Create lookup maps
        baseline_map = {f.id: f for f in baseline_findings.findings}
        current_map = {f.id: f for f in current_findings.findings}

        comparison = ScanComparison(
            baseline_scan_id=baseline_scan_id,
            current_scan_id=current_scan_id,
            baseline_timestamp=baseline_timestamp,
            current_timestamp=current_timestamp,
        )

        # Find new findings (in current but not in baseline)
        for finding_id, finding in current_map.items():
            if finding_id not in baseline_map:
                comparison.new_findings.append(
                    ScanDiff(
                        finding_id=finding_id,
                        diff_type=DiffType.NEW,
                        finding=finding,
                    )
                )

        # Find resolved findings (in baseline but not in current)
        for finding_id, finding in baseline_map.items():
            if finding_id not in current_map:
                comparison.resolved_findings.append(
                    ScanDiff(
                        finding_id=finding_id,
                        diff_type=DiffType.RESOLVED,
                        finding=finding,
                    )
                )

        # Find unchanged and changed findings
        for finding_id in baseline_map.keys() & current_map.keys():
            baseline_finding = baseline_map[finding_id]
            current_finding = current_map[finding_id]

            if baseline_finding.severity != current_finding.severity:
                comparison.severity_changes.append(
                    ScanDiff(
                        finding_id=finding_id,
                        diff_type=DiffType.SEVERITY_CHANGED,
                        finding=current_finding,
                        previous_severity=baseline_finding.severity,
                        current_severity=current_finding.severity,
                    )
                )
            elif baseline_finding.status != current_finding.status:
                comparison.status_changes.append(
                    ScanDiff(
                        finding_id=finding_id,
                        diff_type=DiffType.STATUS_CHANGED,
                        finding=current_finding,
                        previous_status=baseline_finding.status.value,
                        current_status=current_finding.status.value,
                    )
                )
            else:
                comparison.unchanged_findings.append(
                    ScanDiff(
                        finding_id=finding_id,
                        diff_type=DiffType.UNCHANGED,
                        finding=current_finding,
                    )
                )

        return comparison
