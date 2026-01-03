"""
Findings diff command for Mantissa Stance.

Provides comparison between scan snapshots to show
new, resolved, and changed findings.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class DiffChangeType(Enum):
    """Type of change in a finding."""

    NEW = "new"
    RESOLVED = "resolved"
    SEVERITY_CHANGED = "severity_changed"
    UNCHANGED = "unchanged"


@dataclass
class FindingChange:
    """
    Represents a change in a finding.

    Attributes:
        finding_id: The finding identifier
        change_type: Type of change (new, resolved, severity_changed)
        severity: Current or last severity
        previous_severity: Previous severity (for changes)
        rule_id: Policy rule ID
        asset_id: Affected asset ID
        description: Finding description
    """

    finding_id: str
    change_type: DiffChangeType
    severity: str
    previous_severity: str | None = None
    rule_id: str | None = None
    asset_id: str | None = None
    description: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "finding_id": self.finding_id,
            "change_type": self.change_type.value,
            "severity": self.severity,
            "previous_severity": self.previous_severity,
            "rule_id": self.rule_id,
            "asset_id": self.asset_id,
            "description": self.description,
        }


@dataclass
class DiffSummary:
    """
    Summary of differences between two snapshots.

    Attributes:
        baseline_snapshot: ID of baseline snapshot
        current_snapshot: ID of current snapshot
        baseline_timestamp: When baseline was created
        current_timestamp: When current was created
        new_findings: Number of new findings
        resolved_findings: Number of resolved findings
        severity_changes: Number of severity changes
        unchanged_findings: Number of unchanged findings
        new_by_severity: New findings by severity
        resolved_by_severity: Resolved findings by severity
        net_change: Net change in total findings
        is_improved: Whether posture improved
    """

    baseline_snapshot: str
    current_snapshot: str
    baseline_timestamp: datetime | None = None
    current_timestamp: datetime | None = None
    new_findings: int = 0
    resolved_findings: int = 0
    severity_changes: int = 0
    unchanged_findings: int = 0
    new_by_severity: dict[str, int] = field(default_factory=dict)
    resolved_by_severity: dict[str, int] = field(default_factory=dict)
    net_change: int = 0
    is_improved: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "baseline_snapshot": self.baseline_snapshot,
            "current_snapshot": self.current_snapshot,
            "baseline_timestamp": (
                self.baseline_timestamp.isoformat()
                if self.baseline_timestamp
                else None
            ),
            "current_timestamp": (
                self.current_timestamp.isoformat()
                if self.current_timestamp
                else None
            ),
            "new_findings": self.new_findings,
            "resolved_findings": self.resolved_findings,
            "severity_changes": self.severity_changes,
            "unchanged_findings": self.unchanged_findings,
            "new_by_severity": self.new_by_severity,
            "resolved_by_severity": self.resolved_by_severity,
            "net_change": self.net_change,
            "is_improved": self.is_improved,
        }


@dataclass
class DiffResult:
    """
    Complete diff result between two snapshots.

    Attributes:
        summary: DiffSummary with statistics
        changes: List of FindingChange objects
        baseline_findings: Dict of baseline findings by ID
        current_findings: Dict of current findings by ID
    """

    summary: DiffSummary
    changes: list[FindingChange] = field(default_factory=list)
    baseline_findings: dict[str, dict] = field(default_factory=dict)
    current_findings: dict[str, dict] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "summary": self.summary.to_dict(),
            "changes": [c.to_dict() for c in self.changes],
        }

    def get_new_findings(self) -> list[FindingChange]:
        """Get only new findings."""
        return [c for c in self.changes if c.change_type == DiffChangeType.NEW]

    def get_resolved_findings(self) -> list[FindingChange]:
        """Get only resolved findings."""
        return [c for c in self.changes if c.change_type == DiffChangeType.RESOLVED]

    def get_severity_changes(self) -> list[FindingChange]:
        """Get only severity changes."""
        return [
            c for c in self.changes if c.change_type == DiffChangeType.SEVERITY_CHANGED
        ]


class FindingsDiffer:
    """
    Compares findings between two scan snapshots.

    Provides detailed diff information including new findings,
    resolved findings, and severity changes.
    """

    def __init__(self, storage_type: str = "local"):
        """
        Initialize the differ.

        Args:
            storage_type: Storage backend type
        """
        self._storage_type = storage_type
        self._storage = None

    @property
    def storage(self):
        """Lazy-load storage backend."""
        if self._storage is None:
            from stance.storage import get_storage

            self._storage = get_storage(self._storage_type)
        return self._storage

    def diff(
        self,
        baseline_snapshot: str,
        current_snapshot: str | None = None,
    ) -> DiffResult:
        """
        Compare findings between two snapshots.

        Args:
            baseline_snapshot: Baseline snapshot ID
            current_snapshot: Current snapshot ID (default: latest)

        Returns:
            DiffResult with changes
        """
        # Get baseline findings
        baseline_sql = f"""
        SELECT * FROM findings WHERE snapshot_id = '{baseline_snapshot}'
        """
        baseline_data = self.storage.query_findings(baseline_sql)
        baseline_findings = {f["id"]: f for f in baseline_data}

        # Get current findings
        if current_snapshot:
            current_sql = f"""
            SELECT * FROM findings WHERE snapshot_id = '{current_snapshot}'
            """
        else:
            current_sql = """
            SELECT * FROM findings
            ORDER BY timestamp DESC
            """
            # Get latest snapshot
            current_snapshot = "latest"

        current_data = self.storage.query_findings(current_sql)
        current_findings = {f["id"]: f for f in current_data}

        return self._compute_diff(
            baseline_snapshot,
            current_snapshot,
            baseline_findings,
            current_findings,
        )

    def diff_from_data(
        self,
        baseline_findings: list[dict],
        current_findings: list[dict],
        baseline_id: str = "baseline",
        current_id: str = "current",
    ) -> DiffResult:
        """
        Compare findings from provided data.

        Args:
            baseline_findings: List of baseline finding dicts
            current_findings: List of current finding dicts
            baseline_id: Baseline identifier
            current_id: Current identifier

        Returns:
            DiffResult with changes
        """
        baseline_map = {f.get("id", f.get("finding_id", str(i))): f for i, f in enumerate(baseline_findings)}
        current_map = {f.get("id", f.get("finding_id", str(i))): f for i, f in enumerate(current_findings)}

        return self._compute_diff(baseline_id, current_id, baseline_map, current_map)

    def _compute_diff(
        self,
        baseline_id: str,
        current_id: str,
        baseline_findings: dict[str, dict],
        current_findings: dict[str, dict],
    ) -> DiffResult:
        """
        Compute the diff between two finding sets.

        Args:
            baseline_id: Baseline identifier
            current_id: Current identifier
            baseline_findings: Dict of baseline findings
            current_findings: Dict of current findings

        Returns:
            DiffResult with all changes
        """
        changes: list[FindingChange] = []
        new_by_severity: dict[str, int] = {}
        resolved_by_severity: dict[str, int] = {}
        severity_changes = 0
        unchanged = 0

        baseline_ids = set(baseline_findings.keys())
        current_ids = set(current_findings.keys())

        # New findings (in current but not baseline)
        new_ids = current_ids - baseline_ids
        for fid in new_ids:
            finding = current_findings[fid]
            severity = finding.get("severity", "unknown")
            changes.append(
                FindingChange(
                    finding_id=fid,
                    change_type=DiffChangeType.NEW,
                    severity=severity,
                    rule_id=finding.get("rule_id"),
                    asset_id=finding.get("asset_id"),
                    description=finding.get("description"),
                )
            )
            new_by_severity[severity] = new_by_severity.get(severity, 0) + 1

        # Resolved findings (in baseline but not current)
        resolved_ids = baseline_ids - current_ids
        for fid in resolved_ids:
            finding = baseline_findings[fid]
            severity = finding.get("severity", "unknown")
            changes.append(
                FindingChange(
                    finding_id=fid,
                    change_type=DiffChangeType.RESOLVED,
                    severity=severity,
                    rule_id=finding.get("rule_id"),
                    asset_id=finding.get("asset_id"),
                    description=finding.get("description"),
                )
            )
            resolved_by_severity[severity] = resolved_by_severity.get(severity, 0) + 1

        # Check for severity changes in common findings
        common_ids = baseline_ids & current_ids
        for fid in common_ids:
            baseline = baseline_findings[fid]
            current = current_findings[fid]
            baseline_sev = baseline.get("severity", "unknown")
            current_sev = current.get("severity", "unknown")

            if baseline_sev != current_sev:
                changes.append(
                    FindingChange(
                        finding_id=fid,
                        change_type=DiffChangeType.SEVERITY_CHANGED,
                        severity=current_sev,
                        previous_severity=baseline_sev,
                        rule_id=current.get("rule_id"),
                        asset_id=current.get("asset_id"),
                        description=current.get("description"),
                    )
                )
                severity_changes += 1
            else:
                unchanged += 1

        # Calculate summary
        net_change = len(new_ids) - len(resolved_ids)
        is_improved = net_change < 0 or (
            net_change == 0 and len(resolved_ids) > len(new_ids)
        )

        summary = DiffSummary(
            baseline_snapshot=baseline_id,
            current_snapshot=current_id,
            new_findings=len(new_ids),
            resolved_findings=len(resolved_ids),
            severity_changes=severity_changes,
            unchanged_findings=unchanged,
            new_by_severity=new_by_severity,
            resolved_by_severity=resolved_by_severity,
            net_change=net_change,
            is_improved=is_improved,
        )

        return DiffResult(
            summary=summary,
            changes=changes,
            baseline_findings=baseline_findings,
            current_findings=current_findings,
        )


def format_diff_table(diff: DiffResult, show_unchanged: bool = False) -> str:
    """
    Format diff result as a table.

    Args:
        diff: DiffResult to format
        show_unchanged: Include unchanged findings

    Returns:
        Formatted table string
    """
    lines = []

    # Summary header
    lines.append("")
    lines.append("=" * 70)
    lines.append("FINDINGS DIFF")
    lines.append("=" * 70)
    lines.append(f"Baseline: {diff.summary.baseline_snapshot}")
    lines.append(f"Current:  {diff.summary.current_snapshot}")
    lines.append("-" * 70)

    # Statistics
    status = "IMPROVED" if diff.summary.is_improved else "DEGRADED" if diff.summary.net_change > 0 else "STABLE"
    status_symbol = "+" if diff.summary.is_improved else "-" if diff.summary.net_change > 0 else "="

    lines.append(f"Status: {status_symbol} {status}")
    lines.append(f"New findings:      +{diff.summary.new_findings}")
    lines.append(f"Resolved findings: -{diff.summary.resolved_findings}")
    lines.append(f"Severity changes:   {diff.summary.severity_changes}")
    lines.append(f"Net change:        {diff.summary.net_change:+d}")
    lines.append("")

    # New findings by severity
    if diff.summary.new_by_severity:
        lines.append("New by severity:")
        for sev, count in sorted(diff.summary.new_by_severity.items()):
            lines.append(f"  {sev}: +{count}")
        lines.append("")

    # Resolved by severity
    if diff.summary.resolved_by_severity:
        lines.append("Resolved by severity:")
        for sev, count in sorted(diff.summary.resolved_by_severity.items()):
            lines.append(f"  {sev}: -{count}")
        lines.append("")

    # New findings list
    new_findings = diff.get_new_findings()
    if new_findings:
        lines.append("-" * 70)
        lines.append(f"NEW FINDINGS ({len(new_findings)})")
        lines.append("-" * 70)
        lines.append(f"{'Severity':<10} {'Rule':<25} {'Asset':<30}")
        lines.append("-" * 70)
        for change in new_findings[:20]:  # Limit to 20
            sev = change.severity[:8] if change.severity else ""
            rule = (change.rule_id[:23] if change.rule_id else "")
            asset = (change.asset_id[:28] if change.asset_id else "")
            lines.append(f"{sev:<10} {rule:<25} {asset:<30}")
        if len(new_findings) > 20:
            lines.append(f"... and {len(new_findings) - 20} more")
        lines.append("")

    # Resolved findings list
    resolved_findings = diff.get_resolved_findings()
    if resolved_findings:
        lines.append("-" * 70)
        lines.append(f"RESOLVED FINDINGS ({len(resolved_findings)})")
        lines.append("-" * 70)
        lines.append(f"{'Severity':<10} {'Rule':<25} {'Asset':<30}")
        lines.append("-" * 70)
        for change in resolved_findings[:20]:
            sev = change.severity[:8] if change.severity else ""
            rule = (change.rule_id[:23] if change.rule_id else "")
            asset = (change.asset_id[:28] if change.asset_id else "")
            lines.append(f"{sev:<10} {rule:<25} {asset:<30}")
        if len(resolved_findings) > 20:
            lines.append(f"... and {len(resolved_findings) - 20} more")
        lines.append("")

    # Severity changes
    severity_changes = diff.get_severity_changes()
    if severity_changes:
        lines.append("-" * 70)
        lines.append(f"SEVERITY CHANGES ({len(severity_changes)})")
        lines.append("-" * 70)
        lines.append(f"{'From':<10} {'To':<10} {'Rule':<20} {'Asset':<25}")
        lines.append("-" * 70)
        for change in severity_changes[:20]:
            from_sev = change.previous_severity[:8] if change.previous_severity else ""
            to_sev = change.severity[:8] if change.severity else ""
            rule = (change.rule_id[:18] if change.rule_id else "")
            asset = (change.asset_id[:23] if change.asset_id else "")
            lines.append(f"{from_sev:<10} {to_sev:<10} {rule:<20} {asset:<25}")
        if len(severity_changes) > 20:
            lines.append(f"... and {len(severity_changes) - 20} more")
        lines.append("")

    lines.append("=" * 70)

    return "\n".join(lines)


def cmd_diff(args: argparse.Namespace) -> int:
    """
    Execute findings diff command.

    Args:
        args: Command-line arguments

    Returns:
        Exit code
    """
    baseline = getattr(args, "baseline", None)
    current = getattr(args, "current", None)
    output_format = getattr(args, "format", "table")
    show_unchanged = getattr(args, "show_unchanged", False)

    if not baseline:
        print("Error: --baseline snapshot ID is required")
        return 1

    try:
        differ = FindingsDiffer()
        result = differ.diff(baseline, current)

        if output_format == "json":
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print(format_diff_table(result, show_unchanged))

        # Return non-zero if there are new findings
        if result.summary.new_findings > 0:
            return 1 if getattr(args, "fail_on_new", False) else 0
        return 0

    except Exception as e:
        print(f"Error computing diff: {e}")
        return 1
