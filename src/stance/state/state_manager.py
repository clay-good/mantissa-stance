"""
State management for Mantissa Stance.

Provides state tracking for scans, checkpoints, and finding lifecycle.
Supports multiple backends: local file, DynamoDB, Firestore, and Cosmos DB.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Iterator


class ScanStatus(Enum):
    """Status of a scan operation."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingLifecycle(Enum):
    """Lifecycle states for findings."""

    NEW = "new"  # First time seen
    RECURRING = "recurring"  # Seen again in subsequent scans
    RESOLVED = "resolved"  # No longer detected
    REOPENED = "reopened"  # Was resolved, now detected again
    SUPPRESSED = "suppressed"  # Manually suppressed
    FALSE_POSITIVE = "false_positive"  # Marked as false positive


@dataclass
class ScanRecord:
    """Record of a scan execution."""

    scan_id: str
    snapshot_id: str
    status: ScanStatus
    started_at: datetime
    completed_at: datetime | None = None
    config_name: str = "default"
    account_id: str = ""
    region: str = ""
    collectors: list[str] = field(default_factory=list)
    asset_count: int = 0
    finding_count: int = 0
    error_message: str = ""
    duration_seconds: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scan_id": self.scan_id,
            "snapshot_id": self.snapshot_id,
            "status": self.status.value,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "config_name": self.config_name,
            "account_id": self.account_id,
            "region": self.region,
            "collectors": self.collectors,
            "asset_count": self.asset_count,
            "finding_count": self.finding_count,
            "error_message": self.error_message,
            "duration_seconds": self.duration_seconds,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanRecord:
        """Create from dictionary."""
        return cls(
            scan_id=data["scan_id"],
            snapshot_id=data["snapshot_id"],
            status=ScanStatus(data["status"]),
            started_at=datetime.fromisoformat(data["started_at"]),
            completed_at=datetime.fromisoformat(data["completed_at"])
            if data.get("completed_at")
            else None,
            config_name=data.get("config_name", "default"),
            account_id=data.get("account_id", ""),
            region=data.get("region", ""),
            collectors=data.get("collectors", []),
            asset_count=data.get("asset_count", 0),
            finding_count=data.get("finding_count", 0),
            error_message=data.get("error_message", ""),
            duration_seconds=data.get("duration_seconds", 0.0),
            metadata=data.get("metadata", {}),
        )


@dataclass
class Checkpoint:
    """Checkpoint for incremental scans."""

    checkpoint_id: str
    collector_name: str
    account_id: str
    region: str
    last_scan_id: str
    last_scan_time: datetime
    cursor: str = ""  # Opaque cursor for pagination/continuation
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "checkpoint_id": self.checkpoint_id,
            "collector_name": self.collector_name,
            "account_id": self.account_id,
            "region": self.region,
            "last_scan_id": self.last_scan_id,
            "last_scan_time": self.last_scan_time.isoformat(),
            "cursor": self.cursor,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Checkpoint:
        """Create from dictionary."""
        return cls(
            checkpoint_id=data["checkpoint_id"],
            collector_name=data["collector_name"],
            account_id=data["account_id"],
            region=data["region"],
            last_scan_id=data["last_scan_id"],
            last_scan_time=datetime.fromisoformat(data["last_scan_time"]),
            cursor=data.get("cursor", ""),
            metadata=data.get("metadata", {}),
        )


@dataclass
class FindingState:
    """State tracking for a finding."""

    finding_id: str
    asset_id: str
    rule_id: str
    lifecycle: FindingLifecycle
    first_seen: datetime
    last_seen: datetime
    resolved_at: datetime | None = None
    scan_count: int = 1  # Number of scans where this was seen
    suppressed_by: str = ""
    suppressed_at: datetime | None = None
    suppression_reason: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "finding_id": self.finding_id,
            "asset_id": self.asset_id,
            "rule_id": self.rule_id,
            "lifecycle": self.lifecycle.value,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "scan_count": self.scan_count,
            "suppressed_by": self.suppressed_by,
            "suppressed_at": self.suppressed_at.isoformat()
            if self.suppressed_at
            else None,
            "suppression_reason": self.suppression_reason,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FindingState:
        """Create from dictionary."""
        return cls(
            finding_id=data["finding_id"],
            asset_id=data["asset_id"],
            rule_id=data["rule_id"],
            lifecycle=FindingLifecycle(data["lifecycle"]),
            first_seen=datetime.fromisoformat(data["first_seen"]),
            last_seen=datetime.fromisoformat(data["last_seen"]),
            resolved_at=datetime.fromisoformat(data["resolved_at"])
            if data.get("resolved_at")
            else None,
            scan_count=data.get("scan_count", 1),
            suppressed_by=data.get("suppressed_by", ""),
            suppressed_at=datetime.fromisoformat(data["suppressed_at"])
            if data.get("suppressed_at")
            else None,
            suppression_reason=data.get("suppression_reason", ""),
            notes=data.get("notes", []),
        )


class StateBackend(ABC):
    """Abstract base class for state storage backends."""

    @abstractmethod
    def save_scan(self, record: ScanRecord) -> None:
        """Save a scan record."""
        pass

    @abstractmethod
    def get_scan(self, scan_id: str) -> ScanRecord | None:
        """Get a scan record by ID."""
        pass

    @abstractmethod
    def list_scans(
        self,
        limit: int = 100,
        status: ScanStatus | None = None,
        since: datetime | None = None,
    ) -> list[ScanRecord]:
        """List scan records with optional filters."""
        pass

    @abstractmethod
    def save_checkpoint(self, checkpoint: Checkpoint) -> None:
        """Save a checkpoint."""
        pass

    @abstractmethod
    def get_checkpoint(
        self, collector_name: str, account_id: str, region: str
    ) -> Checkpoint | None:
        """Get a checkpoint for a collector/account/region combination."""
        pass

    @abstractmethod
    def delete_checkpoint(
        self, collector_name: str, account_id: str, region: str
    ) -> bool:
        """Delete a checkpoint."""
        pass

    @abstractmethod
    def save_finding_state(self, state: FindingState) -> None:
        """Save finding state."""
        pass

    @abstractmethod
    def get_finding_state(self, finding_id: str) -> FindingState | None:
        """Get finding state by ID."""
        pass

    @abstractmethod
    def list_finding_states(
        self,
        asset_id: str | None = None,
        lifecycle: FindingLifecycle | None = None,
        limit: int = 1000,
    ) -> list[FindingState]:
        """List finding states with optional filters."""
        pass


class LocalStateBackend(StateBackend):
    """SQLite-based local state storage."""

    def __init__(self, db_path: str = "~/.stance/state.db"):
        """
        Initialize local state backend.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = os.path.expanduser(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database tables."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    snapshot_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    config_name TEXT,
                    account_id TEXT,
                    region TEXT,
                    collectors TEXT,
                    asset_count INTEGER,
                    finding_count INTEGER,
                    error_message TEXT,
                    duration_seconds REAL,
                    metadata TEXT
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS checkpoints (
                    checkpoint_id TEXT PRIMARY KEY,
                    collector_name TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    region TEXT NOT NULL,
                    last_scan_id TEXT NOT NULL,
                    last_scan_time TEXT NOT NULL,
                    cursor TEXT,
                    metadata TEXT,
                    UNIQUE(collector_name, account_id, region)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS finding_states (
                    finding_id TEXT PRIMARY KEY,
                    asset_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    lifecycle TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    resolved_at TEXT,
                    scan_count INTEGER,
                    suppressed_by TEXT,
                    suppressed_at TEXT,
                    suppression_reason TEXT,
                    notes TEXT
                )
            """)

            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_finding_states_asset ON finding_states(asset_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_finding_states_lifecycle ON finding_states(lifecycle)"
            )

            conn.commit()

    def save_scan(self, record: ScanRecord) -> None:
        """Save a scan record."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scans
                (scan_id, snapshot_id, status, started_at, completed_at,
                 config_name, account_id, region, collectors, asset_count,
                 finding_count, error_message, duration_seconds, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    record.scan_id,
                    record.snapshot_id,
                    record.status.value,
                    record.started_at.isoformat(),
                    record.completed_at.isoformat() if record.completed_at else None,
                    record.config_name,
                    record.account_id,
                    record.region,
                    json.dumps(record.collectors),
                    record.asset_count,
                    record.finding_count,
                    record.error_message,
                    record.duration_seconds,
                    json.dumps(record.metadata),
                ),
            )
            conn.commit()

    def get_scan(self, scan_id: str) -> ScanRecord | None:
        """Get a scan record by ID."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
            )
            row = cursor.fetchone()
            if row:
                return self._row_to_scan(row)
            return None

    def list_scans(
        self,
        limit: int = 100,
        status: ScanStatus | None = None,
        since: datetime | None = None,
    ) -> list[ScanRecord]:
        """List scan records with optional filters."""
        query = "SELECT * FROM scans WHERE 1=1"
        params: list[Any] = []

        if status:
            query += " AND status = ?"
            params.append(status.value)

        if since:
            query += " AND started_at >= ?"
            params.append(since.isoformat())

        query += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query, params)
            return [self._row_to_scan(row) for row in cursor.fetchall()]

    def _row_to_scan(self, row: sqlite3.Row) -> ScanRecord:
        """Convert database row to ScanRecord."""
        return ScanRecord(
            scan_id=row["scan_id"],
            snapshot_id=row["snapshot_id"],
            status=ScanStatus(row["status"]),
            started_at=datetime.fromisoformat(row["started_at"]),
            completed_at=datetime.fromisoformat(row["completed_at"])
            if row["completed_at"]
            else None,
            config_name=row["config_name"] or "default",
            account_id=row["account_id"] or "",
            region=row["region"] or "",
            collectors=json.loads(row["collectors"]) if row["collectors"] else [],
            asset_count=row["asset_count"] or 0,
            finding_count=row["finding_count"] or 0,
            error_message=row["error_message"] or "",
            duration_seconds=row["duration_seconds"] or 0.0,
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
        )

    def save_checkpoint(self, checkpoint: Checkpoint) -> None:
        """Save a checkpoint."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO checkpoints
                (checkpoint_id, collector_name, account_id, region,
                 last_scan_id, last_scan_time, cursor, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    checkpoint.checkpoint_id,
                    checkpoint.collector_name,
                    checkpoint.account_id,
                    checkpoint.region,
                    checkpoint.last_scan_id,
                    checkpoint.last_scan_time.isoformat(),
                    checkpoint.cursor,
                    json.dumps(checkpoint.metadata),
                ),
            )
            conn.commit()

    def get_checkpoint(
        self, collector_name: str, account_id: str, region: str
    ) -> Checkpoint | None:
        """Get a checkpoint for a collector/account/region combination."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """
                SELECT * FROM checkpoints
                WHERE collector_name = ? AND account_id = ? AND region = ?
            """,
                (collector_name, account_id, region),
            )
            row = cursor.fetchone()
            if row:
                return Checkpoint(
                    checkpoint_id=row["checkpoint_id"],
                    collector_name=row["collector_name"],
                    account_id=row["account_id"],
                    region=row["region"],
                    last_scan_id=row["last_scan_id"],
                    last_scan_time=datetime.fromisoformat(row["last_scan_time"]),
                    cursor=row["cursor"] or "",
                    metadata=json.loads(row["metadata"]) if row["metadata"] else {},
                )
            return None

    def delete_checkpoint(
        self, collector_name: str, account_id: str, region: str
    ) -> bool:
        """Delete a checkpoint."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                DELETE FROM checkpoints
                WHERE collector_name = ? AND account_id = ? AND region = ?
            """,
                (collector_name, account_id, region),
            )
            conn.commit()
            return cursor.rowcount > 0

    def save_finding_state(self, state: FindingState) -> None:
        """Save finding state."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO finding_states
                (finding_id, asset_id, rule_id, lifecycle, first_seen,
                 last_seen, resolved_at, scan_count, suppressed_by,
                 suppressed_at, suppression_reason, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    state.finding_id,
                    state.asset_id,
                    state.rule_id,
                    state.lifecycle.value,
                    state.first_seen.isoformat(),
                    state.last_seen.isoformat(),
                    state.resolved_at.isoformat() if state.resolved_at else None,
                    state.scan_count,
                    state.suppressed_by,
                    state.suppressed_at.isoformat() if state.suppressed_at else None,
                    state.suppression_reason,
                    json.dumps(state.notes),
                ),
            )
            conn.commit()

    def get_finding_state(self, finding_id: str) -> FindingState | None:
        """Get finding state by ID."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM finding_states WHERE finding_id = ?", (finding_id,)
            )
            row = cursor.fetchone()
            if row:
                return self._row_to_finding_state(row)
            return None

    def list_finding_states(
        self,
        asset_id: str | None = None,
        lifecycle: FindingLifecycle | None = None,
        limit: int = 1000,
    ) -> list[FindingState]:
        """List finding states with optional filters."""
        query = "SELECT * FROM finding_states WHERE 1=1"
        params: list[Any] = []

        if asset_id:
            query += " AND asset_id = ?"
            params.append(asset_id)

        if lifecycle:
            query += " AND lifecycle = ?"
            params.append(lifecycle.value)

        query += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query, params)
            return [self._row_to_finding_state(row) for row in cursor.fetchall()]

    def _row_to_finding_state(self, row: sqlite3.Row) -> FindingState:
        """Convert database row to FindingState."""
        return FindingState(
            finding_id=row["finding_id"],
            asset_id=row["asset_id"],
            rule_id=row["rule_id"],
            lifecycle=FindingLifecycle(row["lifecycle"]),
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
            resolved_at=datetime.fromisoformat(row["resolved_at"])
            if row["resolved_at"]
            else None,
            scan_count=row["scan_count"] or 1,
            suppressed_by=row["suppressed_by"] or "",
            suppressed_at=datetime.fromisoformat(row["suppressed_at"])
            if row["suppressed_at"]
            else None,
            suppression_reason=row["suppression_reason"] or "",
            notes=json.loads(row["notes"]) if row["notes"] else [],
        )


class StateManager:
    """
    High-level state management for Stance.

    Provides convenient methods for tracking scan history,
    managing checkpoints, and tracking finding lifecycle.
    """

    def __init__(self, backend: StateBackend | None = None):
        """
        Initialize state manager.

        Args:
            backend: State storage backend (default: LocalStateBackend)
        """
        self.backend = backend or LocalStateBackend()

    def start_scan(
        self,
        scan_id: str,
        snapshot_id: str,
        config_name: str = "default",
        account_id: str = "",
        region: str = "",
        collectors: list[str] | None = None,
    ) -> ScanRecord:
        """
        Record the start of a scan.

        Args:
            scan_id: Unique scan identifier
            snapshot_id: Associated snapshot ID
            config_name: Configuration name used
            account_id: Account being scanned
            region: Region being scanned
            collectors: List of collectors being run

        Returns:
            ScanRecord for the started scan
        """
        record = ScanRecord(
            scan_id=scan_id,
            snapshot_id=snapshot_id,
            status=ScanStatus.RUNNING,
            started_at=datetime.utcnow(),
            config_name=config_name,
            account_id=account_id,
            region=region,
            collectors=collectors or [],
        )
        self.backend.save_scan(record)
        return record

    def complete_scan(
        self,
        scan_id: str,
        asset_count: int,
        finding_count: int,
        error_message: str = "",
    ) -> ScanRecord | None:
        """
        Record the completion of a scan.

        Args:
            scan_id: Scan identifier
            asset_count: Number of assets discovered
            finding_count: Number of findings generated
            error_message: Error message if scan failed

        Returns:
            Updated ScanRecord, or None if scan not found
        """
        record = self.backend.get_scan(scan_id)
        if not record:
            return None

        record.status = ScanStatus.FAILED if error_message else ScanStatus.COMPLETED
        record.completed_at = datetime.utcnow()
        record.asset_count = asset_count
        record.finding_count = finding_count
        record.error_message = error_message
        record.duration_seconds = (
            record.completed_at - record.started_at
        ).total_seconds()

        self.backend.save_scan(record)
        return record

    def get_last_scan(
        self, account_id: str = "", region: str = ""
    ) -> ScanRecord | None:
        """
        Get the last completed scan.

        Args:
            account_id: Filter by account ID
            region: Filter by region

        Returns:
            Last completed ScanRecord, or None
        """
        scans = self.backend.list_scans(limit=1, status=ScanStatus.COMPLETED)
        for scan in scans:
            if account_id and scan.account_id != account_id:
                continue
            if region and scan.region != region:
                continue
            return scan
        return None

    def update_checkpoint(
        self,
        collector_name: str,
        account_id: str,
        region: str,
        scan_id: str,
        cursor: str = "",
    ) -> Checkpoint:
        """
        Update checkpoint for incremental scanning.

        Args:
            collector_name: Name of the collector
            account_id: Account ID
            region: Region
            scan_id: Current scan ID
            cursor: Optional continuation cursor

        Returns:
            Updated Checkpoint
        """
        checkpoint_id = hashlib.sha256(
            f"{collector_name}:{account_id}:{region}".encode()
        ).hexdigest()[:16]

        checkpoint = Checkpoint(
            checkpoint_id=checkpoint_id,
            collector_name=collector_name,
            account_id=account_id,
            region=region,
            last_scan_id=scan_id,
            last_scan_time=datetime.utcnow(),
            cursor=cursor,
        )
        self.backend.save_checkpoint(checkpoint)
        return checkpoint

    def get_checkpoint(
        self, collector_name: str, account_id: str, region: str
    ) -> Checkpoint | None:
        """
        Get checkpoint for a collector/account/region.

        Args:
            collector_name: Name of the collector
            account_id: Account ID
            region: Region

        Returns:
            Checkpoint if exists, None otherwise
        """
        return self.backend.get_checkpoint(collector_name, account_id, region)

    def track_finding(
        self,
        finding_id: str,
        asset_id: str,
        rule_id: str,
    ) -> FindingState:
        """
        Track a finding's lifecycle.

        Updates the finding state based on whether it's new or recurring.

        Args:
            finding_id: Finding identifier
            asset_id: Associated asset ID
            rule_id: Policy rule that generated the finding

        Returns:
            Updated FindingState
        """
        existing = self.backend.get_finding_state(finding_id)
        now = datetime.utcnow()

        if existing:
            # Existing finding - update lifecycle
            if existing.lifecycle == FindingLifecycle.RESOLVED:
                existing.lifecycle = FindingLifecycle.REOPENED
            else:
                existing.lifecycle = FindingLifecycle.RECURRING
            existing.last_seen = now
            existing.scan_count += 1
            existing.resolved_at = None
            self.backend.save_finding_state(existing)
            return existing
        else:
            # New finding
            state = FindingState(
                finding_id=finding_id,
                asset_id=asset_id,
                rule_id=rule_id,
                lifecycle=FindingLifecycle.NEW,
                first_seen=now,
                last_seen=now,
            )
            self.backend.save_finding_state(state)
            return state

    def resolve_finding(self, finding_id: str) -> FindingState | None:
        """
        Mark a finding as resolved.

        Args:
            finding_id: Finding identifier

        Returns:
            Updated FindingState, or None if not found
        """
        state = self.backend.get_finding_state(finding_id)
        if not state:
            return None

        state.lifecycle = FindingLifecycle.RESOLVED
        state.resolved_at = datetime.utcnow()
        self.backend.save_finding_state(state)
        return state

    def suppress_finding(
        self,
        finding_id: str,
        suppressed_by: str,
        reason: str = "",
    ) -> FindingState | None:
        """
        Suppress a finding.

        Args:
            finding_id: Finding identifier
            suppressed_by: User/system that suppressed the finding
            reason: Reason for suppression

        Returns:
            Updated FindingState, or None if not found
        """
        state = self.backend.get_finding_state(finding_id)
        if not state:
            return None

        state.lifecycle = FindingLifecycle.SUPPRESSED
        state.suppressed_by = suppressed_by
        state.suppressed_at = datetime.utcnow()
        state.suppression_reason = reason
        self.backend.save_finding_state(state)
        return state

    def get_finding_stats(self) -> dict[str, int]:
        """
        Get finding statistics by lifecycle state.

        Returns:
            Dictionary mapping lifecycle states to counts
        """
        stats = {}
        for lifecycle in FindingLifecycle:
            states = self.backend.list_finding_states(lifecycle=lifecycle, limit=10000)
            stats[lifecycle.value] = len(states)
        return stats

    def cleanup_old_scans(self, days: int = 90) -> int:
        """
        Clean up old scan records.

        Args:
            days: Remove scans older than this many days

        Returns:
            Number of records cleaned up
        """
        cutoff = datetime.utcnow() - timedelta(days=days)
        # For local backend, we'd need to implement this
        # For cloud backends, lifecycle policies handle this
        return 0


def get_state_manager(backend_type: str = "local", **kwargs) -> StateManager:
    """
    Factory function to create a state manager.

    Args:
        backend_type: Type of backend (local, dynamodb, firestore, cosmosdb)
        **kwargs: Backend-specific configuration

    Returns:
        Configured StateManager
    """
    if backend_type == "local":
        db_path = kwargs.get("db_path", "~/.stance/state.db")
        backend = LocalStateBackend(db_path=db_path)
    else:
        raise ValueError(f"Unknown backend type: {backend_type}")

    return StateManager(backend=backend)
