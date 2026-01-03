"""
Scan Scheduler for Mantissa Stance.

Provides scheduling capabilities for automated security scans including
cron-based schedules, rate-based schedules, and scan job management.
"""

from __future__ import annotations

import re
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable
from uuid import uuid4


class ScheduleType(Enum):
    """Types of schedule expressions."""

    CRON = "cron"
    RATE = "rate"
    ONCE = "once"


@dataclass
class ScheduleExpression(ABC):
    """Base class for schedule expressions."""

    expression: str
    timezone: str = "UTC"

    @abstractmethod
    def get_next_run(self, after: datetime | None = None) -> datetime:
        """Get the next scheduled run time after the given datetime."""
        pass

    @abstractmethod
    def matches(self, dt: datetime) -> bool:
        """Check if a datetime matches this schedule."""
        pass

    @abstractmethod
    def get_schedule_type(self) -> ScheduleType:
        """Get the type of this schedule."""
        pass


@dataclass
class CronExpression(ScheduleExpression):
    """
    Cron-based schedule expression.

    Supports standard cron format: minute hour day-of-month month day-of-week
    Also supports AWS CloudWatch style: cron(minute hour day-of-month month day-of-week year)

    Examples:
        - "0 * * * *" - Every hour at minute 0
        - "0 0 * * *" - Daily at midnight
        - "0 0 * * 0" - Weekly on Sunday at midnight
        - "cron(0 12 * * ? *)" - Daily at noon (AWS style)
    """

    def __post_init__(self):
        """Parse and validate the cron expression."""
        self._parse_expression()

    def _parse_expression(self) -> None:
        """Parse the cron expression into components."""
        expr = self.expression.strip()

        # Handle AWS-style cron() wrapper
        if expr.startswith("cron(") and expr.endswith(")"):
            expr = expr[5:-1]

        parts = expr.split()

        # Standard 5-field cron or 6-field AWS style
        if len(parts) == 5:
            self._minute, self._hour, self._dom, self._month, self._dow = parts
            self._year = "*"
        elif len(parts) == 6:
            self._minute, self._hour, self._dom, self._month, self._dow, self._year = parts
        else:
            raise ValueError(
                f"Invalid cron expression: {self.expression}. "
                "Expected 5 or 6 fields."
            )

    def get_next_run(self, after: datetime | None = None) -> datetime:
        """
        Get the next scheduled run time.

        Args:
            after: Start time to search from (defaults to now)

        Returns:
            Next datetime that matches the cron schedule
        """
        if after is None:
            after = datetime.utcnow()

        # Start from the next minute
        current = after.replace(second=0, microsecond=0) + timedelta(minutes=1)

        # Search for the next matching time (limit to prevent infinite loops)
        for _ in range(525600):  # Max 1 year of minutes
            if self.matches(current):
                return current
            current += timedelta(minutes=1)

        # Fallback - should not reach here
        return after + timedelta(days=1)

    def matches(self, dt: datetime) -> bool:
        """
        Check if a datetime matches this cron expression.

        Args:
            dt: Datetime to check

        Returns:
            True if the datetime matches the schedule
        """
        return (
            self._matches_field(self._minute, dt.minute, 0, 59)
            and self._matches_field(self._hour, dt.hour, 0, 23)
            and self._matches_field(self._dom, dt.day, 1, 31)
            and self._matches_field(self._month, dt.month, 1, 12)
            and self._matches_dow(dt.weekday())
            and self._matches_field(self._year, dt.year, 2000, 2100)
        )

    def _matches_field(self, field: str, value: int, min_val: int, max_val: int) -> bool:
        """Check if a value matches a cron field."""
        if field == "*" or field == "?":
            return True

        # Handle comma-separated values
        if "," in field:
            return any(
                self._matches_field(part.strip(), value, min_val, max_val)
                for part in field.split(",")
            )

        # Handle ranges (e.g., "1-5")
        if "-" in field and "/" not in field:
            try:
                start, end = field.split("-")
                return int(start) <= value <= int(end)
            except ValueError:
                return False

        # Handle step values (e.g., "*/5")
        if "/" in field:
            base, step = field.split("/")
            try:
                step_val = int(step)
                if base == "*":
                    return (value - min_val) % step_val == 0
                else:
                    start = int(base)
                    return value >= start and (value - start) % step_val == 0
            except ValueError:
                return False

        # Simple numeric match
        try:
            return int(field) == value
        except ValueError:
            return False

    def _matches_dow(self, weekday: int) -> bool:
        """
        Check if weekday matches day-of-week field.

        Python weekday: 0=Monday, 6=Sunday
        Cron weekday: 0=Sunday, 6=Saturday (traditional) or 1=Monday, 7=Sunday (some systems)
        """
        if self._dow == "*" or self._dow == "?":
            return True

        # Convert Python weekday (0=Mon) to cron (0=Sun)
        cron_dow = (weekday + 1) % 7

        return self._matches_field(self._dow, cron_dow, 0, 6)

    def get_schedule_type(self) -> ScheduleType:
        """Get the schedule type."""
        return ScheduleType.CRON


@dataclass
class RateExpression(ScheduleExpression):
    """
    Rate-based schedule expression.

    Runs at fixed intervals from the start time.

    Examples:
        - "rate(5 minutes)" - Every 5 minutes
        - "rate(1 hour)" - Every hour
        - "rate(1 day)" - Every day
    """

    _interval: timedelta = field(default=None, init=False)

    def __post_init__(self):
        """Parse the rate expression."""
        self._parse_expression()

    def _parse_expression(self) -> None:
        """Parse the rate expression into an interval."""
        expr = self.expression.strip()

        # Handle rate() wrapper
        if expr.startswith("rate(") and expr.endswith(")"):
            expr = expr[5:-1]

        # Parse "N unit" format
        match = re.match(r"(\d+)\s*(minute|minutes|hour|hours|day|days)s?", expr, re.I)
        if not match:
            raise ValueError(f"Invalid rate expression: {self.expression}")

        value = int(match.group(1))
        unit = match.group(2).lower()

        if unit in ("minute", "minutes"):
            self._interval = timedelta(minutes=value)
        elif unit in ("hour", "hours"):
            self._interval = timedelta(hours=value)
        elif unit in ("day", "days"):
            self._interval = timedelta(days=value)
        else:
            raise ValueError(f"Unknown time unit: {unit}")

    def get_next_run(self, after: datetime | None = None) -> datetime:
        """
        Get the next scheduled run time.

        Args:
            after: Start time to search from (defaults to now)

        Returns:
            Next datetime based on the rate interval
        """
        if after is None:
            after = datetime.utcnow()

        # Round up to the next interval boundary
        return after + self._interval

    def matches(self, dt: datetime) -> bool:
        """
        Check if a datetime matches this rate expression.

        For rate expressions, we check if the time is at an interval boundary.
        This is approximate since rate schedules don't have fixed times.
        """
        # Rate expressions match at any interval from epoch
        epoch = datetime(2000, 1, 1)
        elapsed = dt - epoch
        interval_seconds = self._interval.total_seconds()

        return elapsed.total_seconds() % interval_seconds < 60

    def get_schedule_type(self) -> ScheduleType:
        """Get the schedule type."""
        return ScheduleType.RATE

    @property
    def interval(self) -> timedelta:
        """Get the interval between runs."""
        return self._interval


@dataclass
class ScanResult:
    """
    Result of a scan execution.

    Attributes:
        job_id: ID of the job that produced this result
        scan_id: Unique ID for this scan execution
        started_at: When the scan started
        completed_at: When the scan completed
        success: Whether the scan completed successfully
        error: Error message if the scan failed
        assets_scanned: Number of assets scanned
        findings_count: Number of findings discovered
        metadata: Additional result metadata
    """

    job_id: str
    scan_id: str
    started_at: datetime
    completed_at: datetime | None = None
    success: bool = True
    error: str = ""
    assets_scanned: int = 0
    findings_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def duration(self) -> timedelta | None:
        """Get the duration of the scan."""
        if self.completed_at and self.started_at:
            return self.completed_at - self.started_at
        return None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "job_id": self.job_id,
            "scan_id": self.scan_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "success": self.success,
            "error": self.error,
            "assets_scanned": self.assets_scanned,
            "findings_count": self.findings_count,
            "duration_seconds": self.duration.total_seconds() if self.duration else None,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanResult:
        """Create from dictionary."""
        return cls(
            job_id=data["job_id"],
            scan_id=data["scan_id"],
            started_at=datetime.fromisoformat(data["started_at"]),
            completed_at=datetime.fromisoformat(data["completed_at"])
            if data.get("completed_at")
            else None,
            success=data.get("success", True),
            error=data.get("error", ""),
            assets_scanned=data.get("assets_scanned", 0),
            findings_count=data.get("findings_count", 0),
            metadata=data.get("metadata", {}),
        )


@dataclass
class ScanJob:
    """
    A scheduled scan job.

    Attributes:
        id: Unique job identifier
        name: Human-readable job name
        schedule: Schedule expression for when to run
        config_name: Name of the scan configuration to use
        enabled: Whether the job is enabled
        last_run: When the job last ran
        next_run: When the job will next run
        run_count: Number of times the job has run
        last_result: Result of the last run
        created_at: When the job was created
        metadata: Additional job metadata
    """

    id: str
    name: str
    schedule: ScheduleExpression
    config_name: str = "default"
    enabled: bool = True
    last_run: datetime | None = None
    next_run: datetime | None = None
    run_count: int = 0
    last_result: ScanResult | None = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Calculate next run time if not set."""
        if self.next_run is None and self.enabled:
            self.next_run = self.schedule.get_next_run()

    def should_run(self, now: datetime | None = None) -> bool:
        """Check if the job should run now."""
        if not self.enabled:
            return False
        if now is None:
            now = datetime.utcnow()
        return self.next_run is not None and now >= self.next_run

    def mark_run(self, result: ScanResult) -> None:
        """Mark the job as having run with the given result."""
        self.last_run = result.started_at
        self.last_result = result
        self.run_count += 1
        self.next_run = self.schedule.get_next_run(result.completed_at or result.started_at)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "schedule_type": self.schedule.get_schedule_type().value,
            "schedule_expression": self.schedule.expression,
            "config_name": self.config_name,
            "enabled": self.enabled,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "run_count": self.run_count,
            "last_result": self.last_result.to_dict() if self.last_result else None,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanJob:
        """Create from dictionary."""
        schedule_type = ScheduleType(data["schedule_type"])
        schedule_expr = data["schedule_expression"]

        if schedule_type == ScheduleType.CRON:
            schedule = CronExpression(expression=schedule_expr)
        elif schedule_type == ScheduleType.RATE:
            schedule = RateExpression(expression=schedule_expr)
        else:
            raise ValueError(f"Unsupported schedule type: {schedule_type}")

        return cls(
            id=data["id"],
            name=data["name"],
            schedule=schedule,
            config_name=data.get("config_name", "default"),
            enabled=data.get("enabled", True),
            last_run=datetime.fromisoformat(data["last_run"]) if data.get("last_run") else None,
            next_run=datetime.fromisoformat(data["next_run"]) if data.get("next_run") else None,
            run_count=data.get("run_count", 0),
            last_result=ScanResult.from_dict(data["last_result"])
            if data.get("last_result")
            else None,
            created_at=datetime.fromisoformat(data["created_at"])
            if data.get("created_at")
            else datetime.utcnow(),
            metadata=data.get("metadata", {}),
        )


class ScanScheduler:
    """
    Manages scheduled scan jobs.

    Provides scheduling, execution, and management of automated security scans.
    """

    def __init__(
        self,
        scan_executor: Callable[[str], ScanResult] | None = None,
        check_interval: int = 60,
    ):
        """
        Initialize the scan scheduler.

        Args:
            scan_executor: Function to execute scans (receives config name, returns ScanResult)
            check_interval: Seconds between schedule checks (default: 60)
        """
        self._jobs: dict[str, ScanJob] = {}
        self._executor = scan_executor
        self._check_interval = check_interval
        self._running = False
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._callbacks: list[Callable[[ScanJob, ScanResult], None]] = []

    def add_job(
        self,
        name: str,
        schedule: ScheduleExpression | str,
        config_name: str = "default",
        enabled: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> ScanJob:
        """
        Add a new scan job.

        Args:
            name: Job name
            schedule: Schedule expression (cron or rate)
            config_name: Scan configuration to use
            enabled: Whether to enable the job
            metadata: Additional job metadata

        Returns:
            The created ScanJob
        """
        # Parse schedule string if needed
        if isinstance(schedule, str):
            schedule = self._parse_schedule(schedule)

        job = ScanJob(
            id=str(uuid4()),
            name=name,
            schedule=schedule,
            config_name=config_name,
            enabled=enabled,
            metadata=metadata or {},
        )

        with self._lock:
            self._jobs[job.id] = job

        return job

    def remove_job(self, job_id: str) -> bool:
        """
        Remove a job by ID.

        Args:
            job_id: Job ID to remove

        Returns:
            True if removed, False if not found
        """
        with self._lock:
            if job_id in self._jobs:
                del self._jobs[job_id]
                return True
            return False

    def get_job(self, job_id: str) -> ScanJob | None:
        """Get a job by ID."""
        return self._jobs.get(job_id)

    def get_jobs(self) -> list[ScanJob]:
        """Get all jobs."""
        return list(self._jobs.values())

    def get_enabled_jobs(self) -> list[ScanJob]:
        """Get all enabled jobs."""
        return [job for job in self._jobs.values() if job.enabled]

    def get_pending_jobs(self, now: datetime | None = None) -> list[ScanJob]:
        """Get jobs that should run now."""
        if now is None:
            now = datetime.utcnow()
        return [job for job in self._jobs.values() if job.should_run(now)]

    def enable_job(self, job_id: str) -> bool:
        """Enable a job."""
        job = self._jobs.get(job_id)
        if job:
            job.enabled = True
            job.next_run = job.schedule.get_next_run()
            return True
        return False

    def disable_job(self, job_id: str) -> bool:
        """Disable a job."""
        job = self._jobs.get(job_id)
        if job:
            job.enabled = False
            return True
        return False

    def run_job_now(self, job_id: str) -> ScanResult | None:
        """
        Run a job immediately regardless of schedule.

        Args:
            job_id: Job ID to run

        Returns:
            ScanResult if executed, None if job not found
        """
        job = self._jobs.get(job_id)
        if not job:
            return None

        return self._execute_job(job)

    def add_callback(self, callback: Callable[[ScanJob, ScanResult], None]) -> None:
        """
        Add a callback to be called after each job execution.

        Args:
            callback: Function taking (ScanJob, ScanResult)
        """
        self._callbacks.append(callback)

    def start(self) -> None:
        """Start the scheduler background thread."""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the scheduler background thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def is_running(self) -> bool:
        """Check if the scheduler is running."""
        return self._running

    def _run_loop(self) -> None:
        """Main scheduler loop."""
        while self._running:
            try:
                self._check_and_run_jobs()
            except Exception:
                # Log error but keep running
                pass
            time.sleep(self._check_interval)

    def _check_and_run_jobs(self) -> None:
        """Check for pending jobs and run them."""
        now = datetime.utcnow()
        pending = self.get_pending_jobs(now)

        for job in pending:
            try:
                self._execute_job(job)
            except Exception:
                # Log error but continue with other jobs
                pass

    def _execute_job(self, job: ScanJob) -> ScanResult:
        """Execute a single job."""
        scan_id = str(uuid4())
        started_at = datetime.utcnow()

        result = ScanResult(
            job_id=job.id,
            scan_id=scan_id,
            started_at=started_at,
        )

        try:
            if self._executor:
                # Run the actual scan
                result = self._executor(job.config_name)
                result.job_id = job.id
                result.scan_id = scan_id
            else:
                # No executor - just mark as complete
                result.completed_at = datetime.utcnow()
                result.success = True

        except Exception as e:
            result.completed_at = datetime.utcnow()
            result.success = False
            result.error = str(e)

        # Update job state
        job.mark_run(result)

        # Notify callbacks
        for callback in self._callbacks:
            try:
                callback(job, result)
            except Exception:
                pass

        return result

    def _parse_schedule(self, expression: str) -> ScheduleExpression:
        """Parse a schedule expression string."""
        expr = expression.strip().lower()

        if expr.startswith("rate(") or re.match(r"^\d+\s+(minute|hour|day)", expr):
            return RateExpression(expression=expression)
        else:
            return CronExpression(expression=expression)

    def get_status(self) -> dict[str, Any]:
        """Get scheduler status."""
        now = datetime.utcnow()
        return {
            "running": self._running,
            "total_jobs": len(self._jobs),
            "enabled_jobs": len(self.get_enabled_jobs()),
            "pending_jobs": len(self.get_pending_jobs(now)),
            "check_interval": self._check_interval,
            "jobs": [job.to_dict() for job in self._jobs.values()],
        }

    def to_dict(self) -> dict[str, Any]:
        """Convert scheduler state to dictionary."""
        return {
            "jobs": [job.to_dict() for job in self._jobs.values()],
            "check_interval": self._check_interval,
        }

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
        scan_executor: Callable[[str], ScanResult] | None = None,
    ) -> ScanScheduler:
        """Create scheduler from dictionary."""
        scheduler = cls(
            scan_executor=scan_executor,
            check_interval=data.get("check_interval", 60),
        )

        for job_data in data.get("jobs", []):
            job = ScanJob.from_dict(job_data)
            scheduler._jobs[job.id] = job

        return scheduler


def parse_schedule(expression: str) -> ScheduleExpression:
    """
    Parse a schedule expression string.

    Args:
        expression: Cron or rate expression

    Returns:
        Parsed ScheduleExpression

    Raises:
        ValueError: If the expression is invalid
    """
    expr = expression.strip().lower()

    if expr.startswith("rate(") or re.match(r"^\d+\s+(minute|hour|day)", expr):
        return RateExpression(expression=expression)
    else:
        return CronExpression(expression=expression)
