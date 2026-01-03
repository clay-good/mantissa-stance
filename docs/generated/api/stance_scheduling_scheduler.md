# stance.scheduling.scheduler

Scan Scheduler for Mantissa Stance.

Provides scheduling capabilities for automated security scans including
cron-based schedules, rate-based schedules, and scan job management.

## Contents

### Classes

- [ScheduleType](#scheduletype)
- [ScheduleExpression](#scheduleexpression)
- [CronExpression](#cronexpression)
- [RateExpression](#rateexpression)
- [ScanResult](#scanresult)
- [ScanJob](#scanjob)
- [ScanScheduler](#scanscheduler)

### Functions

- [parse_schedule](#parse_schedule)

## ScheduleType

**Inherits from:** Enum

Types of schedule expressions.

## ScheduleExpression

**Inherits from:** ABC

**Tags:** dataclass

Base class for schedule expressions.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `expression` | `str` | - |
| `timezone` | `str` | `UTC` |

### Methods

#### `get_next_run(self, after: datetime | None) -> datetime`

**Decorators:** @abstractmethod

Get the next scheduled run time after the given datetime.

**Parameters:**

- `after` (`datetime | None`)

**Returns:**

`datetime`

#### `matches(self, dt: datetime) -> bool`

**Decorators:** @abstractmethod

Check if a datetime matches this schedule.

**Parameters:**

- `dt` (`datetime`)

**Returns:**

`bool`

#### `get_schedule_type(self) -> ScheduleType`

**Decorators:** @abstractmethod

Get the type of this schedule.

**Returns:**

`ScheduleType`

## CronExpression

**Inherits from:** ScheduleExpression

**Tags:** dataclass

Cron-based schedule expression.

Supports standard cron format: minute hour day-of-month month day-of-week
Also supports AWS CloudWatch style: cron(minute hour day-of-month month day-of-week year)

Examples:
    - "0 * * * *" - Every hour at minute 0
    - "0 0 * * *" - Daily at midnight
    - "0 0 * * 0" - Weekly on Sunday at midnight
    - "cron(0 12 * * ? *)" - Daily at noon (AWS style)

### Methods

#### `get_next_run(self, after: datetime | None) -> datetime`

Get the next scheduled run time.

**Parameters:**

- `after` (`datetime | None`) - Start time to search from (defaults to now)

**Returns:**

`datetime` - Next datetime that matches the cron schedule

#### `matches(self, dt: datetime) -> bool`

Check if a datetime matches this cron expression.

**Parameters:**

- `dt` (`datetime`) - Datetime to check

**Returns:**

`bool` - True if the datetime matches the schedule

#### `get_schedule_type(self) -> ScheduleType`

Get the schedule type.

**Returns:**

`ScheduleType`

## RateExpression

**Inherits from:** ScheduleExpression

**Tags:** dataclass

Rate-based schedule expression.

Runs at fixed intervals from the start time.

Examples:
    - "rate(5 minutes)" - Every 5 minutes
    - "rate(1 hour)" - Every hour
    - "rate(1 day)" - Every day

### Attributes

| Name | Type | Default |
|------|------|---------|
| `_interval` | `timedelta` | `field(...)` |

### Properties

#### `interval(self) -> timedelta`

Get the interval between runs.

**Returns:**

`timedelta`

### Methods

#### `get_next_run(self, after: datetime | None) -> datetime`

Get the next scheduled run time.

**Parameters:**

- `after` (`datetime | None`) - Start time to search from (defaults to now)

**Returns:**

`datetime` - Next datetime based on the rate interval

#### `matches(self, dt: datetime) -> bool`

Check if a datetime matches this rate expression.  For rate expressions, we check if the time is at an interval boundary. This is approximate since rate schedules don't have fixed times.

**Parameters:**

- `dt` (`datetime`)

**Returns:**

`bool`

#### `get_schedule_type(self) -> ScheduleType`

Get the schedule type.

**Returns:**

`ScheduleType`

## ScanResult

**Tags:** dataclass

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

### Attributes

| Name | Type | Default |
|------|------|---------|
| `job_id` | `str` | - |
| `scan_id` | `str` | - |
| `started_at` | `datetime` | - |
| `completed_at` | `datetime | None` | - |
| `success` | `bool` | `True` |
| `error` | `str` | `` |
| `assets_scanned` | `int` | `0` |
| `findings_count` | `int` | `0` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |

### Properties

#### `duration(self) -> timedelta | None`

Get the duration of the scan.

**Returns:**

`timedelta | None`

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

### Class Methods

#### `from_dict(cls, data: dict[(str, Any)]) -> ScanResult`

**Decorators:** @classmethod

Create from dictionary.

**Parameters:**

- `data` (`dict[(str, Any)]`)

**Returns:**

`ScanResult`

## ScanJob

**Tags:** dataclass

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

### Attributes

| Name | Type | Default |
|------|------|---------|
| `id` | `str` | - |
| `name` | `str` | - |
| `schedule` | `ScheduleExpression` | - |
| `config_name` | `str` | `default` |
| `enabled` | `bool` | `True` |
| `last_run` | `datetime | None` | - |
| `next_run` | `datetime | None` | - |
| `run_count` | `int` | `0` |
| `last_result` | `ScanResult | None` | - |
| `created_at` | `datetime` | `field(...)` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |

### Methods

#### `should_run(self, now: datetime | None) -> bool`

Check if the job should run now.

**Parameters:**

- `now` (`datetime | None`)

**Returns:**

`bool`

#### `mark_run(self, result: ScanResult) -> None`

Mark the job as having run with the given result.

**Parameters:**

- `result` (`ScanResult`)

**Returns:**

`None`

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

### Class Methods

#### `from_dict(cls, data: dict[(str, Any)]) -> ScanJob`

**Decorators:** @classmethod

Create from dictionary.

**Parameters:**

- `data` (`dict[(str, Any)]`)

**Returns:**

`ScanJob`

## ScanScheduler

Manages scheduled scan jobs.

Provides scheduling, execution, and management of automated security scans.

### Methods

#### `__init__(self, scan_executor: Callable[([str], ScanResult)] | None, check_interval: int = 60)`

Initialize the scan scheduler.

**Parameters:**

- `scan_executor` (`Callable[([str], ScanResult)] | None`) - Function to execute scans (receives config name, returns ScanResult)
- `check_interval` (`int`) - default: `60` - Seconds between schedule checks (default: 60)

#### `add_job(self, name: str, schedule: ScheduleExpression | str, config_name: str = default, enabled: bool = True, metadata: dict[(str, Any)] | None) -> ScanJob`

Add a new scan job.

**Parameters:**

- `name` (`str`) - Job name
- `schedule` (`ScheduleExpression | str`) - Schedule expression (cron or rate)
- `config_name` (`str`) - default: `default` - Scan configuration to use
- `enabled` (`bool`) - default: `True` - Whether to enable the job
- `metadata` (`dict[(str, Any)] | None`) - Additional job metadata

**Returns:**

`ScanJob` - The created ScanJob

#### `remove_job(self, job_id: str) -> bool`

Remove a job by ID.

**Parameters:**

- `job_id` (`str`) - Job ID to remove

**Returns:**

`bool` - True if removed, False if not found

#### `get_job(self, job_id: str) -> ScanJob | None`

Get a job by ID.

**Parameters:**

- `job_id` (`str`)

**Returns:**

`ScanJob | None`

#### `get_jobs(self) -> list[ScanJob]`

Get all jobs.

**Returns:**

`list[ScanJob]`

#### `get_enabled_jobs(self) -> list[ScanJob]`

Get all enabled jobs.

**Returns:**

`list[ScanJob]`

#### `get_pending_jobs(self, now: datetime | None) -> list[ScanJob]`

Get jobs that should run now.

**Parameters:**

- `now` (`datetime | None`)

**Returns:**

`list[ScanJob]`

#### `enable_job(self, job_id: str) -> bool`

Enable a job.

**Parameters:**

- `job_id` (`str`)

**Returns:**

`bool`

#### `disable_job(self, job_id: str) -> bool`

Disable a job.

**Parameters:**

- `job_id` (`str`)

**Returns:**

`bool`

#### `run_job_now(self, job_id: str) -> ScanResult | None`

Run a job immediately regardless of schedule.

**Parameters:**

- `job_id` (`str`) - Job ID to run

**Returns:**

`ScanResult | None` - ScanResult if executed, None if job not found

#### `add_callback(self, callback: Callable[([ScanJob, ScanResult], None)]) -> None`

Add a callback to be called after each job execution.

**Parameters:**

- `callback` (`Callable[([ScanJob, ScanResult], None)]`) - Function taking (ScanJob, ScanResult)

**Returns:**

`None`

#### `start(self) -> None`

Start the scheduler background thread.

**Returns:**

`None`

#### `stop(self) -> None`

Stop the scheduler background thread.

**Returns:**

`None`

#### `is_running(self) -> bool`

Check if the scheduler is running.

**Returns:**

`bool`

#### `get_status(self) -> dict[(str, Any)]`

Get scheduler status.

**Returns:**

`dict[(str, Any)]`

#### `to_dict(self) -> dict[(str, Any)]`

Convert scheduler state to dictionary.

**Returns:**

`dict[(str, Any)]`

### Class Methods

#### `from_dict(cls, data: dict[(str, Any)], scan_executor: Callable[([str], ScanResult)] | None) -> ScanScheduler`

**Decorators:** @classmethod

Create scheduler from dictionary.

**Parameters:**

- `data` (`dict[(str, Any)]`)
- `scan_executor` (`Callable[([str], ScanResult)] | None`)

**Returns:**

`ScanScheduler`

### `parse_schedule(expression: str) -> ScheduleExpression`

Parse a schedule expression string.

**Parameters:**

- `expression` (`str`) - Cron or rate expression

**Returns:**

`ScheduleExpression` - Parsed ScheduleExpression

**Raises:**

- `ValueError`: If the expression is invalid
