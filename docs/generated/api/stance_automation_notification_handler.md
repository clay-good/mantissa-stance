# stance.automation.notification_handler

Notification Handler for Mantissa Stance.

Integrates the scheduling system with the alerting system to provide
automated notifications for scan results, new findings, and security trends.

## Contents

### Classes

- [NotificationType](#notificationtype)
- [NotificationConfig](#notificationconfig)
- [ScanNotification](#scannotification)
- [ScanSummaryNotification](#scansummarynotification)
- [FindingNotification](#findingnotification)
- [TrendNotification](#trendnotification)
- [NotificationHandler](#notificationhandler)

### Functions

- [create_scheduler_callback](#create_scheduler_callback)

## NotificationType

**Inherits from:** Enum

Types of notifications that can be sent.

## NotificationConfig

**Tags:** dataclass

Configuration for notifications.

Attributes:
    notify_on_scan_complete: Send notification when scan completes
    notify_on_scan_failure: Send notification when scan fails
    notify_on_new_findings: Send notification for new findings
    notify_on_critical: Send notification for critical findings
    notify_on_resolved: Send notification for resolved findings
    notify_on_trend_change: Send notification on trend changes
    min_severity_for_new: Minimum severity to notify on new findings
    critical_threshold: Number of critical findings to trigger alert
    trend_threshold_percent: Percentage change to trigger trend alert
    include_summary: Include summary in notifications
    include_details: Include detailed findings in notifications
    destinations: Override destinations (empty = use router defaults)

### Attributes

| Name | Type | Default |
|------|------|---------|
| `notify_on_scan_complete` | `bool` | `True` |
| `notify_on_scan_failure` | `bool` | `True` |
| `notify_on_new_findings` | `bool` | `True` |
| `notify_on_critical` | `bool` | `True` |
| `notify_on_resolved` | `bool` | `False` |
| `notify_on_trend_change` | `bool` | `True` |
| `min_severity_for_new` | `Severity` | `"Attribute(value=Name(id='Severity', ctx=Load()), attr='HIGH', ctx=Load())"` |
| `critical_threshold` | `int` | `1` |
| `trend_threshold_percent` | `float` | `10.0` |
| `include_summary` | `bool` | `True` |
| `include_details` | `bool` | `False` |
| `destinations` | `list[str]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

### Class Methods

#### `from_dict(cls, data: dict[(str, Any)]) -> NotificationConfig`

**Decorators:** @classmethod

Create from dictionary.

**Parameters:**

- `data` (`dict[(str, Any)]`)

**Returns:**

`NotificationConfig`

## ScanNotification

**Tags:** dataclass

Base notification for scan events.

Attributes:
    notification_type: Type of notification
    timestamp: When the notification was created
    scan_id: ID of the scan
    job_name: Name of the scheduled job (if applicable)
    config_name: Scan configuration name
    message: Notification message
    details: Additional details

### Attributes

| Name | Type | Default |
|------|------|---------|
| `notification_type` | `NotificationType` | - |
| `timestamp` | `datetime` | - |
| `scan_id` | `str` | - |
| `job_name` | `str` | `` |
| `config_name` | `str` | `default` |
| `message` | `str` | `` |
| `details` | `dict[(str, Any)]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## ScanSummaryNotification

**Inherits from:** ScanNotification

**Tags:** dataclass

Notification with scan summary.

Attributes:
    success: Whether scan completed successfully
    duration_seconds: How long the scan took
    assets_scanned: Number of assets scanned
    findings_total: Total findings count
    findings_by_severity: Breakdown by severity
    error_message: Error message if failed

### Attributes

| Name | Type | Default |
|------|------|---------|
| `success` | `bool` | `True` |
| `duration_seconds` | `float` | `0.0` |
| `assets_scanned` | `int` | `0` |
| `findings_total` | `int` | `0` |
| `findings_by_severity` | `dict[(str, int)]` | `field(...)` |
| `error_message` | `str` | `` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## FindingNotification

**Inherits from:** ScanNotification

**Tags:** dataclass

Notification for specific findings.

Attributes:
    findings: List of findings to notify about
    is_new: Whether these are new findings
    is_resolved: Whether these are resolved findings

### Attributes

| Name | Type | Default |
|------|------|---------|
| `findings` | `list[Finding]` | `field(...)` |
| `is_new` | `bool` | `True` |
| `is_resolved` | `bool` | `False` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## TrendNotification

**Inherits from:** ScanNotification

**Tags:** dataclass

Notification for security trend changes.

Attributes:
    direction: Trend direction (improving/declining)
    change_percent: Percentage change
    current_findings: Current findings count
    previous_findings: Previous findings count
    period_days: Days in the comparison period

### Attributes

| Name | Type | Default |
|------|------|---------|
| `direction` | `str` | `stable` |
| `change_percent` | `float` | `0.0` |
| `current_findings` | `int` | `0` |
| `previous_findings` | `int` | `0` |
| `period_days` | `int` | `7` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## NotificationHandler

Handles notifications for scheduled scans and security events.

Integrates with the AlertRouter to send notifications through
configured destinations (Slack, PagerDuty, Email, etc.).

Example:
    >>> from stance.alerting import AlertRouter, SlackDestination
    >>> from stance.automation import NotificationHandler, NotificationConfig
    >>>
    >>> router = AlertRouter()
    >>> router.add_destination(SlackDestination(webhook_url="..."))
    >>>
    >>> handler = NotificationHandler(router)
    >>> handler.configure(NotificationConfig(notify_on_critical=True))
    >>>
    >>> # Use as scheduler callback
    >>> scheduler.add_callback(handler.on_scan_complete)

### Properties

#### `config(self) -> NotificationConfig`

Get current configuration.

**Returns:**

`NotificationConfig`

### Methods

#### `__init__(self, router: AlertRouter | None, config: NotificationConfig | None)`

Initialize the notification handler.

**Parameters:**

- `router` (`AlertRouter | None`) - AlertRouter for sending notifications
- `config` (`NotificationConfig | None`) - Notification configuration

#### `configure(self, config: NotificationConfig) -> None`

Update notification configuration.

**Parameters:**

- `config` (`NotificationConfig`) - New configuration

**Returns:**

`None`

#### `set_router(self, router: AlertRouter) -> None`

Set the alert router.

**Parameters:**

- `router` (`AlertRouter`) - AlertRouter to use for notifications

**Returns:**

`None`

#### `add_callback(self, callback: Callable[([ScanNotification], None)]) -> None`

Add a callback for notifications.  Callbacks are called for every notification, regardless of whether it's sent through the router.

**Parameters:**

- `callback` (`Callable[([ScanNotification], None)]`) - Function to call with notification

**Returns:**

`None`

#### `on_scan_complete(self, result: ScanResult) -> None`

Handle scan completion event.  This method can be registered as a scheduler callback.

**Parameters:**

- `result` (`ScanResult`) - Result from the completed scan

**Returns:**

`None`

#### `on_findings_detected(self, scan_id: str, findings: FindingCollection, comparison: ScanComparison | None, job_name: str = ) -> None`

Handle new findings detected.

**Parameters:**

- `scan_id` (`str`) - ID of the scan
- `findings` (`FindingCollection`) - All findings from scan
- `comparison` (`ScanComparison | None`) - Comparison with previous scan (if available)
- `job_name` (`str`) - default: `` - Name of scheduled job

**Returns:**

`None`

#### `on_trend_change(self, scan_id: str, direction: str, change_percent: float, current_findings: int, previous_findings: int, period_days: int = 7, job_name: str = ) -> None`

Handle security trend change.

**Parameters:**

- `scan_id` (`str`) - ID of the scan
- `direction` (`str`) - Trend direction (improving/declining/stable)
- `change_percent` (`float`) - Percentage change
- `current_findings` (`int`) - Current findings count
- `previous_findings` (`int`) - Previous findings count
- `period_days` (`int`) - default: `7` - Days in comparison period
- `job_name` (`str`) - default: `` - Name of scheduled job

**Returns:**

`None`

#### `get_history(self, limit: int | None, notification_type: NotificationType | None) -> list[ScanNotification]`

Get notification history.

**Parameters:**

- `limit` (`int | None`) - Maximum number to return
- `notification_type` (`NotificationType | None`) - Filter by type

**Returns:**

`list[ScanNotification]` - List of notifications (most recent first)

#### `clear_history(self) -> None`

Clear notification history.

**Returns:**

`None`

### `create_scheduler_callback(handler: NotificationHandler) -> Callable[([ScanResult], None)]`

Create a callback function for the scheduler.

**Parameters:**

- `handler` (`NotificationHandler`) - NotificationHandler to use

**Returns:**

`Callable[([ScanResult], None)]` - Callback function suitable for ScanScheduler.add_callback()
