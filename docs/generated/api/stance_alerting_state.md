# stance.alerting.state

Alert state management for Mantissa Stance.

Provides persistent tracking of sent alerts for deduplication,
acknowledgment, and audit trail across cloud providers.

## Contents

### Classes

- [AlertRecord](#alertrecord)
- [AlertStateBackend](#alertstatebackend)
- [InMemoryAlertState](#inmemoryalertstate)
- [DynamoDBAlertState](#dynamodbalertstate)
- [FirestoreAlertState](#firestorealertstate)
- [CosmosDBAlertState](#cosmosdbalertstate)
- [AlertState](#alertstate)

## AlertRecord

**Tags:** dataclass

Record of a sent alert.

Attributes:
    id: Unique alert record ID
    finding_id: ID of the finding
    destination: Destination name
    sent_at: When alert was sent
    acknowledged_at: When alert was acknowledged (if applicable)
    acknowledged_by: Who acknowledged the alert
    dedup_key: Deduplication key
    status: Alert status (sent, acknowledged, resolved, expired)
    metadata: Additional metadata

### Attributes

| Name | Type | Default |
|------|------|---------|
| `id` | `str` | - |
| `finding_id` | `str` | - |
| `destination` | `str` | - |
| `sent_at` | `datetime` | - |
| `acknowledged_at` | `datetime | None` | - |
| `acknowledged_by` | `str | None` | - |
| `dedup_key` | `str` | `` |
| `status` | `str` | `sent` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary representation.

**Returns:**

`dict[(str, Any)]`

### Class Methods

#### `from_dict(cls, data: dict[(str, Any)]) -> AlertRecord`

**Decorators:** @classmethod

Create from dictionary.

**Parameters:**

- `data` (`dict[(str, Any)]`)

**Returns:**

`AlertRecord`

## AlertStateBackend

**Inherits from:** ABC

Abstract base for alert state backends.

### Methods

#### `record_alert(self, record: AlertRecord) -> None`

**Decorators:** @abstractmethod

Record a sent alert.

**Parameters:**

- `record` (`AlertRecord`)

**Returns:**

`None`

#### `get_alert(self, alert_id: str) -> AlertRecord | None`

**Decorators:** @abstractmethod

Get an alert record by ID.

**Parameters:**

- `alert_id` (`str`)

**Returns:**

`AlertRecord | None`

#### `get_alerts_for_finding(self, finding_id: str) -> list[AlertRecord]`

**Decorators:** @abstractmethod

Get all alerts for a finding.

**Parameters:**

- `finding_id` (`str`)

**Returns:**

`list[AlertRecord]`

#### `check_dedup(self, dedup_key: str, window: timedelta) -> bool`

**Decorators:** @abstractmethod

Check if alert was recently sent (returns True if duplicate).

**Parameters:**

- `dedup_key` (`str`)
- `window` (`timedelta`)

**Returns:**

`bool`

#### `acknowledge(self, alert_id: str, by: str) -> bool`

**Decorators:** @abstractmethod

Acknowledge an alert.

**Parameters:**

- `alert_id` (`str`)
- `by` (`str`)

**Returns:**

`bool`

#### `expire_old_alerts(self, before: datetime) -> int`

**Decorators:** @abstractmethod

Expire old alert records.

**Parameters:**

- `before` (`datetime`)

**Returns:**

`int`

## InMemoryAlertState

**Inherits from:** AlertStateBackend

In-memory alert state backend.

Suitable for development and testing. Data is lost on restart.

### Methods

#### `__init__(self) -> None`

Initialize in-memory state.

**Returns:**

`None`

#### `record_alert(self, record: AlertRecord) -> None`

Record a sent alert.

**Parameters:**

- `record` (`AlertRecord`)

**Returns:**

`None`

#### `get_alert(self, alert_id: str) -> AlertRecord | None`

Get an alert record by ID.

**Parameters:**

- `alert_id` (`str`)

**Returns:**

`AlertRecord | None`

#### `get_alerts_for_finding(self, finding_id: str) -> list[AlertRecord]`

Get all alerts for a finding.

**Parameters:**

- `finding_id` (`str`)

**Returns:**

`list[AlertRecord]`

#### `check_dedup(self, dedup_key: str, window: timedelta) -> bool`

Check if alert was recently sent.

**Parameters:**

- `dedup_key` (`str`)
- `window` (`timedelta`)

**Returns:**

`bool`

#### `acknowledge(self, alert_id: str, by: str) -> bool`

Acknowledge an alert.

**Parameters:**

- `alert_id` (`str`)
- `by` (`str`)

**Returns:**

`bool`

#### `expire_old_alerts(self, before: datetime) -> int`

Expire old alert records.

**Parameters:**

- `before` (`datetime`)

**Returns:**

`int`

## DynamoDBAlertState

**Inherits from:** AlertStateBackend

DynamoDB-backed alert state for AWS deployments.

Uses a single table with composite keys for efficient queries.

### Methods

#### `__init__(self, table_name: str, session: Any | None, region: str = us-east-1) -> None`

Initialize DynamoDB state backend.

**Parameters:**

- `table_name` (`str`) - DynamoDB table name
- `session` (`Any | None`) - Optional boto3 session
- `region` (`str`) - default: `us-east-1` - AWS region

**Returns:**

`None`

#### `record_alert(self, record: AlertRecord) -> None`

Record a sent alert.

**Parameters:**

- `record` (`AlertRecord`)

**Returns:**

`None`

#### `get_alert(self, alert_id: str) -> AlertRecord | None`

Get an alert record by ID.

**Parameters:**

- `alert_id` (`str`)

**Returns:**

`AlertRecord | None`

#### `get_alerts_for_finding(self, finding_id: str) -> list[AlertRecord]`

Get all alerts for a finding.

**Parameters:**

- `finding_id` (`str`)

**Returns:**

`list[AlertRecord]`

#### `check_dedup(self, dedup_key: str, window: timedelta) -> bool`

Check if alert was recently sent.

**Parameters:**

- `dedup_key` (`str`)
- `window` (`timedelta`)

**Returns:**

`bool`

#### `acknowledge(self, alert_id: str, by: str) -> bool`

Acknowledge an alert.

**Parameters:**

- `alert_id` (`str`)
- `by` (`str`)

**Returns:**

`bool`

#### `expire_old_alerts(self, before: datetime) -> int`

Expire old alerts (TTL handles cleanup).

**Parameters:**

- `before` (`datetime`)

**Returns:**

`int`

## FirestoreAlertState

**Inherits from:** AlertStateBackend

Firestore-backed alert state for GCP deployments.

### Methods

#### `__init__(self, project_id: str, collection: str = stance_alerts, credentials: Any | None) -> None`

Initialize Firestore state backend.

**Parameters:**

- `project_id` (`str`) - GCP project ID
- `collection` (`str`) - default: `stance_alerts` - Firestore collection name
- `credentials` (`Any | None`) - Optional GCP credentials

**Returns:**

`None`

#### `record_alert(self, record: AlertRecord) -> None`

Record a sent alert.

**Parameters:**

- `record` (`AlertRecord`)

**Returns:**

`None`

#### `get_alert(self, alert_id: str) -> AlertRecord | None`

Get an alert record by ID.

**Parameters:**

- `alert_id` (`str`)

**Returns:**

`AlertRecord | None`

#### `get_alerts_for_finding(self, finding_id: str) -> list[AlertRecord]`

Get all alerts for a finding.

**Parameters:**

- `finding_id` (`str`)

**Returns:**

`list[AlertRecord]`

#### `check_dedup(self, dedup_key: str, window: timedelta) -> bool`

Check if alert was recently sent.

**Parameters:**

- `dedup_key` (`str`)
- `window` (`timedelta`)

**Returns:**

`bool`

#### `acknowledge(self, alert_id: str, by: str) -> bool`

Acknowledge an alert.

**Parameters:**

- `alert_id` (`str`)
- `by` (`str`)

**Returns:**

`bool`

#### `expire_old_alerts(self, before: datetime) -> int`

Expire old alerts.

**Parameters:**

- `before` (`datetime`)

**Returns:**

`int`

## CosmosDBAlertState

**Inherits from:** AlertStateBackend

Azure Cosmos DB-backed alert state for Azure deployments.

### Methods

#### `__init__(self, endpoint: str, key: str, database_name: str = stance, container_name: str = alerts) -> None`

Initialize Cosmos DB state backend.

**Parameters:**

- `endpoint` (`str`) - Cosmos DB endpoint
- `key` (`str`) - Cosmos DB key
- `database_name` (`str`) - default: `stance` - Database name
- `container_name` (`str`) - default: `alerts` - Container name

**Returns:**

`None`

#### `record_alert(self, record: AlertRecord) -> None`

Record a sent alert.

**Parameters:**

- `record` (`AlertRecord`)

**Returns:**

`None`

#### `get_alert(self, alert_id: str) -> AlertRecord | None`

Get an alert record by ID.

**Parameters:**

- `alert_id` (`str`)

**Returns:**

`AlertRecord | None`

#### `get_alerts_for_finding(self, finding_id: str) -> list[AlertRecord]`

Get all alerts for a finding.

**Parameters:**

- `finding_id` (`str`)

**Returns:**

`list[AlertRecord]`

#### `check_dedup(self, dedup_key: str, window: timedelta) -> bool`

Check if alert was recently sent.

**Parameters:**

- `dedup_key` (`str`)
- `window` (`timedelta`)

**Returns:**

`bool`

#### `acknowledge(self, alert_id: str, by: str) -> bool`

Acknowledge an alert.

**Parameters:**

- `alert_id` (`str`)
- `by` (`str`)

**Returns:**

`bool`

#### `expire_old_alerts(self, before: datetime) -> int`

Expire old alerts.

**Parameters:**

- `before` (`datetime`)

**Returns:**

`int`

## AlertState

High-level alert state manager.

Provides a unified interface for alert state management
across different backends.

### Methods

#### `__init__(self, backend: AlertStateBackend | None, dedup_window: timedelta | None) -> None`

Initialize alert state manager.

**Parameters:**

- `backend` (`AlertStateBackend | None`) - State backend to use (defaults to in-memory)
- `dedup_window` (`timedelta | None`) - Deduplication window (default: 24 hours)

**Returns:**

`None`

#### `record_sent(self, finding_id: str, destination: str, dedup_key: str = , metadata: dict[(str, Any)] | None) -> AlertRecord`

Record a sent alert.

**Parameters:**

- `finding_id` (`str`) - Finding ID
- `destination` (`str`) - Destination name
- `dedup_key` (`str`) - default: `` - Deduplication key
- `metadata` (`dict[(str, Any)] | None`) - Additional metadata

**Returns:**

`AlertRecord` - Created AlertRecord

#### `is_duplicate(self, dedup_key: str) -> bool`

Check if an alert is a duplicate.

**Parameters:**

- `dedup_key` (`str`)

**Returns:**

`bool`

#### `acknowledge(self, alert_id: str, by: str) -> bool`

Acknowledge an alert.

**Parameters:**

- `alert_id` (`str`)
- `by` (`str`)

**Returns:**

`bool`

#### `get_alerts_for_finding(self, finding_id: str) -> list[AlertRecord]`

Get all alerts for a finding.

**Parameters:**

- `finding_id` (`str`)

**Returns:**

`list[AlertRecord]`

#### `cleanup(self, max_age_days: int = 30) -> int`

Clean up old alert records.

**Parameters:**

- `max_age_days` (`int`) - default: `30` - Maximum age in days

**Returns:**

`int` - Number of records expired
