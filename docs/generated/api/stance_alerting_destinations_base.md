# stance.alerting.destinations.base

Base alert destination for Mantissa Stance.

Provides abstract interface for alert destinations.

## Contents

### Classes

- [AlertPayload](#alertpayload)
- [BaseDestination](#basedestination)

## AlertPayload

**Tags:** dataclass

Structured alert payload for destinations.

Attributes:
    title: Alert title
    description: Alert description
    severity: Severity level
    finding: Original finding
    context: Additional context
    formatted_body: Pre-formatted body (if applicable)

### Attributes

| Name | Type | Default |
|------|------|---------|
| `title` | `str` | - |
| `description` | `str` | - |
| `severity` | `Severity` | - |
| `finding` | `Finding` | - |
| `context` | `dict[(str, Any)]` | - |
| `formatted_body` | `str` | `` |

## BaseDestination

**Inherits from:** ABC

Abstract base class for alert destinations.

All destination implementations should inherit from this class
and implement the required methods.

### Properties

#### `name(self) -> str`

Get destination name.

**Returns:**

`str`

#### `config(self) -> dict[(str, Any)]`

Get destination configuration.

**Returns:**

`dict[(str, Any)]`

### Methods

#### `__init__(self, name: str, config: dict[(str, Any)]) -> None`

Initialize the destination.

**Parameters:**

- `name` (`str`) - Unique destination name
- `config` (`dict[(str, Any)]`) - Destination-specific configuration

**Returns:**

`None`

#### `send(self, finding: Finding, context: dict[(str, Any)]) -> bool`

**Decorators:** @abstractmethod

Send an alert for a finding.

**Parameters:**

- `finding` (`Finding`) - Finding to alert on
- `context` (`dict[(str, Any)]`) - Additional context

**Returns:**

`bool` - True if alert was sent successfully

#### `test_connection(self) -> bool`

**Decorators:** @abstractmethod

Test if destination is reachable.

**Returns:**

`bool` - True if connection is successful

#### `format_title(self, finding: Finding) -> str`

Format alert title.

**Parameters:**

- `finding` (`Finding`) - Finding to format

**Returns:**

`str` - Formatted title string

#### `format_description(self, finding: Finding) -> str`

Format alert description.

**Parameters:**

- `finding` (`Finding`) - Finding to format

**Returns:**

`str` - Formatted description string

#### `get_severity_color(self, severity: Severity) -> str`

Get color code for severity.

**Parameters:**

- `severity` (`Severity`) - Severity level

**Returns:**

`str` - Hex color code
