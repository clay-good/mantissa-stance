# stance.alerting.destinations.pagerduty

PagerDuty alert destination for Mantissa Stance.

Sends alerts to PagerDuty using the Events API v2.

## Contents

### Classes

- [PagerDutyDestination](#pagerdutydestination)

## Constants

### `PAGERDUTY_EVENTS_API`

Type: `str`

Value: `https://events.pagerduty.com/v2/enqueue`

## PagerDutyDestination

**Inherits from:** BaseDestination

PagerDuty Events API v2 destination.

Sends alerts to PagerDuty with proper severity mapping and
deduplication key generation.

Example config:
    {
        "routing_key": "your-routing-key",
        "service_name": "Mantissa Stance",
    }

### Methods

#### `__init__(self, name: str = pagerduty, config: dict[(str, Any)] | None) -> None`

Initialize PagerDuty destination.

**Parameters:**

- `name` (`str`) - default: `pagerduty` - Destination name
- `config` (`dict[(str, Any)] | None`) - Configuration with routing_key

**Returns:**

`None`

#### `send(self, finding: Finding, context: dict[(str, Any)]) -> bool`

Send alert to PagerDuty.

**Parameters:**

- `finding` (`Finding`)
- `context` (`dict[(str, Any)]`)

**Returns:**

`bool`

#### `test_connection(self) -> bool`

Test PagerDuty connection.

**Returns:**

`bool`

#### `resolve(self, finding: Finding) -> bool`

Resolve a PagerDuty incident for a finding.

**Parameters:**

- `finding` (`Finding`) - Finding to resolve

**Returns:**

`bool` - True if resolution was successful

#### `acknowledge(self, finding: Finding) -> bool`

Acknowledge a PagerDuty incident for a finding.

**Parameters:**

- `finding` (`Finding`) - Finding to acknowledge

**Returns:**

`bool` - True if acknowledgment was successful
