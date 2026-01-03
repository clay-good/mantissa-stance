# stance.alerting.destinations

Alert destinations for Mantissa Stance.

Provides integrations for sending security alerts to various
notification platforms and services.

## Contents

### Functions

- [create_destination](#create_destination)

### `create_destination(destination_type: str, name: str, config: dict) -> BaseDestination`

Factory function to create destination by type.

**Parameters:**

- `destination_type` (`str`) - Type of destination (slack, pagerduty, email, etc.)
- `name` (`str`) - Destination name
- `config` (`dict`) - Destination configuration

**Returns:**

`BaseDestination` - Configured destination instance

**Raises:**

- `ValueError`: If destination type is unknown
