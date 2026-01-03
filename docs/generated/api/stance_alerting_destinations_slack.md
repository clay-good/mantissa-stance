# stance.alerting.destinations.slack

Slack alert destination for Mantissa Stance.

Sends alerts to Slack channels via incoming webhooks.

## Contents

### Classes

- [SlackDestination](#slackdestination)

## SlackDestination

**Inherits from:** BaseDestination

Slack webhook-based alert destination.

Sends rich formatted messages to Slack using Block Kit.

Example config:
    {
        "webhook_url": "https://hooks.slack.com/services/XXX/YYY/ZZZ",
        "channel": "#security-alerts",  # Optional override
        "username": "Stance Alerts",     # Optional
        "icon_emoji": ":shield:",        # Optional
    }

### Methods

#### `__init__(self, name: str = slack, config: dict[(str, Any)] | None) -> None`

Initialize Slack destination.

**Parameters:**

- `name` (`str`) - default: `slack` - Destination name
- `config` (`dict[(str, Any)] | None`) - Configuration with webhook_url

**Returns:**

`None`

#### `send(self, finding: Finding, context: dict[(str, Any)]) -> bool`

Send alert to Slack.

**Parameters:**

- `finding` (`Finding`)
- `context` (`dict[(str, Any)]`)

**Returns:**

`bool`

#### `test_connection(self) -> bool`

Test Slack webhook connection.

**Returns:**

`bool`
