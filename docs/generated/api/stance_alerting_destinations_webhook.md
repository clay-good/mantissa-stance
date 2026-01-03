# stance.alerting.destinations.webhook

Generic webhook alert destination for Mantissa Stance.

Sends alerts to configurable HTTP endpoints.

## Contents

### Classes

- [WebhookDestination](#webhookdestination)
- [TeamsDestination](#teamsdestination)
- [JiraDestination](#jiradestination)

## WebhookDestination

**Inherits from:** BaseDestination

Generic HTTP webhook destination.

Sends alerts to any HTTP endpoint with configurable
payload format and authentication.

Example config:
    {
        "url": "https://api.example.com/alerts",
        "method": "POST",
        "headers": {"X-API-Key": "secret"},
        "auth_type": "bearer",  # none, basic, bearer
        "auth_token": "token",
        "payload_format": "json",  # json, form
        "custom_fields": {"source": "stance"},
    }

### Methods

#### `__init__(self, name: str = webhook, config: dict[(str, Any)] | None) -> None`

Initialize webhook destination.

**Parameters:**

- `name` (`str`) - default: `webhook` - Destination name
- `config` (`dict[(str, Any)] | None`) - Webhook configuration

**Returns:**

`None`

#### `send(self, finding: Finding, context: dict[(str, Any)]) -> bool`

Send alert via webhook.

**Parameters:**

- `finding` (`Finding`)
- `context` (`dict[(str, Any)]`)

**Returns:**

`bool`

#### `test_connection(self) -> bool`

Test webhook connection.

**Returns:**

`bool`

## TeamsDestination

**Inherits from:** BaseDestination

Microsoft Teams webhook destination.

Sends alerts using Adaptive Cards via incoming webhooks.

Example config:
    {
        "webhook_url": "https://outlook.office.com/webhook/XXX",
    }

### Methods

#### `__init__(self, name: str = teams, config: dict[(str, Any)] | None) -> None`

Initialize Teams destination.

**Parameters:**

- `name` (`str`) - default: `teams` - Destination name
- `config` (`dict[(str, Any)] | None`) - Teams configuration

**Returns:**

`None`

#### `send(self, finding: Finding, context: dict[(str, Any)]) -> bool`

Send alert to Teams.

**Parameters:**

- `finding` (`Finding`)
- `context` (`dict[(str, Any)]`)

**Returns:**

`bool`

#### `test_connection(self) -> bool`

Test Teams webhook connection.

**Returns:**

`bool`

## JiraDestination

**Inherits from:** BaseDestination

Jira issue creation destination.

Creates Jira issues for security findings.

Example config:
    {
        "url": "https://your-domain.atlassian.net",
        "email": "user@example.com",
        "api_token": "your-api-token",
        "project_key": "SEC",
        "issue_type": "Bug",
    }

### Methods

#### `__init__(self, name: str = jira, config: dict[(str, Any)] | None) -> None`

Initialize Jira destination.

**Parameters:**

- `name` (`str`) - default: `jira` - Destination name
- `config` (`dict[(str, Any)] | None`) - Jira configuration

**Returns:**

`None`

#### `send(self, finding: Finding, context: dict[(str, Any)]) -> bool`

Create Jira issue for finding.

**Parameters:**

- `finding` (`Finding`)
- `context` (`dict[(str, Any)]`)

**Returns:**

`bool`

#### `test_connection(self) -> bool`

Test Jira connection.

**Returns:**

`bool`
