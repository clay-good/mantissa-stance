# stance.alerting.destinations.email

Email alert destination for Mantissa Stance.

Sends alerts via SMTP with HTML formatting.

## Contents

### Classes

- [EmailDestination](#emaildestination)

## EmailDestination

**Inherits from:** BaseDestination

SMTP-based email alert destination.

Sends formatted HTML emails for security findings.

Example config:
    {
        "smtp_host": "smtp.example.com",
        "smtp_port": 587,
        "smtp_user": "user@example.com",
        "smtp_password": "password",
        "from_address": "stance@example.com",
        "to_addresses": ["security@example.com"],
        "use_tls": true,
    }

### Methods

#### `__init__(self, name: str = email, config: dict[(str, Any)] | None) -> None`

Initialize email destination.

**Parameters:**

- `name` (`str`) - default: `email` - Destination name
- `config` (`dict[(str, Any)] | None`) - SMTP configuration

**Returns:**

`None`

#### `send(self, finding: Finding, context: dict[(str, Any)]) -> bool`

Send alert via email.

**Parameters:**

- `finding` (`Finding`)
- `context` (`dict[(str, Any)]`)

**Returns:**

`bool`

#### `test_connection(self) -> bool`

Test SMTP connection.

**Returns:**

`bool`
