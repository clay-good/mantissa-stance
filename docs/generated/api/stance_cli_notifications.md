# stance.cli_notifications

CLI commands for Notifications management.

Provides command-line interface for managing notifications configuration,
viewing notification history, and controlling notification behavior.

## Contents

### Functions

- [get_notification_handler](#get_notification_handler)
- [cmd_notifications](#cmd_notifications)
- [add_notifications_parser](#add_notifications_parser)

### `get_notification_handler() -> NotificationHandler`

Get or create the global notification handler.

**Returns:**

`NotificationHandler`

### `cmd_notifications(args: argparse.Namespace) -> int`

Handle notifications commands.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int`

### `add_notifications_parser(subparsers: Any) -> None`

Add notifications command parser.

**Parameters:**

- `subparsers` (`Any`)

**Returns:**

`None`
