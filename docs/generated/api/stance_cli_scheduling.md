# stance.cli_scheduling

CLI command handlers for scheduling and automation features.

Implements CLI subcommands for scan scheduling, history viewing,
trend analysis, and notification management.

## Contents

### Functions

- [cmd_schedule](#cmd_schedule)
- [cmd_history](#cmd_history)
- [cmd_trends](#cmd_trends)

### `cmd_schedule(args: argparse.Namespace) -> int`

Handle schedule subcommand.  Manages scheduled scan jobs including listing, adding, removing, enabling, and disabling jobs.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int` - Exit code (0 success, 1 error)

### `cmd_history(args: argparse.Namespace) -> int`

Handle history subcommand.  Views scan history and compares scans.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int` - Exit code (0 success, 1 error)

### `cmd_trends(args: argparse.Namespace) -> int`

Handle trends subcommand.  Provides advanced trend analysis with forecasting.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int` - Exit code (0 success, 1 error)
