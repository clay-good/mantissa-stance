# stance.cli_dspm

CLI command handlers for DSPM (Data Security Posture Management).

Provides commands for:
- Scanning cloud storage for sensitive data
- Analyzing data access patterns
- Cost analysis for data storage
- Extended source scanning (databases, SaaS)

## Contents

### Functions

- [cmd_dspm](#cmd_dspm)

### `cmd_dspm(args: argparse.Namespace) -> int`

Route DSPM subcommands to appropriate handlers.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int` - Exit code (0 success, 1 error)
