# stance.cli_identity

CLI command handlers for Identity Security.

Provides commands for:
- Analyzing data access mappings
- Detecting principal exposure to sensitive data
- Finding over-privileged access

## Contents

### Functions

- [cmd_identity](#cmd_identity)

### `cmd_identity(args: argparse.Namespace) -> int`

Route Identity subcommands to appropriate handlers.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int` - Exit code (0 success, 1 error)
