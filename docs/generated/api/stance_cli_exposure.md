# stance.cli_exposure

CLI command handlers for Exposure Management.

Provides commands for:
- Public asset inventory
- Certificate monitoring
- DNS/subdomain inventory
- Sensitive data exposure detection

## Contents

### Functions

- [cmd_exposure](#cmd_exposure)

### `cmd_exposure(args: argparse.Namespace) -> int`

Route Exposure subcommands to appropriate handlers.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int` - Exit code (0 success, 1 error)
