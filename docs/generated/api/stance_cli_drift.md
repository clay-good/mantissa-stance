# stance.cli_drift

CLI command handlers for Drift Detection.

Provides commands for:
- Detecting configuration drift from baselines
- Managing baselines (create, list, update, delete)
- Viewing drift history and change tracking
- Generating drift reports

## Contents

### Functions

- [cmd_drift](#cmd_drift)

### `cmd_drift(args: argparse.Namespace) -> int`

Route drift subcommands to appropriate handlers.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int` - Exit code (0 success, 1 error)
