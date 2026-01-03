# stance.cli_analytics

CLI command handlers for Vulnerability Analytics.

Provides commands for:
- Attack path analysis
- Risk scoring
- Blast radius calculation
- MITRE ATT&CK mapping

## Contents

### Functions

- [cmd_analytics](#cmd_analytics)

### `cmd_analytics(args: argparse.Namespace) -> int`

Route analytics subcommands to appropriate handlers.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int` - Exit code (0 success, 1 error)
