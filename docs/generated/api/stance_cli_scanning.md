# stance.cli_scanning

CLI commands for Multi-Account Scanning module.

Provides command-line interface for multi-account scanning orchestration:
- Organization-level scanning with parallel execution
- Progress tracking and monitoring
- Account status and results viewing
- Cross-account findings aggregation

## Contents

### Functions

- [add_scanning_parser](#add_scanning_parser)
- [cmd_scanning](#cmd_scanning)

### `add_scanning_parser(subparsers: Any) -> None`

Add scanning parser to CLI subparsers.

**Parameters:**

- `subparsers` (`Any`)

**Returns:**

`None`

### `cmd_scanning(args: argparse.Namespace) -> int`

Handle scanning commands.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int`
