# stance.cli_alerting

CLI commands for alerting module in Mantissa Stance.

Provides command-line interface for managing alert routing,
destinations, suppression rules, and alert state.

## Contents

### Functions

- [add_alerting_parser](#add_alerting_parser)
- [cmd_alerting](#cmd_alerting)

### `add_alerting_parser(subparsers: argparse._SubParsersAction) -> None`

Add alerting subcommand parser.

**Parameters:**

- `subparsers` (`argparse._SubParsersAction`) - Parent subparsers object

**Returns:**

`None`

### `cmd_alerting(args: argparse.Namespace) -> int`

Handle alerting commands.

**Parameters:**

- `args` (`argparse.Namespace`) - Parsed command-line arguments

**Returns:**

`int` - Exit code (0 for success, non-zero for error)
