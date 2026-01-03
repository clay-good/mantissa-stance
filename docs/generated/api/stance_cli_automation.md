# stance.cli_automation

CLI commands for automation module in Mantissa Stance.

Provides command-line interface for managing notification automation,
configuration, and notification history.

## Contents

### Functions

- [add_automation_parser](#add_automation_parser)
- [cmd_automation](#cmd_automation)

### `add_automation_parser(subparsers: argparse._SubParsersAction) -> None`

Add automation subcommand parser.

**Parameters:**

- `subparsers` (`argparse._SubParsersAction`) - Parent subparsers object

**Returns:**

`None`

### `cmd_automation(args: argparse.Namespace) -> int`

Handle automation commands.

**Parameters:**

- `args` (`argparse.Namespace`) - Parsed command-line arguments

**Returns:**

`int` - Exit code (0 for success, non-zero for error)
