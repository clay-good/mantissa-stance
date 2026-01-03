# stance.cli_exceptions

CLI commands for Policy Exceptions management.

Provides command-line interface for managing policy exceptions,
suppressions, false positives, risk acceptances, and compensating controls.

## Contents

### Functions

- [cmd_exceptions](#cmd_exceptions)
- [add_exceptions_parser](#add_exceptions_parser)

### `cmd_exceptions(args: argparse.Namespace) -> int`

Handle exceptions commands.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int`

### `add_exceptions_parser(subparsers: argparse._SubParsersAction) -> None`

Add exceptions management parser to CLI.

**Parameters:**

- `subparsers` (`argparse._SubParsersAction`)

**Returns:**

`None`
