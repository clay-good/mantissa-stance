# stance.cli_engine

CLI commands for the Policy Engine module.

Provides commands for policy management, validation, evaluation,
expression testing, and compliance calculation.

## Contents

### Functions

- [add_engine_parser](#add_engine_parser)
- [cmd_engine](#cmd_engine)

### `add_engine_parser(subparsers: Any) -> None`

Add engine subcommand parser.

**Parameters:**

- `subparsers` (`Any`) - Argument parser subparsers

**Returns:**

`None`

### `cmd_engine(args: argparse.Namespace) -> int`

Handle engine commands.

**Parameters:**

- `args` (`argparse.Namespace`) - Parsed command arguments

**Returns:**

`int` - Exit code (0 for success, 1 for error)
