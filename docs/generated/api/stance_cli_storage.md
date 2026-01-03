# stance.cli_storage

CLI commands for the Storage module.

Provides commands for managing storage backends, snapshots, and data persistence.

## Contents

### Functions

- [add_storage_parser](#add_storage_parser)
- [cmd_storage](#cmd_storage)

### `add_storage_parser(subparsers: Any) -> None`

Add storage subcommand parser.

**Parameters:**

- `subparsers` (`Any`) - Argument parser subparsers

**Returns:**

`None`

### `cmd_storage(args: argparse.Namespace) -> int`

Handle storage commands.

**Parameters:**

- `args` (`argparse.Namespace`) - Parsed command arguments

**Returns:**

`int` - Exit code (0 for success, 1 for error)
