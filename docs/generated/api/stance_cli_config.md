# stance.cli_config

CLI commands for configuration management.

Provides commands for managing scan configurations including
listing, viewing, creating, editing, and deleting configurations.

## Contents

### Functions

- [add_config_parser](#add_config_parser)
- [cmd_config](#cmd_config)

### `add_config_parser(subparsers: Any) -> None`

Add config subcommands to the CLI.

**Parameters:**

- `subparsers` (`Any`)

**Returns:**

`None`

### `cmd_config(args: argparse.Namespace) -> int`

Handle config commands.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int`
