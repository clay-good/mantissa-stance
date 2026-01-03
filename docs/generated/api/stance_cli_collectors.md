# stance.cli_collectors

CLI commands for Collectors module.

Provides command-line interface for collector management:
- List available collectors by provider
- Get collector details and configuration
- Show collector capabilities and resource types
- View collector registry information

## Contents

### Functions

- [add_collectors_parser](#add_collectors_parser)
- [cmd_collectors](#cmd_collectors)

### `add_collectors_parser(subparsers: Any) -> None`

Add collectors parser to CLI subparsers.

**Parameters:**

- `subparsers` (`Any`)

**Returns:**

`None`

### `cmd_collectors(args: argparse.Namespace) -> int`

Handle collectors commands.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int`
