# stance.cli_plugins

CLI commands for Plugin System management.

Provides command-line interface for managing plugins including
listing, loading, unloading, enabling, disabling, and configuring.

## Contents

### Functions

- [get_plugin_manager](#get_plugin_manager)
- [cmd_plugins](#cmd_plugins)
- [add_plugins_parser](#add_plugins_parser)

### `get_plugin_manager() -> PluginManager`

Get or create the global plugin manager instance.

**Returns:**

`PluginManager`

### `cmd_plugins(args: argparse.Namespace) -> int`

Handle plugin commands.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int`

### `add_plugins_parser(subparsers: argparse._SubParsersAction) -> None`

Add plugin management parser to CLI.

**Parameters:**

- `subparsers` (`argparse._SubParsersAction`)

**Returns:**

`None`
