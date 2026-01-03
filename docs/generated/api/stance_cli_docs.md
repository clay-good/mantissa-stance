# stance.cli_docs

CLI commands for documentation management.

Provides commands for generating, viewing, and managing documentation
including API reference, CLI reference, and policy documentation.

## Contents

### Functions

- [add_docs_parser](#add_docs_parser)
- [cmd_docs](#cmd_docs)

### `add_docs_parser(subparsers: Any) -> None`

Add docs subcommands to the CLI.

**Parameters:**

- `subparsers` (`Any`)

**Returns:**

`None`

### `cmd_docs(args: argparse.Namespace) -> int`

Handle docs commands.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int`
