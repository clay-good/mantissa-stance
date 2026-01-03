# stance.cli_aggregation

CLI commands for multi-cloud aggregation.

Provides CLI access to the aggregation module for:
- Multi-cloud findings aggregation
- Cross-cloud synchronization
- Federated query capabilities

## Contents

### Functions

- [cmd_aggregation](#cmd_aggregation)
- [add_aggregation_parser](#add_aggregation_parser)

### `cmd_aggregation(args: argparse.Namespace) -> int`

Handle aggregation subcommands.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int`

### `add_aggregation_parser(subparsers: argparse._SubParsersAction) -> None`

Add aggregation command parser.

**Parameters:**

- `subparsers` (`argparse._SubParsersAction`)

**Returns:**

`None`
