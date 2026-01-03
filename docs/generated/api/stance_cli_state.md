# stance.cli_state

CLI commands for State module.

Provides command-line interface for state management:
- Scan history tracking and viewing
- Checkpoint management for incremental scans
- Finding lifecycle tracking
- State export and import

## Contents

### Functions

- [add_state_parser](#add_state_parser)
- [cmd_state](#cmd_state)

### `add_state_parser(subparsers: Any) -> None`

Add state parser to CLI subparsers.

**Parameters:**

- `subparsers` (`Any`)

**Returns:**

`None`

### `cmd_state(args: argparse.Namespace) -> int`

Handle state commands.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int`
