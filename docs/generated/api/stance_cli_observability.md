# stance.cli_observability

CLI commands for Observability module.

Provides command-line interface for logging, metrics, and tracing:
- Logging configuration and log level management
- Metrics collection and viewing
- Tracing configuration and span inspection
- Observability backends status

## Contents

### Functions

- [add_observability_parser](#add_observability_parser)
- [cmd_observability](#cmd_observability)

### `add_observability_parser(subparsers: Any) -> None`

Add observability parser to CLI subparsers.

**Parameters:**

- `subparsers` (`Any`)

**Returns:**

`None`

### `cmd_observability(args: argparse.Namespace) -> int`

Handle observability commands.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int`
