# stance.cli_reporting

CLI commands for Reporting module.

Provides command-line interface for trend analysis and security reporting:
- Trend analysis (findings, severity, compliance)
- Findings velocity calculation
- Improvement rate tracking
- Period comparison
- Forecasting with linear regression
- Reporting module status and capabilities

## Contents

### Functions

- [add_reporting_parser](#add_reporting_parser)
- [cmd_reporting](#cmd_reporting)

### `add_reporting_parser(subparsers: Any) -> None`

Add reporting parser to CLI subparsers.

**Parameters:**

- `subparsers` (`Any`)

**Returns:**

`None`

### `cmd_reporting(args: argparse.Namespace) -> int`

Handle reporting commands.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int`
