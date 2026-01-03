# stance.cli_export

CLI commands for Export module.

Provides command-line interface for report generation and data export:
- Multi-format export (JSON, CSV, HTML, PDF)
- Multiple report types (full, executive, findings, compliance, assets)
- Export configuration and options
- Export module status and capabilities

## Contents

### Functions

- [add_export_parser](#add_export_parser)
- [cmd_export](#cmd_export)

### `add_export_parser(subparsers: Any) -> None`

Add export parser to CLI subparsers.

**Parameters:**

- `subparsers` (`Any`)

**Returns:**

`None`

### `cmd_export(args: argparse.Namespace) -> int`

Handle export commands.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int`
