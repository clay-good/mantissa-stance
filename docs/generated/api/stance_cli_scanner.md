# stance.cli_scanner

CLI commands for Scanner module.

Provides command-line interface for container image scanning:
- Scanner availability and version checking
- Vulnerability scanning with Trivy
- CVE enrichment with EPSS and KEV data
- Vulnerability prioritization
- Scanner configuration and status

## Contents

### Functions

- [add_scanner_parser](#add_scanner_parser)
- [cmd_scanner](#cmd_scanner)

### `add_scanner_parser(subparsers: Any) -> None`

Add scanner parser to CLI subparsers.

**Parameters:**

- `subparsers` (`Any`)

**Returns:**

`None`

### `cmd_scanner(args: argparse.Namespace) -> int`

Handle scanner commands.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int`
