# stance.cli_enrich

CLI command handlers for Enrichment.

Provides commands for:
- Enriching findings with threat intelligence and CVE details
- Enriching assets with context, criticality, and IP information
- Viewing enrichment status and availability
- Looking up specific IPs or CVEs

## Contents

### Functions

- [cmd_enrich](#cmd_enrich)

### `cmd_enrich(args: argparse.Namespace) -> int`

Route enrichment subcommands to appropriate handlers.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int` - Exit code (0 success, 1 error)
