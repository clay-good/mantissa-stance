# stance.cli_cloud

CLI commands for Cloud module.

Provides command-line interface for cloud provider management:
- List supported cloud providers
- Get provider details and SDK requirements
- Validate cloud credentials
- Get account/project information
- List available regions

## Contents

### Functions

- [add_cloud_parser](#add_cloud_parser)
- [cmd_cloud](#cmd_cloud)

### `add_cloud_parser(subparsers: Any) -> None`

Add cloud parser to CLI subparsers.

**Parameters:**

- `subparsers` (`Any`)

**Returns:**

`None`

### `cmd_cloud(args: argparse.Namespace) -> int`

Handle cloud commands.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int`
