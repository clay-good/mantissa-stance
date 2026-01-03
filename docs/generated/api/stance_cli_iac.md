# stance.cli_iac

CLI commands for Infrastructure as Code (IaC) scanning.

Provides CLI commands for scanning Terraform, CloudFormation, ARM templates,
and Kubernetes manifests for security misconfigurations.

## Contents

### Functions

- [add_iac_parser](#add_iac_parser)
- [cmd_iac](#cmd_iac)

### `add_iac_parser(subparsers: argparse._SubParsersAction) -> None`

Add IaC subcommand parser.

**Parameters:**

- `subparsers` (`argparse._SubParsersAction`)

**Returns:**

`None`

### `cmd_iac(args: argparse.Namespace) -> int`

Handle IaC subcommand.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int`
