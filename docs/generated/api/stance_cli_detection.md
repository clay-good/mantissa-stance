# stance.cli_detection

CLI commands for Detection module.

Provides command-line interface for secrets detection:
- Scan text/files for secrets
- List supported secret patterns
- Check entropy of strings
- Validate sensitive field names
- Show detection statistics

## Contents

### Functions

- [add_detection_parser](#add_detection_parser)
- [cmd_detection](#cmd_detection)

### `add_detection_parser(subparsers: Any) -> None`

Add detection parser to CLI subparsers.

**Parameters:**

- `subparsers` (`Any`)

**Returns:**

`None`

### `cmd_detection(args: argparse.Namespace) -> int`

Handle detection commands.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int`
