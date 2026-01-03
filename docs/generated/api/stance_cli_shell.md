# stance.cli_shell

Interactive shell (REPL) for Mantissa Stance.

Provides an interactive command-line environment for exploring
findings, assets, and running queries without repeated CLI invocations.

## Contents

### Classes

- [StanceShell](#stanceshell)

### Functions

- [cmd_shell](#cmd_shell)

## StanceShell

**Inherits from:** cmd.Cmd

Interactive shell for Stance CSPM.

Provides commands for exploring findings, assets, policies,
and running queries in an interactive session.

### Properties

#### `storage(self)`

Lazy-load storage backend.

### Methods

#### `__init__(self, storage_type: str = local, verbose: bool = False, llm_provider: str | None)`

Initialize the shell.

**Parameters:**

- `storage_type` (`str`) - default: `local` - Storage backend to use
- `verbose` (`bool`) - default: `False` - Enable verbose output
- `llm_provider` (`str | None`) - LLM provider for natural language queries

#### `precmd(self, line: str) -> str`

Record command in history before execution.

**Parameters:**

- `line` (`str`)

**Returns:**

`str`

#### `postcmd(self, stop: bool, line: str) -> bool`

Save history after each command.

**Parameters:**

- `stop` (`bool`)
- `line` (`str`)

**Returns:**

`bool`

#### `default(self, line: str) -> None`

Handle unknown commands as potential queries.

**Parameters:**

- `line` (`str`)

**Returns:**

`None`

#### `emptyline(self) -> bool`

Don't repeat last command on empty line.

**Returns:**

`bool`

#### `do_quit(self, arg: str) -> bool`

Exit the shell.

**Parameters:**

- `arg` (`str`)

**Returns:**

`bool`

#### `do_exit(self, arg: str) -> bool`

Exit the shell (alias for quit).

**Parameters:**

- `arg` (`str`)

**Returns:**

`bool`

#### `do_EOF(self, arg: str) -> bool`

Exit on Ctrl+D.

**Parameters:**

- `arg` (`str`)

**Returns:**

`bool`

#### `do_version(self, arg: str) -> None`

Show version information.

**Parameters:**

- `arg` (`str`)

**Returns:**

`None`

#### `do_clear(self, arg: str) -> None`

Clear the screen.

**Parameters:**

- `arg` (`str`)

**Returns:**

`None`

#### `do_findings(self, arg: str) -> None`

List or search findings.  Usage: findings              - List recent findings findings --severity critical  - Filter by severity findings --limit 10   - Limit results findings --json       - Output as JSON

**Parameters:**

- `arg` (`str`)

**Returns:**

`None`

#### `do_finding(self, arg: str) -> None`

Show details of a specific finding.  Usage: finding <id>          - Show finding details finding --json <id>   - Output as JSON

**Parameters:**

- `arg` (`str`)

**Returns:**

`None`

#### `do_assets(self, arg: str) -> None`

List or search assets.  Usage: assets                - List recent assets assets --type ec2     - Filter by type assets --limit 10     - Limit results assets --json         - Output as JSON

**Parameters:**

- `arg` (`str`)

**Returns:**

`None`

#### `do_asset(self, arg: str) -> None`

Show details of a specific asset.  Usage: asset <id>            - Show asset details asset --json <id>     - Output as JSON

**Parameters:**

- `arg` (`str`)

**Returns:**

`None`

#### `do_sql(self, arg: str) -> None`

Execute a SQL query.  Usage: sql SELECT * FROM findings WHERE severity = 'critical' SELECT * FROM assets WHERE asset_type LIKE '%s3%'

**Parameters:**

- `arg` (`str`)

**Returns:**

`None`

#### `do_query(self, arg: str) -> None`

Execute a natural language query (requires LLM).  Usage: query Show me all critical findings query How many S3 buckets have public access?

**Parameters:**

- `arg` (`str`)

**Returns:**

`None`

#### `do_policies(self, arg: str) -> None`

List available policies.  Usage: policies              - List all policies policies --severity critical  - Filter by severity policies --limit 20   - Limit results

**Parameters:**

- `arg` (`str`)

**Returns:**

`None`

#### `do_policy(self, arg: str) -> None`

Show details of a specific policy.  Usage: policy <policy_id>

**Parameters:**

- `arg` (`str`)

**Returns:**

`None`

#### `do_summary(self, arg: str) -> None`

Show summary of current posture.  Usage: summary               - Show findings summary summary --json        - Output as JSON

**Parameters:**

- `arg` (`str`)

**Returns:**

`None`

#### `do_last(self, arg: str) -> None`

Show last query results.  Usage: last                  - Show last results last --json           - Output as JSON last 5                - Show first 5 results

**Parameters:**

- `arg` (`str`)

**Returns:**

`None`

#### `do_count(self, arg: str) -> None`

Show count of last query results.

**Parameters:**

- `arg` (`str`)

**Returns:**

`None`

#### `do_history(self, arg: str) -> None`

Show command history.

**Parameters:**

- `arg` (`str`)

**Returns:**

`None`

#### `do_set(self, arg: str) -> None`

Set shell configuration.  Usage: set verbose on        - Enable verbose output set verbose off       - Disable verbose output set llm <provider>    - Set LLM provider

**Parameters:**

- `arg` (`str`)

**Returns:**

`None`

#### `help_commands(self) -> None`

Show available commands.

**Returns:**

`None`

### `cmd_shell(args: argparse.Namespace) -> int`

Launch interactive shell.

**Parameters:**

- `args` (`argparse.Namespace`) - Command-line arguments

**Returns:**

`int` - Exit code
