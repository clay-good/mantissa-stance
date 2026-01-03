# stance.cli_llm

CLI commands for LLM module.

Provides command-line interface for AI-powered features:
- LLM provider management
- Natural language query generation
- Finding explanations
- Policy generation
- Data sanitization

## Contents

### Functions

- [add_llm_parser](#add_llm_parser)
- [cmd_llm](#cmd_llm)

### `add_llm_parser(subparsers: Any) -> None`

Add LLM parser to CLI subparsers.

**Parameters:**

- `subparsers` (`Any`)

**Returns:**

`None`

### `cmd_llm(args: argparse.Namespace) -> int`

Handle LLM commands.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int`
