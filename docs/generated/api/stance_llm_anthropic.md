# stance.llm.anthropic

Anthropic Claude provider for Mantissa Stance.

Uses direct HTTP requests to the Anthropic API without
requiring the anthropic SDK.

## Contents

### Classes

- [AnthropicProvider](#anthropicprovider)

## AnthropicProvider

**Inherits from:** LLMProvider

Anthropic Claude API provider using direct HTTP.

Uses urllib.request from stdlib for API calls,
avoiding external dependencies.

### Properties

#### `provider_name(self) -> str`

Return provider name.

**Returns:**

`str`

#### `model_name(self) -> str`

Return model name.

**Returns:**

`str`

### Methods

#### `__init__(self, api_key: str | None, model: str | None)`

Initialize the Anthropic provider.

**Parameters:**

- `api_key` (`str | None`) - Anthropic API key. If None, reads from ANTHROPIC_API_KEY environment variable.
- `model` (`str | None`) - Model to use. Defaults to claude-3-haiku.

**Raises:**

- `AuthenticationError`: If no API key is provided or found

#### `generate(self, prompt: str, system_prompt: str | None, max_tokens: int = 1024) -> str`

Generate completion from prompt using Claude.

**Parameters:**

- `prompt` (`str`) - User prompt
- `system_prompt` (`str | None`) - Optional system context
- `max_tokens` (`int`) - default: `1024` - Maximum response tokens

**Returns:**

`str` - Generated text response

**Raises:**

- `LLMError`: If generation fails
- `RateLimitError`: If rate limit exceeded
- `AuthenticationError`: If authentication fails
