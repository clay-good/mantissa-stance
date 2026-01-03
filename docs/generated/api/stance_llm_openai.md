# stance.llm.openai

OpenAI GPT provider for Mantissa Stance.

Uses direct HTTP requests to the OpenAI API without
requiring the openai SDK.

## Contents

### Classes

- [OpenAIProvider](#openaiprovider)

## OpenAIProvider

**Inherits from:** LLMProvider

OpenAI GPT API provider using direct HTTP.

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

Initialize the OpenAI provider.

**Parameters:**

- `api_key` (`str | None`) - OpenAI API key. If None, reads from OPENAI_API_KEY environment variable.
- `model` (`str | None`) - Model to use. Defaults to gpt-4o-mini.

**Raises:**

- `AuthenticationError`: If no API key is provided or found

#### `generate(self, prompt: str, system_prompt: str | None, max_tokens: int = 1024) -> str`

Generate completion from prompt using GPT.

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
