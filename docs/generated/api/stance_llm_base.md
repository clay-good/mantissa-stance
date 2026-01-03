# stance.llm.base

LLM provider base classes for Mantissa Stance.

Provides abstract interface for LLM providers used in
natural language query translation.

## Contents

### Classes

- [LLMError](#llmerror)
- [RateLimitError](#ratelimiterror)
- [AuthenticationError](#authenticationerror)
- [LLMResponse](#llmresponse)
- [LLMProvider](#llmprovider)

## LLMError

**Inherits from:** Exception

Exception raised for LLM provider errors.

### Methods

#### `__init__(self, message: str, provider: str | None, status_code: int | None, retry_after: int | None)`

**Parameters:**

- `message` (`str`)
- `provider` (`str | None`)
- `status_code` (`int | None`)
- `retry_after` (`int | None`)

## RateLimitError

**Inherits from:** LLMError

Exception raised when rate limit is exceeded.

## AuthenticationError

**Inherits from:** LLMError

Exception raised for authentication failures.

## LLMResponse

**Tags:** dataclass

Response from an LLM provider.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `text` | `str` | - |
| `provider` | `str` | - |
| `model` | `str` | - |
| `tokens_used` | `int` | - |
| `duration_seconds` | `float` | - |

## LLMProvider

**Inherits from:** ABC

Abstract base class for LLM providers.

All LLM provider implementations must inherit from this class
and implement the required methods.

### Properties

#### `provider_name(self) -> str`

**Decorators:** @property, @abstractmethod

Return provider name.

**Returns:**

`str` - Provider name (e.g., "anthropic", "openai", "gemini")

#### `model_name(self) -> str`

**Decorators:** @property, @abstractmethod

Return model name being used.

**Returns:**

`str` - Model identifier string

### Methods

#### `generate(self, prompt: str, system_prompt: str | None, max_tokens: int = 1024) -> str`

**Decorators:** @abstractmethod

Generate completion from prompt.

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
