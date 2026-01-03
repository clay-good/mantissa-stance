# stance.llm

LLM providers for Mantissa Stance.

This package provides LLM provider integrations for:

- Natural language query translation (QueryGenerator)
- AI-powered finding explanations (FindingExplainer)
- AI-powered policy generation (PolicyGenerator)
- Data sanitization for privacy (DataSanitizer)

Supported LLM providers:
- AnthropicProvider: Claude models via Anthropic API
- OpenAIProvider: GPT models via OpenAI API
- GeminiProvider: Gemini models via Google API

All providers use BYOK (Bring Your Own Key) via environment variables:
- ANTHROPIC_API_KEY for Anthropic
- OPENAI_API_KEY for OpenAI
- GOOGLE_API_KEY for Google Gemini

## Contents

### Functions

- [get_llm_provider](#get_llm_provider)

### `get_llm_provider(provider: str = anthropic, **kwargs) -> LLMProvider`

Get LLM provider by name.

**Parameters:**

- `provider` (`str`) - default: `anthropic` - Provider name ("anthropic", "openai", or "gemini") **kwargs: Provider-specific configuration - api_key: API key (or use env var) - model: Model name override
- `**kwargs`

**Returns:**

`LLMProvider` - Configured LLMProvider instance

**Raises:**

- `ValueError`: If provider is unknown

**Examples:**

```python
>>> # Use Anthropic with default model
    >>> provider = get_llm_provider("anthropic")
    >>>
    >>> # Use OpenAI with specific model
    >>> provider = get_llm_provider("openai", model="gpt-4")
    >>>
    >>> # Use Gemini with custom API key
    >>> provider = get_llm_provider("gemini", api_key="your-key")
```
