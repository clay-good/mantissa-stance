"""
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
"""

from __future__ import annotations

from stance.llm.base import (
    LLMProvider,
    LLMResponse,
    LLMError,
    RateLimitError,
    AuthenticationError,
)
from stance.llm.anthropic import AnthropicProvider
from stance.llm.openai import OpenAIProvider
from stance.llm.gemini import GeminiProvider
from stance.llm.query_generator import (
    QueryGenerator,
    GeneratedQuery,
    POSTURE_SCHEMA,
)
from stance.llm.explainer import (
    FindingExplainer,
    FindingExplanation,
    create_explainer,
)
from stance.llm.sanitizer import (
    DataSanitizer,
    SanitizationResult,
    create_sanitizer,
)
from stance.llm.policy_generator import (
    PolicyGenerator,
    GeneratedPolicy,
    create_policy_generator,
    save_policy,
    RESOURCE_TYPES,
    COMPLIANCE_FRAMEWORKS,
)

__all__ = [
    # Base classes
    "LLMProvider",
    "LLMResponse",
    "LLMError",
    "RateLimitError",
    "AuthenticationError",
    # Providers
    "AnthropicProvider",
    "OpenAIProvider",
    "GeminiProvider",
    # Query generation
    "QueryGenerator",
    "GeneratedQuery",
    "POSTURE_SCHEMA",
    # Finding explanation (AI)
    "FindingExplainer",
    "FindingExplanation",
    "create_explainer",
    # Policy generation (AI)
    "PolicyGenerator",
    "GeneratedPolicy",
    "create_policy_generator",
    "save_policy",
    "RESOURCE_TYPES",
    "COMPLIANCE_FRAMEWORKS",
    # Data sanitization
    "DataSanitizer",
    "SanitizationResult",
    "create_sanitizer",
    # Factory function
    "get_llm_provider",
]


def get_llm_provider(
    provider: str = "anthropic",
    **kwargs,
) -> LLMProvider:
    """
    Get LLM provider by name.

    Args:
        provider: Provider name ("anthropic", "openai", or "gemini")
        **kwargs: Provider-specific configuration
            - api_key: API key (or use env var)
            - model: Model name override

    Returns:
        Configured LLMProvider instance

    Raises:
        ValueError: If provider is unknown

    Environment variables checked:
        - anthropic: ANTHROPIC_API_KEY
        - openai: OPENAI_API_KEY
        - gemini: GOOGLE_API_KEY

    Example:
        >>> # Use Anthropic with default model
        >>> provider = get_llm_provider("anthropic")
        >>>
        >>> # Use OpenAI with specific model
        >>> provider = get_llm_provider("openai", model="gpt-4")
        >>>
        >>> # Use Gemini with custom API key
        >>> provider = get_llm_provider("gemini", api_key="your-key")
    """
    provider_lower = provider.lower()

    if provider_lower == "anthropic":
        return AnthropicProvider(**kwargs)
    elif provider_lower == "openai":
        return OpenAIProvider(**kwargs)
    elif provider_lower == "gemini":
        return GeminiProvider(**kwargs)
    else:
        raise ValueError(
            f"Unknown LLM provider: {provider}. "
            f"Supported providers: anthropic, openai, gemini"
        )
