"""
LLM provider base classes for Mantissa Stance.

Provides abstract interface for LLM providers used in
natural language query translation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


class LLMError(Exception):
    """Exception raised for LLM provider errors."""

    def __init__(
        self,
        message: str,
        provider: str | None = None,
        status_code: int | None = None,
        retry_after: int | None = None,
    ):
        self.provider = provider
        self.status_code = status_code
        self.retry_after = retry_after
        super().__init__(message)


class RateLimitError(LLMError):
    """Exception raised when rate limit is exceeded."""

    pass


class AuthenticationError(LLMError):
    """Exception raised for authentication failures."""

    pass


@dataclass
class LLMResponse:
    """Response from an LLM provider."""

    text: str
    provider: str
    model: str
    tokens_used: int
    duration_seconds: float


class LLMProvider(ABC):
    """
    Abstract base class for LLM providers.

    All LLM provider implementations must inherit from this class
    and implement the required methods.
    """

    @abstractmethod
    def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        max_tokens: int = 1024,
    ) -> str:
        """
        Generate completion from prompt.

        Args:
            prompt: User prompt
            system_prompt: Optional system context
            max_tokens: Maximum response tokens

        Returns:
            Generated text response

        Raises:
            LLMError: If generation fails
            RateLimitError: If rate limit exceeded
            AuthenticationError: If authentication fails
        """
        pass

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """
        Return provider name.

        Returns:
            Provider name (e.g., "anthropic", "openai", "gemini")
        """
        pass

    @property
    @abstractmethod
    def model_name(self) -> str:
        """
        Return model name being used.

        Returns:
            Model identifier string
        """
        pass
