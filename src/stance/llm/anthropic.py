"""
Anthropic Claude provider for Mantissa Stance.

Uses direct HTTP requests to the Anthropic API without
requiring the anthropic SDK.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any

from stance.llm.base import (
    LLMProvider,
    LLMError,
    RateLimitError,
    AuthenticationError,
)


class AnthropicProvider(LLMProvider):
    """
    Anthropic Claude API provider using direct HTTP.

    Uses urllib.request from stdlib for API calls,
    avoiding external dependencies.
    """

    API_ENDPOINT = "https://api.anthropic.com/v1/messages"
    API_VERSION = "2023-06-01"
    DEFAULT_MODEL = "claude-3-haiku-20240307"

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
    ):
        """
        Initialize the Anthropic provider.

        Args:
            api_key: Anthropic API key. If None, reads from
                    ANTHROPIC_API_KEY environment variable.
            model: Model to use. Defaults to claude-3-haiku.

        Raises:
            AuthenticationError: If no API key is provided or found
        """
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self._api_key:
            raise AuthenticationError(
                "No API key provided. Set ANTHROPIC_API_KEY environment variable "
                "or pass api_key parameter.",
                provider="anthropic",
            )

        self._model = model or self.DEFAULT_MODEL

    @property
    def provider_name(self) -> str:
        """Return provider name."""
        return "anthropic"

    @property
    def model_name(self) -> str:
        """Return model name."""
        return self._model

    def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        max_tokens: int = 1024,
    ) -> str:
        """
        Generate completion from prompt using Claude.

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
        start_time = time.time()

        messages = [{"role": "user", "content": prompt}]

        try:
            response = self._make_request(messages, system_prompt, max_tokens)
            content = response.get("content", [])

            if not content:
                raise LLMError(
                    "Empty response from Anthropic API",
                    provider="anthropic",
                )

            # Extract text from content blocks
            text_parts = []
            for block in content:
                if block.get("type") == "text":
                    text_parts.append(block.get("text", ""))

            return "".join(text_parts)

        except (RateLimitError, AuthenticationError):
            raise
        except LLMError:
            raise
        except Exception as e:
            raise LLMError(
                f"Anthropic API error: {e}",
                provider="anthropic",
            )

    def _make_request(
        self,
        messages: list[dict[str, Any]],
        system: str | None,
        max_tokens: int,
    ) -> dict[str, Any]:
        """
        Make HTTP request to Anthropic API.

        Args:
            messages: List of message objects
            system: Optional system prompt
            max_tokens: Maximum tokens to generate

        Returns:
            API response dictionary

        Raises:
            LLMError: If request fails
        """
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": self.API_VERSION,
            "content-type": "application/json",
        }

        body: dict[str, Any] = {
            "model": self._model,
            "messages": messages,
            "max_tokens": max_tokens,
        }

        if system:
            body["system"] = system

        data = json.dumps(body).encode("utf-8")

        request = urllib.request.Request(
            self.API_ENDPOINT,
            data=data,
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                response_data = response.read().decode("utf-8")
                return json.loads(response_data)

        except urllib.error.HTTPError as e:
            self._handle_error(e)
            raise  # Should not reach here

        except urllib.error.URLError as e:
            raise LLMError(
                f"Network error: {e.reason}",
                provider="anthropic",
            )

    def _handle_error(self, error: urllib.error.HTTPError) -> None:
        """
        Handle HTTP error responses.

        Args:
            error: HTTP error from urllib

        Raises:
            RateLimitError: For 429 responses
            AuthenticationError: For 401 responses
            LLMError: For other errors
        """
        status_code = error.code

        try:
            body = error.read().decode("utf-8")
            error_data = json.loads(body)
            message = error_data.get("error", {}).get("message", str(error))
        except (json.JSONDecodeError, UnicodeDecodeError):
            message = str(error)

        if status_code == 401:
            raise AuthenticationError(
                f"Authentication failed: {message}. "
                "Check your ANTHROPIC_API_KEY.",
                provider="anthropic",
                status_code=status_code,
            )

        if status_code == 429:
            # Extract retry-after header if present
            retry_after = error.headers.get("retry-after")
            retry_seconds = int(retry_after) if retry_after else 60

            raise RateLimitError(
                f"Rate limit exceeded: {message}. "
                f"Retry after {retry_seconds} seconds.",
                provider="anthropic",
                status_code=status_code,
                retry_after=retry_seconds,
            )

        if status_code >= 500:
            raise LLMError(
                f"Anthropic server error ({status_code}): {message}. "
                "Please retry later.",
                provider="anthropic",
                status_code=status_code,
            )

        raise LLMError(
            f"Anthropic API error ({status_code}): {message}",
            provider="anthropic",
            status_code=status_code,
        )
