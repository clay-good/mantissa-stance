"""
OpenAI GPT provider for Mantissa Stance.

Uses direct HTTP requests to the OpenAI API without
requiring the openai SDK.
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


class OpenAIProvider(LLMProvider):
    """
    OpenAI GPT API provider using direct HTTP.

    Uses urllib.request from stdlib for API calls,
    avoiding external dependencies.
    """

    API_ENDPOINT = "https://api.openai.com/v1/chat/completions"
    DEFAULT_MODEL = "gpt-4o-mini"

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
    ):
        """
        Initialize the OpenAI provider.

        Args:
            api_key: OpenAI API key. If None, reads from
                    OPENAI_API_KEY environment variable.
            model: Model to use. Defaults to gpt-4o-mini.

        Raises:
            AuthenticationError: If no API key is provided or found
        """
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self._api_key:
            raise AuthenticationError(
                "No API key provided. Set OPENAI_API_KEY environment variable "
                "or pass api_key parameter.",
                provider="openai",
            )

        self._model = model or self.DEFAULT_MODEL

    @property
    def provider_name(self) -> str:
        """Return provider name."""
        return "openai"

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
        Generate completion from prompt using GPT.

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

        messages: list[dict[str, str]] = []

        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        messages.append({"role": "user", "content": prompt})

        try:
            response = self._make_request(messages, max_tokens)
            choices = response.get("choices", [])

            if not choices:
                raise LLMError(
                    "Empty response from OpenAI API",
                    provider="openai",
                )

            message = choices[0].get("message", {})
            return message.get("content", "")

        except (RateLimitError, AuthenticationError):
            raise
        except LLMError:
            raise
        except Exception as e:
            raise LLMError(
                f"OpenAI API error: {e}",
                provider="openai",
            )

    def _make_request(
        self,
        messages: list[dict[str, str]],
        max_tokens: int,
    ) -> dict[str, Any]:
        """
        Make HTTP request to OpenAI API.

        Args:
            messages: List of message objects
            max_tokens: Maximum tokens to generate

        Returns:
            API response dictionary

        Raises:
            LLMError: If request fails
        """
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

        body = {
            "model": self._model,
            "messages": messages,
            "max_tokens": max_tokens,
        }

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
                provider="openai",
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
                "Check your OPENAI_API_KEY.",
                provider="openai",
                status_code=status_code,
            )

        if status_code == 429:
            # Extract retry-after header if present
            retry_after = error.headers.get("retry-after")
            retry_seconds = int(retry_after) if retry_after else 60

            raise RateLimitError(
                f"Rate limit exceeded: {message}. "
                f"Retry after {retry_seconds} seconds.",
                provider="openai",
                status_code=status_code,
                retry_after=retry_seconds,
            )

        if status_code >= 500:
            raise LLMError(
                f"OpenAI server error ({status_code}): {message}. "
                "Please retry later.",
                provider="openai",
                status_code=status_code,
            )

        raise LLMError(
            f"OpenAI API error ({status_code}): {message}",
            provider="openai",
            status_code=status_code,
        )
