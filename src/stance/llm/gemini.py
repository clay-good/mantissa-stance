"""
Google Gemini provider for Mantissa Stance.

Uses direct HTTP requests to the Gemini API without
requiring the google SDK.
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


class GeminiProvider(LLMProvider):
    """
    Google Gemini API provider using direct HTTP.

    Uses urllib.request from stdlib for API calls,
    avoiding external dependencies.
    """

    API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"
    DEFAULT_MODEL = "gemini-1.5-flash"

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
    ):
        """
        Initialize the Gemini provider.

        Args:
            api_key: Google API key. If None, reads from
                    GOOGLE_API_KEY environment variable.
            model: Model to use. Defaults to gemini-1.5-flash.

        Raises:
            AuthenticationError: If no API key is provided or found
        """
        self._api_key = api_key or os.environ.get("GOOGLE_API_KEY")
        if not self._api_key:
            raise AuthenticationError(
                "No API key provided. Set GOOGLE_API_KEY environment variable "
                "or pass api_key parameter.",
                provider="gemini",
            )

        self._model = model or self.DEFAULT_MODEL

    @property
    def provider_name(self) -> str:
        """Return provider name."""
        return "gemini"

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
        Generate completion from prompt using Gemini.

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

        contents = [{"parts": [{"text": prompt}]}]

        try:
            response = self._make_request(contents, system_prompt, max_tokens)
            candidates = response.get("candidates", [])

            if not candidates:
                raise LLMError(
                    "Empty response from Gemini API",
                    provider="gemini",
                )

            content = candidates[0].get("content", {})
            parts = content.get("parts", [])

            if not parts:
                raise LLMError(
                    "No content in Gemini response",
                    provider="gemini",
                )

            # Extract text from parts
            text_parts = []
            for part in parts:
                if "text" in part:
                    text_parts.append(part["text"])

            return "".join(text_parts)

        except (RateLimitError, AuthenticationError):
            raise
        except LLMError:
            raise
        except Exception as e:
            raise LLMError(
                f"Gemini API error: {e}",
                provider="gemini",
            )

    def _make_request(
        self,
        contents: list[dict[str, Any]],
        system_instruction: str | None,
        max_tokens: int,
    ) -> dict[str, Any]:
        """
        Make HTTP request to Gemini API.

        Args:
            contents: List of content objects
            system_instruction: Optional system instruction
            max_tokens: Maximum tokens to generate

        Returns:
            API response dictionary

        Raises:
            LLMError: If request fails
        """
        url = f"{self.API_BASE}/{self._model}:generateContent?key={self._api_key}"

        headers = {
            "Content-Type": "application/json",
        }

        body: dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "maxOutputTokens": max_tokens,
            },
        }

        if system_instruction:
            body["systemInstruction"] = {
                "parts": [{"text": system_instruction}]
            }

        data = json.dumps(body).encode("utf-8")

        request = urllib.request.Request(
            url,
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
                provider="gemini",
            )

    def _handle_error(self, error: urllib.error.HTTPError) -> None:
        """
        Handle HTTP error responses.

        Args:
            error: HTTP error from urllib

        Raises:
            RateLimitError: For 429 responses
            AuthenticationError: For 401/403 responses
            LLMError: For other errors
        """
        status_code = error.code

        try:
            body = error.read().decode("utf-8")
            error_data = json.loads(body)
            error_info = error_data.get("error", {})
            message = error_info.get("message", str(error))
        except (json.JSONDecodeError, UnicodeDecodeError):
            message = str(error)

        if status_code in (401, 403):
            raise AuthenticationError(
                f"Authentication failed: {message}. "
                "Check your GOOGLE_API_KEY.",
                provider="gemini",
                status_code=status_code,
            )

        if status_code == 429:
            # Extract retry-after header if present
            retry_after = error.headers.get("retry-after")
            retry_seconds = int(retry_after) if retry_after else 60

            raise RateLimitError(
                f"Rate limit exceeded: {message}. "
                f"Retry after {retry_seconds} seconds.",
                provider="gemini",
                status_code=status_code,
                retry_after=retry_seconds,
            )

        if status_code >= 500:
            raise LLMError(
                f"Gemini server error ({status_code}): {message}. "
                "Please retry later.",
                provider="gemini",
                status_code=status_code,
            )

        raise LLMError(
            f"Gemini API error ({status_code}): {message}",
            provider="gemini",
            status_code=status_code,
        )
