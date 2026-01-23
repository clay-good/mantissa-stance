"""
LLM handlers for the Stance web API.

This module handles all /api/llm/* endpoints for LLM-assisted
query generation and policy management.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


# =============================================================================
# Prompt Injection Prevention
# =============================================================================

class PromptInjectionError(ValueError):
    """Raised when prompt injection is detected."""
    pass


def sanitize_llm_input(
    text: str,
    max_length: int = 4000,
    allow_code_blocks: bool = False,
) -> str:
    """
    Sanitize user input before including in LLM prompts.

    This function helps prevent prompt injection attacks by:
    - Limiting input length
    - Removing control characters
    - Escaping common injection patterns
    - Detecting suspicious instruction-like content

    Args:
        text: User input text
        max_length: Maximum allowed length
        allow_code_blocks: Whether to allow code block markers

    Returns:
        Sanitized text

    Raises:
        PromptInjectionError: If suspicious content is detected
    """
    if not text:
        return ""

    # Check length
    if len(text) > max_length:
        raise PromptInjectionError(f"Input exceeds maximum length of {max_length} characters")

    # Check for null bytes
    if "\x00" in text:
        raise PromptInjectionError("Input contains invalid characters")

    # Remove control characters (except newlines and tabs for formatting)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)

    # Detect common prompt injection patterns
    injection_patterns = [
        # Direct instruction attempts
        r"ignore\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?|rules?)",
        r"disregard\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?|rules?)",
        r"forget\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?|rules?)",
        r"override\s+(all\s+)?(previous|above|prior)",
        r"new\s+(instructions?|prompt|task|role)",
        r"you\s+are\s+now\s+[a-zA-Z]+",  # Role change attempts
        r"system\s*:\s*",  # System prompt injection
        r"\[INST\]",  # Llama instruction format
        r"<\|system\|>",  # ChatML format
        r"<\|user\|>",
        r"<\|assistant\|>",
        r"###\s*(System|Human|Assistant|User)\s*:",  # Common chat formats
        r"ASSISTANT:",
        r"USER:",
        r"SYSTEM:",
        # Jailbreak patterns
        r"DAN\s+mode",
        r"jailbreak",
        r"bypass\s+(safety|security|filter)",
        # Output manipulation
        r"respond\s+with\s+(only|just)",
        r"output\s+(only|just|exactly)",
        r"print\s+(only|just)",
    ]

    text_lower = text.lower()
    for pattern in injection_patterns:
        if re.search(pattern, text_lower, re.IGNORECASE):
            logger.warning(f"Potential prompt injection detected: pattern={pattern[:30]}...")
            raise PromptInjectionError(
                "Input contains potentially malicious content. "
                "Please rephrase your request."
            )

    # Remove or escape code blocks if not allowed
    if not allow_code_blocks:
        # Replace triple backticks with escaped version
        text = text.replace("```", "\\`\\`\\`")

    # Escape XML-like tags that might be interpreted as special tokens
    text = re.sub(r"<\|([^|>]+)\|>", r"&lt;|\1|&gt;", text)
    text = re.sub(r"<(/?)(\w+)>", r"&lt;\1\2&gt;", text)

    return text


def validate_llm_query_request(question: str) -> tuple[bool, str | None]:
    """
    Validate a natural language query request.

    Args:
        question: The user's natural language question

    Returns:
        Tuple of (valid: bool, error_message: str | None)
    """
    try:
        sanitize_llm_input(question, max_length=2000)
        return True, None
    except PromptInjectionError as e:
        return False, str(e)


class LlmHandler(RoutedHandler):
    """
    Handler for LLM API endpoints.

    Handles:
    - Query generation
    - Finding explanation
    - Policy generation
    - Data sanitization
    """

    base_path = "/api/llm/"

    # =========================================================================
    # GET endpoints
    # =========================================================================

    @route("providers")
    def llm_providers(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available LLM providers."""
        providers = [
            {
                "id": "openai",
                "name": "OpenAI",
                "models": ["gpt-4", "gpt-3.5-turbo"],
                "available": False,
                "requires_key": True,
            },
            {
                "id": "anthropic",
                "name": "Anthropic",
                "models": ["claude-3-opus", "claude-3-sonnet", "claude-3-haiku"],
                "available": False,
                "requires_key": True,
            },
            {
                "id": "ollama",
                "name": "Ollama (Local)",
                "models": ["llama2", "mistral", "codellama"],
                "available": False,
                "requires_key": False,
            },
        ]
        return HandlerResponse.success({"providers": providers, "total": len(providers)})

    @route("provider")
    def llm_provider(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get provider details."""
        provider_id = self.get_param(params, "id", "")
        if not provider_id:
            return HandlerResponse.error("Missing required parameter: id", HttpStatus.BAD_REQUEST)

        providers = {
            "openai": {
                "id": "openai",
                "name": "OpenAI",
                "description": "OpenAI API for GPT models",
                "models": ["gpt-4", "gpt-4-turbo", "gpt-3.5-turbo"],
                "endpoint": "https://api.openai.com/v1",
                "requires_key": True,
                "key_env_var": "OPENAI_API_KEY",
            },
            "anthropic": {
                "id": "anthropic",
                "name": "Anthropic",
                "description": "Anthropic API for Claude models",
                "models": ["claude-3-opus-20240229", "claude-3-sonnet-20240229", "claude-3-haiku-20240307"],
                "endpoint": "https://api.anthropic.com",
                "requires_key": True,
                "key_env_var": "ANTHROPIC_API_KEY",
            },
        }

        provider = providers.get(provider_id)
        if not provider:
            return HandlerResponse.not_found(f"Provider: {provider_id}")

        return HandlerResponse.success(provider)

    @route("generate-query")
    def llm_generate_query(self, params: dict, body: dict | None) -> HandlerResponse:
        """Generate SQL query from natural language."""
        question = self.get_param(params, "question", "")
        if not question:
            return HandlerResponse.error("Missing required parameter: question", HttpStatus.BAD_REQUEST)

        # Validate and sanitize input to prevent prompt injection
        valid, error = validate_llm_query_request(question)
        if not valid:
            return HandlerResponse.error(error or "Invalid input", HttpStatus.BAD_REQUEST)

        # Demo response
        return HandlerResponse.success({
            "question": question,
            "generated_query": "SELECT * FROM findings WHERE severity = 'critical'",
            "confidence": 0.85,
            "explanation": "This query selects all critical severity findings.",
            "provider": "demo",
        })

    @route("validate-query")
    def llm_validate_query(self, params: dict, body: dict | None) -> HandlerResponse:
        """Validate and explain a query."""
        query = self.get_param(params, "query", "")
        if not query:
            return HandlerResponse.error("Missing required parameter: query", HttpStatus.BAD_REQUEST)

        # Sanitize input
        try:
            query = sanitize_llm_input(query, max_length=5000, allow_code_blocks=True)
        except PromptInjectionError as e:
            return HandlerResponse.error(str(e), HttpStatus.BAD_REQUEST)

        return HandlerResponse.success({
            "query": query,
            "valid": True,
            "explanation": "This query retrieves findings data.",
            "suggestions": [],
        })

    @route("explain-finding")
    def llm_explain_finding(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get LLM explanation for a finding."""
        finding_id = self.get_param(params, "finding_id", "")
        if not finding_id:
            return HandlerResponse.error("Missing required parameter: finding_id", HttpStatus.BAD_REQUEST)

        # Validate finding_id format (should be alphanumeric with hyphens/underscores)
        if not re.match(r"^[\w\-]+$", finding_id):
            return HandlerResponse.error("Invalid finding_id format", HttpStatus.BAD_REQUEST)

        return HandlerResponse.success({
            "finding_id": finding_id,
            "explanation": "This finding indicates a potential security risk.",
            "risk_analysis": "The risk level is high due to exposure.",
            "remediation_steps": [
                "Identify the affected resource",
                "Apply the recommended fix",
                "Verify the fix is in place",
            ],
            "provider": "demo",
        })

    @route("generate-policy")
    def llm_generate_policy(self, params: dict, body: dict | None) -> HandlerResponse:
        """Generate policy from description."""
        description = self.get_param(params, "description", "")
        if not description:
            return HandlerResponse.error("Missing required parameter: description", HttpStatus.BAD_REQUEST)

        # Sanitize input to prevent prompt injection
        try:
            description = sanitize_llm_input(description, max_length=2000)
        except PromptInjectionError as e:
            return HandlerResponse.error(str(e), HttpStatus.BAD_REQUEST)

        return HandlerResponse.success({
            "description": description,
            "generated_policy": {
                "id": "generated-policy-001",
                "name": "Generated Policy",
                "severity": "high",
                "check": "resource.encryption.enabled == true",
            },
            "confidence": 0.75,
            "provider": "demo",
        })

    @route("suggest-policies")
    def llm_suggest_policies(self, params: dict, body: dict | None) -> HandlerResponse:
        """Suggest policies for a resource type."""
        resource_type = self.get_param(params, "resource_type", "")
        if not resource_type:
            return HandlerResponse.error("Missing required parameter: resource_type", HttpStatus.BAD_REQUEST)

        # Validate resource_type format (should be alphanumeric with dots/hyphens/underscores)
        if not re.match(r"^[\w\.\-]+$", resource_type) or len(resource_type) > 200:
            return HandlerResponse.error("Invalid resource_type format", HttpStatus.BAD_REQUEST)

        suggestions = [
            {"name": "Enable encryption", "description": "Ensure encryption is enabled"},
            {"name": "Restrict access", "description": "Limit access to authorized users"},
        ]

        return HandlerResponse.success({
            "resource_type": resource_type,
            "suggestions": suggestions,
            "total": len(suggestions),
        })

    @route("sanitize")
    def llm_sanitize(self, params: dict, body: dict | None) -> HandlerResponse:
        """Sanitize text before sending to LLM."""
        text = self.get_param(params, "text", "")
        if not text:
            return HandlerResponse.error("Missing required parameter: text", HttpStatus.BAD_REQUEST)

        # Simple sanitization demo
        sanitized = text.replace("password", "[REDACTED]")
        sanitized = sanitized.replace("secret", "[REDACTED]")

        return HandlerResponse.success({
            "original_length": len(text),
            "sanitized_length": len(sanitized),
            "redactions": 0,
            "sanitized_preview": sanitized[:100] + "..." if len(sanitized) > 100 else sanitized,
        })

    @route("check-sensitive")
    def llm_check_sensitive(self, params: dict, body: dict | None) -> HandlerResponse:
        """Check if text contains sensitive data."""
        text = self.get_param(params, "text", "")
        if not text:
            return HandlerResponse.error("Missing required parameter: text", HttpStatus.BAD_REQUEST)

        sensitive_patterns = ["password", "secret", "api_key", "token"]
        found = [p for p in sensitive_patterns if p.lower() in text.lower()]

        return HandlerResponse.success({
            "contains_sensitive": len(found) > 0,
            "patterns_found": found,
            "recommendation": "Sanitize before sending to LLM" if found else "Safe to send",
        })

    @route("resource-types")
    def llm_resource_types(self, params: dict, body: dict | None) -> HandlerResponse:
        """List resource types for policy generation."""
        types = [
            {"type": "aws_s3_bucket", "provider": "aws", "category": "Storage"},
            {"type": "aws_security_group", "provider": "aws", "category": "Network"},
            {"type": "aws_iam_role", "provider": "aws", "category": "Identity"},
            {"type": "gcp_storage_bucket", "provider": "gcp", "category": "Storage"},
        ]
        return HandlerResponse.success({"resource_types": types, "total": len(types)})

    @route("frameworks")
    def llm_frameworks(self, params: dict, body: dict | None) -> HandlerResponse:
        """List compliance frameworks for policy mapping."""
        frameworks = [
            {"id": "cis", "name": "CIS Benchmarks"},
            {"id": "nist", "name": "NIST 800-53"},
            {"id": "pci", "name": "PCI DSS"},
            {"id": "soc2", "name": "SOC 2"},
        ]
        return HandlerResponse.success({"frameworks": frameworks, "total": len(frameworks)})

    @route("models")
    def llm_models(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available models."""
        models = [
            {"id": "gpt-4", "provider": "openai", "context_length": 8192},
            {"id": "gpt-3.5-turbo", "provider": "openai", "context_length": 4096},
            {"id": "claude-3-opus", "provider": "anthropic", "context_length": 200000},
            {"id": "claude-3-sonnet", "provider": "anthropic", "context_length": 200000},
        ]
        return HandlerResponse.success({"models": models, "total": len(models)})

    @route("status")
    def llm_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get LLM module status."""
        return HandlerResponse.success({
            "module": "llm",
            "status": "operational",
            "providers_available": 0,
            "capabilities": [
                "query_generation",
                "finding_explanation",
                "policy_generation",
                "data_sanitization",
            ],
        })

    @route("summary")
    def llm_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get LLM module summary."""
        return HandlerResponse.success({
            "module": "llm",
            "description": "LLM-assisted security analysis and policy generation",
            "features": [
                "Natural language to SQL query generation",
                "Finding explanation and remediation guidance",
                "Policy generation from descriptions",
                "Sensitive data sanitization",
            ],
            "supported_providers": ["openai", "anthropic", "ollama"],
        })
