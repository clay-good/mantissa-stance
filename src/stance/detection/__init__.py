"""
Detection module for Mantissa Stance.

Provides deterministic detection capabilities for:
- Secrets in cloud configurations
- Hard-coded credentials
- Sensitive data exposure

All detection is pattern-based and entropy-based (no LLM required).
"""

from __future__ import annotations

from stance.detection.secrets import (
    SecretsDetector,
    SecretMatch,
    SecretsResult,
    SECRET_PATTERNS,
    SENSITIVE_FIELD_NAMES,
    create_secrets_detector,
    scan_assets_for_secrets,
)

__all__ = [
    # Secrets detection
    "SecretsDetector",
    "SecretMatch",
    "SecretsResult",
    "SECRET_PATTERNS",
    "SENSITIVE_FIELD_NAMES",
    "create_secrets_detector",
    "scan_assets_for_secrets",
]
