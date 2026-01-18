"""
Detection handlers for the Stance web API.

This module handles all /api/detection/* endpoints for sensitive
data detection and pattern management.
"""

from __future__ import annotations

import logging
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


class DetectionHandler(RoutedHandler):
    """
    Handler for detection API endpoints.

    Handles:
    - Sensitive data detection
    - Pattern management
    - Field classification
    - Entropy analysis
    """

    base_path = "/api/detection/"

    # =========================================================================
    # GET endpoints
    # =========================================================================

    @route("scan")
    def detection_scan(self, params: dict, body: dict | None) -> HandlerResponse:
        """Scan for sensitive data."""
        path = self.get_param(params, "path", ".")

        # Demo findings
        findings = [
            {"type": "api_key", "location": f"{path}/config.py:15", "severity": "high"},
            {"type": "password", "location": f"{path}/settings.py:42", "severity": "critical"},
        ]

        return HandlerResponse.success({
            "path": path,
            "findings": findings,
            "total": len(findings),
            "by_type": {"api_key": 1, "password": 1},
        })

    @route("patterns")
    def detection_patterns(self, params: dict, body: dict | None) -> HandlerResponse:
        """List detection patterns."""
        patterns = [
            {"id": "aws_access_key", "name": "AWS Access Key", "category": "credentials", "enabled": True},
            {"id": "github_token", "name": "GitHub Token", "category": "credentials", "enabled": True},
            {"id": "private_key", "name": "Private Key", "category": "crypto", "enabled": True},
            {"id": "email", "name": "Email Address", "category": "pii", "enabled": True},
            {"id": "ssn", "name": "Social Security Number", "category": "pii", "enabled": True},
        ]
        return HandlerResponse.success({"patterns": patterns, "total": len(patterns)})

    @route("pattern")
    def detection_pattern(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get specific pattern details."""
        pattern_id = self.get_param(params, "id", "")
        if not pattern_id:
            return HandlerResponse.error("Missing required parameter: id", HttpStatus.BAD_REQUEST)

        patterns = {
            "aws_access_key": {
                "id": "aws_access_key",
                "name": "AWS Access Key",
                "regex": r"AKIA[0-9A-Z]{16}",
                "category": "credentials",
                "severity": "critical",
                "description": "AWS access key ID",
                "enabled": True,
            },
        }

        pattern = patterns.get(pattern_id)
        if not pattern:
            return HandlerResponse.not_found(f"Pattern: {pattern_id}")

        return HandlerResponse.success(pattern)

    @route("entropy")
    def detection_entropy(self, params: dict, body: dict | None) -> HandlerResponse:
        """Calculate entropy for a string."""
        text = self.get_param(params, "text", "")
        if not text:
            return HandlerResponse.error("Missing required parameter: text", HttpStatus.BAD_REQUEST)

        # Simple entropy calculation
        from collections import Counter
        import math
        freq = Counter(text)
        length = len(text)
        entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())

        return HandlerResponse.success({
            "text_length": length,
            "entropy": round(entropy, 4),
            "is_high_entropy": entropy > 4.5,
            "threshold": 4.5,
        })

    @route("sensitive-fields")
    def detection_sensitive_fields(self, params: dict, body: dict | None) -> HandlerResponse:
        """List known sensitive field names."""
        fields = [
            {"name": "password", "category": "credentials", "sensitivity": "high"},
            {"name": "api_key", "category": "credentials", "sensitivity": "high"},
            {"name": "secret", "category": "credentials", "sensitivity": "high"},
            {"name": "email", "category": "pii", "sensitivity": "medium"},
            {"name": "ssn", "category": "pii", "sensitivity": "critical"},
            {"name": "credit_card", "category": "pci", "sensitivity": "critical"},
        ]
        return HandlerResponse.success({"fields": fields, "total": len(fields)})

    @route("check-field")
    def detection_check_field(self, params: dict, body: dict | None) -> HandlerResponse:
        """Check if a field name is sensitive."""
        field_name = self.get_param(params, "name", "")
        if not field_name:
            return HandlerResponse.error("Missing required parameter: name", HttpStatus.BAD_REQUEST)

        sensitive_patterns = ["password", "secret", "key", "token", "api_key", "credential"]
        is_sensitive = any(pattern in field_name.lower() for pattern in sensitive_patterns)

        return HandlerResponse.success({
            "field_name": field_name,
            "is_sensitive": is_sensitive,
            "matched_patterns": [p for p in sensitive_patterns if p in field_name.lower()],
        })

    @route("categories")
    def detection_categories(self, params: dict, body: dict | None) -> HandlerResponse:
        """List detection categories."""
        categories = [
            {"id": "credentials", "name": "Credentials", "description": "API keys, passwords, tokens", "pattern_count": 15},
            {"id": "pii", "name": "PII", "description": "Personal identifiable information", "pattern_count": 12},
            {"id": "pci", "name": "PCI", "description": "Payment card data", "pattern_count": 5},
            {"id": "crypto", "name": "Cryptographic", "description": "Private keys, certificates", "pattern_count": 8},
            {"id": "network", "name": "Network", "description": "IPs, hostnames, URLs", "pattern_count": 6},
        ]
        return HandlerResponse.success({"categories": categories, "total": len(categories)})

    @route("severity-levels")
    def detection_severity_levels(self, params: dict, body: dict | None) -> HandlerResponse:
        """List detection severity levels."""
        levels = [
            {"level": "critical", "description": "Immediate exposure risk", "priority": 1},
            {"level": "high", "description": "High sensitivity data", "priority": 2},
            {"level": "medium", "description": "Moderate sensitivity", "priority": 3},
            {"level": "low", "description": "Low sensitivity", "priority": 4},
            {"level": "info", "description": "Informational", "priority": 5},
        ]
        return HandlerResponse.success({"levels": levels, "total": len(levels)})

    @route("stats")
    def detection_stats(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get detection statistics."""
        return HandlerResponse.success({
            "total_patterns": 46,
            "enabled_patterns": 42,
            "categories": 5,
            "severity_levels": 5,
            "scans_run": 0,
            "findings_total": 0,
        })

    @route("status")
    def detection_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get detection module status."""
        return HandlerResponse.success({
            "module": "detection",
            "status": "operational",
            "capabilities": [
                "pattern_matching",
                "entropy_analysis",
                "field_classification",
                "sensitive_data_detection",
            ],
            "patterns_loaded": 46,
        })

    @route("summary")
    def detection_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get detection module summary."""
        return HandlerResponse.success({
            "module": "detection",
            "description": "Sensitive data detection and classification",
            "features": [
                "Pattern-based detection",
                "Entropy analysis",
                "Field name classification",
                "Multiple data categories",
                "Configurable patterns",
            ],
            "total_patterns": 46,
            "categories": ["credentials", "pii", "pci", "crypto", "network"],
        })
