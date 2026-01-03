"""
Base alert destination for Mantissa Stance.

Provides abstract interface for alert destinations.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from stance.models.finding import Finding, Severity

logger = logging.getLogger(__name__)


@dataclass
class AlertPayload:
    """
    Structured alert payload for destinations.

    Attributes:
        title: Alert title
        description: Alert description
        severity: Severity level
        finding: Original finding
        context: Additional context
        formatted_body: Pre-formatted body (if applicable)
    """

    title: str
    description: str
    severity: Severity
    finding: Finding
    context: dict[str, Any]
    formatted_body: str = ""


class BaseDestination(ABC):
    """
    Abstract base class for alert destinations.

    All destination implementations should inherit from this class
    and implement the required methods.
    """

    def __init__(self, name: str, config: dict[str, Any]) -> None:
        """
        Initialize the destination.

        Args:
            name: Unique destination name
            config: Destination-specific configuration
        """
        self._name = name
        self._config = config

    @property
    def name(self) -> str:
        """Get destination name."""
        return self._name

    @property
    def config(self) -> dict[str, Any]:
        """Get destination configuration."""
        return self._config

    @abstractmethod
    def send(self, finding: Finding, context: dict[str, Any]) -> bool:
        """
        Send an alert for a finding.

        Args:
            finding: Finding to alert on
            context: Additional context

        Returns:
            True if alert was sent successfully
        """
        ...

    @abstractmethod
    def test_connection(self) -> bool:
        """
        Test if destination is reachable.

        Returns:
            True if connection is successful
        """
        ...

    def format_title(self, finding: Finding) -> str:
        """
        Format alert title.

        Args:
            finding: Finding to format

        Returns:
            Formatted title string
        """
        severity_prefix = f"[{finding.severity.value.upper()}]"
        return f"{severity_prefix} {finding.title}"

    def format_description(self, finding: Finding) -> str:
        """
        Format alert description.

        Args:
            finding: Finding to format

        Returns:
            Formatted description string
        """
        parts = [finding.description]

        if finding.rule_id:
            parts.append(f"Rule: {finding.rule_id}")

        if finding.asset_id:
            parts.append(f"Asset: {finding.asset_id}")

        if finding.cve_id:
            parts.append(f"CVE: {finding.cve_id}")
            if finding.cvss_score:
                parts.append(f"CVSS: {finding.cvss_score}")

        if finding.remediation_guidance:
            parts.append(f"Remediation: {finding.remediation_guidance}")

        return "\n".join(parts)

    def get_severity_color(self, severity: Severity) -> str:
        """
        Get color code for severity.

        Args:
            severity: Severity level

        Returns:
            Hex color code
        """
        colors = {
            Severity.CRITICAL: "#FF0000",  # Red
            Severity.HIGH: "#FF6600",  # Orange
            Severity.MEDIUM: "#FFCC00",  # Yellow
            Severity.LOW: "#00CC00",  # Green
            Severity.INFO: "#0066CC",  # Blue
        }
        return colors.get(severity, "#808080")

    def _build_payload(
        self, finding: Finding, context: dict[str, Any]
    ) -> AlertPayload:
        """Build alert payload from finding."""
        return AlertPayload(
            title=self.format_title(finding),
            description=self.format_description(finding),
            severity=finding.severity,
            finding=finding,
            context=context,
        )
