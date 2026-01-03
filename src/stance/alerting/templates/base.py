"""
Base alert templates for Mantissa Stance.

Provides abstract template interface and common template utilities.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from stance.models.finding import Finding, Severity, FindingType


@dataclass
class TemplateContext:
    """
    Context for template rendering.

    Attributes:
        finding: The finding to render
        asset_name: Human-readable asset name
        account_name: Cloud account name
        environment: Environment tag (prod, staging, dev)
        custom_data: Additional custom data
    """

    finding: Finding
    asset_name: str = ""
    account_name: str = ""
    environment: str = ""
    custom_data: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.custom_data is None:
            self.custom_data = {}


class AlertTemplate(ABC):
    """
    Abstract base class for alert templates.

    Templates format findings for specific destinations or purposes.
    """

    @abstractmethod
    def format_title(self, context: TemplateContext) -> str:
        """
        Format alert title.

        Args:
            context: Template context

        Returns:
            Formatted title string
        """
        ...

    @abstractmethod
    def format_body(self, context: TemplateContext) -> str:
        """
        Format alert body.

        Args:
            context: Template context

        Returns:
            Formatted body string
        """
        ...

    def format_severity(self, severity: Severity) -> str:
        """
        Format severity for display.

        Args:
            severity: Severity level

        Returns:
            Formatted severity string
        """
        return severity.value.upper()

    def get_severity_indicator(self, severity: Severity) -> str:
        """
        Get severity indicator symbol.

        Args:
            severity: Severity level

        Returns:
            Indicator string
        """
        indicators = {
            Severity.CRITICAL: "[!!!]",
            Severity.HIGH: "[!!]",
            Severity.MEDIUM: "[!]",
            Severity.LOW: "[*]",
            Severity.INFO: "[i]",
        }
        return indicators.get(severity, "[?]")


class DefaultTemplate(AlertTemplate):
    """Default plain text alert template."""

    def format_title(self, context: TemplateContext) -> str:
        """Format title with severity indicator."""
        indicator = self.get_severity_indicator(context.finding.severity)
        return f"{indicator} {context.finding.title}"

    def format_body(self, context: TemplateContext) -> str:
        """Format body as plain text."""
        finding = context.finding
        lines = [
            f"Severity: {self.format_severity(finding.severity)}",
            f"Type: {finding.finding_type.value}",
            f"Status: {finding.status.value}",
            "",
            "Description:",
            finding.description,
        ]

        if context.asset_name or finding.asset_id:
            lines.extend(["", f"Asset: {context.asset_name or finding.asset_id}"])

        if context.account_name:
            lines.append(f"Account: {context.account_name}")

        if context.environment:
            lines.append(f"Environment: {context.environment}")

        if finding.rule_id:
            lines.extend(["", f"Rule: {finding.rule_id}"])

        if finding.cve_id:
            lines.extend(["", f"CVE: {finding.cve_id}"])
            if finding.cvss_score:
                lines.append(f"CVSS Score: {finding.cvss_score}")

        if finding.remediation_guidance:
            lines.extend(["", "Remediation:", finding.remediation_guidance])

        if finding.compliance_frameworks:
            lines.extend([
                "",
                "Compliance Frameworks:",
                ", ".join(finding.compliance_frameworks)
            ])

        lines.extend(["", "---", f"Finding ID: {finding.id}"])

        return "\n".join(lines)


class MisconfigurationTemplate(AlertTemplate):
    """Template optimized for misconfiguration findings."""

    def format_title(self, context: TemplateContext) -> str:
        """Format title emphasizing the misconfiguration."""
        indicator = self.get_severity_indicator(context.finding.severity)
        return f"{indicator} Misconfiguration: {context.finding.title}"

    def format_body(self, context: TemplateContext) -> str:
        """Format body with misconfiguration details."""
        finding = context.finding
        lines = [
            f"Severity: {self.format_severity(finding.severity)}",
            "",
            "What was found:",
            finding.description,
        ]

        if finding.resource_path:
            lines.extend([
                "",
                "Configuration Issue:",
                f"  Path: {finding.resource_path}",
            ])
            if finding.expected_value:
                lines.append(f"  Expected: {finding.expected_value}")
            if finding.actual_value:
                lines.append(f"  Actual: {finding.actual_value}")

        if context.asset_name or finding.asset_id:
            lines.extend([
                "",
                "Affected Resource:",
                f"  {context.asset_name or finding.asset_id}",
            ])

        if finding.rule_id:
            lines.append(f"  Policy Rule: {finding.rule_id}")

        if finding.remediation_guidance:
            lines.extend([
                "",
                "How to fix:",
                finding.remediation_guidance,
            ])

        if finding.compliance_frameworks:
            lines.extend([
                "",
                "Compliance Impact:",
                f"  Affects: {', '.join(finding.compliance_frameworks)}"
            ])

        return "\n".join(lines)


class VulnerabilityTemplate(AlertTemplate):
    """Template optimized for vulnerability findings."""

    def format_title(self, context: TemplateContext) -> str:
        """Format title with CVE if available."""
        indicator = self.get_severity_indicator(context.finding.severity)
        finding = context.finding

        if finding.cve_id:
            return f"{indicator} {finding.cve_id}: {finding.title}"
        return f"{indicator} Vulnerability: {finding.title}"

    def format_body(self, context: TemplateContext) -> str:
        """Format body with vulnerability details."""
        finding = context.finding
        lines = [
            f"Severity: {self.format_severity(finding.severity)}",
        ]

        if finding.cve_id:
            lines.append(f"CVE: {finding.cve_id}")
        if finding.cvss_score:
            lines.append(f"CVSS Score: {finding.cvss_score}")

        lines.extend(["", "Description:", finding.description])

        if finding.package_name:
            lines.extend([
                "",
                "Affected Package:",
                f"  Name: {finding.package_name}",
            ])
            if finding.installed_version:
                lines.append(f"  Installed: {finding.installed_version}")
            if finding.fixed_version:
                lines.append(f"  Fixed in: {finding.fixed_version}")

        if context.asset_name or finding.asset_id:
            lines.extend([
                "",
                "Affected System:",
                f"  {context.asset_name or finding.asset_id}",
            ])

        if finding.has_fix_available():
            lines.extend([
                "",
                "Remediation:",
                f"  Upgrade to version {finding.fixed_version}",
            ])
        elif finding.remediation_guidance:
            lines.extend([
                "",
                "Remediation:",
                finding.remediation_guidance,
            ])
        else:
            lines.extend([
                "",
                "Note: No fix is currently available. Consider compensating controls.",
            ])

        return "\n".join(lines)


class ComplianceTemplate(AlertTemplate):
    """Template for compliance-focused alerts."""

    def format_title(self, context: TemplateContext) -> str:
        """Format title with compliance focus."""
        indicator = self.get_severity_indicator(context.finding.severity)
        finding = context.finding

        if finding.compliance_frameworks:
            frameworks = ", ".join(finding.compliance_frameworks[:2])
            return f"{indicator} Compliance Violation ({frameworks}): {finding.title}"
        return f"{indicator} Compliance Issue: {finding.title}"

    def format_body(self, context: TemplateContext) -> str:
        """Format body with compliance details."""
        finding = context.finding
        lines = [
            f"Severity: {self.format_severity(finding.severity)}",
            f"Type: {finding.finding_type.value}",
        ]

        if finding.compliance_frameworks:
            lines.extend([
                "",
                "Compliance Impact:",
            ])
            for framework in finding.compliance_frameworks:
                lines.append(f"  - {framework}")

        lines.extend(["", "Issue Description:", finding.description])

        if context.asset_name or finding.asset_id:
            lines.extend([
                "",
                "Affected Resource:",
                f"  {context.asset_name or finding.asset_id}",
            ])

        if finding.rule_id:
            lines.append(f"  Policy: {finding.rule_id}")

        if finding.remediation_guidance:
            lines.extend([
                "",
                "Required Action:",
                finding.remediation_guidance,
            ])

        lines.extend([
            "",
            "Note: This finding may impact compliance audits.",
            "Please remediate promptly to maintain compliance status.",
        ])

        return "\n".join(lines)


class CriticalExposureTemplate(AlertTemplate):
    """Template for critical exposure alerts requiring immediate action."""

    def format_title(self, context: TemplateContext) -> str:
        """Format title with urgency."""
        return f"[CRITICAL] IMMEDIATE ACTION REQUIRED: {context.finding.title}"

    def format_body(self, context: TemplateContext) -> str:
        """Format body with urgency and clear action items."""
        finding = context.finding
        lines = [
            "=" * 60,
            "CRITICAL SECURITY EXPOSURE DETECTED",
            "=" * 60,
            "",
            "This finding requires immediate attention.",
            "",
            "Summary:",
            finding.description,
            "",
        ]

        if context.asset_name or finding.asset_id:
            lines.extend([
                "Affected Resource:",
                f"  {context.asset_name or finding.asset_id}",
                "",
            ])

        lines.extend([
            "Risk:",
            "  - This resource may be publicly exposed",
            "  - Potential for data breach or unauthorized access",
            "  - Immediate remediation recommended",
            "",
        ])

        if finding.remediation_guidance:
            lines.extend([
                "IMMEDIATE ACTION REQUIRED:",
                finding.remediation_guidance,
                "",
            ])

        lines.extend([
            "Escalation:",
            "  - Security team has been notified",
            "  - Please respond within 1 hour",
            "  - Contact security@company.com for assistance",
            "",
            "=" * 60,
            f"Finding ID: {finding.id}",
        ])

        return "\n".join(lines)


def get_template_for_finding(finding: Finding) -> AlertTemplate:
    """
    Get appropriate template based on finding type and severity.

    Args:
        finding: Finding to get template for

    Returns:
        Appropriate AlertTemplate instance
    """
    # Critical severity always gets critical template
    if finding.severity == Severity.CRITICAL:
        return CriticalExposureTemplate()

    # Choose based on finding type
    if finding.finding_type == FindingType.VULNERABILITY:
        return VulnerabilityTemplate()

    # Choose based on compliance impact
    if finding.compliance_frameworks:
        return ComplianceTemplate()

    # Default to misconfiguration template
    if finding.finding_type == FindingType.MISCONFIGURATION:
        return MisconfigurationTemplate()

    return DefaultTemplate()
