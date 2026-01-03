"""
Alert templates for Mantissa Stance.

Provides templates for formatting security findings
for different destinations and use cases.
"""

from stance.alerting.templates.base import (
    AlertTemplate,
    TemplateContext,
    DefaultTemplate,
    MisconfigurationTemplate,
    VulnerabilityTemplate,
    ComplianceTemplate,
    CriticalExposureTemplate,
    get_template_for_finding,
)

__all__ = [
    "AlertTemplate",
    "TemplateContext",
    "DefaultTemplate",
    "MisconfigurationTemplate",
    "VulnerabilityTemplate",
    "ComplianceTemplate",
    "CriticalExposureTemplate",
    "get_template_for_finding",
]
