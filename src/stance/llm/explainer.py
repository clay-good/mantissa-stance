"""
Finding explainer for Mantissa Stance.

Provides AI-powered explanations and remediation guidance for security findings.
Uses LLM providers to generate human-readable explanations tailored to the
specific finding context.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from stance.llm.base import LLMProvider, LLMError
from stance.models.finding import Finding, Severity


@dataclass
class FindingExplanation:
    """Result of finding explanation generation."""

    finding_id: str
    summary: str
    risk_explanation: str
    business_impact: str
    remediation_steps: list[str]
    technical_details: str
    references: list[str]
    is_valid: bool
    error: str | None = None


# System prompt for finding explanations
EXPLANATION_SYSTEM_PROMPT = """You are a cloud security expert helping teams understand and remediate security findings.

Your explanations should be:
1. Clear and actionable - avoid jargon when possible
2. Risk-focused - explain WHY this matters, not just WHAT is wrong
3. Prioritized - help teams understand urgency
4. Practical - provide concrete remediation steps

Response format (follow exactly):
SUMMARY: [1-2 sentence summary of the finding]

RISK: [2-3 sentences explaining the security risk]

BUSINESS IMPACT: [1-2 sentences on business/compliance impact]

REMEDIATION STEPS:
1. [First step]
2. [Second step]
3. [Third step]
...

TECHNICAL DETAILS: [Technical explanation for engineers]

REFERENCES:
- [Reference URL or documentation link]
- [Another reference]
"""


class FindingExplainer:
    """
    Generates AI-powered explanations for security findings.

    Uses an LLM provider to create detailed, actionable explanations
    that help security teams understand and remediate findings quickly.
    """

    def __init__(
        self,
        llm_provider: LLMProvider,
        sanitizer: Any | None = None,
    ):
        """
        Initialize the finding explainer.

        Args:
            llm_provider: LLM provider for generating explanations
            sanitizer: Optional DataSanitizer for privacy protection
        """
        self._llm = llm_provider
        self._sanitizer = sanitizer

    def explain_finding(
        self,
        finding: Finding,
        asset_context: dict[str, Any] | None = None,
        include_remediation: bool = True,
    ) -> FindingExplanation:
        """
        Generate a detailed explanation for a security finding.

        Args:
            finding: The finding to explain
            asset_context: Optional additional context about the affected asset
            include_remediation: Whether to include remediation steps

        Returns:
            FindingExplanation with detailed analysis
        """
        # Build the prompt
        prompt = self._build_prompt(finding, asset_context, include_remediation)

        # Sanitize if sanitizer is available
        if self._sanitizer:
            prompt = self._sanitizer.sanitize(prompt)

        try:
            # Generate explanation using LLM
            response = self._llm.generate(
                prompt=prompt,
                system_prompt=EXPLANATION_SYSTEM_PROMPT,
                max_tokens=1500,
            )

            # Parse the response
            return self._parse_response(finding.id, response)

        except LLMError as e:
            return FindingExplanation(
                finding_id=finding.id,
                summary="",
                risk_explanation="",
                business_impact="",
                remediation_steps=[],
                technical_details="",
                references=[],
                is_valid=False,
                error=f"LLM error: {e}",
            )

    def explain_multiple(
        self,
        findings: list[Finding],
        max_findings: int = 10,
    ) -> list[FindingExplanation]:
        """
        Generate explanations for multiple findings.

        Args:
            findings: List of findings to explain
            max_findings: Maximum number of findings to process

        Returns:
            List of FindingExplanation objects
        """
        results = []
        for finding in findings[:max_findings]:
            explanation = self.explain_finding(finding)
            results.append(explanation)
        return results

    def get_summary_for_severity(
        self,
        findings: list[Finding],
        severity: Severity,
    ) -> str:
        """
        Generate a summary of findings for a specific severity level.

        Args:
            findings: List of findings to summarize
            severity: Severity level to focus on

        Returns:
            Summary string
        """
        filtered = [f for f in findings if f.severity == severity]
        if not filtered:
            return f"No {severity.value} findings."

        # Build summary prompt
        prompt = self._build_summary_prompt(filtered, severity)

        try:
            response = self._llm.generate(
                prompt=prompt,
                system_prompt="You are a security analyst. Provide a brief executive summary.",
                max_tokens=500,
            )
            return response.strip()
        except LLMError:
            return f"Found {len(filtered)} {severity.value} findings."

    def _build_prompt(
        self,
        finding: Finding,
        asset_context: dict[str, Any] | None,
        include_remediation: bool,
    ) -> str:
        """
        Build the prompt for finding explanation.

        Args:
            finding: Finding to explain
            asset_context: Optional asset context
            include_remediation: Whether to include remediation

        Returns:
            Formatted prompt string
        """
        prompt_parts = [
            "Explain this security finding:",
            "",
            f"Title: {finding.title}",
            f"Severity: {finding.severity.value}",
            f"Type: {finding.finding_type.value}",
            f"Status: {finding.status.value}",
        ]

        if finding.description:
            prompt_parts.extend(["", f"Description: {finding.description}"])

        if finding.rule_id:
            prompt_parts.append(f"Policy Rule: {finding.rule_id}")

        # CSPM-specific context
        if finding.resource_path:
            prompt_parts.append(f"Resource Path: {finding.resource_path}")
        if finding.expected_value:
            prompt_parts.append(f"Expected: {finding.expected_value}")
        if finding.actual_value:
            prompt_parts.append(f"Actual: {finding.actual_value}")

        # Vulnerability-specific context
        if finding.cve_id:
            prompt_parts.append(f"CVE: {finding.cve_id}")
        if finding.cvss_score is not None:
            prompt_parts.append(f"CVSS Score: {finding.cvss_score}")
        if finding.package_name:
            prompt_parts.append(f"Affected Package: {finding.package_name}")
        if finding.installed_version:
            prompt_parts.append(f"Installed Version: {finding.installed_version}")
        if finding.fixed_version:
            prompt_parts.append(f"Fixed Version: {finding.fixed_version}")

        # Compliance context
        if finding.compliance_frameworks:
            frameworks = ", ".join(finding.compliance_frameworks)
            prompt_parts.append(f"Compliance Frameworks: {frameworks}")

        # Asset context
        if asset_context:
            prompt_parts.extend(["", "Asset Context:"])
            for key, value in asset_context.items():
                # Skip sensitive keys
                if key.lower() not in ("secret", "password", "key", "token"):
                    prompt_parts.append(f"  {key}: {value}")

        # Existing remediation guidance
        if finding.remediation_guidance:
            prompt_parts.extend([
                "",
                "Existing Guidance:",
                finding.remediation_guidance,
            ])

        if include_remediation:
            prompt_parts.extend([
                "",
                "Provide detailed remediation steps.",
            ])
        else:
            prompt_parts.extend([
                "",
                "Focus on explaining the risk. Skip remediation steps.",
            ])

        return "\n".join(prompt_parts)

    def _build_summary_prompt(
        self,
        findings: list[Finding],
        severity: Severity,
    ) -> str:
        """
        Build a summary prompt for multiple findings.

        Args:
            findings: Findings to summarize
            severity: Severity level

        Returns:
            Formatted prompt string
        """
        prompt_parts = [
            f"Summarize these {len(findings)} {severity.value} security findings:",
            "",
        ]

        for i, finding in enumerate(findings[:10], 1):
            prompt_parts.append(f"{i}. {finding.title}")
            if finding.description:
                desc = finding.description[:100]
                if len(finding.description) > 100:
                    desc += "..."
                prompt_parts.append(f"   {desc}")

        if len(findings) > 10:
            prompt_parts.append(f"... and {len(findings) - 10} more")

        prompt_parts.extend([
            "",
            "Provide a brief executive summary (2-3 paragraphs) covering:",
            "1. Overall risk exposure",
            "2. Common patterns or root causes",
            "3. Recommended prioritization",
        ])

        return "\n".join(prompt_parts)

    def _parse_response(
        self,
        finding_id: str,
        response: str,
    ) -> FindingExplanation:
        """
        Parse LLM response into structured FindingExplanation.

        Args:
            finding_id: ID of the finding
            response: Raw LLM response

        Returns:
            Structured FindingExplanation
        """
        # Extract sections using simple pattern matching
        summary = self._extract_section(response, "SUMMARY")
        risk = self._extract_section(response, "RISK")
        impact = self._extract_section(response, "BUSINESS IMPACT")
        tech_details = self._extract_section(response, "TECHNICAL DETAILS")

        # Extract remediation steps
        steps = self._extract_list_section(response, "REMEDIATION STEPS")

        # Extract references
        refs = self._extract_list_section(response, "REFERENCES")

        # Validate we got meaningful content
        is_valid = bool(summary and (risk or tech_details))

        return FindingExplanation(
            finding_id=finding_id,
            summary=summary,
            risk_explanation=risk,
            business_impact=impact,
            remediation_steps=steps,
            technical_details=tech_details,
            references=refs,
            is_valid=is_valid,
            error=None if is_valid else "Failed to parse complete response",
        )

    def _extract_section(self, text: str, section_name: str) -> str:
        """
        Extract a named section from the response.

        Args:
            text: Full response text
            section_name: Name of section to extract

        Returns:
            Extracted section content
        """
        # Pattern: SECTION_NAME: content (until next section or end)
        pattern = rf"{section_name}:\s*(.+?)(?=\n[A-Z][A-Z\s]+:|$)"
        match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return ""

    def _extract_list_section(self, text: str, section_name: str) -> list[str]:
        """
        Extract a list section from the response.

        Args:
            text: Full response text
            section_name: Name of section to extract

        Returns:
            List of items
        """
        section = self._extract_section(text, section_name)
        if not section:
            return []

        items = []
        # Match numbered items (1. item) or bulleted items (- item)
        for line in section.split("\n"):
            line = line.strip()
            # Remove numbering/bullets
            cleaned = re.sub(r"^[\d]+\.\s*", "", line)
            cleaned = re.sub(r"^[-*]\s*", "", cleaned)
            if cleaned:
                items.append(cleaned)

        return items


def create_explainer(
    provider: str = "anthropic",
    enable_sanitization: bool = True,
    **kwargs,
) -> FindingExplainer:
    """
    Create a FindingExplainer with specified configuration.

    Args:
        provider: LLM provider name (anthropic, openai, gemini)
        enable_sanitization: Whether to enable data sanitization
        **kwargs: Additional provider configuration

    Returns:
        Configured FindingExplainer instance
    """
    from stance.llm import get_llm_provider

    llm = get_llm_provider(provider, **kwargs)

    sanitizer = None
    if enable_sanitization:
        try:
            from stance.llm.sanitizer import DataSanitizer
            sanitizer = DataSanitizer()
        except ImportError:
            pass

    return FindingExplainer(llm_provider=llm, sanitizer=sanitizer)
