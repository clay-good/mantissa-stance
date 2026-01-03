"""
Policy generator for Mantissa Stance.

Generates security policies from natural language descriptions using LLM providers.
Creates valid YAML policy files that can be used by the policy engine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from stance.llm.base import LLMProvider, LLMError
from stance.models.finding import Severity


@dataclass
class GeneratedPolicy:
    """Result of policy generation."""

    description: str
    policy_id: str
    policy_name: str
    yaml_content: str
    resource_type: str
    severity: str
    is_valid: bool
    validation_errors: list[str] = field(default_factory=list)
    error: str | None = None


# Available resource types for each cloud provider
RESOURCE_TYPES = {
    "aws": [
        "aws_iam_user",
        "aws_iam_role",
        "aws_iam_policy",
        "aws_iam_group",
        "aws_iam_account_password_policy",
        "aws_iam_account_summary",
        "aws_s3_bucket",
        "aws_ec2_instance",
        "aws_security_group",
        "aws_vpc",
        "aws_subnet",
        "aws_rds_instance",
        "aws_lambda_function",
        "aws_dynamodb_table",
        "aws_kms_key",
        "aws_cloudtrail_trail",
        "aws_sns_topic",
        "aws_sqs_queue",
    ],
    "gcp": [
        "gcp_iam_service_account",
        "gcp_iam_policy",
        "gcp_storage_bucket",
        "gcp_compute_instance",
        "gcp_compute_firewall",
        "gcp_compute_network",
        "gcp_cloudsql_instance",
        "gcp_cloud_function",
        "gcp_pubsub_topic",
        "gcp_kms_key",
    ],
    "azure": [
        "azure_user",
        "azure_service_principal",
        "azure_role_assignment",
        "azure_storage_account",
        "azure_storage_container",
        "azure_vm",
        "azure_network_security_group",
        "azure_virtual_network",
        "azure_sql_database",
        "azure_function_app",
        "azure_key_vault",
    ],
}

# Compliance frameworks that can be referenced
COMPLIANCE_FRAMEWORKS = {
    "cis-aws-foundations": "CIS Amazon Web Services Foundations Benchmark",
    "cis-gcp-foundations": "CIS Google Cloud Platform Foundations Benchmark",
    "cis-azure-foundations": "CIS Microsoft Azure Foundations Benchmark",
    "pci-dss": "Payment Card Industry Data Security Standard",
    "soc2": "SOC 2 Type II",
    "hipaa": "Health Insurance Portability and Accountability Act",
    "nist-800-53": "NIST Special Publication 800-53",
    "aws-foundational-security": "AWS Foundational Security Best Practices",
    "iso-27001": "ISO/IEC 27001 Information Security",
}

# System prompt for policy generation
POLICY_SYSTEM_PROMPT = """You are a cloud security policy expert for Mantissa Stance CSPM.

Generate YAML policies following this exact format:

id: {cloud}-{service}-{number}
name: Short descriptive name
description: |
  Detailed description of what this policy checks and why it matters.
  Include the security rationale.

enabled: true
severity: critical|high|medium|low|info

resource_type: {exact_resource_type}

check:
  type: expression
  expression: "{path.to.field} == expected_value"

compliance:
  - framework: {framework_id}
    version: "{version}"
    control: "{control_id}"

remediation:
  guidance: |
    Step-by-step instructions to fix this issue:
    1. First step
    2. Second step
    3. Third step
  automation_supported: false

tags:
  - relevant
  - tags
  - here

references:
  - https://documentation.url

RULES:
1. Use ONLY expression checks (not SQL)
2. Expression syntax: path.to.field == value, path.to.field != value,
   path.to.field > value, path.to.field >= value, path.to.field < value,
   path.to.field <= value, value in path.to.array, path.to.field exists
3. For boolean checks: use == true or == false
4. For string checks: use == 'string_value'
5. For numeric checks: use == number or >= number etc.
6. Use lowercase for severity values
7. Always set automation_supported: false
8. Generate unique ID based on cloud provider and service
9. Return ONLY the YAML content, no markdown code blocks or explanations
"""


class PolicyGenerator:
    """
    Generates security policies from natural language descriptions.

    Uses an LLM provider to translate natural language requirements
    into valid YAML policy files.
    """

    def __init__(
        self,
        llm_provider: LLMProvider,
        cloud_provider: str = "aws",
    ):
        """
        Initialize the policy generator.

        Args:
            llm_provider: LLM provider for generation
            cloud_provider: Default cloud provider (aws, gcp, azure)
        """
        self._llm = llm_provider
        self._cloud_provider = cloud_provider.lower()

    def generate_policy(
        self,
        description: str,
        severity: str | None = None,
        resource_type: str | None = None,
        compliance_framework: str | None = None,
    ) -> GeneratedPolicy:
        """
        Generate a security policy from natural language description.

        Args:
            description: Natural language description of the policy
            severity: Optional severity hint (critical, high, medium, low, info)
            resource_type: Optional specific resource type
            compliance_framework: Optional compliance framework to reference

        Returns:
            GeneratedPolicy with YAML content and validation results
        """
        # Build the prompt
        prompt = self._build_prompt(
            description, severity, resource_type, compliance_framework
        )

        try:
            # Generate policy using LLM
            yaml_content = self._llm.generate(
                prompt=prompt,
                system_prompt=POLICY_SYSTEM_PROMPT,
                max_tokens=1500,
            )

            # Clean up the response
            yaml_content = self._clean_yaml(yaml_content)

            # Parse and validate the generated policy
            validation_result = self._validate_policy(yaml_content)

            # Extract policy metadata
            policy_id = self._extract_field(yaml_content, "id")
            policy_name = self._extract_field(yaml_content, "name")
            detected_resource_type = self._extract_field(yaml_content, "resource_type")
            detected_severity = self._extract_field(yaml_content, "severity")

            return GeneratedPolicy(
                description=description,
                policy_id=policy_id,
                policy_name=policy_name,
                yaml_content=yaml_content,
                resource_type=detected_resource_type,
                severity=detected_severity,
                is_valid=validation_result["is_valid"],
                validation_errors=validation_result["errors"],
            )

        except LLMError as e:
            return GeneratedPolicy(
                description=description,
                policy_id="",
                policy_name="",
                yaml_content="",
                resource_type="",
                severity="",
                is_valid=False,
                error=f"LLM error: {e}",
            )

    def generate_multiple(
        self,
        descriptions: list[str],
        cloud_provider: str | None = None,
    ) -> list[GeneratedPolicy]:
        """
        Generate multiple policies from a list of descriptions.

        Args:
            descriptions: List of natural language descriptions
            cloud_provider: Optional cloud provider override

        Returns:
            List of GeneratedPolicy objects
        """
        results = []
        for desc in descriptions:
            result = self.generate_policy(desc)
            results.append(result)
        return results

    def suggest_policy_ideas(
        self,
        resource_type: str,
        count: int = 5,
    ) -> list[str]:
        """
        Suggest policy ideas for a given resource type.

        Args:
            resource_type: Cloud resource type
            count: Number of suggestions to generate

        Returns:
            List of policy description suggestions
        """
        prompt = f"""Suggest {count} security policy ideas for {resource_type} resources.

For each policy, provide a one-line description of what to check.
Return ONLY the descriptions, one per line, no numbering or bullets.

Focus on:
- Common security misconfigurations
- Compliance requirements (CIS, PCI-DSS, SOC2)
- Best practices for the resource type
"""

        try:
            response = self._llm.generate(
                prompt=prompt,
                system_prompt="You are a cloud security expert. Provide concise policy suggestions.",
                max_tokens=500,
            )

            # Parse suggestions
            lines = response.strip().split("\n")
            suggestions = [
                line.strip()
                for line in lines
                if line.strip() and not line.strip().startswith(("#", "-", "*"))
            ]
            return suggestions[:count]

        except LLMError:
            return []

    def _build_prompt(
        self,
        description: str,
        severity: str | None,
        resource_type: str | None,
        compliance_framework: str | None,
    ) -> str:
        """
        Build the prompt for policy generation.

        Args:
            description: User's policy description
            severity: Optional severity hint
            resource_type: Optional resource type
            compliance_framework: Optional compliance framework

        Returns:
            Formatted prompt string
        """
        prompt_parts = [
            f"Generate a security policy for this requirement:",
            "",
            f'"{description}"',
            "",
        ]

        # Add context about available resource types
        cloud_resources = RESOURCE_TYPES.get(self._cloud_provider, [])
        prompt_parts.extend([
            f"Cloud Provider: {self._cloud_provider.upper()}",
            f"Available resource types: {', '.join(cloud_resources[:10])}...",
            "",
        ])

        if severity:
            prompt_parts.append(f"Suggested severity: {severity}")

        if resource_type:
            prompt_parts.append(f"Resource type: {resource_type}")

        if compliance_framework:
            framework_name = COMPLIANCE_FRAMEWORKS.get(
                compliance_framework, compliance_framework
            )
            prompt_parts.append(f"Map to compliance framework: {framework_name}")

        prompt_parts.extend([
            "",
            "Generate the complete YAML policy. Return ONLY the YAML, nothing else.",
        ])

        return "\n".join(prompt_parts)

    def _clean_yaml(self, content: str) -> str:
        """
        Clean up LLM-generated YAML.

        Args:
            content: Raw YAML from LLM

        Returns:
            Cleaned YAML string
        """
        # Remove markdown code blocks
        content = re.sub(r"```yaml\s*", "", content)
        content = re.sub(r"```\s*", "", content)

        # Remove any preamble text before the YAML
        lines = content.split("\n")
        yaml_start = 0
        for i, line in enumerate(lines):
            if line.strip().startswith("id:"):
                yaml_start = i
                break

        content = "\n".join(lines[yaml_start:])

        return content.strip()

    def _validate_policy(self, yaml_content: str) -> dict[str, Any]:
        """
        Validate generated policy YAML.

        Args:
            yaml_content: YAML content to validate

        Returns:
            Dictionary with is_valid bool and errors list
        """
        errors: list[str] = []

        if not yaml_content.strip():
            errors.append("Empty policy content")
            return {"is_valid": False, "errors": errors}

        # Check required fields
        required_fields = ["id", "name", "severity", "resource_type", "check"]
        for field in required_fields:
            if f"{field}:" not in yaml_content:
                errors.append(f"Missing required field: {field}")

        # Validate severity value
        severity = self._extract_field(yaml_content, "severity")
        valid_severities = ["critical", "high", "medium", "low", "info"]
        if severity and severity.lower() not in valid_severities:
            errors.append(f"Invalid severity: {severity}")

        # Validate check section
        if "check:" in yaml_content:
            if "type:" not in yaml_content:
                errors.append("Check section missing type field")
            if "expression:" not in yaml_content and "query:" not in yaml_content:
                errors.append("Check section missing expression or query")

        # Validate expression syntax (basic check)
        expression = self._extract_field(yaml_content, "expression")
        if expression:
            # Check for common issues
            if not any(op in expression for op in ["==", "!=", ">", "<", ">=", "<=", " in ", "exists"]):
                errors.append("Expression missing comparison operator")

        # Validate resource_type format (e.g., aws_s3_bucket, aws_iam_account_summary)
        resource_type = self._extract_field(yaml_content, "resource_type")
        if resource_type:
            if not re.match(r"^(aws|gcp|azure)_[a-z0-9_]+$", resource_type):
                errors.append(f"Invalid resource_type format: {resource_type}")

        # Validate ID format (e.g., aws-iam-001, aws-s3-010)
        policy_id = self._extract_field(yaml_content, "id")
        if policy_id:
            if not re.match(r"^(aws|gcp|azure)-[a-z0-9]+-\d+$", policy_id):
                errors.append(f"Invalid policy ID format: {policy_id} (expected: cloud-service-number)")

        return {"is_valid": len(errors) == 0, "errors": errors}

    def _extract_field(self, yaml_content: str, field_name: str) -> str:
        """
        Extract a field value from YAML content.

        Args:
            yaml_content: YAML string
            field_name: Field name to extract

        Returns:
            Field value or empty string
        """
        # Simple regex extraction for single-line values (allows indentation)
        pattern = rf"^\s*{field_name}:\s*(.+?)$"
        match = re.search(pattern, yaml_content, re.MULTILINE)
        if match:
            value = match.group(1).strip()
            # Remove quotes if present
            if (value.startswith('"') and value.endswith('"')) or \
               (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]
            return value
        return ""


def create_policy_generator(
    provider: str = "anthropic",
    cloud_provider: str = "aws",
    **kwargs,
) -> PolicyGenerator:
    """
    Create a PolicyGenerator with specified configuration.

    Args:
        provider: LLM provider name (anthropic, openai, gemini)
        cloud_provider: Cloud provider (aws, gcp, azure)
        **kwargs: Additional provider configuration

    Returns:
        Configured PolicyGenerator instance
    """
    from stance.llm import get_llm_provider

    llm = get_llm_provider(provider, **kwargs)
    return PolicyGenerator(llm_provider=llm, cloud_provider=cloud_provider)


def save_policy(policy: GeneratedPolicy, output_path: str) -> bool:
    """
    Save a generated policy to a YAML file.

    Args:
        policy: Generated policy to save
        output_path: Path to save the file

    Returns:
        True if saved successfully, False otherwise
    """
    if not policy.is_valid:
        return False

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(policy.yaml_content)
            if not policy.yaml_content.endswith("\n"):
                f.write("\n")
        return True
    except OSError:
        return False
