"""
IaC security policies for Mantissa Stance.

Provides policy definitions and evaluation for Infrastructure as Code
security scanning. Supports Terraform, CloudFormation, and other IaC formats.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from stance.iac.base import (
    IaCFile,
    IaCFinding,
    IaCFormat,
    IaCResource,
)
from stance.models import Severity

logger = logging.getLogger(__name__)


@dataclass
class IaCPolicyCheck:
    """
    Check definition for an IaC policy.

    Attributes:
        check_type: Type of check (attribute, pattern, exists, custom)
        path: Dot-notation path to the attribute to check
        operator: Comparison operator
        value: Expected value for comparison
        pattern: Regex pattern for pattern checks
        message: Custom message template for findings
    """

    check_type: str  # attribute, pattern, exists, not_exists, any_of, all_of
    path: str = ""
    operator: str = ""  # eq, ne, gt, lt, gte, lte, in, not_in, contains, matches
    value: Any = None
    pattern: str = ""
    message: str = ""
    checks: list["IaCPolicyCheck"] = field(default_factory=list)  # For any_of, all_of


@dataclass
class IaCPolicyCompliance:
    """Compliance framework mapping for a policy."""

    framework: str
    version: str
    control: str


@dataclass
class IaCPolicy:
    """
    Security policy for IaC resources.

    Attributes:
        id: Unique policy identifier
        name: Human-readable policy name
        description: Detailed description of the security issue
        enabled: Whether the policy is active
        severity: Severity level of findings
        resource_types: List of resource types this policy applies to
        providers: List of cloud providers (aws, gcp, azure)
        formats: List of IaC formats (terraform, cloudformation, arm)
        check: Check definition
        remediation: Remediation guidance
        compliance: Compliance framework mappings
        tags: Policy tags for categorization
        references: External reference URLs
    """

    id: str
    name: str
    description: str
    enabled: bool
    severity: Severity
    resource_types: list[str]
    check: IaCPolicyCheck
    providers: list[str] = field(default_factory=list)
    formats: list[str] = field(default_factory=list)
    remediation: str = ""
    compliance: list[IaCPolicyCompliance] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def matches_resource(self, resource: IaCResource) -> bool:
        """Check if this policy applies to a resource."""
        # Check resource type
        if self.resource_types and resource.resource_type not in self.resource_types:
            # Also check wildcards
            matches_wildcard = any(
                self._matches_wildcard(resource.resource_type, rt)
                for rt in self.resource_types
            )
            if not matches_wildcard:
                return False

        # Check provider
        if self.providers and resource.provider not in self.providers:
            return False

        return True

    def _matches_wildcard(self, resource_type: str, pattern: str) -> bool:
        """Check if resource type matches a wildcard pattern."""
        if "*" not in pattern:
            return resource_type == pattern

        # Convert pattern to regex
        regex_pattern = pattern.replace("*", ".*")
        return bool(re.match(f"^{regex_pattern}$", resource_type))


@dataclass
class IaCPolicyCollection:
    """Collection of IaC policies."""

    policies: list[IaCPolicy] = field(default_factory=list)

    def __iter__(self) -> Iterator[IaCPolicy]:
        """Iterate over policies."""
        return iter(self.policies)

    def __len__(self) -> int:
        """Return number of policies."""
        return len(self.policies)

    def add(self, policy: IaCPolicy) -> None:
        """Add a policy to the collection."""
        self.policies.append(policy)

    def filter_enabled(self) -> "IaCPolicyCollection":
        """Return only enabled policies."""
        return IaCPolicyCollection(
            policies=[p for p in self.policies if p.enabled]
        )

    def filter_by_severity(self, severity: Severity) -> "IaCPolicyCollection":
        """Filter policies by severity."""
        return IaCPolicyCollection(
            policies=[p for p in self.policies if p.severity == severity]
        )

    def filter_by_provider(self, provider: str) -> "IaCPolicyCollection":
        """Filter policies by cloud provider."""
        return IaCPolicyCollection(
            policies=[
                p for p in self.policies
                if not p.providers or provider in p.providers
            ]
        )

    def filter_by_resource_type(self, resource_type: str) -> "IaCPolicyCollection":
        """Filter policies that apply to a resource type."""
        return IaCPolicyCollection(
            policies=[
                p for p in self.policies
                if not p.resource_types or
                resource_type in p.resource_types or
                any(p._matches_wildcard(resource_type, rt) for rt in p.resource_types)
            ]
        )

    def get_by_id(self, policy_id: str) -> IaCPolicy | None:
        """Get a policy by ID."""
        for policy in self.policies:
            if policy.id == policy_id:
                return policy
        return None


class IaCPolicyLoader:
    """
    Loads IaC policies from YAML files.

    Searches for policies in specified directories and loads them
    into IaCPolicy objects.
    """

    def __init__(self, policy_dirs: list[str | Path] | None = None) -> None:
        """
        Initialize the policy loader.

        Args:
            policy_dirs: Directories to search for policies
        """
        self._policy_dirs = [Path(d) for d in (policy_dirs or [])]
        if not self._policy_dirs:
            # Default policy directories
            self._policy_dirs = [
                Path("policies/iac"),
                Path("policies/terraform"),
            ]

    def load_all(self) -> IaCPolicyCollection:
        """
        Load all policies from configured directories.

        Returns:
            IaCPolicyCollection with all loaded policies
        """
        collection = IaCPolicyCollection()

        for policy_dir in self._policy_dirs:
            if not policy_dir.exists():
                continue

            for yaml_file in policy_dir.glob("**/*.yaml"):
                try:
                    policy = self.load_policy(yaml_file)
                    if policy:
                        collection.add(policy)
                except Exception as e:
                    logger.warning(f"Failed to load policy from {yaml_file}: {e}")

            for yml_file in policy_dir.glob("**/*.yml"):
                try:
                    policy = self.load_policy(yml_file)
                    if policy:
                        collection.add(policy)
                except Exception as e:
                    logger.warning(f"Failed to load policy from {yml_file}: {e}")

        return collection

    def load_policy(self, file_path: Path) -> IaCPolicy | None:
        """
        Load a single policy from a YAML file.

        Args:
            file_path: Path to the YAML file

        Returns:
            IaCPolicy object or None if loading fails
        """
        try:
            content = file_path.read_text(encoding="utf-8")
            data = self._parse_yaml(content)
            return self._dict_to_policy(data)
        except Exception as e:
            logger.warning(f"Failed to parse policy {file_path}: {e}")
            return None

    def load_from_string(self, content: str) -> IaCPolicy | None:
        """
        Load a policy from YAML string content.

        Args:
            content: YAML content

        Returns:
            IaCPolicy object or None if loading fails
        """
        try:
            data = self._parse_yaml(content)
            return self._dict_to_policy(data)
        except Exception as e:
            logger.warning(f"Failed to parse policy from string: {e}")
            return None

    def _parse_yaml(self, content: str) -> dict[str, Any]:
        """Parse YAML content into a dictionary."""
        try:
            import yaml
            return yaml.safe_load(content) or {}
        except ImportError:
            # Fallback to simple YAML parser
            return self._simple_yaml_parse(content)

    def _simple_yaml_parse(self, content: str) -> dict[str, Any]:
        """Simple YAML parser for basic structures."""
        # Use the CloudFormation YAML parser which handles more cases
        try:
            from stance.iac.cloudformation import SimpleYAMLParser
            parser = SimpleYAMLParser(content)
            result = parser.parse()
            # Handle the _value wrapper for non-dict results
            if "_value" in result and len(result) == 1:
                return {}
            return result
        except Exception:
            pass

        # Fallback to basic parsing
        result: dict[str, Any] = {}
        current_key = ""
        in_multiline = False
        in_list = False
        list_items: list[Any] = []
        multiline_value: list[str] = []
        base_indent = 0

        lines = content.split("\n")
        i = 0

        while i < len(lines):
            line = lines[i]
            stripped = line.strip()
            indent = len(line) - len(line.lstrip())

            # Skip empty lines and comments
            if not stripped or stripped.startswith("#"):
                i += 1
                continue

            # Check for list continuation
            if in_list:
                if stripped.startswith("- "):
                    list_items.append(self._parse_value(stripped[2:].strip()))
                    i += 1
                    continue
                else:
                    # End of list
                    result[current_key] = list_items
                    in_list = False
                    list_items = []
                    # Don't increment i, reprocess this line

            # Check for multiline string start
            if in_multiline:
                if indent <= base_indent and stripped:
                    # End of multiline
                    result[current_key] = "\n".join(multiline_value)
                    in_multiline = False
                    # Don't increment i, reprocess this line
                    continue
                else:
                    multiline_value.append(line.strip())
                    i += 1
                    continue

            # Parse key-value
            if ":" in stripped and not stripped.startswith("-"):
                colon_pos = stripped.index(":")
                key = stripped[:colon_pos].strip()
                value = stripped[colon_pos + 1:].strip()
                base_indent = indent

                if value == "|":
                    # Start multiline string
                    in_multiline = True
                    current_key = key
                    multiline_value = []
                elif value.startswith("[") and value.endswith("]"):
                    # Inline list
                    items = value[1:-1].split(",")
                    result[key] = [item.strip().strip("'\"") for item in items if item.strip()]
                elif value:
                    # Simple value
                    result[key] = self._parse_value(value)
                else:
                    # Check if next line is a list or nested structure
                    if i + 1 < len(lines):
                        next_line = lines[i + 1].strip()
                        if next_line.startswith("- "):
                            # Start of list
                            in_list = True
                            current_key = key
                            list_items = []
                        elif next_line.startswith("-"):
                            # List item on its own line
                            in_list = True
                            current_key = key
                            list_items = []
                        else:
                            result[key] = {}
                    else:
                        result[key] = {}

            i += 1

        if in_multiline and multiline_value:
            result[current_key] = "\n".join(multiline_value)
        if in_list and list_items:
            result[current_key] = list_items

        return result

    def _parse_value(self, value: str) -> Any:
        """Parse a YAML value."""
        value = value.strip()

        # Remove quotes
        if (value.startswith('"') and value.endswith('"')) or \
           (value.startswith("'") and value.endswith("'")):
            return value[1:-1]

        # Boolean
        if value.lower() == "true":
            return True
        if value.lower() == "false":
            return False

        # Null
        if value.lower() in ("null", "~"):
            return None

        # Number
        try:
            if "." in value:
                return float(value)
            return int(value)
        except ValueError:
            pass

        return value

    def _dict_to_policy(self, data: dict[str, Any]) -> IaCPolicy:
        """Convert a dictionary to an IaCPolicy object."""
        # Parse severity
        severity_str = data.get("severity", "medium").lower()
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        severity = severity_map.get(severity_str, Severity.MEDIUM)

        # Parse check
        check_data = data.get("check", {})
        check = self._parse_check(check_data)

        # Parse compliance
        compliance = []
        for comp_data in data.get("compliance", []):
            if isinstance(comp_data, dict):
                compliance.append(IaCPolicyCompliance(
                    framework=comp_data.get("framework", ""),
                    version=comp_data.get("version", ""),
                    control=comp_data.get("control", ""),
                ))

        # Parse resource types
        resource_types = data.get("resource_types", [])
        if isinstance(resource_types, str):
            resource_types = [resource_types]

        # Handle single resource_type field
        if not resource_types and "resource_type" in data:
            rt = data["resource_type"]
            resource_types = [rt] if isinstance(rt, str) else rt

        # Parse providers
        providers = data.get("providers", [])
        if isinstance(providers, str):
            providers = [providers]

        # Parse formats
        formats = data.get("formats", [])
        if isinstance(formats, str):
            formats = [formats]

        # Parse tags
        tags = data.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]

        # Parse references
        references = data.get("references", [])
        if isinstance(references, str):
            references = [references]

        # Parse remediation
        remediation = data.get("remediation", "")
        if isinstance(remediation, dict):
            remediation = remediation.get("guidance", "")

        return IaCPolicy(
            id=data.get("id", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            enabled=data.get("enabled", True),
            severity=severity,
            resource_types=resource_types,
            check=check,
            providers=providers,
            formats=formats,
            remediation=remediation,
            compliance=compliance,
            tags=tags,
            references=references,
        )

    def _parse_check(self, data: dict[str, Any] | str) -> IaCPolicyCheck:
        """Parse a check definition."""
        if isinstance(data, str):
            # Simple expression check
            return IaCPolicyCheck(
                check_type="expression",
                path=data,
            )

        check_type = data.get("type", "attribute")

        # Parse nested checks for any_of and all_of
        nested_checks = []
        if "checks" in data:
            for check_data in data["checks"]:
                nested_checks.append(self._parse_check(check_data))

        return IaCPolicyCheck(
            check_type=check_type,
            path=data.get("path", data.get("attribute", "")),
            operator=data.get("operator", data.get("op", "")),
            value=data.get("value"),
            pattern=data.get("pattern", ""),
            message=data.get("message", ""),
            checks=nested_checks,
        )


class IaCPolicyEvaluator:
    """
    Evaluates IaC policies against parsed resources.

    Generates findings for resources that violate policy rules.
    """

    def __init__(self, policies: IaCPolicyCollection | None = None) -> None:
        """
        Initialize the policy evaluator.

        Args:
            policies: Collection of policies to evaluate
        """
        self._policies = policies or IaCPolicyCollection()

    def set_policies(self, policies: IaCPolicyCollection) -> None:
        """Set the policy collection."""
        self._policies = policies

    def evaluate_file(self, iac_file: IaCFile) -> list[IaCFinding]:
        """
        Evaluate all policies against resources in an IaC file.

        Args:
            iac_file: Parsed IaC file

        Returns:
            List of findings for policy violations
        """
        findings: list[IaCFinding] = []

        enabled_policies = self._policies.filter_enabled()

        for resource in iac_file.resources:
            for policy in enabled_policies:
                if policy.matches_resource(resource):
                    finding = self._evaluate_resource(policy, resource)
                    if finding:
                        findings.append(finding)

        return findings

    def evaluate_resource(
        self,
        resource: IaCResource,
        policies: IaCPolicyCollection | None = None,
    ) -> list[IaCFinding]:
        """
        Evaluate policies against a single resource.

        Args:
            resource: Resource to evaluate
            policies: Optional policy collection (uses default if None)

        Returns:
            List of findings for policy violations
        """
        findings: list[IaCFinding] = []
        policy_collection = policies or self._policies

        for policy in policy_collection.filter_enabled():
            if policy.matches_resource(resource):
                finding = self._evaluate_resource(policy, resource)
                if finding:
                    findings.append(finding)

        return findings

    def _evaluate_resource(
        self,
        policy: IaCPolicy,
        resource: IaCResource,
    ) -> IaCFinding | None:
        """
        Evaluate a single policy against a resource.

        Returns finding if policy is violated, None if compliant.
        """
        check = policy.check

        try:
            is_compliant = self._evaluate_check(check, resource)

            if not is_compliant:
                return self._create_finding(policy, resource, check)

        except Exception as e:
            logger.debug(f"Error evaluating policy {policy.id} on {resource.full_address}: {e}")
            # Errors during evaluation don't generate findings

        return None

    def _evaluate_check(self, check: IaCPolicyCheck, resource: IaCResource) -> bool:
        """
        Evaluate a check against a resource.

        Returns True if compliant, False if violated.
        """
        check_type = check.check_type.lower()

        if check_type == "attribute":
            return self._check_attribute(check, resource)
        elif check_type == "exists":
            return self._check_exists(check, resource)
        elif check_type == "not_exists":
            return not self._check_exists(check, resource)
        elif check_type == "pattern":
            return self._check_pattern(check, resource)
        elif check_type == "any_of":
            return any(self._evaluate_check(c, resource) for c in check.checks)
        elif check_type == "all_of":
            return all(self._evaluate_check(c, resource) for c in check.checks)
        elif check_type == "expression":
            return self._check_expression(check, resource)
        else:
            logger.warning(f"Unknown check type: {check_type}")
            return True  # Unknown checks pass by default

    def _check_attribute(self, check: IaCPolicyCheck, resource: IaCResource) -> bool:
        """Check an attribute value against expected value."""
        actual = resource.get_config_value(check.path)
        expected = check.value
        operator = check.operator.lower() if check.operator else "eq"

        if actual is None and operator not in ("exists", "not_exists", "ne"):
            # Missing attribute fails most checks
            return False

        if operator in ("eq", "==", "equals"):
            return actual == expected
        elif operator in ("ne", "!=", "not_equals"):
            return actual != expected
        elif operator in ("gt", ">"):
            return actual is not None and actual > expected
        elif operator in ("lt", "<"):
            return actual is not None and actual < expected
        elif operator in ("gte", ">="):
            return actual is not None and actual >= expected
        elif operator in ("lte", "<="):
            return actual is not None and actual <= expected
        elif operator == "in":
            if isinstance(expected, list):
                return actual in expected
            return False
        elif operator == "not_in":
            if isinstance(expected, list):
                return actual not in expected
            return True
        elif operator == "contains":
            if isinstance(actual, (list, str)):
                return expected in actual
            return False
        elif operator == "not_contains":
            if isinstance(actual, (list, str)):
                return expected not in actual
            return True
        elif operator == "matches":
            if isinstance(actual, str):
                return bool(re.match(check.pattern or str(expected), actual))
            return False
        elif operator == "starts_with":
            return isinstance(actual, str) and actual.startswith(str(expected))
        elif operator == "ends_with":
            return isinstance(actual, str) and actual.endswith(str(expected))
        else:
            logger.warning(f"Unknown operator: {operator}")
            return True

    def _check_exists(self, check: IaCPolicyCheck, resource: IaCResource) -> bool:
        """Check if an attribute exists."""
        return resource.has_config(check.path)

    def _check_pattern(self, check: IaCPolicyCheck, resource: IaCResource) -> bool:
        """Check if an attribute matches a pattern."""
        actual = resource.get_config_value(check.path)
        if actual is None:
            return False

        if not isinstance(actual, str):
            actual = str(actual)

        pattern = check.pattern
        if not pattern:
            return True

        return bool(re.match(pattern, actual))

    def _check_expression(self, check: IaCPolicyCheck, resource: IaCResource) -> bool:
        """
        Evaluate a boolean expression against resource config.

        Supports simple expressions like:
        - resource.encryption.enabled == true
        - resource.public == false
        """
        expression = check.path
        if not expression:
            return True

        # Simple expression parser for common patterns
        # Format: resource.path.to.value == expected
        expression = expression.strip()

        # Handle common operators
        for op in ["==", "!=", ">=", "<=", ">", "<"]:
            if op in expression:
                parts = expression.split(op, 1)
                if len(parts) == 2:
                    path_part = parts[0].strip()
                    value_part = parts[1].strip()

                    # Remove 'resource.' prefix if present
                    if path_part.startswith("resource."):
                        path_part = path_part[9:]

                    actual = resource.get_config_value(path_part)
                    expected = self._parse_expression_value(value_part)

                    if op == "==":
                        return actual == expected
                    elif op == "!=":
                        return actual != expected
                    elif op == ">=":
                        return actual is not None and actual >= expected
                    elif op == "<=":
                        return actual is not None and actual <= expected
                    elif op == ">":
                        return actual is not None and actual > expected
                    elif op == "<":
                        return actual is not None and actual < expected

        # Check for simple existence (just a path)
        if expression.startswith("resource."):
            path = expression[9:]
            return resource.has_config(path)

        return True

    def _parse_expression_value(self, value: str) -> Any:
        """Parse a value from an expression."""
        value = value.strip()

        if value.lower() == "true":
            return True
        elif value.lower() == "false":
            return False
        elif value.lower() == "null" or value.lower() == "none":
            return None

        # Remove quotes
        if (value.startswith('"') and value.endswith('"')) or \
           (value.startswith("'") and value.endswith("'")):
            return value[1:-1]

        # Try number
        try:
            if "." in value:
                return float(value)
            return int(value)
        except ValueError:
            pass

        return value

    def _create_finding(
        self,
        policy: IaCPolicy,
        resource: IaCResource,
        check: IaCPolicyCheck,
    ) -> IaCFinding:
        """Create a finding for a policy violation."""
        # Get actual value for the finding
        actual_value = None
        expected_value = None

        if check.path:
            actual_value = str(resource.get_config_value(check.path))

        if check.value is not None:
            expected_value = str(check.value)
        elif check.check_type == "exists":
            expected_value = "attribute should exist"
            actual_value = "attribute missing"
        elif check.check_type == "not_exists":
            expected_value = "attribute should not exist"
            actual_value = "attribute exists"

        # Generate message
        message = check.message or policy.description

        return IaCFinding(
            rule_id=policy.id,
            resource=resource,
            severity=policy.severity,
            title=policy.name,
            description=message,
            remediation=policy.remediation,
            expected_value=expected_value,
            actual_value=actual_value,
        )


# Default IaC policies (built-in)
DEFAULT_IAC_POLICIES: list[dict[str, Any]] = [
    # AWS S3 Policies
    {
        "id": "iac-aws-s3-encryption",
        "name": "S3 bucket encryption not configured",
        "description": "S3 buckets should have server-side encryption enabled to protect data at rest.",
        "enabled": True,
        "severity": "high",
        "resource_types": ["aws_s3_bucket"],
        "providers": ["aws"],
        "check": {
            "type": "any_of",
            "checks": [
                {"type": "exists", "path": "server_side_encryption_configuration"},
                {"type": "exists", "path": "encryption"},
            ],
        },
        "remediation": "Add a server_side_encryption_configuration block with SSE-S3 or SSE-KMS.",
        "compliance": [
            {"framework": "CIS AWS", "version": "1.5.0", "control": "2.1.1"},
        ],
        "tags": ["s3", "encryption", "data-protection"],
    },
    {
        "id": "iac-aws-s3-public-access",
        "name": "S3 bucket allows public access",
        "description": "S3 buckets should block public access to prevent data exposure.",
        "enabled": True,
        "severity": "critical",
        "resource_types": ["aws_s3_bucket_public_access_block"],
        "providers": ["aws"],
        "check": {
            "type": "all_of",
            "checks": [
                {"type": "attribute", "path": "block_public_acls", "operator": "eq", "value": True},
                {"type": "attribute", "path": "block_public_policy", "operator": "eq", "value": True},
                {"type": "attribute", "path": "ignore_public_acls", "operator": "eq", "value": True},
                {"type": "attribute", "path": "restrict_public_buckets", "operator": "eq", "value": True},
            ],
        },
        "remediation": "Set all public access block settings to true.",
        "tags": ["s3", "public-access", "data-protection"],
    },
    {
        "id": "iac-aws-s3-versioning",
        "name": "S3 bucket versioning not enabled",
        "description": "S3 buckets should have versioning enabled to protect against accidental deletion.",
        "enabled": True,
        "severity": "medium",
        "resource_types": ["aws_s3_bucket_versioning"],
        "providers": ["aws"],
        "check": {
            "type": "attribute",
            "path": "versioning_configuration.status",
            "operator": "eq",
            "value": "Enabled",
        },
        "remediation": "Enable versioning on the S3 bucket.",
        "tags": ["s3", "versioning", "data-protection"],
    },
    {
        "id": "iac-aws-s3-logging",
        "name": "S3 bucket logging not enabled",
        "description": "S3 buckets should have access logging enabled for audit purposes.",
        "enabled": True,
        "severity": "low",
        "resource_types": ["aws_s3_bucket_logging"],
        "providers": ["aws"],
        "check": {
            "type": "exists",
            "path": "target_bucket",
        },
        "remediation": "Configure access logging with a target bucket.",
        "tags": ["s3", "logging", "audit"],
    },
    # AWS Security Group Policies
    {
        "id": "iac-aws-sg-ssh-open",
        "name": "Security group allows SSH from 0.0.0.0/0",
        "description": "Security groups should not allow unrestricted SSH access from the internet.",
        "enabled": True,
        "severity": "high",
        "resource_types": ["aws_security_group", "aws_security_group_rule"],
        "providers": ["aws"],
        "check": {
            "type": "all_of",
            "checks": [
                {
                    "type": "any_of",
                    "checks": [
                        {"type": "attribute", "path": "ingress.from_port", "operator": "ne", "value": 22},
                        {"type": "attribute", "path": "from_port", "operator": "ne", "value": 22},
                    ],
                },
            ],
        },
        "remediation": "Restrict SSH access to specific IP ranges or use a bastion host.",
        "tags": ["security-group", "ssh", "network"],
    },
    {
        "id": "iac-aws-sg-rdp-open",
        "name": "Security group allows RDP from 0.0.0.0/0",
        "description": "Security groups should not allow unrestricted RDP access from the internet.",
        "enabled": True,
        "severity": "high",
        "resource_types": ["aws_security_group", "aws_security_group_rule"],
        "providers": ["aws"],
        "check": {
            "type": "all_of",
            "checks": [
                {
                    "type": "any_of",
                    "checks": [
                        {"type": "attribute", "path": "ingress.from_port", "operator": "ne", "value": 3389},
                        {"type": "attribute", "path": "from_port", "operator": "ne", "value": 3389},
                    ],
                },
            ],
        },
        "remediation": "Restrict RDP access to specific IP ranges or use a VPN.",
        "tags": ["security-group", "rdp", "network"],
    },
    # AWS EC2 Policies
    {
        "id": "iac-aws-ec2-imdsv2",
        "name": "EC2 instance not requiring IMDSv2",
        "description": "EC2 instances should require IMDSv2 to protect against SSRF attacks.",
        "enabled": True,
        "severity": "medium",
        "resource_types": ["aws_instance", "aws_launch_template"],
        "providers": ["aws"],
        "check": {
            "type": "attribute",
            "path": "metadata_options.http_tokens",
            "operator": "eq",
            "value": "required",
        },
        "remediation": "Set metadata_options.http_tokens to 'required' to enforce IMDSv2.",
        "tags": ["ec2", "imds", "ssrf"],
    },
    {
        "id": "iac-aws-ec2-ebs-encryption",
        "name": "EC2 instance EBS volume not encrypted",
        "description": "EBS volumes should be encrypted to protect data at rest.",
        "enabled": True,
        "severity": "medium",
        "resource_types": ["aws_ebs_volume", "aws_instance"],
        "providers": ["aws"],
        "check": {
            "type": "attribute",
            "path": "encrypted",
            "operator": "eq",
            "value": True,
        },
        "remediation": "Set encrypted = true on EBS volumes.",
        "tags": ["ec2", "ebs", "encryption"],
    },
    # AWS IAM Policies
    {
        "id": "iac-aws-iam-admin-policy",
        "name": "IAM policy grants admin access",
        "description": "IAM policies should follow least privilege and not grant full admin access.",
        "enabled": True,
        "severity": "critical",
        "resource_types": ["aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"],
        "providers": ["aws"],
        "check": {
            "type": "not_exists",
            "path": "policy",  # Will need custom logic to check for *:*
        },
        "remediation": "Use specific actions and resources instead of wildcards.",
        "tags": ["iam", "permissions", "least-privilege"],
    },
    {
        "id": "iac-aws-iam-password-policy",
        "name": "IAM password policy not configured",
        "description": "AWS accounts should have a strong password policy configured.",
        "enabled": True,
        "severity": "medium",
        "resource_types": ["aws_iam_account_password_policy"],
        "providers": ["aws"],
        "check": {
            "type": "all_of",
            "checks": [
                {"type": "attribute", "path": "minimum_password_length", "operator": "gte", "value": 14},
                {"type": "attribute", "path": "require_symbols", "operator": "eq", "value": True},
                {"type": "attribute", "path": "require_numbers", "operator": "eq", "value": True},
            ],
        },
        "remediation": "Configure a password policy with minimum 14 characters and complexity requirements.",
        "tags": ["iam", "password", "authentication"],
    },
    # AWS RDS Policies
    {
        "id": "iac-aws-rds-encryption",
        "name": "RDS instance not encrypted",
        "description": "RDS instances should have encryption at rest enabled.",
        "enabled": True,
        "severity": "high",
        "resource_types": ["aws_db_instance", "aws_rds_cluster"],
        "providers": ["aws"],
        "check": {
            "type": "attribute",
            "path": "storage_encrypted",
            "operator": "eq",
            "value": True,
        },
        "remediation": "Set storage_encrypted = true on RDS instances.",
        "tags": ["rds", "encryption", "database"],
    },
    {
        "id": "iac-aws-rds-public",
        "name": "RDS instance publicly accessible",
        "description": "RDS instances should not be publicly accessible.",
        "enabled": True,
        "severity": "critical",
        "resource_types": ["aws_db_instance"],
        "providers": ["aws"],
        "check": {
            "type": "attribute",
            "path": "publicly_accessible",
            "operator": "eq",
            "value": False,
        },
        "remediation": "Set publicly_accessible = false on RDS instances.",
        "tags": ["rds", "public-access", "database"],
    },
    {
        "id": "iac-aws-rds-backup",
        "name": "RDS backup retention too short",
        "description": "RDS instances should have adequate backup retention.",
        "enabled": True,
        "severity": "medium",
        "resource_types": ["aws_db_instance", "aws_rds_cluster"],
        "providers": ["aws"],
        "check": {
            "type": "attribute",
            "path": "backup_retention_period",
            "operator": "gte",
            "value": 7,
        },
        "remediation": "Set backup_retention_period to at least 7 days.",
        "tags": ["rds", "backup", "database"],
    },
    # AWS Lambda Policies
    {
        "id": "iac-aws-lambda-public",
        "name": "Lambda function has public URL",
        "description": "Lambda functions with public URLs should be carefully reviewed.",
        "enabled": True,
        "severity": "medium",
        "resource_types": ["aws_lambda_function_url"],
        "providers": ["aws"],
        "check": {
            "type": "attribute",
            "path": "authorization_type",
            "operator": "ne",
            "value": "NONE",
        },
        "remediation": "Set authorization_type to 'AWS_IAM' for Lambda function URLs.",
        "tags": ["lambda", "public-access", "serverless"],
    },
    # AWS KMS Policies
    {
        "id": "iac-aws-kms-rotation",
        "name": "KMS key rotation not enabled",
        "description": "KMS keys should have automatic rotation enabled.",
        "enabled": True,
        "severity": "medium",
        "resource_types": ["aws_kms_key"],
        "providers": ["aws"],
        "check": {
            "type": "attribute",
            "path": "enable_key_rotation",
            "operator": "eq",
            "value": True,
        },
        "remediation": "Set enable_key_rotation = true on KMS keys.",
        "tags": ["kms", "encryption", "key-rotation"],
    },
    # AWS CloudTrail Policies
    {
        "id": "iac-aws-cloudtrail-encryption",
        "name": "CloudTrail not encrypted with KMS",
        "description": "CloudTrail logs should be encrypted with a KMS key.",
        "enabled": True,
        "severity": "medium",
        "resource_types": ["aws_cloudtrail"],
        "providers": ["aws"],
        "check": {
            "type": "exists",
            "path": "kms_key_id",
        },
        "remediation": "Configure a KMS key for CloudTrail encryption.",
        "tags": ["cloudtrail", "encryption", "logging"],
    },
    {
        "id": "iac-aws-cloudtrail-validation",
        "name": "CloudTrail log validation not enabled",
        "description": "CloudTrail should have log file validation enabled.",
        "enabled": True,
        "severity": "medium",
        "resource_types": ["aws_cloudtrail"],
        "providers": ["aws"],
        "check": {
            "type": "attribute",
            "path": "enable_log_file_validation",
            "operator": "eq",
            "value": True,
        },
        "remediation": "Set enable_log_file_validation = true.",
        "tags": ["cloudtrail", "integrity", "logging"],
    },
    # GCP Storage Policies
    {
        "id": "iac-gcp-storage-public",
        "name": "GCS bucket allows public access",
        "description": "GCS buckets should not allow public access.",
        "enabled": True,
        "severity": "critical",
        "resource_types": ["google_storage_bucket"],
        "providers": ["gcp"],
        "check": {
            "type": "attribute",
            "path": "public_access_prevention",
            "operator": "eq",
            "value": "enforced",
        },
        "remediation": "Set public_access_prevention = 'enforced' on GCS buckets.",
        "tags": ["gcs", "public-access", "storage"],
    },
    {
        "id": "iac-gcp-storage-uniform-access",
        "name": "GCS bucket not using uniform access",
        "description": "GCS buckets should use uniform bucket-level access.",
        "enabled": True,
        "severity": "medium",
        "resource_types": ["google_storage_bucket"],
        "providers": ["gcp"],
        "check": {
            "type": "attribute",
            "path": "uniform_bucket_level_access",
            "operator": "eq",
            "value": True,
        },
        "remediation": "Set uniform_bucket_level_access = true.",
        "tags": ["gcs", "iam", "storage"],
    },
    # GCP Compute Policies
    {
        "id": "iac-gcp-compute-public-ip",
        "name": "GCE instance has public IP",
        "description": "GCE instances should not have public IP addresses unless necessary.",
        "enabled": True,
        "severity": "medium",
        "resource_types": ["google_compute_instance"],
        "providers": ["gcp"],
        "check": {
            "type": "not_exists",
            "path": "network_interface.access_config",
        },
        "remediation": "Remove access_config to disable public IP, use Cloud NAT for egress.",
        "tags": ["gce", "public-ip", "network"],
    },
    {
        "id": "iac-gcp-compute-shielded-vm",
        "name": "GCE instance not using Shielded VM",
        "description": "GCE instances should use Shielded VM features.",
        "enabled": True,
        "severity": "medium",
        "resource_types": ["google_compute_instance"],
        "providers": ["gcp"],
        "check": {
            "type": "all_of",
            "checks": [
                {"type": "attribute", "path": "shielded_instance_config.enable_secure_boot", "operator": "eq", "value": True},
                {"type": "attribute", "path": "shielded_instance_config.enable_vtpm", "operator": "eq", "value": True},
            ],
        },
        "remediation": "Enable Shielded VM features in shielded_instance_config.",
        "tags": ["gce", "shielded-vm", "security"],
    },
    # Azure Storage Policies
    {
        "id": "iac-azure-storage-https",
        "name": "Azure storage not requiring HTTPS",
        "description": "Azure storage accounts should require HTTPS.",
        "enabled": True,
        "severity": "high",
        "resource_types": ["azurerm_storage_account"],
        "providers": ["azure"],
        "check": {
            "type": "attribute",
            "path": "enable_https_traffic_only",
            "operator": "eq",
            "value": True,
        },
        "remediation": "Set enable_https_traffic_only = true.",
        "tags": ["storage", "https", "encryption"],
    },
    {
        "id": "iac-azure-storage-tls",
        "name": "Azure storage using old TLS version",
        "description": "Azure storage accounts should use TLS 1.2 or higher.",
        "enabled": True,
        "severity": "medium",
        "resource_types": ["azurerm_storage_account"],
        "providers": ["azure"],
        "check": {
            "type": "attribute",
            "path": "min_tls_version",
            "operator": "eq",
            "value": "TLS1_2",
        },
        "remediation": "Set min_tls_version = 'TLS1_2'.",
        "tags": ["storage", "tls", "encryption"],
    },
    # Azure SQL Policies
    {
        "id": "iac-azure-sql-tde",
        "name": "Azure SQL TDE not enabled",
        "description": "Azure SQL databases should have Transparent Data Encryption enabled.",
        "enabled": True,
        "severity": "high",
        "resource_types": ["azurerm_mssql_database"],
        "providers": ["azure"],
        "check": {
            "type": "any_of",
            "checks": [
                {"type": "not_exists", "path": "transparent_data_encryption_enabled"},
                {"type": "attribute", "path": "transparent_data_encryption_enabled", "operator": "eq", "value": True},
            ],
        },
        "remediation": "Ensure transparent_data_encryption_enabled is not set to false.",
        "tags": ["sql", "encryption", "database"],
    },
]


def get_default_iac_policies() -> IaCPolicyCollection:
    """
    Get the collection of default built-in IaC policies.

    Returns:
        IaCPolicyCollection with default policies
    """
    loader = IaCPolicyLoader()
    collection = IaCPolicyCollection()

    for policy_data in DEFAULT_IAC_POLICIES:
        policy = loader._dict_to_policy(policy_data)
        collection.add(policy)

    return collection
