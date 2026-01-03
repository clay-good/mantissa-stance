"""
Policy loader for Mantissa Stance.

Loads and validates security policies from YAML files.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

from stance.models import (
    Policy,
    PolicyCollection,
    Check,
    CheckType,
    ComplianceMapping,
    Remediation,
    Severity,
)

logger = logging.getLogger(__name__)


class PolicyLoadError(Exception):
    """Exception raised when policy loading fails."""

    def __init__(self, message: str, source_path: str | None = None):
        self.source_path = source_path
        prefix = f"{source_path}: " if source_path else ""
        super().__init__(f"{prefix}{message}")


class PolicyLoader:
    """
    Loads and validates security policies from YAML files.

    Supports loading individual policy files or discovering all policies
    in configured directories.
    """

    def __init__(self, policy_dirs: list[str] | None = None):
        """
        Initialize the policy loader.

        Args:
            policy_dirs: Directories to search for policies.
                        Defaults to ["policies/"]
        """
        self._policy_dirs = policy_dirs or ["policies/"]
        self._expression_validator: Any = None

    def load_all(self) -> PolicyCollection:
        """
        Load all policies from configured directories.

        Returns:
            PolicyCollection with all valid policies

        Raises:
            PolicyLoadError: If no policies could be loaded
        """
        policies: list[Policy] = []
        errors: list[str] = []

        policy_files = self.discover_policies()

        if not policy_files:
            logger.warning("No policy files found in configured directories")
            return PolicyCollection([])

        for path in policy_files:
            try:
                policy = self.load_policy(path)
                validation_errors = self.validate_policy(policy)
                if validation_errors:
                    logger.warning(
                        f"Policy {path} has validation errors: {validation_errors}"
                    )
                    errors.extend([f"{path}: {e}" for e in validation_errors])
                else:
                    policies.append(policy)
            except Exception as e:
                logger.warning(f"Failed to load policy {path}: {e}")
                errors.append(f"{path}: {e}")

        if not policies and errors:
            logger.error(f"No valid policies loaded. Errors: {errors}")

        logger.info(f"Loaded {len(policies)} policies from {len(policy_files)} files")

        return PolicyCollection(policies)

    def load_policy(self, path: str) -> Policy:
        """
        Load a single policy from file path.

        Args:
            path: Path to the policy YAML file

        Returns:
            Loaded Policy object

        Raises:
            PolicyLoadError: If policy cannot be loaded
        """
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()

            data = self._parse_yaml(content)
            return self._dict_to_policy(data, path)

        except FileNotFoundError:
            raise PolicyLoadError(f"File not found", path)
        except Exception as e:
            raise PolicyLoadError(str(e), path)

    def validate_policy(self, policy: Policy) -> list[str]:
        """
        Validate policy schema and check logic.

        Args:
            policy: Policy to validate

        Returns:
            List of validation errors (empty if valid)
        """
        errors: list[str] = []

        # Check required fields
        if not policy.id:
            errors.append("Missing required field: id")
        if not policy.name:
            errors.append("Missing required field: name")
        if not policy.resource_type:
            errors.append("Missing required field: resource_type")
        if not policy.check:
            errors.append("Missing required field: check")

        # Validate check
        if policy.check:
            errors.extend(self._validate_check(policy.check))

        # Validate compliance mappings
        for mapping in policy.compliance:
            if not mapping.framework:
                errors.append("Compliance mapping missing framework")
            if not mapping.control:
                errors.append("Compliance mapping missing control")

        return errors

    def discover_policies(self) -> list[str]:
        """
        Find all YAML files in policy directories.

        Returns:
            List of policy file paths
        """
        policy_files: list[str] = []

        for dir_path in self._policy_dirs:
            dir_path = os.path.expanduser(dir_path)

            if not os.path.isdir(dir_path):
                logger.debug(f"Policy directory not found: {dir_path}")
                continue

            for root, _, files in os.walk(dir_path):
                for file in files:
                    if file.endswith((".yaml", ".yml")):
                        policy_files.append(os.path.join(root, file))

        return sorted(policy_files)

    def _parse_yaml(self, content: str) -> dict[str, Any]:
        """
        Parse YAML content into dictionary.

        Uses pyyaml if available, falls back to simple parser.

        Args:
            content: YAML content string

        Returns:
            Parsed dictionary
        """
        try:
            import yaml

            return yaml.safe_load(content) or {}
        except ImportError:
            return self._simple_yaml_parse(content)

    def _simple_yaml_parse(self, content: str) -> dict[str, Any]:
        """
        Simple YAML parser for basic policy files.

        Supports: strings, numbers, bools, lists, dicts, multiline strings.
        Does not support: anchors, aliases, complex features.

        Args:
            content: YAML content string

        Returns:
            Parsed dictionary
        """
        result: dict[str, Any] = {}
        lines = content.split("\n")
        i = 0

        while i < len(lines):
            line = lines[i]

            # Skip empty lines and comments
            if not line.strip() or line.strip().startswith("#"):
                i += 1
                continue

            # Count indentation
            indent = len(line) - len(line.lstrip())

            # Parse key-value at root level (indent 0)
            if indent == 0:
                key, value, i = self._parse_yaml_entry(lines, i, 0)
                if key:
                    result[key] = value
            else:
                i += 1

        return result

    def _parse_yaml_entry(
        self, lines: list[str], start: int, base_indent: int
    ) -> tuple[str | None, Any, int]:
        """Parse a YAML entry (key-value pair)."""
        line = lines[start]
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            return None, None, start + 1

        # Check for key: value
        if ":" not in stripped:
            return None, None, start + 1

        colon_pos = stripped.index(":")
        key = stripped[:colon_pos].strip()
        rest = stripped[colon_pos + 1 :].strip()

        current_indent = len(line) - len(line.lstrip())
        next_line = start + 1

        # Multiline string with |
        if rest == "|":
            value_lines = []
            while next_line < len(lines):
                next_stripped = lines[next_line]
                if not next_stripped.strip():
                    value_lines.append("")
                    next_line += 1
                    continue
                next_indent = len(next_stripped) - len(next_stripped.lstrip())
                if next_indent <= current_indent:
                    break
                value_lines.append(next_stripped.strip())
                next_line += 1
            return key, "\n".join(value_lines), next_line

        # List value
        if rest == "" and next_line < len(lines):
            next_stripped = lines[next_line].strip()
            if next_stripped.startswith("- "):
                items = []
                while next_line < len(lines):
                    nl = lines[next_line]
                    if not nl.strip():
                        next_line += 1
                        continue
                    nl_indent = len(nl) - len(nl.lstrip())
                    if nl_indent <= current_indent:
                        break
                    if nl.strip().startswith("- "):
                        item_value = nl.strip()[2:].strip()
                        list_item_indent = nl_indent
                        # Check if it's a nested dict
                        if ":" in item_value:
                            # Parse as nested dict with potential continuation
                            nested_dict: dict[str, Any] = {}
                            # Parse first key: value on same line as -
                            k, v = item_value.split(":", 1)
                            nested_dict[k.strip()] = self._parse_value(v.strip())
                            next_line += 1
                            # Continue parsing additional keys at the same indent level
                            while next_line < len(lines):
                                cont_line = lines[next_line]
                                if not cont_line.strip():
                                    next_line += 1
                                    continue
                                cont_indent = len(cont_line) - len(cont_line.lstrip())
                                cont_stripped = cont_line.strip()
                                # If we hit a new list item or return to parent level, stop
                                if cont_stripped.startswith("- ") or cont_indent <= current_indent:
                                    break
                                # If at the nested dict level (same as first key after -)
                                if cont_indent > list_item_indent and ":" in cont_stripped:
                                    ck, cv = cont_stripped.split(":", 1)
                                    nested_dict[ck.strip()] = self._parse_value(cv.strip())
                                    next_line += 1
                                else:
                                    break
                            items.append(nested_dict)
                        else:
                            items.append(self._parse_value(item_value))
                            next_line += 1
                    else:
                        next_line += 1
                return key, items, next_line

            # Nested dict
            if ":" in next_stripped:
                nested: dict[str, Any] = {}
                while next_line < len(lines):
                    nl = lines[next_line]
                    if not nl.strip() or nl.strip().startswith("#"):
                        next_line += 1
                        continue
                    nl_indent = len(nl) - len(nl.lstrip())
                    if nl_indent <= current_indent:
                        break
                    nk, nv, next_line = self._parse_yaml_entry(
                        lines, next_line, current_indent + 2
                    )
                    if nk:
                        nested[nk] = nv
                return key, nested, next_line

        # Simple value
        return key, self._parse_value(rest), next_line

    def _parse_value(self, value: str) -> Any:
        """Parse a YAML value string."""
        if not value:
            return None

        # Remove quotes
        if (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        ):
            return value[1:-1]

        # Booleans
        lower = value.lower()
        if lower == "true":
            return True
        if lower == "false":
            return False
        if lower == "null" or lower == "~":
            return None

        # Numbers
        try:
            if "." in value:
                return float(value)
            return int(value)
        except ValueError:
            pass

        return value

    def _dict_to_policy(self, data: dict[str, Any], source_path: str) -> Policy:
        """
        Convert dictionary to Policy object.

        Args:
            data: Parsed policy data
            source_path: Source file path

        Returns:
            Policy object
        """
        # Parse check
        check_data = data.get("check", {})
        check_type_str = check_data.get("type", "expression")
        check_type = CheckType.EXPRESSION
        if check_type_str.lower() == "sql":
            check_type = CheckType.SQL

        check = Check(
            check_type=check_type,
            expression=check_data.get("expression"),
            query=check_data.get("query"),
        )

        # Parse compliance mappings
        compliance: list[ComplianceMapping] = []
        for mapping_data in data.get("compliance", []):
            if isinstance(mapping_data, dict):
                compliance.append(
                    ComplianceMapping(
                        framework=mapping_data.get("framework", ""),
                        version=mapping_data.get("version", ""),
                        control=mapping_data.get("control", ""),
                    )
                )

        # Parse remediation
        remediation_data = data.get("remediation", {})
        remediation = Remediation(
            guidance=remediation_data.get("guidance", ""),
            automation_supported=remediation_data.get("automation_supported", False),
        )

        # Parse severity
        severity_str = data.get("severity", "medium")
        severity = Severity.from_string(severity_str)

        # Parse tags
        tags = data.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]

        # Parse references
        references = data.get("references", [])
        if isinstance(references, str):
            references = [references]

        return Policy(
            id=data.get("id", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            enabled=data.get("enabled", True),
            severity=severity,
            resource_type=data.get("resource_type", ""),
            check=check,
            compliance=compliance,
            remediation=remediation,
            tags=tags,
            references=references,
        )

    def _validate_check(self, check: Check) -> list[str]:
        """
        Validate check configuration.

        Args:
            check: Check to validate

        Returns:
            List of validation errors
        """
        errors: list[str] = []

        if check.check_type == CheckType.EXPRESSION:
            if not check.expression:
                errors.append("Expression check requires 'expression' field")
            else:
                # Try to validate expression syntax
                try:
                    from stance.engine.expressions import ExpressionEvaluator

                    evaluator = ExpressionEvaluator()
                    expr_errors = evaluator.validate(check.expression)
                    errors.extend(expr_errors)
                except ImportError:
                    pass  # Skip validation if evaluator not available
                except Exception as e:
                    errors.append(f"Expression validation failed: {e}")

        elif check.check_type == CheckType.SQL:
            if not check.query:
                errors.append("SQL check requires 'query' field")
            else:
                # Validate SQL is SELECT only
                normalized = " ".join(check.query.split()).upper()
                if not normalized.startswith("SELECT"):
                    errors.append("SQL check must be a SELECT statement")

                dangerous = ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE"]
                for kw in dangerous:
                    if re.search(r"\b" + kw + r"\b", normalized):
                        errors.append(f"SQL check cannot contain {kw}")

        return errors
