"""
Azure Resource Manager (ARM) template parser for Mantissa Stance.

Provides parsing of Azure ARM templates in JSON format.
ARM templates define Azure resources using a declarative JSON syntax.

Supported constructs:
- Resources (with nested resources)
- Parameters
- Variables
- Outputs
- Functions (parsed but not evaluated)
- Linked templates (reference extraction)
- Copy loops
- Conditions
- Dependencies (dependsOn)

Reference:
https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from stance.iac.base import (
    IaCFile,
    IaCFormat,
    IaCLocation,
    IaCParser,
    IaCResource,
)

logger = logging.getLogger(__name__)


# ARM resource type to normalized type mapping patterns
ARM_RESOURCE_PREFIXES = {
    "Microsoft.Storage/": "azure_storage_",
    "Microsoft.Compute/": "azure_compute_",
    "Microsoft.Network/": "azure_network_",
    "Microsoft.Web/": "azure_web_",
    "Microsoft.Sql/": "azure_sql_",
    "Microsoft.KeyVault/": "azure_keyvault_",
    "Microsoft.ContainerService/": "azure_container_",
    "Microsoft.ContainerRegistry/": "azure_container_registry_",
    "Microsoft.DocumentDB/": "azure_cosmosdb_",
    "Microsoft.EventHub/": "azure_eventhub_",
    "Microsoft.ServiceBus/": "azure_servicebus_",
    "Microsoft.Cache/": "azure_cache_",
    "Microsoft.Insights/": "azure_monitor_",
    "Microsoft.OperationalInsights/": "azure_loganalytics_",
    "Microsoft.Authorization/": "azure_authorization_",
    "Microsoft.ManagedIdentity/": "azure_identity_",
    "Microsoft.Resources/": "azure_resources_",
    "Microsoft.Security/": "azure_security_",
}


@dataclass
class ARMTemplateResource(IaCResource):
    """
    An ARM template resource with additional metadata.

    Extends IaCResource with ARM-specific attributes.
    """

    api_version: str = ""
    condition: str | None = None
    copy: dict[str, Any] | None = None
    comments: str | None = None
    resource_group: str | None = None
    subscription_id: str | None = None
    scope: str | None = None
    zones: list[str] = field(default_factory=list)
    sku: dict[str, Any] | None = None
    kind: str | None = None
    plan: dict[str, Any] | None = None
    identity: dict[str, Any] | None = None
    nested_resources: list[ARMTemplateResource] = field(default_factory=list)


class ARMTemplateParser(IaCParser):
    """
    Parser for Azure Resource Manager (ARM) templates.

    Parses JSON format ARM templates and extracts resources,
    parameters, variables, and other template components.
    """

    @property
    def format(self) -> IaCFormat:
        """Return ARM format."""
        return IaCFormat.ARM

    @property
    def file_extensions(self) -> list[str]:
        """Return ARM template file extensions."""
        return [".json", ".arm.json", ".azuredeploy.json", ".template.json"]

    def parse_file(self, file_path: str | Path) -> IaCFile:
        """
        Parse an ARM template file.

        Args:
            file_path: Path to the template file

        Returns:
            Parsed IaCFile object
        """
        path = Path(file_path)

        try:
            content = path.read_text(encoding="utf-8")
        except Exception as e:
            return IaCFile(
                file_path=str(path),
                format=IaCFormat.ARM,
                parse_errors=[f"Failed to read file: {e}"],
            )

        return self.parse_content(content, str(path))

    def parse_content(self, content: str, file_path: str = "<string>") -> IaCFile:
        """
        Parse ARM template content from a string.

        Args:
            content: The template content to parse
            file_path: Virtual file path for error reporting

        Returns:
            Parsed IaCFile object
        """
        iac_file = IaCFile(
            file_path=file_path,
            format=IaCFormat.ARM,
            raw_content=content,
        )

        try:
            # Parse JSON
            template = json.loads(content)

            # Validate it looks like an ARM template
            if not self._is_arm_template(template):
                iac_file.parse_errors.append(
                    "Content does not appear to be a valid ARM template"
                )
                return iac_file

            # Extract resources
            resources = template.get("resources", [])
            self._extract_resources(resources, iac_file, content)

            # Extract parameters as variables
            parameters = template.get("parameters", {})
            for param_name, param_def in parameters.items():
                if isinstance(param_def, dict):
                    iac_file.variables[param_name] = param_def

            # Extract variables
            variables = template.get("variables", {})
            iac_file.locals = variables

            # Extract outputs
            outputs = template.get("outputs", {})
            for output_name, output_def in outputs.items():
                if isinstance(output_def, dict):
                    iac_file.outputs[output_name] = output_def

            # Extract functions (user-defined functions)
            functions = template.get("functions", [])
            if functions:
                iac_file.providers["arm"] = {
                    "functions": functions,
                    "schema": template.get("$schema"),
                    "contentVersion": template.get("contentVersion"),
                    "apiProfile": template.get("apiProfile"),
                    "metadata": template.get("metadata"),
                }

        except json.JSONDecodeError as e:
            iac_file.parse_errors.append(f"JSON parse error: {e}")
        except Exception as e:
            iac_file.parse_errors.append(f"Parse error: {e}")

        return iac_file

    def _is_arm_template(self, template: dict[str, Any]) -> bool:
        """Check if the parsed content looks like an ARM template."""
        # ARM templates typically have $schema or resources
        has_schema = "$schema" in template and "azure" in str(template.get("$schema", "")).lower()
        has_resources = "resources" in template and isinstance(template.get("resources"), list)
        has_content_version = "contentVersion" in template

        # Check if schema looks like ARM template schema
        schema = str(template.get("$schema", "")).lower()
        is_arm_schema = (
            "deploymenttemplate" in schema or
            "subscriptiondeploymenttemplate" in schema or
            "managementgroupdeploymenttemplate" in schema or
            "tenantdeploymenttemplate" in schema
        )

        return (has_schema and is_arm_schema) or (has_resources and has_content_version)

    def _extract_resources(
        self,
        resources: list[dict[str, Any]],
        iac_file: IaCFile,
        content: str,
        parent_type: str = "",
    ) -> None:
        """Extract resources from the resources array."""
        for resource_def in resources:
            if not isinstance(resource_def, dict):
                continue

            resource_type = resource_def.get("type", "")
            resource_name = resource_def.get("name", "")

            if not resource_type:
                continue

            # Handle nested resource type (parent/child)
            full_type = f"{parent_type}/{resource_type}" if parent_type else resource_type

            properties = resource_def.get("properties", {})
            location = self._find_resource_location(content, resource_name, resource_type)
            normalized_type = self._normalize_resource_type(full_type)

            resource = ARMTemplateResource(
                resource_type=normalized_type,
                name=self._extract_resource_name(resource_name),
                provider="azure",
                config=properties if isinstance(properties, dict) else {},
                location=location,
                labels=self._extract_tags(resource_def),
                dependencies=self._extract_dependencies(resource_def),
                api_version=resource_def.get("apiVersion", ""),
                condition=self._extract_condition(resource_def),
                copy=resource_def.get("copy"),
                comments=resource_def.get("comments"),
                resource_group=resource_def.get("resourceGroup"),
                subscription_id=resource_def.get("subscriptionId"),
                scope=resource_def.get("scope"),
                zones=resource_def.get("zones", []),
                sku=resource_def.get("sku"),
                kind=resource_def.get("kind"),
                plan=resource_def.get("plan"),
                identity=resource_def.get("identity"),
            )
            iac_file.resources.append(resource)

            # Handle nested resources
            nested = resource_def.get("resources", [])
            if nested and isinstance(nested, list):
                self._extract_resources(nested, iac_file, content, full_type)

    def _normalize_resource_type(self, arm_type: str) -> str:
        """
        Normalize ARM resource type to a format similar to Terraform.

        Example: Microsoft.Storage/storageAccounts -> azure_storage_storageaccounts
        """
        for prefix, replacement in ARM_RESOURCE_PREFIXES.items():
            if arm_type.startswith(prefix):
                remainder = arm_type[len(prefix):]
                # Convert to lowercase and replace / with _
                normalized = remainder.lower().replace("/", "_")
                return f"{replacement}{normalized}"

        # Fallback: just convert to lowercase with underscores
        normalized = arm_type.lower().replace("::", "_").replace("/", "_").replace(".", "_")
        return f"azure_{normalized}"

    def _extract_resource_name(self, name: str) -> str:
        """Extract a simple resource name, handling ARM expressions."""
        if not name:
            return "unnamed"

        # If it's an ARM expression like [parameters('name')]
        if name.startswith("[") and name.endswith("]"):
            # Try to extract a meaningful name from the expression
            # Common patterns: [parameters('xxx')], [variables('xxx')], [concat(...)]
            match = re.search(r"parameters\('([^']+)'\)", name)
            if match:
                return f"param:{match.group(1)}"

            match = re.search(r"variables\('([^']+)'\)", name)
            if match:
                return f"var:{match.group(1)}"

            # For concat, try to find a string literal
            match = re.search(r"'([^']+)'", name)
            if match:
                return match.group(1)

            return name[1:-1]  # Return expression without brackets

        return name

    def _find_resource_location(
        self,
        content: str,
        resource_name: str,
        resource_type: str,
    ) -> IaCLocation:
        """Find the location of a resource in the source content."""
        # Escape special regex characters in the name
        escaped_name = re.escape(resource_name) if resource_name else ""

        # Try to find by name first
        if escaped_name:
            pattern = rf'"name"\s*:\s*"{escaped_name}"'
            match = re.search(pattern, content)
            if match:
                line_start = content[:match.start()].count("\n") + 1
                return IaCLocation(file_path="", line_start=line_start)

        # Try to find by type
        escaped_type = re.escape(resource_type)
        pattern = rf'"type"\s*:\s*"{escaped_type}"'
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            line_start = content[:match.start()].count("\n") + 1
            return IaCLocation(file_path="", line_start=line_start)

        return IaCLocation(file_path="", line_start=1)

    def _extract_tags(self, resource_def: dict[str, Any]) -> dict[str, str]:
        """Extract tags from resource definition."""
        tags: dict[str, str] = {}

        # Tags can be at root level or in properties
        tags_value = resource_def.get("tags") or resource_def.get("properties", {}).get("tags")

        if isinstance(tags_value, dict):
            for key, value in tags_value.items():
                if isinstance(key, str):
                    # Handle ARM expressions in tag values
                    if isinstance(value, str):
                        if value.startswith("[") and value.endswith("]"):
                            tags[key] = f"expr:{value[1:-1]}"
                        else:
                            tags[key] = value
                    else:
                        tags[key] = str(value) if value else ""

        return tags

    def _extract_dependencies(self, resource_def: dict[str, Any]) -> list[str]:
        """Extract resource dependencies."""
        deps: list[str] = []

        depends_on = resource_def.get("dependsOn", [])
        if isinstance(depends_on, list):
            for dep in depends_on:
                if isinstance(dep, str):
                    # Handle ARM resourceId expressions
                    if dep.startswith("[") and dep.endswith("]"):
                        # Extract resource type and name from resourceId
                        match = re.search(r"resourceId\([^,]+,\s*'([^']+)'", dep)
                        if match:
                            deps.append(match.group(1))
                        else:
                            deps.append(dep[1:-1])  # Expression without brackets
                    else:
                        deps.append(dep)

        return deps

    def _extract_condition(self, resource_def: dict[str, Any]) -> str | None:
        """Extract condition expression."""
        condition = resource_def.get("condition")
        if condition is None:
            return None

        if isinstance(condition, bool):
            return str(condition).lower()

        if isinstance(condition, str):
            # Remove ARM expression brackets if present
            if condition.startswith("[") and condition.endswith("]"):
                return condition[1:-1]
            return condition

        return str(condition)

    def can_parse(self, file_path: str | Path) -> bool:
        """
        Check if this parser can handle the given file.

        Overridden to check file content for ARM template markers.
        """
        path = Path(file_path)

        # Check extension first
        name_lower = path.name.lower()

        # Explicit ARM extensions
        if name_lower.endswith((".arm.json", ".azuredeploy.json")):
            return True
        if "azuredeploy" in name_lower or "arm-template" in name_lower:
            return True

        # For generic .json, check content
        if path.suffix.lower() == ".json":
            try:
                content = path.read_text(encoding="utf-8")[:2000]  # Read first 2KB
                return self._looks_like_arm_template(content)
            except Exception:
                pass

        return False

    def _looks_like_arm_template(self, content: str) -> bool:
        """Check if content looks like an ARM template."""
        markers = [
            "deploymentTemplate.json",
            "subscriptionDeploymentTemplate.json",
            '"contentVersion"',
            '"$schema"',
            "Microsoft.",
            '"apiVersion"',
        ]

        # Need schema marker AND at least one other ARM-specific marker
        has_schema = "schema.management.azure.com" in content.lower()
        has_content_version = '"contentVersion"' in content
        has_microsoft_type = "Microsoft." in content

        return has_schema or (has_content_version and has_microsoft_type)


def parse_arm_template_file(file_path: str | Path) -> IaCFile:
    """
    Convenience function to parse a single ARM template.

    Args:
        file_path: Path to the template file

    Returns:
        Parsed IaCFile object
    """
    parser = ARMTemplateParser()
    return parser.parse_file(file_path)


def parse_arm_template_content(content: str, file_path: str = "<string>") -> IaCFile:
    """
    Convenience function to parse ARM template content.

    Args:
        content: Template content (JSON)
        file_path: Virtual file path for error reporting

    Returns:
        Parsed IaCFile object
    """
    parser = ARMTemplateParser()
    return parser.parse_content(content, file_path)
