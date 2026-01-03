"""
CloudFormation template parser for Mantissa Stance.

Provides parsing of AWS CloudFormation templates in both JSON and YAML formats
without external dependencies (uses stdlib json and a minimal YAML parser).

Supported constructs:
- Resources
- Parameters
- Outputs
- Conditions
- Mappings
- Metadata
- Intrinsic functions (parsed but not evaluated)
- Nested stacks (reference extraction)
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


# CloudFormation resource type to provider mapping
CFN_RESOURCE_PROVIDERS = {
    "AWS::": "aws",
    "Alexa::": "aws",
    "Custom::": "aws",
}


class SimpleYAMLParser:
    """
    Minimal YAML parser for CloudFormation templates.

    This parser handles the subset of YAML needed for CloudFormation:
    - Key-value pairs
    - Lists
    - Nested objects
    - Multi-line strings (literal and folded)
    - CloudFormation intrinsic functions (!Ref, !Sub, etc.)
    - Comments
    - Anchors and aliases (basic support)

    Note: This is not a full YAML parser. For complex YAML features,
    consider using PyYAML if available.
    """

    # CloudFormation intrinsic function tags
    CFN_TAGS = {
        "!Ref": "Ref",
        "!Sub": "Fn::Sub",
        "!GetAtt": "Fn::GetAtt",
        "!Join": "Fn::Join",
        "!Select": "Fn::Select",
        "!Split": "Fn::Split",
        "!If": "Fn::If",
        "!Equals": "Fn::Equals",
        "!And": "Fn::And",
        "!Or": "Fn::Or",
        "!Not": "Fn::Not",
        "!Condition": "Condition",
        "!FindInMap": "Fn::FindInMap",
        "!Base64": "Fn::Base64",
        "!Cidr": "Fn::Cidr",
        "!ImportValue": "Fn::ImportValue",
        "!GetAZs": "Fn::GetAZs",
        "!Transform": "Fn::Transform",
    }

    def __init__(self, content: str) -> None:
        """Initialize the parser with YAML content."""
        self._content = content
        self._lines: list[str] = []
        self._pos = 0
        self._anchors: dict[str, Any] = {}
        self._errors: list[str] = []

    def parse(self) -> dict[str, Any]:
        """
        Parse YAML content into a dictionary.

        Returns:
            Parsed dictionary structure
        """
        # Preprocess content
        self._lines = self._preprocess(self._content)
        self._pos = 0

        if not self._lines:
            return {}

        try:
            result = self._parse_value(0)
            if isinstance(result, dict):
                return result
            return {"_value": result}
        except Exception as e:
            self._errors.append(f"Parse error: {e}")
            return {}

    @property
    def errors(self) -> list[str]:
        """Get parsing errors."""
        return self._errors

    def _preprocess(self, content: str) -> list[str]:
        """Preprocess content into lines, removing comments."""
        lines = content.split("\n")
        result = []

        in_literal = False
        literal_indent = 0

        for line in lines:
            # Check for literal/folded block indicators
            stripped = line.lstrip()
            if not in_literal and (stripped.endswith("|") or stripped.endswith("|+") or
                                   stripped.endswith("|-") or stripped.endswith(">") or
                                   stripped.endswith(">+") or stripped.endswith(">-")):
                in_literal = True
                literal_indent = len(line) - len(stripped)
                result.append(line)
                continue

            if in_literal:
                current_indent = len(line) - len(line.lstrip()) if line.strip() else literal_indent + 1
                if line.strip() and current_indent <= literal_indent:
                    in_literal = False
                else:
                    result.append(line)
                    continue

            # Remove inline comments (but not inside strings)
            processed = self._remove_inline_comment(line)
            result.append(processed)

        return result

    def _remove_inline_comment(self, line: str) -> str:
        """Remove inline comments while preserving strings."""
        in_string = False
        string_char = None
        i = 0

        while i < len(line):
            char = line[i]

            if not in_string and char in ("'", '"'):
                in_string = True
                string_char = char
            elif in_string and char == string_char:
                # Check for escaped quote
                if i > 0 and line[i-1] != "\\":
                    in_string = False
                    string_char = None
            elif not in_string and char == "#":
                return line[:i].rstrip()

            i += 1

        return line

    def _get_indent(self, line: str) -> int:
        """Get the indentation level of a line."""
        return len(line) - len(line.lstrip())

    def _parse_value(self, min_indent: int) -> Any:
        """Parse a YAML value at the current position."""
        while self._pos < len(self._lines):
            line = self._lines[self._pos]
            stripped = line.strip()

            # Skip empty lines
            if not stripped:
                self._pos += 1
                continue

            indent = self._get_indent(line)

            # If we've decreased in indentation, return
            if indent < min_indent:
                return None

            # Check for list item
            if stripped.startswith("- "):
                return self._parse_list(indent)
            elif stripped == "-":
                return self._parse_list(indent)

            # Check for key-value
            if ":" in stripped:
                return self._parse_mapping(indent)

            # Scalar value
            self._pos += 1
            return self._parse_scalar(stripped)

        return None

    def _parse_mapping(self, min_indent: int) -> dict[str, Any]:
        """Parse a YAML mapping (dictionary)."""
        result: dict[str, Any] = {}

        while self._pos < len(self._lines):
            line = self._lines[self._pos]
            stripped = line.strip()

            if not stripped:
                self._pos += 1
                continue

            indent = self._get_indent(line)

            if indent < min_indent:
                break

            if indent > min_indent and result:
                # This is a nested structure, but we already have content
                break

            # Parse key-value pair
            if ":" in stripped:
                # Handle CFN tags
                for tag, fn_name in self.CFN_TAGS.items():
                    if stripped.startswith(tag):
                        # Handle inline value after tag
                        key_part = stripped.split(":")[0]
                        rest = stripped[len(key_part)+1:].strip()
                        if rest:
                            self._pos += 1
                            value = {fn_name: self._parse_scalar(rest)}
                            return value
                        else:
                            self._pos += 1
                            nested = self._parse_value(indent + 1)
                            return {fn_name: nested}

                # Find the key-value separator
                colon_idx = self._find_colon_index(stripped)
                if colon_idx == -1:
                    self._pos += 1
                    continue

                key = stripped[:colon_idx].strip()
                value_part = stripped[colon_idx+1:].strip()

                # Handle anchor definition
                anchor = None
                if key.startswith("&"):
                    anchor_end = key.find(" ")
                    if anchor_end > 0:
                        anchor = key[1:anchor_end]
                        key = key[anchor_end+1:].strip()

                # Check if value is inline or on next lines
                if value_part:
                    # Check for CFN tag in value
                    for tag, fn_name in self.CFN_TAGS.items():
                        if value_part.startswith(tag):
                            tag_value = value_part[len(tag):].strip()
                            value = {fn_name: self._parse_scalar(tag_value)}
                            break
                    else:
                        # Check for literal/folded block
                        if value_part in ("|", "|-", "|+", ">", ">-", ">+"):
                            self._pos += 1
                            value = self._parse_block_scalar(indent)
                        else:
                            value = self._parse_scalar(value_part)

                    self._pos += 1
                else:
                    # Value on next line(s)
                    self._pos += 1
                    value = self._parse_value(indent + 1)

                # Store anchor
                if anchor:
                    self._anchors[anchor] = value

                result[key] = value
            else:
                self._pos += 1

        return result

    def _find_colon_index(self, s: str) -> int:
        """Find the index of the key-value separator colon."""
        in_string = False
        string_char = None

        for i, char in enumerate(s):
            if not in_string and char in ("'", '"'):
                in_string = True
                string_char = char
            elif in_string and char == string_char:
                in_string = False
                string_char = None
            elif not in_string and char == ":":
                # Check if followed by space or end of string
                if i + 1 >= len(s) or s[i + 1] in (" ", "\t"):
                    return i

        return -1

    def _parse_list(self, min_indent: int) -> list[Any]:
        """Parse a YAML list."""
        result: list[Any] = []

        while self._pos < len(self._lines):
            line = self._lines[self._pos]
            stripped = line.strip()

            if not stripped:
                self._pos += 1
                continue

            indent = self._get_indent(line)

            if indent < min_indent:
                break

            if not stripped.startswith("-"):
                break

            # Parse list item
            if stripped == "-":
                # Item value on next line
                self._pos += 1
                value = self._parse_value(indent + 2)
            else:
                # Inline value
                item_value = stripped[1:].strip()

                # Check for CFN tag first
                for tag, fn_name in self.CFN_TAGS.items():
                    if item_value.startswith(tag):
                        tag_value = item_value[len(tag):].strip()
                        value = {fn_name: self._parse_scalar(tag_value)}
                        self._pos += 1
                        break
                else:
                    # Check if it's a nested mapping (has colon with key-value)
                    if ":" in item_value:
                        # Parse the first key-value pair
                        self._pos += 1
                        colon_idx = self._find_colon_index(item_value)
                        if colon_idx > 0:
                            first_key = item_value[:colon_idx].strip()
                            first_value_str = item_value[colon_idx+1:].strip()

                            # Parse the first value
                            if first_value_str:
                                first_value = self._parse_scalar(first_value_str)
                            else:
                                first_value = None

                            # Start building the nested mapping
                            nested_map: dict[str, Any] = {first_key: first_value}

                            # Check for additional keys at the same level
                            item_indent = indent + 2  # List item content indent
                            while self._pos < len(self._lines):
                                next_line = self._lines[self._pos]
                                next_stripped = next_line.strip()

                                if not next_stripped:
                                    self._pos += 1
                                    continue

                                next_indent = self._get_indent(next_line)

                                # If we're back at the list level or less, stop
                                if next_indent < item_indent:
                                    break

                                # If it's a new list item, stop
                                if next_indent == indent and next_stripped.startswith("-"):
                                    break

                                # Parse additional key-value pairs
                                if ":" in next_stripped and next_indent >= item_indent:
                                    colon_idx = self._find_colon_index(next_stripped)
                                    if colon_idx > 0:
                                        key = next_stripped[:colon_idx].strip()
                                        val_str = next_stripped[colon_idx+1:].strip()

                                        if val_str:
                                            nested_map[key] = self._parse_scalar(val_str)
                                        else:
                                            self._pos += 1
                                            nested_map[key] = self._parse_value(next_indent + 2)
                                            continue

                                        self._pos += 1
                                    else:
                                        break
                                else:
                                    break

                            value = nested_map
                        else:
                            value = self._parse_scalar(item_value)
                    else:
                        value = self._parse_scalar(item_value)
                        self._pos += 1

            result.append(value)

        return result

    def _parse_block_scalar(self, base_indent: int) -> str:
        """Parse a literal or folded block scalar."""
        lines: list[str] = []
        block_indent = None

        while self._pos < len(self._lines):
            line = self._lines[self._pos]

            if not line.strip():
                lines.append("")
                self._pos += 1
                continue

            indent = self._get_indent(line)

            if block_indent is None:
                if indent <= base_indent:
                    break
                block_indent = indent

            if indent < block_indent:
                break

            # Strip the block indentation
            lines.append(line[block_indent:] if len(line) > block_indent else "")
            self._pos += 1

        return "\n".join(lines).rstrip("\n")

    def _parse_scalar(self, value: str) -> Any:
        """Parse a scalar value."""
        if not value:
            return None

        # Handle alias
        if value.startswith("*"):
            anchor_name = value[1:].strip()
            return self._anchors.get(anchor_name, value)

        # Handle quoted strings
        if (value.startswith('"') and value.endswith('"')) or \
           (value.startswith("'") and value.endswith("'")):
            return value[1:-1]

        # Handle inline list
        if value.startswith("[") and value.endswith("]"):
            return self._parse_inline_list(value)

        # Handle inline mapping
        if value.startswith("{") and value.endswith("}"):
            return self._parse_inline_mapping(value)

        # Handle special values
        lower = value.lower()
        if lower in ("true", "yes", "on"):
            return True
        if lower in ("false", "no", "off"):
            return False
        if lower in ("null", "~", ""):
            return None

        # Try number
        try:
            if "." in value or "e" in value.lower():
                return float(value)
            return int(value)
        except ValueError:
            pass

        return value

    def _parse_inline_list(self, value: str) -> list[Any]:
        """Parse an inline YAML list [a, b, c]."""
        content = value[1:-1].strip()
        if not content:
            return []

        items = []
        current = ""
        depth = 0
        in_string = False
        string_char = None

        for char in content:
            if not in_string and char in ("'", '"'):
                in_string = True
                string_char = char
                current += char
            elif in_string and char == string_char:
                in_string = False
                string_char = None
                current += char
            elif not in_string and char in ("[", "{"):
                depth += 1
                current += char
            elif not in_string and char in ("]", "}"):
                depth -= 1
                current += char
            elif not in_string and char == "," and depth == 0:
                items.append(self._parse_scalar(current.strip()))
                current = ""
            else:
                current += char

        if current.strip():
            items.append(self._parse_scalar(current.strip()))

        return items

    def _parse_inline_mapping(self, value: str) -> dict[str, Any]:
        """Parse an inline YAML mapping {a: b, c: d}."""
        content = value[1:-1].strip()
        if not content:
            return {}

        result: dict[str, Any] = {}
        pairs = self._split_inline_mapping(content)

        for pair in pairs:
            if ":" in pair:
                idx = pair.find(":")
                key = pair[:idx].strip()
                val = pair[idx+1:].strip()
                result[key] = self._parse_scalar(val)

        return result

    def _split_inline_mapping(self, content: str) -> list[str]:
        """Split inline mapping content by commas."""
        pairs = []
        current = ""
        depth = 0
        in_string = False
        string_char = None

        for char in content:
            if not in_string and char in ("'", '"'):
                in_string = True
                string_char = char
                current += char
            elif in_string and char == string_char:
                in_string = False
                string_char = None
                current += char
            elif not in_string and char in ("[", "{"):
                depth += 1
                current += char
            elif not in_string and char in ("]", "}"):
                depth -= 1
                current += char
            elif not in_string and char == "," and depth == 0:
                pairs.append(current.strip())
                current = ""
            else:
                current += char

        if current.strip():
            pairs.append(current.strip())

        return pairs


@dataclass
class CloudFormationResource(IaCResource):
    """
    A CloudFormation resource with additional metadata.

    Extends IaCResource with CloudFormation-specific attributes.
    """

    logical_id: str = ""
    condition: str | None = None
    creation_policy: dict[str, Any] | None = None
    update_policy: dict[str, Any] | None = None
    deletion_policy: str | None = None
    update_replace_policy: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class CloudFormationParser(IaCParser):
    """
    Parser for AWS CloudFormation templates.

    Parses both JSON and YAML format CloudFormation templates and extracts
    resources, parameters, outputs, and other template components.
    """

    @property
    def format(self) -> IaCFormat:
        """Return CloudFormation format."""
        return IaCFormat.CLOUDFORMATION

    @property
    def file_extensions(self) -> list[str]:
        """Return CloudFormation file extensions."""
        return [".json", ".yaml", ".yml", ".template", ".cfn.json", ".cfn.yaml", ".cfn.yml"]

    def parse_file(self, file_path: str | Path) -> IaCFile:
        """
        Parse a CloudFormation template file.

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
                format=IaCFormat.CLOUDFORMATION,
                parse_errors=[f"Failed to read file: {e}"],
            )

        return self.parse_content(content, str(path))

    def parse_content(self, content: str, file_path: str = "<string>") -> IaCFile:
        """
        Parse CloudFormation content from a string.

        Args:
            content: The template content to parse
            file_path: Virtual file path for error reporting

        Returns:
            Parsed IaCFile object
        """
        iac_file = IaCFile(
            file_path=file_path,
            format=IaCFormat.CLOUDFORMATION,
            raw_content=content,
        )

        try:
            # Determine format and parse
            template = self._parse_template(content, iac_file)

            if template is None:
                return iac_file

            # Validate it looks like CloudFormation
            if not self._is_cloudformation_template(template):
                iac_file.parse_errors.append(
                    "Content does not appear to be a valid CloudFormation template"
                )
                return iac_file

            # Extract resources
            resources = template.get("Resources", {})
            for logical_id, resource_def in resources.items():
                if not isinstance(resource_def, dict):
                    continue

                resource_type = resource_def.get("Type", "")
                if not resource_type:
                    continue

                properties = resource_def.get("Properties", {})
                location = self._find_resource_location(content, logical_id)
                provider = self._detect_provider(resource_type)

                # Map CFN resource type to Terraform-like format for policy matching
                normalized_type = self._normalize_resource_type(resource_type)

                resource = CloudFormationResource(
                    resource_type=normalized_type,
                    name=logical_id,
                    provider=provider,
                    config=properties if isinstance(properties, dict) else {},
                    location=location,
                    labels=self._extract_tags(properties),
                    dependencies=self._extract_dependencies(resource_def),
                    logical_id=logical_id,
                    condition=resource_def.get("Condition"),
                    creation_policy=resource_def.get("CreationPolicy"),
                    update_policy=resource_def.get("UpdatePolicy"),
                    deletion_policy=resource_def.get("DeletionPolicy"),
                    update_replace_policy=resource_def.get("UpdateReplacePolicy"),
                    metadata=resource_def.get("Metadata", {}),
                )
                iac_file.resources.append(resource)

            # Extract parameters as variables
            parameters = template.get("Parameters", {})
            for param_name, param_def in parameters.items():
                if isinstance(param_def, dict):
                    iac_file.variables[param_name] = param_def

            # Extract outputs
            outputs = template.get("Outputs", {})
            for output_name, output_def in outputs.items():
                if isinstance(output_def, dict):
                    iac_file.outputs[output_name] = output_def

            # Store conditions and mappings in locals
            conditions = template.get("Conditions", {})
            mappings = template.get("Mappings", {})
            iac_file.locals = {
                "Conditions": conditions,
                "Mappings": mappings,
            }

            # Extract metadata at template level
            template_metadata = template.get("Metadata", {})
            if template_metadata:
                iac_file.providers["cloudformation"] = {
                    "metadata": template_metadata,
                    "aws_template_format_version": template.get("AWSTemplateFormatVersion"),
                    "description": template.get("Description"),
                    "transform": template.get("Transform"),
                }

        except Exception as e:
            iac_file.parse_errors.append(f"Parse error: {e}")

        return iac_file

    def _parse_template(self, content: str, iac_file: IaCFile) -> dict[str, Any] | None:
        """Parse template content as JSON or YAML."""
        content_stripped = content.strip()

        # Try JSON first if content looks like JSON
        if content_stripped.startswith("{"):
            try:
                return json.loads(content)
            except json.JSONDecodeError as e:
                iac_file.parse_errors.append(f"JSON parse error: {e}")
                return None

        # Try YAML
        try:
            parser = SimpleYAMLParser(content)
            result = parser.parse()
            if parser.errors:
                iac_file.parse_errors.extend(parser.errors)
            return result
        except Exception as e:
            iac_file.parse_errors.append(f"YAML parse error: {e}")
            return None

    def _is_cloudformation_template(self, template: dict[str, Any]) -> bool:
        """Check if the parsed content looks like a CloudFormation template."""
        # Must have Resources section or AWSTemplateFormatVersion
        has_resources = "Resources" in template
        has_version = "AWSTemplateFormatVersion" in template

        # SAM templates may not have traditional Resources
        has_transform = "Transform" in template

        return has_resources or has_version or has_transform

    def _detect_provider(self, resource_type: str) -> str:
        """Detect cloud provider from CloudFormation resource type."""
        for prefix, provider in CFN_RESOURCE_PROVIDERS.items():
            if resource_type.startswith(prefix):
                return provider
        return "aws"  # Default to AWS for CloudFormation

    def _normalize_resource_type(self, cfn_type: str) -> str:
        """
        Normalize CloudFormation resource type to a format similar to Terraform.

        Example: AWS::S3::Bucket -> aws_s3_bucket
        """
        # Remove AWS:: prefix and convert to lowercase with underscores
        normalized = cfn_type.replace("::", "_").lower()
        return normalized

    def _find_resource_location(self, content: str, logical_id: str) -> IaCLocation:
        """Find the location of a resource in the source content."""
        # Pattern for JSON format
        json_pattern = rf'"{logical_id}"\s*:\s*\{{'
        match = re.search(json_pattern, content)

        if not match:
            # Pattern for YAML format
            yaml_pattern = rf'^[ \t]*{logical_id}\s*:'
            match = re.search(yaml_pattern, content, re.MULTILINE)

        if match:
            line_start = content[:match.start()].count("\n") + 1

            # Try to find the end of the resource block
            # This is approximate - finding exact end requires full parsing
            remaining = content[match.end():]

            # For JSON, count braces
            if content.strip().startswith("{"):
                brace_count = 1
                pos = 0
                for i, char in enumerate(remaining):
                    if char == "{":
                        brace_count += 1
                    elif char == "}":
                        brace_count -= 1
                        if brace_count == 0:
                            pos = match.end() + i + 1
                            break
                line_end = content[:pos].count("\n") + 1
            else:
                # For YAML, estimate based on indentation
                line_end = line_start + 10  # Rough estimate

            return IaCLocation(
                file_path="",
                line_start=line_start,
                line_end=line_end,
            )

        return IaCLocation(file_path="", line_start=1)

    def _extract_tags(self, properties: Any) -> dict[str, str]:
        """Extract tags from resource properties."""
        if not isinstance(properties, dict):
            return {}

        tags: dict[str, str] = {}

        # CloudFormation tags can be in different formats
        tags_value = properties.get("Tags")

        if isinstance(tags_value, list):
            # Format: [{"Key": "Name", "Value": "MyResource"}, ...]
            for tag in tags_value:
                if isinstance(tag, dict):
                    key = tag.get("Key", tag.get("key", ""))
                    value = tag.get("Value", tag.get("value", ""))
                    if key and isinstance(key, str):
                        tags[key] = str(value) if value else ""
        elif isinstance(tags_value, dict):
            # Format: {"Name": "MyResource", ...}
            for key, value in tags_value.items():
                if isinstance(key, str):
                    tags[key] = str(value) if value else ""

        return tags

    def _extract_dependencies(self, resource_def: dict[str, Any]) -> list[str]:
        """Extract resource dependencies."""
        deps: list[str] = []

        # Explicit DependsOn
        depends_on = resource_def.get("DependsOn")
        if isinstance(depends_on, str):
            deps.append(depends_on)
        elif isinstance(depends_on, list):
            deps.extend(str(d) for d in depends_on if d)

        # Implicit dependencies from Ref and GetAtt would require
        # recursive traversal of all properties

        return deps

    def can_parse(self, file_path: str | Path) -> bool:
        """
        Check if this parser can handle the given file.

        Overridden to check file content for CloudFormation markers.
        """
        path = Path(file_path)

        # Check extension first
        suffix = path.suffix.lower()
        name_lower = path.name.lower()

        # Explicit CloudFormation extensions
        if name_lower.endswith((".cfn.json", ".cfn.yaml", ".cfn.yml")):
            return True
        if name_lower.endswith(".template"):
            return True

        # For generic .json/.yaml/.yml, check content
        if suffix in (".json", ".yaml", ".yml"):
            try:
                content = path.read_text(encoding="utf-8")[:2000]  # Read first 2KB
                return self._looks_like_cloudformation(content)
            except Exception:
                pass

        return False

    def _looks_like_cloudformation(self, content: str) -> bool:
        """Check if content looks like CloudFormation."""
        # Look for CloudFormation markers
        markers = [
            "AWSTemplateFormatVersion",
            '"Resources"',
            "Resources:",
            "AWS::",
            "Fn::Ref",
            "!Ref",
            "Fn::GetAtt",
            "!GetAtt",
        ]
        return any(marker in content for marker in markers)


def parse_cloudformation_file(file_path: str | Path) -> IaCFile:
    """
    Convenience function to parse a single CloudFormation template.

    Args:
        file_path: Path to the template file

    Returns:
        Parsed IaCFile object
    """
    parser = CloudFormationParser()
    return parser.parse_file(file_path)


def parse_cloudformation_content(content: str, file_path: str = "<string>") -> IaCFile:
    """
    Convenience function to parse CloudFormation template content.

    Args:
        content: Template content (JSON or YAML)
        file_path: Virtual file path for error reporting

    Returns:
        Parsed IaCFile object
    """
    parser = CloudFormationParser()
    return parser.parse_content(content, file_path)
