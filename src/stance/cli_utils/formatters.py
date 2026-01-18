"""
Unified output formatting for CLI commands.

This module provides a single, consistent implementation for formatting
CLI output as JSON, CSV, or ASCII tables. It replaces 40+ duplicate
implementations across the codebase.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Sequence


class OutputFormat(str, Enum):
    """Supported output formats for CLI commands."""

    TABLE = "table"
    JSON = "json"
    CSV = "csv"
    SUMMARY = "summary"


@dataclass
class TableConfig:
    """Configuration for table formatting."""

    max_column_width: int = 50
    min_column_width: int = 5
    truncate_suffix: str = "..."
    header_separator: str = "-"
    column_separator: str = " | "
    show_row_numbers: bool = False
    compact: bool = False
    wrap_headers: bool = True
    column_widths: dict[str, int] = field(default_factory=dict)
    column_alignments: dict[str, str] = field(default_factory=dict)  # 'left', 'right', 'center'


class CliFormatter:
    """
    Unified output formatter for CLI commands.

    Provides consistent formatting for JSON, CSV, and table outputs,
    eliminating code duplication across CLI modules.

    Usage:
        from stance.cli_utils.formatters import CliFormatter

        # Format as table (default)
        output = CliFormatter.format(data)

        # Format as JSON
        output = CliFormatter.format(data, 'json')

        # Format with custom table config
        config = TableConfig(max_column_width=30)
        output = CliFormatter.format(data, 'table', table_config=config)

        # Format single value with truncation
        truncated = CliFormatter.truncate("very long string", 10)
    """

    @staticmethod
    def format(
        data: list[dict[str, Any]] | dict[str, Any] | Any,
        format_type: str | OutputFormat = OutputFormat.TABLE,
        table_config: TableConfig | None = None,
        headers: list[str] | None = None,
        exclude_fields: list[str] | None = None,
        include_fields: list[str] | None = None,
        sort_by: str | None = None,
        sort_reverse: bool = False,
    ) -> str:
        """
        Format data for CLI output.

        Args:
            data: Data to format (list of dicts, dict, or other)
            format_type: Output format ('table', 'json', 'csv', 'summary')
            table_config: Configuration for table formatting
            headers: Optional list of headers to use (overrides auto-detection)
            exclude_fields: Fields to exclude from output
            include_fields: Only include these fields (if specified)
            sort_by: Field name to sort by
            sort_reverse: Sort in descending order

        Returns:
            Formatted string output
        """
        if isinstance(format_type, str):
            format_type = OutputFormat(format_type.lower())

        # Handle empty data
        if not data:
            if format_type == OutputFormat.JSON:
                return json.dumps([] if isinstance(data, list) else {}, indent=2)
            elif format_type == OutputFormat.CSV:
                return ""
            else:
                return "No data to display."

        # Normalize data to list of dicts
        normalized_data = CliFormatter._normalize_data(data)

        # Filter fields
        if include_fields:
            normalized_data = [
                {k: v for k, v in row.items() if k in include_fields}
                for row in normalized_data
            ]
        if exclude_fields:
            normalized_data = [
                {k: v for k, v in row.items() if k not in exclude_fields}
                for row in normalized_data
            ]

        # Sort if requested
        if sort_by and normalized_data:
            normalized_data = sorted(
                normalized_data,
                key=lambda x: x.get(sort_by, ""),
                reverse=sort_reverse,
            )

        # Format based on type
        if format_type == OutputFormat.JSON:
            return CliFormatter._format_json(normalized_data)
        elif format_type == OutputFormat.CSV:
            return CliFormatter._format_csv(normalized_data, headers)
        elif format_type == OutputFormat.SUMMARY:
            return CliFormatter._format_summary(normalized_data)
        else:  # TABLE
            return CliFormatter._format_table(
                normalized_data, table_config or TableConfig(), headers
            )

    @staticmethod
    def truncate(value: Any, max_length: int = 50, suffix: str = "...") -> str:
        """
        Truncate a value to a maximum length with suffix.

        Args:
            value: Value to truncate
            max_length: Maximum length (including suffix)
            suffix: Suffix to add when truncated

        Returns:
            Truncated string
        """
        str_value = str(value) if value is not None else ""
        if len(str_value) <= max_length:
            return str_value
        return str_value[: max_length - len(suffix)] + suffix

    @staticmethod
    def format_value(
        value: Any,
        field_type: str | None = None,
        max_length: int | None = None,
    ) -> str:
        """
        Format a single value for display.

        Args:
            value: Value to format
            field_type: Optional type hint ('datetime', 'bool', 'list', 'dict')
            max_length: Optional max length for truncation

        Returns:
            Formatted string
        """
        if value is None:
            return "-"

        # Auto-detect type if not specified
        if field_type is None:
            if isinstance(value, datetime):
                field_type = "datetime"
            elif isinstance(value, bool):
                field_type = "bool"
            elif isinstance(value, list):
                field_type = "list"
            elif isinstance(value, dict):
                field_type = "dict"

        # Format based on type
        if field_type == "datetime":
            if isinstance(value, datetime):
                formatted = value.strftime("%Y-%m-%d %H:%M:%S")
            else:
                formatted = str(value)
        elif field_type == "bool":
            formatted = "Yes" if value else "No"
        elif field_type == "list":
            if isinstance(value, list):
                formatted = ", ".join(str(v) for v in value[:3])
                if len(value) > 3:
                    formatted += f" (+{len(value) - 3} more)"
            else:
                formatted = str(value)
        elif field_type == "dict":
            if isinstance(value, dict):
                formatted = json.dumps(value, default=str)
            else:
                formatted = str(value)
        else:
            formatted = str(value)

        # Truncate if needed
        if max_length:
            formatted = CliFormatter.truncate(formatted, max_length)

        return formatted

    @staticmethod
    def format_error(error: str | Exception, format_type: str = "table") -> str:
        """
        Format an error message for CLI output.

        Args:
            error: Error message or exception
            format_type: Output format

        Returns:
            Formatted error string
        """
        error_str = str(error)
        if format_type == "json":
            return json.dumps({"error": error_str}, indent=2)
        return f"Error: {error_str}"

    @staticmethod
    def format_success(message: str, format_type: str = "table") -> str:
        """
        Format a success message for CLI output.

        Args:
            message: Success message
            format_type: Output format

        Returns:
            Formatted success string
        """
        if format_type == "json":
            return json.dumps({"status": "success", "message": message}, indent=2)
        return f"Success: {message}"

    @staticmethod
    def _normalize_data(data: Any) -> list[dict[str, Any]]:
        """Normalize various data types to list of dicts."""
        if isinstance(data, list):
            if not data:
                return []
            if isinstance(data[0], dict):
                return data
            # Convert list of objects to list of dicts
            return [
                item.__dict__ if hasattr(item, "__dict__") else {"value": item}
                for item in data
            ]
        elif isinstance(data, dict):
            return [data]
        elif hasattr(data, "__dict__"):
            return [data.__dict__]
        else:
            return [{"value": data}]

    @staticmethod
    def _format_json(data: list[dict[str, Any]]) -> str:
        """Format data as JSON with proper serialization."""

        def json_serializer(obj: Any) -> Any:
            if isinstance(obj, datetime):
                return obj.isoformat()
            if isinstance(obj, Enum):
                return obj.value
            if hasattr(obj, "__dict__"):
                return obj.__dict__
            return str(obj)

        # Return single item if only one, otherwise list
        output_data = data[0] if len(data) == 1 else data
        return json.dumps(output_data, indent=2, default=json_serializer)

    @staticmethod
    def _format_csv(
        data: list[dict[str, Any]], headers: list[str] | None = None
    ) -> str:
        """Format data as CSV."""
        if not data:
            return ""

        # Use provided headers or extract from data
        if headers is None:
            headers = list(data[0].keys())

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()

        for row in data:
            # Convert complex types to strings
            formatted_row = {}
            for key, value in row.items():
                if key in headers:
                    if isinstance(value, (list, dict)):
                        formatted_row[key] = json.dumps(value, default=str)
                    elif isinstance(value, datetime):
                        formatted_row[key] = value.isoformat()
                    elif isinstance(value, Enum):
                        formatted_row[key] = value.value
                    else:
                        formatted_row[key] = value
            writer.writerow(formatted_row)

        return output.getvalue()

    @staticmethod
    def _format_table(
        data: list[dict[str, Any]],
        config: TableConfig,
        headers: list[str] | None = None,
    ) -> str:
        """Format data as an ASCII table."""
        if not data:
            return "No data to display."

        # Determine headers
        if headers is None:
            headers = list(data[0].keys())

        # Calculate column widths
        widths: dict[str, int] = {}
        for header in headers:
            # Start with header width
            header_width = len(str(header))

            # Check all data values
            max_data_width = 0
            for row in data:
                value = row.get(header, "")
                formatted = CliFormatter.format_value(value)
                max_data_width = max(max_data_width, len(formatted))

            # Use configured width or calculate
            if header in config.column_widths:
                widths[header] = config.column_widths[header]
            else:
                width = max(header_width, max_data_width, config.min_column_width)
                widths[header] = min(width, config.max_column_width)

        # Build table
        lines: list[str] = []

        # Header row
        header_cells = []
        for header in headers:
            cell = str(header)[: widths[header]]
            alignment = config.column_alignments.get(header, "left")
            if alignment == "right":
                cell = cell.rjust(widths[header])
            elif alignment == "center":
                cell = cell.center(widths[header])
            else:
                cell = cell.ljust(widths[header])
            header_cells.append(cell)
        lines.append(config.column_separator.join(header_cells))

        # Separator row
        separator_cells = [config.header_separator * widths[h] for h in headers]
        lines.append(config.column_separator.join(separator_cells))

        # Data rows
        for i, row in enumerate(data):
            cells = []
            for header in headers:
                value = row.get(header, "")
                formatted = CliFormatter.format_value(value, max_length=widths[header])
                alignment = config.column_alignments.get(header, "left")
                if alignment == "right":
                    formatted = formatted.rjust(widths[header])
                elif alignment == "center":
                    formatted = formatted.center(widths[header])
                else:
                    formatted = formatted.ljust(widths[header])
                cells.append(formatted)

            row_str = config.column_separator.join(cells)
            if config.show_row_numbers:
                row_str = f"{i + 1:4d}. {row_str}"
            lines.append(row_str)

        return "\n".join(lines)

    @staticmethod
    def _format_summary(data: list[dict[str, Any]]) -> str:
        """Format data as a summary with counts and statistics."""
        if not data:
            return "No data to summarize."

        lines = [f"Total records: {len(data)}"]

        # Try to extract useful summary info
        if data:
            sample = data[0]
            for key, value in sample.items():
                if key.lower() in ("severity", "status", "type", "category", "level"):
                    # Count by this field
                    counts: dict[str, int] = {}
                    for row in data:
                        val = str(row.get(key, "unknown"))
                        counts[val] = counts.get(val, 0) + 1
                    lines.append(f"\nBy {key}:")
                    for val, count in sorted(counts.items()):
                        lines.append(f"  {val}: {count}")

        return "\n".join(lines)


def format_findings_table(
    findings: Sequence[Any],
    format_type: str = "table",
    max_title_width: int = 50,
) -> str:
    """
    Format a list of findings for CLI output.

    This is a convenience function for the common case of formatting findings.

    Args:
        findings: List of Finding objects
        format_type: Output format ('table', 'json', 'csv')
        max_title_width: Maximum width for title column

    Returns:
        Formatted string
    """
    if not findings:
        return CliFormatter.format([], format_type)

    # Convert findings to dicts
    data = []
    for f in findings:
        row = {
            "id": CliFormatter.truncate(f.id, 16) if hasattr(f, "id") else "-",
            "title": CliFormatter.truncate(f.title, max_title_width)
            if hasattr(f, "title")
            else "-",
            "severity": f.severity.value if hasattr(f, "severity") else "-",
            "resource": CliFormatter.truncate(
                getattr(f, "resource_path", getattr(f, "resource_id", "-")), 30
            ),
            "status": f.status.value if hasattr(f, "status") else "-",
        }
        data.append(row)

    config = TableConfig(
        column_widths={"id": 19, "severity": 10, "status": 10},
        column_alignments={"severity": "center", "status": "center"},
    )

    return CliFormatter.format(data, format_type, table_config=config)


def format_assets_table(
    assets: Sequence[Any],
    format_type: str = "table",
) -> str:
    """
    Format a list of assets for CLI output.

    Args:
        assets: List of Asset objects
        format_type: Output format ('table', 'json', 'csv')

    Returns:
        Formatted string
    """
    if not assets:
        return CliFormatter.format([], format_type)

    data = []
    for a in assets:
        row = {
            "id": CliFormatter.truncate(a.id, 16) if hasattr(a, "id") else "-",
            "name": CliFormatter.truncate(getattr(a, "name", "-"), 30),
            "type": getattr(a, "resource_type", "-"),
            "provider": getattr(a, "cloud_provider", "-"),
            "region": getattr(a, "region", "-"),
        }
        data.append(row)

    config = TableConfig(
        column_widths={"id": 19, "type": 25, "provider": 10, "region": 15},
    )

    return CliFormatter.format(data, format_type, table_config=config)
