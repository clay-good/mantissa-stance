"""
Base command class for CLI commands.

This module provides a base class that CLI commands can inherit from
to get common functionality like output formatting and error handling.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from abc import ABC, abstractmethod
from typing import Any

from stance.cli_utils.formatters import CliFormatter, OutputFormat, TableConfig

logger = logging.getLogger(__name__)


class BaseCommand(ABC):
    """
    Base class for CLI commands.

    Provides common functionality for CLI commands including:
    - Output formatting (JSON, CSV, table)
    - Error handling and reporting
    - Logging
    - Storage access patterns

    Usage:
        class ScanCommand(BaseCommand):
            def execute(self) -> int:
                storage = self.get_storage()
                findings = storage.get_findings()
                self.output(findings)
                return 0

        # In handler:
        def cmd_scan(args: argparse.Namespace) -> int:
            return ScanCommand(args).run()
    """

    def __init__(
        self,
        args: argparse.Namespace,
        table_config: TableConfig | None = None,
    ) -> None:
        """
        Initialize the command with parsed arguments.

        Args:
            args: Parsed command-line arguments
            table_config: Optional custom table configuration
        """
        self.args = args
        self.table_config = table_config or TableConfig()
        self._storage = None

    @property
    def format(self) -> str:
        """Get the output format from args."""
        return getattr(self.args, "format", "table")

    @property
    def verbose(self) -> bool:
        """Check if verbose mode is enabled."""
        return getattr(self.args, "verbose", False)

    @property
    def quiet(self) -> bool:
        """Check if quiet mode is enabled."""
        return getattr(self.args, "quiet", False)

    @property
    def output_path(self) -> str | None:
        """Get the output file path if specified."""
        return getattr(self.args, "output", None)

    @abstractmethod
    def execute(self) -> int:
        """
        Execute the command.

        Override this method in subclasses to implement command logic.

        Returns:
            Exit code (0 for success, non-zero for error)
        """
        pass

    def run(self) -> int:
        """
        Run the command with error handling.

        This is the main entry point for executing the command.
        It wraps execute() with error handling.

        Returns:
            Exit code (0 for success, non-zero for error)
        """
        try:
            return self.execute()
        except KeyboardInterrupt:
            self.info("\nOperation cancelled.")
            return 130
        except Exception as e:
            logger.exception(f"Command failed: {e}")
            self.error(str(e))
            return 1

    def output(
        self,
        data: list[dict[str, Any]] | dict[str, Any] | Any,
        headers: list[str] | None = None,
        exclude_fields: list[str] | None = None,
        include_fields: list[str] | None = None,
    ) -> None:
        """
        Output data in the requested format.

        Args:
            data: Data to output
            headers: Optional explicit headers
            exclude_fields: Fields to exclude
            include_fields: Only include these fields
        """
        formatted = CliFormatter.format(
            data,
            self.format,
            table_config=self.table_config,
            headers=headers,
            exclude_fields=exclude_fields,
            include_fields=include_fields,
        )
        self._write_output(formatted)

    def output_raw(self, text: str) -> None:
        """
        Output raw text without formatting.

        Args:
            text: Text to output
        """
        self._write_output(text)

    def error(self, message: str, exit_code: int | None = None) -> int:
        """
        Output an error message.

        Args:
            message: Error message
            exit_code: Optional exit code to return

        Returns:
            The exit code (default 1)
        """
        if self.format == "json":
            error_data = {"error": message}
            print(json.dumps(error_data, indent=2), file=sys.stderr)
        else:
            print(f"Error: {message}", file=sys.stderr)
        return exit_code if exit_code is not None else 1

    def success(self, message: str) -> None:
        """
        Output a success message.

        Args:
            message: Success message
        """
        if self.format == "json":
            print(json.dumps({"status": "success", "message": message}, indent=2))
        elif not self.quiet:
            print(f"Success: {message}")

    def info(self, message: str) -> None:
        """
        Output an informational message.

        Only outputs in non-JSON formats and when not in quiet mode.

        Args:
            message: Info message
        """
        if self.format != "json" and not self.quiet:
            print(message)

    def debug(self, message: str) -> None:
        """
        Output a debug message.

        Only outputs in verbose mode and non-JSON formats.

        Args:
            message: Debug message
        """
        if self.verbose and self.format != "json":
            print(f"DEBUG: {message}")

    def warn(self, message: str) -> None:
        """
        Output a warning message.

        Args:
            message: Warning message
        """
        if self.format == "json":
            print(json.dumps({"warning": message}, indent=2), file=sys.stderr)
        elif not self.quiet:
            print(f"Warning: {message}", file=sys.stderr)

    def confirm(self, message: str, default: bool = False) -> bool:
        """
        Ask for user confirmation.

        Args:
            message: Confirmation message
            default: Default value if user just presses Enter

        Returns:
            True if confirmed, False otherwise
        """
        # Skip confirmation if --yes was passed
        if getattr(self.args, "yes", False) or getattr(self.args, "force", False):
            return True

        default_str = "Y/n" if default else "y/N"
        try:
            response = input(f"{message} [{default_str}]: ").strip().lower()
            if not response:
                return default
            return response in ("y", "yes")
        except EOFError:
            return default

    def get_storage(self, backend: str | None = None) -> Any:
        """
        Get the storage backend.

        Args:
            backend: Optional backend name (uses args.storage if not specified)

        Returns:
            Storage backend instance
        """
        if self._storage is None:
            from stance.storage import get_storage

            backend_name = backend or getattr(self.args, "storage", "local")
            self._storage = get_storage(backend_name)
        return self._storage

    def get_scan_id(self) -> str | None:
        """
        Get the scan ID from args or find the latest.

        Returns:
            Scan ID or None if no scans exist
        """
        scan_id = getattr(self.args, "scan_id", None)
        if scan_id:
            return scan_id

        storage = self.get_storage()
        return storage.get_latest_snapshot_id()

    def require_scan_data(self) -> str:
        """
        Require that scan data exists.

        Returns:
            The scan ID

        Raises:
            RuntimeError: If no scan data exists
        """
        scan_id = self.get_scan_id()
        if not scan_id:
            raise RuntimeError("No scan data found. Run 'stance scan' first.")
        return scan_id

    def _write_output(self, content: str) -> None:
        """
        Write content to output (stdout or file).

        Args:
            content: Content to write
        """
        if self.output_path:
            try:
                with open(self.output_path, "w") as f:
                    f.write(content)
                    if not content.endswith("\n"):
                        f.write("\n")
                if not self.quiet and self.format != "json":
                    print(f"Output written to {self.output_path}")
            except IOError as e:
                raise RuntimeError(f"Could not write to {self.output_path}: {e}")
        else:
            print(content)


class ListCommand(BaseCommand):
    """
    Base class for list/search commands.

    Provides common functionality for commands that list resources
    with filtering, sorting, and pagination.
    """

    @property
    def limit(self) -> int:
        """Get the result limit."""
        return getattr(self.args, "limit", 100)

    @property
    def filter_expr(self) -> str | None:
        """Get the filter expression."""
        return getattr(self.args, "filter", None)

    @property
    def sort_by(self) -> str | None:
        """Get the sort field."""
        return getattr(self.args, "sort", None)

    @property
    def sort_reverse(self) -> bool:
        """Check if sort should be reversed."""
        return getattr(self.args, "reverse", False)

    def filter_data(self, data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Apply filter expression to data.

        Args:
            data: List of data items

        Returns:
            Filtered data
        """
        if not self.filter_expr:
            return data

        # Simple filter expression parsing
        # Supports: field==value, field!=value, field>value, field<value
        result = []
        for item in data:
            if self._matches_filter(item, self.filter_expr):
                result.append(item)
        return result

    def sort_data(self, data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Sort data by the specified field.

        Args:
            data: List of data items

        Returns:
            Sorted data
        """
        if not self.sort_by:
            return data

        return sorted(
            data,
            key=lambda x: x.get(self.sort_by, ""),
            reverse=self.sort_reverse,
        )

    def paginate_data(self, data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Apply limit to data.

        Args:
            data: List of data items

        Returns:
            Limited data
        """
        if self.limit and len(data) > self.limit:
            return data[: self.limit]
        return data

    def process_data(self, data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Apply filter, sort, and pagination to data.

        Args:
            data: List of data items

        Returns:
            Processed data
        """
        data = self.filter_data(data)
        data = self.sort_data(data)
        data = self.paginate_data(data)
        return data

    def _matches_filter(self, item: dict[str, Any], expr: str) -> bool:
        """
        Check if an item matches a filter expression.

        Args:
            item: Data item
            expr: Filter expression

        Returns:
            True if matches
        """
        # Parse expression
        operators = ["==", "!=", ">=", "<=", ">", "<", "~="]
        for op in operators:
            if op in expr:
                parts = expr.split(op, 1)
                if len(parts) == 2:
                    field, value = parts[0].strip(), parts[1].strip()
                    item_value = item.get(field)

                    # Remove quotes from value
                    if value.startswith(("'", '"')) and value.endswith(("'", '"')):
                        value = value[1:-1]

                    return self._compare(item_value, op, value)
        return True

    def _compare(self, item_value: Any, op: str, value: str) -> bool:
        """
        Compare values using the specified operator.

        Args:
            item_value: Value from item
            op: Comparison operator
            value: Value to compare against

        Returns:
            True if comparison matches
        """
        if item_value is None:
            return False

        str_item = str(item_value)

        if op == "==":
            return str_item == value
        elif op == "!=":
            return str_item != value
        elif op == "~=":  # Contains
            return value.lower() in str_item.lower()
        elif op in (">", "<", ">=", "<="):
            try:
                num_item = float(item_value)
                num_value = float(value)
                if op == ">":
                    return num_item > num_value
                elif op == "<":
                    return num_item < num_value
                elif op == ">=":
                    return num_item >= num_value
                elif op == "<=":
                    return num_item <= num_value
            except (ValueError, TypeError):
                # Fall back to string comparison
                if op == ">":
                    return str_item > value
                elif op == "<":
                    return str_item < value
                elif op == ">=":
                    return str_item >= value
                elif op == "<=":
                    return str_item <= value
        return True
