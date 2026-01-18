"""
Argument parser builder utilities for CLI commands.

This module provides standardized argument definitions that can be reused
across CLI modules, eliminating 600+ duplicate argument definitions.
"""

from __future__ import annotations

import argparse
from typing import Any, Callable, Sequence


class ParserBuilder:
    """
    Builder class for standardized CLI argument definitions.

    Provides reusable methods for adding common arguments like
    --format, --limit, --output, etc. to argument parsers.

    Usage:
        from stance.cli_utils.parser_builder import ParserBuilder

        # Add standard arguments to a parser
        list_parser = subparsers.add_parser('list')
        ParserBuilder.add_format_argument(list_parser)
        ParserBuilder.add_limit_argument(list_parser)
        ParserBuilder.add_output_argument(list_parser)

        # Or use the builder pattern
        builder = ParserBuilder(list_parser)
        builder.add_format().add_limit().add_output()
    """

    def __init__(self, parser: argparse.ArgumentParser) -> None:
        """
        Initialize with an argument parser.

        Args:
            parser: The argparse.ArgumentParser to add arguments to
        """
        self.parser = parser

    def add_format(
        self,
        choices: Sequence[str] | None = None,
        default: str = "table",
        help_text: str | None = None,
    ) -> "ParserBuilder":
        """
        Add standard --format/-f argument.

        Args:
            choices: Valid format choices (default: table, json, csv)
            default: Default format (default: table)
            help_text: Custom help text

        Returns:
            self for method chaining
        """
        ParserBuilder.add_format_argument(
            self.parser, choices=choices, default=default, help_text=help_text
        )
        return self

    def add_limit(
        self,
        default: int = 100,
        help_text: str | None = None,
    ) -> "ParserBuilder":
        """
        Add standard --limit argument.

        Args:
            default: Default limit value
            help_text: Custom help text

        Returns:
            self for method chaining
        """
        ParserBuilder.add_limit_argument(self.parser, default=default, help_text=help_text)
        return self

    def add_output(
        self,
        help_text: str | None = None,
    ) -> "ParserBuilder":
        """
        Add standard -o/--output argument.

        Args:
            help_text: Custom help text

        Returns:
            self for method chaining
        """
        ParserBuilder.add_output_argument(self.parser, help_text=help_text)
        return self

    def add_storage(
        self,
        default: str = "local",
        help_text: str | None = None,
    ) -> "ParserBuilder":
        """
        Add standard --storage argument.

        Args:
            default: Default storage backend
            help_text: Custom help text

        Returns:
            self for method chaining
        """
        ParserBuilder.add_storage_argument(self.parser, default=default, help_text=help_text)
        return self

    def add_filter(
        self,
        help_text: str | None = None,
    ) -> "ParserBuilder":
        """
        Add standard --filter argument.

        Args:
            help_text: Custom help text

        Returns:
            self for method chaining
        """
        ParserBuilder.add_filter_argument(self.parser, help_text=help_text)
        return self

    def add_sort(
        self,
        choices: Sequence[str] | None = None,
        default: str | None = None,
        help_text: str | None = None,
    ) -> "ParserBuilder":
        """
        Add standard --sort argument.

        Args:
            choices: Valid sort field choices
            default: Default sort field
            help_text: Custom help text

        Returns:
            self for method chaining
        """
        ParserBuilder.add_sort_argument(
            self.parser, choices=choices, default=default, help_text=help_text
        )
        return self

    def add_verbose(
        self,
        help_text: str | None = None,
    ) -> "ParserBuilder":
        """
        Add standard -v/--verbose argument.

        Args:
            help_text: Custom help text

        Returns:
            self for method chaining
        """
        ParserBuilder.add_verbose_argument(self.parser, help_text=help_text)
        return self

    def add_quiet(
        self,
        help_text: str | None = None,
    ) -> "ParserBuilder":
        """
        Add standard -q/--quiet argument.

        Args:
            help_text: Custom help text

        Returns:
            self for method chaining
        """
        ParserBuilder.add_quiet_argument(self.parser, help_text=help_text)
        return self

    # Static methods for direct use without builder pattern

    @staticmethod
    def add_format_argument(
        parser: argparse.ArgumentParser,
        choices: Sequence[str] | None = None,
        default: str = "table",
        help_text: str | None = None,
    ) -> None:
        """
        Add standard --format/-f argument to a parser.

        Args:
            parser: The parser to add the argument to
            choices: Valid format choices (default: table, json, csv)
            default: Default format (default: table)
            help_text: Custom help text
        """
        if choices is None:
            choices = ["table", "json", "csv"]
        parser.add_argument(
            "--format",
            "-f",
            type=str,
            choices=choices,
            default=default,
            help=help_text or f"Output format (default: {default})",
        )

    @staticmethod
    def add_limit_argument(
        parser: argparse.ArgumentParser,
        default: int = 100,
        help_text: str | None = None,
    ) -> None:
        """
        Add standard --limit argument to a parser.

        Args:
            parser: The parser to add the argument to
            default: Default limit value
            help_text: Custom help text
        """
        parser.add_argument(
            "--limit",
            type=int,
            default=default,
            help=help_text or f"Maximum number of results to return (default: {default})",
        )

    @staticmethod
    def add_output_argument(
        parser: argparse.ArgumentParser,
        help_text: str | None = None,
    ) -> None:
        """
        Add standard -o/--output argument to a parser.

        Args:
            parser: The parser to add the argument to
            help_text: Custom help text
        """
        parser.add_argument(
            "-o",
            "--output",
            type=str,
            help=help_text or "Output file path (writes to stdout if not specified)",
        )

    @staticmethod
    def add_storage_argument(
        parser: argparse.ArgumentParser,
        default: str = "local",
        help_text: str | None = None,
    ) -> None:
        """
        Add standard --storage argument to a parser.

        Args:
            parser: The parser to add the argument to
            default: Default storage backend
            help_text: Custom help text
        """
        parser.add_argument(
            "--storage",
            type=str,
            default=default,
            choices=["local", "s3", "gcs", "azure", "postgresql", "sqlite"],
            help=help_text or f"Storage backend to use (default: {default})",
        )

    @staticmethod
    def add_filter_argument(
        parser: argparse.ArgumentParser,
        help_text: str | None = None,
    ) -> None:
        """
        Add standard --filter argument to a parser.

        Args:
            parser: The parser to add the argument to
            help_text: Custom help text
        """
        parser.add_argument(
            "--filter",
            type=str,
            help=help_text or "Filter expression (e.g., 'severity==HIGH' or 'status==OPEN')",
        )

    @staticmethod
    def add_sort_argument(
        parser: argparse.ArgumentParser,
        choices: Sequence[str] | None = None,
        default: str | None = None,
        help_text: str | None = None,
    ) -> None:
        """
        Add standard --sort argument to a parser.

        Args:
            parser: The parser to add the argument to
            choices: Valid sort field choices
            default: Default sort field
            help_text: Custom help text
        """
        kwargs: dict[str, Any] = {
            "type": str,
            "help": help_text or "Field to sort results by",
        }
        if choices:
            kwargs["choices"] = list(choices)
        if default:
            kwargs["default"] = default
        parser.add_argument("--sort", **kwargs)

    @staticmethod
    def add_reverse_argument(
        parser: argparse.ArgumentParser,
        help_text: str | None = None,
    ) -> None:
        """
        Add standard --reverse argument for sort order.

        Args:
            parser: The parser to add the argument to
            help_text: Custom help text
        """
        parser.add_argument(
            "--reverse",
            action="store_true",
            help=help_text or "Reverse sort order (descending)",
        )

    @staticmethod
    def add_verbose_argument(
        parser: argparse.ArgumentParser,
        help_text: str | None = None,
    ) -> None:
        """
        Add standard -v/--verbose argument to a parser.

        Args:
            parser: The parser to add the argument to
            help_text: Custom help text
        """
        parser.add_argument(
            "-v",
            "--verbose",
            action="store_true",
            help=help_text or "Enable verbose output",
        )

    @staticmethod
    def add_quiet_argument(
        parser: argparse.ArgumentParser,
        help_text: str | None = None,
    ) -> None:
        """
        Add standard -q/--quiet argument to a parser.

        Args:
            parser: The parser to add the argument to
            help_text: Custom help text
        """
        parser.add_argument(
            "-q",
            "--quiet",
            action="store_true",
            help=help_text or "Suppress non-essential output",
        )

    @staticmethod
    def add_severity_argument(
        parser: argparse.ArgumentParser,
        help_text: str | None = None,
    ) -> None:
        """
        Add standard --severity argument to a parser.

        Args:
            parser: The parser to add the argument to
            help_text: Custom help text
        """
        parser.add_argument(
            "--severity",
            type=str,
            choices=["critical", "high", "medium", "low", "info"],
            help=help_text or "Filter by severity level",
        )

    @staticmethod
    def add_status_argument(
        parser: argparse.ArgumentParser,
        help_text: str | None = None,
    ) -> None:
        """
        Add standard --status argument to a parser.

        Args:
            parser: The parser to add the argument to
            help_text: Custom help text
        """
        parser.add_argument(
            "--status",
            type=str,
            choices=["open", "resolved", "suppressed", "acknowledged"],
            help=help_text or "Filter by status",
        )

    @staticmethod
    def add_provider_argument(
        parser: argparse.ArgumentParser,
        help_text: str | None = None,
    ) -> None:
        """
        Add standard --provider argument to a parser.

        Args:
            parser: The parser to add the argument to
            help_text: Custom help text
        """
        parser.add_argument(
            "--provider",
            type=str,
            choices=["aws", "gcp", "azure", "kubernetes"],
            help=help_text or "Cloud provider to filter by",
        )

    @staticmethod
    def add_region_argument(
        parser: argparse.ArgumentParser,
        help_text: str | None = None,
    ) -> None:
        """
        Add standard --region argument to a parser.

        Args:
            parser: The parser to add the argument to
            help_text: Custom help text
        """
        parser.add_argument(
            "--region",
            type=str,
            help=help_text or "Cloud region to filter by",
        )

    @staticmethod
    def add_scan_id_argument(
        parser: argparse.ArgumentParser,
        required: bool = False,
        help_text: str | None = None,
    ) -> None:
        """
        Add standard --scan-id argument to a parser.

        Args:
            parser: The parser to add the argument to
            required: Whether the argument is required
            help_text: Custom help text
        """
        parser.add_argument(
            "--scan-id",
            type=str,
            required=required,
            help=help_text or "Scan ID to use (defaults to latest)",
        )

    @staticmethod
    def add_config_argument(
        parser: argparse.ArgumentParser,
        help_text: str | None = None,
    ) -> None:
        """
        Add standard --config argument to a parser.

        Args:
            parser: The parser to add the argument to
            help_text: Custom help text
        """
        parser.add_argument(
            "--config",
            type=str,
            help=help_text or "Path to configuration file",
        )

    @staticmethod
    def add_dry_run_argument(
        parser: argparse.ArgumentParser,
        help_text: str | None = None,
    ) -> None:
        """
        Add standard --dry-run argument to a parser.

        Args:
            parser: The parser to add the argument to
            help_text: Custom help text
        """
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help=help_text or "Show what would be done without making changes",
        )

    @staticmethod
    def add_force_argument(
        parser: argparse.ArgumentParser,
        help_text: str | None = None,
    ) -> None:
        """
        Add standard --force argument to a parser.

        Args:
            parser: The parser to add the argument to
            help_text: Custom help text
        """
        parser.add_argument(
            "--force",
            action="store_true",
            help=help_text or "Force operation without confirmation",
        )

    @staticmethod
    def add_yes_argument(
        parser: argparse.ArgumentParser,
        help_text: str | None = None,
    ) -> None:
        """
        Add standard -y/--yes argument to a parser.

        Args:
            parser: The parser to add the argument to
            help_text: Custom help text
        """
        parser.add_argument(
            "-y",
            "--yes",
            action="store_true",
            help=help_text or "Automatically answer yes to prompts",
        )

    @staticmethod
    def add_common_list_arguments(parser: argparse.ArgumentParser) -> None:
        """
        Add common arguments for list commands.

        Adds: --format, --limit, --filter, --sort, --reverse, --output

        Args:
            parser: The parser to add arguments to
        """
        ParserBuilder.add_format_argument(parser)
        ParserBuilder.add_limit_argument(parser)
        ParserBuilder.add_filter_argument(parser)
        ParserBuilder.add_sort_argument(parser)
        ParserBuilder.add_reverse_argument(parser)
        ParserBuilder.add_output_argument(parser)

    @staticmethod
    def add_common_show_arguments(parser: argparse.ArgumentParser) -> None:
        """
        Add common arguments for show/get commands.

        Adds: --format, --output, --verbose

        Args:
            parser: The parser to add arguments to
        """
        ParserBuilder.add_format_argument(parser, choices=["table", "json"])
        ParserBuilder.add_output_argument(parser)
        ParserBuilder.add_verbose_argument(parser)

    @staticmethod
    def add_common_scan_arguments(parser: argparse.ArgumentParser) -> None:
        """
        Add common arguments for scan commands.

        Adds: --storage, --format, --output, --verbose, --provider, --region

        Args:
            parser: The parser to add arguments to
        """
        ParserBuilder.add_storage_argument(parser)
        ParserBuilder.add_format_argument(parser)
        ParserBuilder.add_output_argument(parser)
        ParserBuilder.add_verbose_argument(parser)
        ParserBuilder.add_provider_argument(parser)
        ParserBuilder.add_region_argument(parser)


def create_subparser(
    subparsers: Any,
    name: str,
    help_text: str,
    description: str | None = None,
    handler: Callable[[argparse.Namespace], int] | None = None,
) -> argparse.ArgumentParser:
    """
    Create a subparser with standard configuration.

    Args:
        subparsers: The subparsers object from parent parser
        name: Name of the subcommand
        help_text: Brief help text shown in parent command's help
        description: Detailed description for the subcommand's help
        handler: Optional handler function to set as default

    Returns:
        The created ArgumentParser
    """
    parser = subparsers.add_parser(
        name,
        help=help_text,
        description=description or help_text,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    if handler:
        parser.set_defaults(func=handler)
    return parser
