"""
CLI infrastructure module for Mantissa Stance.

This module provides shared utilities for CLI commands including:
- Unified output formatting (JSON, CSV, table)
- Argument parser builders
- Command registry for routing
- Error handling decorators
- Base command class
"""

from stance.cli_utils.formatters import CliFormatter, TableConfig
from stance.cli_utils.parser_builder import ParserBuilder
from stance.cli_utils.command_registry import CommandRegistry
from stance.cli_utils.decorators import cli_command, require_storage, require_scan_data
from stance.cli_utils.base_command import BaseCommand

__all__ = [
    "CliFormatter",
    "TableConfig",
    "ParserBuilder",
    "CommandRegistry",
    "cli_command",
    "require_storage",
    "require_scan_data",
    "BaseCommand",
]

__version__ = "1.0.0"
