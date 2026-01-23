"""
CLI command decorators for error handling and common patterns.

This module provides decorators that wrap CLI command handlers with
consistent error handling, logging, and common functionality.
"""

from __future__ import annotations

import argparse
import functools
import json
import logging
import os
import secrets
import sys
import traceback
from typing import Any, Callable, TypeVar

logger = logging.getLogger(__name__)


def _is_production_environment() -> bool:
    """Check if running in a production environment."""
    return any([
        os.environ.get("STANCE_ENV", "").lower() == "production",
        os.environ.get("STANCE_PRODUCTION", "").lower() in ("1", "true", "yes"),
        os.environ.get("ENV", "").lower() == "production",
        os.environ.get("ENVIRONMENT", "").lower() == "production",
    ])


def _sanitize_cli_error(error: Exception) -> tuple[str, str]:
    """
    Sanitize an error message for CLI output to prevent information leakage.

    In production, returns a generic error message with an error ID.
    In development, returns the error type and message without stack traces.

    Args:
        error: The exception to sanitize

    Returns:
        Tuple of (user_message, error_id)
    """
    error_id = secrets.token_hex(8)
    error_str = str(error)

    # Always log the full error including stack trace for debugging
    logger.error(
        "Error [%s] (%s): %s\n%s",
        error_id,
        type(error).__name__,
        error_str,
        traceback.format_exc(),
    )

    if _is_production_environment():
        # In production, return generic message with error ID for correlation
        return f"An error occurred (ref: {error_id}). Check logs for details.", error_id
    else:
        # In development, return type and message but NOT stack traces in output
        # Stack traces are logged, not returned to user
        return f"{type(error).__name__}: {error_str}", error_id

# Type variable for command handlers
F = TypeVar("F", bound=Callable[..., int])


def cli_command(func: F) -> F:
    """
    Decorator for CLI commands with automatic error handling.

    Wraps a command handler to:
    - Catch and log exceptions
    - Format errors appropriately (JSON or text)
    - Return proper exit codes
    - Log execution for debugging

    Usage:
        @cli_command
        def cmd_scan(args: argparse.Namespace) -> int:
            # Implementation without try/except
            storage = get_storage(args.storage)
            results = storage.get_findings()
            print(format_output(results, args.format))
            return 0

    Args:
        func: The command handler function

    Returns:
        Wrapped function with error handling
    """

    @functools.wraps(func)
    def wrapper(args: argparse.Namespace) -> int:
        try:
            logger.debug(f"Executing command: {func.__name__}")
            result = func(args)
            logger.debug(f"Command {func.__name__} completed with code {result}")
            return result
        except KeyboardInterrupt:
            # User interrupted - clean exit
            logger.info(f"Command {func.__name__} interrupted by user")
            format_type = getattr(args, "format", "table")
            if format_type == "json":
                print(json.dumps({"status": "interrupted"}, indent=2))
            else:
                print("\nOperation cancelled.")
            return 130  # Standard exit code for SIGINT
        except Exception as e:
            # Sanitize error message for user output - full details go to logs only
            user_message, error_id = _sanitize_cli_error(e)
            format_type = getattr(args, "format", "table")
            if format_type == "json":
                error_data = {
                    "error": user_message,
                    "error_id": error_id,
                }
                print(json.dumps(error_data, indent=2))
            else:
                print(f"Error: {user_message}", file=sys.stderr)
            return 1

    return wrapper  # type: ignore


def require_storage(storage_getter: Callable[..., Any] | None = None) -> Callable[[F], F]:
    """
    Decorator that ensures storage is available before command execution.

    Automatically initializes storage from args.storage or custom getter,
    and passes it to the command handler.

    Usage:
        @require_storage()
        def cmd_list(args: argparse.Namespace, storage: StorageBackend) -> int:
            findings = storage.get_findings()
            return 0

        # Or with custom storage getter:
        @require_storage(lambda args: get_custom_storage(args.backend))
        def cmd_list(args: argparse.Namespace, storage: CustomStorage) -> int:
            ...

    Args:
        storage_getter: Optional function to get storage (receives args)

    Returns:
        Decorator function
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(args: argparse.Namespace) -> int:
            try:
                if storage_getter:
                    storage = storage_getter(args)
                else:
                    # Import here to avoid circular imports
                    from stance.storage import get_storage

                    storage_name = getattr(args, "storage", "local")
                    storage = get_storage(storage_name)
                return func(args, storage)
            except ImportError as e:
                user_message, error_id = _sanitize_cli_error(e)
                print(f"Error: Storage backend not available (ref: {error_id})", file=sys.stderr)
                return 1
            except Exception as e:
                user_message, error_id = _sanitize_cli_error(e)
                format_type = getattr(args, "format", "table")
                if format_type == "json":
                    print(json.dumps({"error": user_message, "error_id": error_id}, indent=2))
                else:
                    print(f"Error: {user_message}", file=sys.stderr)
                return 1

        return wrapper  # type: ignore

    return decorator


def require_scan_data(func: F) -> F:
    """
    Decorator that ensures scan data exists before command execution.

    Checks for existing scan data in storage and provides a helpful
    error message if no data is found.

    Usage:
        @require_scan_data
        def cmd_show_findings(args: argparse.Namespace) -> int:
            storage = get_storage(args.storage)
            # We know scan data exists at this point
            findings = storage.get_findings()
            ...

    Args:
        func: The command handler function

    Returns:
        Wrapped function with scan data check
    """

    @functools.wraps(func)
    def wrapper(args: argparse.Namespace) -> int:
        try:
            # Import here to avoid circular imports
            from stance.storage import get_storage

            storage_name = getattr(args, "storage", "local")
            storage = get_storage(storage_name)

            # Check for scan data
            snapshot_id = storage.get_latest_snapshot_id()
            if not snapshot_id:
                format_type = getattr(args, "format", "table")
                if format_type == "json":
                    print(
                        json.dumps(
                            {
                                "error": "No scan data found",
                                "hint": "Run 'stance scan' first to collect data",
                            },
                            indent=2,
                        )
                    )
                else:
                    print("Error: No scan data found.", file=sys.stderr)
                    print("Hint: Run 'stance scan' first to collect data.", file=sys.stderr)
                return 1

            return func(args)
        except Exception as e:
            user_message, _ = _sanitize_cli_error(e)
            print(f"Error: {user_message}", file=sys.stderr)
            return 1

    return wrapper  # type: ignore


def with_output_handling(func: F) -> F:
    """
    Decorator that handles output file writing if --output is specified.

    If args.output is set, redirects stdout to the specified file.
    Otherwise, output goes to stdout as normal.

    Usage:
        @with_output_handling
        def cmd_export(args: argparse.Namespace) -> int:
            print(format_output(data, args.format))
            return 0
            # Output automatically goes to file if -o/--output specified

    Args:
        func: The command handler function

    Returns:
        Wrapped function with output handling
    """

    @functools.wraps(func)
    def wrapper(args: argparse.Namespace) -> int:
        output_path = getattr(args, "output", None)

        if output_path:
            try:
                with open(output_path, "w") as f:
                    # Temporarily redirect stdout
                    old_stdout = sys.stdout
                    sys.stdout = f
                    try:
                        result = func(args)
                    finally:
                        sys.stdout = old_stdout
                logger.info(f"Output written to {output_path}")
                return result
            except IOError as e:
                # For IO errors, it's safe to show the path but sanitize the error
                user_message, error_id = _sanitize_cli_error(e)
                print(f"Error: Could not write to output file (ref: {error_id})", file=sys.stderr)
                return 1
        else:
            return func(args)

    return wrapper  # type: ignore


def suppress_output_on_json(func: F) -> F:
    """
    Decorator that suppresses progress/status messages when format is JSON.

    Many commands print status messages that would corrupt JSON output.
    This decorator provides a clean way to handle this.

    Usage:
        @suppress_output_on_json
        def cmd_scan(args: argparse.Namespace) -> int:
            print("Scanning...")  # Only shown for table format
            # Do work
            return 0

    Args:
        func: The command handler function

    Returns:
        Wrapped function with conditional output suppression
    """

    @functools.wraps(func)
    def wrapper(args: argparse.Namespace) -> int:
        format_type = getattr(args, "format", "table")

        if format_type == "json":
            # Suppress non-JSON output
            import io

            captured = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = captured
            try:
                result = func(args)
                output = captured.getvalue()
                # Only print if it looks like JSON
                sys.stdout = old_stdout
                output = output.strip()
                if output:
                    try:
                        # Validate it's JSON
                        json.loads(output)
                        print(output)
                    except json.JSONDecodeError:
                        # Not JSON, must be the final result
                        # Try to find JSON in the output
                        lines = output.split("\n")
                        json_lines = []
                        in_json = False
                        for line in lines:
                            stripped = line.strip()
                            if stripped.startswith("{") or stripped.startswith("["):
                                in_json = True
                            if in_json:
                                json_lines.append(line)
                            if in_json and (stripped.endswith("}") or stripped.endswith("]")):
                                # Try to parse
                                try:
                                    candidate = "\n".join(json_lines)
                                    json.loads(candidate)
                                    print(candidate)
                                    json_lines = []
                                    in_json = False
                                except json.JSONDecodeError:
                                    pass
                return result
            finally:
                if sys.stdout != old_stdout:
                    sys.stdout = old_stdout
        else:
            return func(args)

    return wrapper  # type: ignore


def validate_args(
    validators: dict[str, Callable[[Any], bool | str]],
) -> Callable[[F], F]:
    """
    Decorator that validates command arguments before execution.

    Runs validation functions on specified argument values.
    Validators return True if valid, or an error message string if invalid.

    Usage:
        @validate_args({
            'domain': lambda d: True if is_valid_domain(d) else "Invalid domain format",
            'port': lambda p: True if 1 <= p <= 65535 else "Port must be 1-65535",
        })
        def cmd_scan(args: argparse.Namespace) -> int:
            # Args are validated at this point
            ...

    Args:
        validators: Dict mapping arg names to validator functions

    Returns:
        Decorator function
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(args: argparse.Namespace) -> int:
            for arg_name, validator in validators.items():
                value = getattr(args, arg_name, None)
                if value is not None:
                    result = validator(value)
                    if result is not True:
                        error_msg = result if isinstance(result, str) else f"Invalid {arg_name}"
                        format_type = getattr(args, "format", "table")
                        if format_type == "json":
                            print(
                                json.dumps(
                                    {"error": error_msg, "argument": arg_name},
                                    indent=2,
                                )
                            )
                        else:
                            print(f"Error: {error_msg}", file=sys.stderr)
                        return 1
            return func(args)

        return wrapper  # type: ignore

    return decorator


def requires_confirmation(
    message: str = "Are you sure you want to proceed?",
    flag_attr: str = "yes",
) -> Callable[[F], F]:
    """
    Decorator that requires user confirmation before executing.

    Checks for a --yes/-y flag to skip confirmation.

    Usage:
        @requires_confirmation("This will delete all data. Continue?")
        def cmd_delete(args: argparse.Namespace) -> int:
            # Only runs if user confirms or --yes was passed
            ...

    Args:
        message: The confirmation message to display
        flag_attr: The arg attribute name for the --yes flag

    Returns:
        Decorator function
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(args: argparse.Namespace) -> int:
            skip_confirm = getattr(args, flag_attr, False) or getattr(args, "force", False)

            if not skip_confirm:
                try:
                    response = input(f"{message} [y/N]: ").strip().lower()
                    if response not in ("y", "yes"):
                        print("Operation cancelled.")
                        return 0
                except EOFError:
                    # Non-interactive, treat as no
                    print("Error: Confirmation required. Use --yes to skip.", file=sys.stderr)
                    return 1

            return func(args)

        return wrapper  # type: ignore

    return decorator
