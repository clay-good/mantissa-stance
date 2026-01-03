"""
Structured logging configuration for Mantissa Stance.

Provides consistent, structured logging across all modules
with support for different output formats and log levels.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime
from typing import Any


class StructuredFormatter(logging.Formatter):
    """
    Formatter that outputs structured JSON logs.

    Useful for log aggregation systems like CloudWatch, Stackdriver,
    or Azure Monitor.
    """

    def __init__(
        self,
        include_timestamp: bool = True,
        include_level: bool = True,
        include_logger: bool = True,
        include_location: bool = False,
        extra_fields: dict[str, Any] | None = None,
    ):
        """
        Initialize structured formatter.

        Args:
            include_timestamp: Include timestamp in output
            include_level: Include log level in output
            include_logger: Include logger name in output
            include_location: Include file/line location
            extra_fields: Additional fields to include in every log
        """
        super().__init__()
        self.include_timestamp = include_timestamp
        self.include_level = include_level
        self.include_logger = include_logger
        self.include_location = include_location
        self.extra_fields = extra_fields or {}

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data: dict[str, Any] = {}

        if self.include_timestamp:
            log_data["timestamp"] = datetime.utcnow().isoformat() + "Z"

        if self.include_level:
            log_data["level"] = record.levelname.lower()

        if self.include_logger:
            log_data["logger"] = record.name

        log_data["message"] = record.getMessage()

        if self.include_location:
            log_data["location"] = {
                "file": record.pathname,
                "line": record.lineno,
                "function": record.funcName,
            }

        # Include exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Include any extra fields from the record
        for key, value in record.__dict__.items():
            if key not in (
                "name",
                "msg",
                "args",
                "created",
                "filename",
                "funcName",
                "levelname",
                "levelno",
                "lineno",
                "module",
                "msecs",
                "pathname",
                "process",
                "processName",
                "relativeCreated",
                "stack_info",
                "exc_info",
                "exc_text",
                "thread",
                "threadName",
                "message",
            ):
                log_data[key] = value

        # Include configured extra fields
        log_data.update(self.extra_fields)

        return json.dumps(log_data, default=str)


class HumanReadableFormatter(logging.Formatter):
    """
    Formatter that outputs human-readable logs.

    Useful for local development and CLI usage.
    """

    COLORS = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def __init__(
        self,
        use_colors: bool = True,
        include_timestamp: bool = True,
        include_level: bool = True,
    ):
        """
        Initialize human-readable formatter.

        Args:
            use_colors: Use ANSI colors in output
            include_timestamp: Include timestamp in output
            include_level: Include log level in output
        """
        super().__init__()
        self.use_colors = use_colors and sys.stdout.isatty()
        self.include_timestamp = include_timestamp
        self.include_level = include_level

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as human-readable text."""
        parts = []

        if self.include_timestamp:
            timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            parts.append(f"[{timestamp}]")

        if self.include_level:
            level = record.levelname
            if self.use_colors and level in self.COLORS:
                level = f"{self.COLORS[level]}{level}{self.RESET}"
            parts.append(f"{level:>8}")

        parts.append(f"{record.name}:")
        parts.append(record.getMessage())

        output = " ".join(parts)

        if record.exc_info:
            output += "\n" + self.formatException(record.exc_info)

        return output


class StanceLogger:
    """
    Wrapper around Python logging for Stance-specific logging.

    Provides convenient methods for logging with context and metrics.
    """

    def __init__(self, name: str, level: int = logging.INFO):
        """
        Initialize Stance logger.

        Args:
            name: Logger name
            level: Default log level
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        self._context: dict[str, Any] = {}

    def set_context(self, **kwargs: Any) -> None:
        """Set persistent context fields for all logs."""
        self._context.update(kwargs)

    def clear_context(self) -> None:
        """Clear context fields."""
        self._context.clear()

    def _log(
        self,
        level: int,
        message: str,
        exc_info: bool = False,
        **kwargs: Any,
    ) -> None:
        """Internal logging method with context."""
        extra = {**self._context, **kwargs}
        self.logger.log(level, message, exc_info=exc_info, extra=extra)

    def debug(self, message: str, **kwargs: Any) -> None:
        """Log debug message."""
        self._log(logging.DEBUG, message, **kwargs)

    def info(self, message: str, **kwargs: Any) -> None:
        """Log info message."""
        self._log(logging.INFO, message, **kwargs)

    def warning(self, message: str, **kwargs: Any) -> None:
        """Log warning message."""
        self._log(logging.WARNING, message, **kwargs)

    def error(self, message: str, exc_info: bool = False, **kwargs: Any) -> None:
        """Log error message."""
        self._log(logging.ERROR, message, exc_info=exc_info, **kwargs)

    def critical(self, message: str, exc_info: bool = False, **kwargs: Any) -> None:
        """Log critical message."""
        self._log(logging.CRITICAL, message, exc_info=exc_info, **kwargs)

    def scan_started(
        self,
        scan_id: str,
        config_name: str = "default",
        collectors: list[str] | None = None,
    ) -> None:
        """Log scan start event."""
        self.info(
            "Scan started",
            event_type="scan.started",
            scan_id=scan_id,
            config_name=config_name,
            collectors=collectors or [],
        )

    def scan_completed(
        self,
        scan_id: str,
        asset_count: int,
        finding_count: int,
        duration_seconds: float,
    ) -> None:
        """Log scan completion event."""
        self.info(
            "Scan completed",
            event_type="scan.completed",
            scan_id=scan_id,
            asset_count=asset_count,
            finding_count=finding_count,
            duration_seconds=duration_seconds,
        )

    def scan_failed(self, scan_id: str, error: str) -> None:
        """Log scan failure event."""
        self.error(
            "Scan failed",
            event_type="scan.failed",
            scan_id=scan_id,
            error=error,
        )

    def finding_generated(
        self,
        finding_id: str,
        severity: str,
        rule_id: str,
        asset_id: str,
    ) -> None:
        """Log finding generation event."""
        self.info(
            "Finding generated",
            event_type="finding.generated",
            finding_id=finding_id,
            severity=severity,
            rule_id=rule_id,
            asset_id=asset_id,
        )

    def collector_started(self, collector_name: str, region: str = "") -> None:
        """Log collector start event."""
        self.debug(
            "Collector started",
            event_type="collector.started",
            collector_name=collector_name,
            region=region,
        )

    def collector_completed(
        self,
        collector_name: str,
        asset_count: int,
        duration_seconds: float,
    ) -> None:
        """Log collector completion event."""
        self.debug(
            "Collector completed",
            event_type="collector.completed",
            collector_name=collector_name,
            asset_count=asset_count,
            duration_seconds=duration_seconds,
        )


def configure_logging(
    level: str = "INFO",
    format: str = "human",
    output: str = "stderr",
    extra_fields: dict[str, Any] | None = None,
) -> None:
    """
    Configure logging for Stance.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format: Output format (human, json)
        output: Output destination (stderr, stdout)
        extra_fields: Extra fields to include in structured logs
    """
    # Get root logger
    root_logger = logging.getLogger("stance")
    root_logger.setLevel(getattr(logging, level.upper()))

    # Remove existing handlers
    root_logger.handlers.clear()

    # Create handler
    if output == "stdout":
        handler = logging.StreamHandler(sys.stdout)
    else:
        handler = logging.StreamHandler(sys.stderr)

    # Create formatter
    if format == "json":
        formatter = StructuredFormatter(extra_fields=extra_fields)
    else:
        formatter = HumanReadableFormatter()

    handler.setFormatter(formatter)
    root_logger.addHandler(handler)


def get_logger(name: str) -> StanceLogger:
    """
    Get a Stance logger instance.

    Args:
        name: Logger name (typically module name)

    Returns:
        StanceLogger instance
    """
    return StanceLogger(f"stance.{name}")


# Configure logging from environment on import
_log_level = os.getenv("STANCE_LOG_LEVEL", "INFO")
_log_format = os.getenv("STANCE_LOG_FORMAT", "human")
configure_logging(level=_log_level, format=_log_format)
