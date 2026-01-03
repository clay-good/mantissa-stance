# stance.observability.logging

Structured logging configuration for Mantissa Stance.

Provides consistent, structured logging across all modules
with support for different output formats and log levels.

## Contents

### Classes

- [StructuredFormatter](#structuredformatter)
- [HumanReadableFormatter](#humanreadableformatter)
- [StanceLogger](#stancelogger)

### Functions

- [configure_logging](#configure_logging)
- [get_logger](#get_logger)

## StructuredFormatter

**Inherits from:** logging.Formatter

Formatter that outputs structured JSON logs.

Useful for log aggregation systems like CloudWatch, Stackdriver,
or Azure Monitor.

### Methods

#### `__init__(self, include_timestamp: bool = True, include_level: bool = True, include_logger: bool = True, include_location: bool = False, extra_fields: dict[(str, Any)] | None)`

Initialize structured formatter.

**Parameters:**

- `include_timestamp` (`bool`) - default: `True` - Include timestamp in output
- `include_level` (`bool`) - default: `True` - Include log level in output
- `include_logger` (`bool`) - default: `True` - Include logger name in output
- `include_location` (`bool`) - default: `False` - Include file/line location
- `extra_fields` (`dict[(str, Any)] | None`) - Additional fields to include in every log

#### `format(self, record: logging.LogRecord) -> str`

Format log record as JSON.

**Parameters:**

- `record` (`logging.LogRecord`)

**Returns:**

`str`

## HumanReadableFormatter

**Inherits from:** logging.Formatter

Formatter that outputs human-readable logs.

Useful for local development and CLI usage.

### Methods

#### `__init__(self, use_colors: bool = True, include_timestamp: bool = True, include_level: bool = True)`

Initialize human-readable formatter.

**Parameters:**

- `use_colors` (`bool`) - default: `True` - Use ANSI colors in output
- `include_timestamp` (`bool`) - default: `True` - Include timestamp in output
- `include_level` (`bool`) - default: `True` - Include log level in output

#### `format(self, record: logging.LogRecord) -> str`

Format log record as human-readable text.

**Parameters:**

- `record` (`logging.LogRecord`)

**Returns:**

`str`

## StanceLogger

Wrapper around Python logging for Stance-specific logging.

Provides convenient methods for logging with context and metrics.

### Methods

#### `__init__(self, name: str, level: int = "Attribute(value=Name(id='logging', ctx=Load()), attr='INFO', ctx=Load())")`

Initialize Stance logger.

**Parameters:**

- `name` (`str`) - Logger name
- `level` (`int`) - default: `"Attribute(value=Name(id='logging', ctx=Load()), attr='INFO', ctx=Load())"` - Default log level

#### `set_context(self, **kwargs: Any) -> None`

Set persistent context fields for all logs.

**Parameters:**

- `**kwargs` (`Any`)

**Returns:**

`None`

#### `clear_context(self) -> None`

Clear context fields.

**Returns:**

`None`

#### `debug(self, message: str, **kwargs: Any) -> None`

Log debug message.

**Parameters:**

- `message` (`str`)
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `info(self, message: str, **kwargs: Any) -> None`

Log info message.

**Parameters:**

- `message` (`str`)
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `warning(self, message: str, **kwargs: Any) -> None`

Log warning message.

**Parameters:**

- `message` (`str`)
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `error(self, message: str, exc_info: bool = False, **kwargs: Any) -> None`

Log error message.

**Parameters:**

- `message` (`str`)
- `exc_info` (`bool`) - default: `False`
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `critical(self, message: str, exc_info: bool = False, **kwargs: Any) -> None`

Log critical message.

**Parameters:**

- `message` (`str`)
- `exc_info` (`bool`) - default: `False`
- `**kwargs` (`Any`)

**Returns:**

`None`

#### `scan_started(self, scan_id: str, config_name: str = default, collectors: list[str] | None) -> None`

Log scan start event.

**Parameters:**

- `scan_id` (`str`)
- `config_name` (`str`) - default: `default`
- `collectors` (`list[str] | None`)

**Returns:**

`None`

#### `scan_completed(self, scan_id: str, asset_count: int, finding_count: int, duration_seconds: float) -> None`

Log scan completion event.

**Parameters:**

- `scan_id` (`str`)
- `asset_count` (`int`)
- `finding_count` (`int`)
- `duration_seconds` (`float`)

**Returns:**

`None`

#### `scan_failed(self, scan_id: str, error: str) -> None`

Log scan failure event.

**Parameters:**

- `scan_id` (`str`)
- `error` (`str`)

**Returns:**

`None`

#### `finding_generated(self, finding_id: str, severity: str, rule_id: str, asset_id: str) -> None`

Log finding generation event.

**Parameters:**

- `finding_id` (`str`)
- `severity` (`str`)
- `rule_id` (`str`)
- `asset_id` (`str`)

**Returns:**

`None`

#### `collector_started(self, collector_name: str, region: str = ) -> None`

Log collector start event.

**Parameters:**

- `collector_name` (`str`)
- `region` (`str`) - default: ``

**Returns:**

`None`

#### `collector_completed(self, collector_name: str, asset_count: int, duration_seconds: float) -> None`

Log collector completion event.

**Parameters:**

- `collector_name` (`str`)
- `asset_count` (`int`)
- `duration_seconds` (`float`)

**Returns:**

`None`

### `configure_logging(level: str = INFO, format: str = human, output: str = stderr, extra_fields: dict[(str, Any)] | None) -> None`

Configure logging for Stance.

**Parameters:**

- `level` (`str`) - default: `INFO` - Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `format` (`str`) - default: `human` - Output format (human, json)
- `output` (`str`) - default: `stderr` - Output destination (stderr, stdout)
- `extra_fields` (`dict[(str, Any)] | None`) - Extra fields to include in structured logs

**Returns:**

`None`

### `get_logger(name: str) -> StanceLogger`

Get a Stance logger instance.

**Parameters:**

- `name` (`str`) - Logger name (typically module name)

**Returns:**

`StanceLogger` - StanceLogger instance
