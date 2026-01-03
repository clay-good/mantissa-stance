# stance.export.base

Base export functionality for Mantissa Stance.

Provides abstract interfaces and common utilities for exporting
data in various formats (PDF, CSV, JSON).

## Contents

### Classes

- [ExportFormat](#exportformat)
- [ReportType](#reporttype)
- [ExportOptions](#exportoptions)
- [ExportResult](#exportresult)
- [ReportData](#reportdata)
- [BaseExporter](#baseexporter)
- [ExportManager](#exportmanager)

## ExportFormat

**Inherits from:** Enum

Supported export formats.

## ReportType

**Inherits from:** Enum

Types of reports that can be generated.

## ExportOptions

**Tags:** dataclass

Options for export operations.

Attributes:
    format: Output format
    report_type: Type of report to generate
    include_charts: Whether to include visual charts (PDF/HTML only)
    include_raw_data: Whether to include raw configuration data
    severity_filter: Only include findings at or above this severity
    frameworks: Compliance frameworks to include (empty = all)
    date_range_days: Number of days of historical data to include
    output_path: Where to write the output
    title: Report title
    author: Report author name

### Attributes

| Name | Type | Default |
|------|------|---------|
| `format` | `ExportFormat` | `"Attribute(value=Name(id='ExportFormat', ctx=Load()), attr='JSON', ctx=Load())"` |
| `report_type` | `ReportType` | `"Attribute(value=Name(id='ReportType', ctx=Load()), attr='FULL_REPORT', ctx=Load())"` |
| `include_charts` | `bool` | `True` |
| `include_raw_data` | `bool` | `False` |
| `severity_filter` | `Severity | None` | - |
| `frameworks` | `list[str]` | `field(...)` |
| `date_range_days` | `int` | `30` |
| `output_path` | `Path | str | None` | - |
| `title` | `str` | `Mantissa Stance Security Report` |
| `author` | `str` | `Mantissa Stance` |

## ExportResult

**Tags:** dataclass

Result of an export operation.

Attributes:
    success: Whether export completed successfully
    format: Format used for export
    output_path: Path to output file (if written to disk)
    content: Export content (if not written to disk)
    bytes_written: Size of output in bytes
    generated_at: When the export was generated
    error: Error message if export failed

### Attributes

| Name | Type | Default |
|------|------|---------|
| `success` | `bool` | - |
| `format` | `ExportFormat` | - |
| `output_path` | `Path | None` | - |
| `content` | `bytes | str | None` | - |
| `bytes_written` | `int` | `0` |
| `generated_at` | `datetime` | `field(...)` |
| `error` | `str | None` | - |

## ReportData

**Tags:** dataclass

Data container for report generation.

Aggregates all data needed for generating reports.

Attributes:
    assets: Asset collection
    findings: Finding collection
    compliance_scores: Compliance scores by framework
    scan_metadata: Metadata about the scan
    trends: Historical trend data
    generated_at: When data was collected

### Attributes

| Name | Type | Default |
|------|------|---------|
| `assets` | `AssetCollection | list[Asset]` | - |
| `findings` | `FindingCollection | list[Finding]` | - |
| `compliance_scores` | `dict[(str, dict[(str, Any)])]` | `field(...)` |
| `scan_metadata` | `dict[(str, Any)]` | `field(...)` |
| `trends` | `dict[(str, list[dict[(str, Any)]])]` | `field(...)` |
| `generated_at` | `datetime` | `field(...)` |

### Methods

#### `get_assets_list(self) -> list[Asset]`

Get assets as a list.

**Returns:**

`list[Asset]`

#### `get_findings_list(self) -> list[Finding]`

Get findings as a list.

**Returns:**

`list[Finding]`

#### `get_finding_counts_by_severity(self) -> dict[(str, int)]`

Get count of findings by severity.

**Returns:**

`dict[(str, int)]`

#### `get_finding_counts_by_status(self) -> dict[(str, int)]`

Get count of findings by status.

**Returns:**

`dict[(str, int)]`

#### `get_asset_counts_by_type(self) -> dict[(str, int)]`

Get count of assets by type.

**Returns:**

`dict[(str, int)]`

#### `get_overall_compliance_score(self) -> float`

Calculate overall compliance score across all frameworks.

**Returns:**

`float`

## BaseExporter

**Inherits from:** ABC

Abstract base class for exporters.

Exporters transform report data into specific output formats.

### Properties

#### `format(self) -> ExportFormat`

**Decorators:** @property, @abstractmethod

Return the export format this exporter produces.

**Returns:**

`ExportFormat`

### Methods

#### `export(self, data: ReportData, options: ExportOptions) -> ExportResult`

**Decorators:** @abstractmethod

Export data in the exporter's format.

**Parameters:**

- `data` (`ReportData`) - Report data to export
- `options` (`ExportOptions`) - Export options

**Returns:**

`ExportResult` - ExportResult with success status and output

## ExportManager

Manages export operations across multiple formats.

Provides a unified interface for exporting data to various formats.

### Methods

#### `__init__(self)`

Initialize export manager with registered exporters.

#### `register_exporter(self, exporter: BaseExporter) -> None`

Register an exporter for its format.

**Parameters:**

- `exporter` (`BaseExporter`)

**Returns:**

`None`

#### `get_exporter(self, format: ExportFormat) -> BaseExporter | None`

Get exporter for a specific format.

**Parameters:**

- `format` (`ExportFormat`)

**Returns:**

`BaseExporter | None`

#### `export(self, data: ReportData, options: ExportOptions) -> ExportResult`

Export data using the appropriate exporter.

**Parameters:**

- `data` (`ReportData`) - Report data to export
- `options` (`ExportOptions`) - Export options (format determines exporter)

**Returns:**

`ExportResult` - ExportResult with success status and output

#### `available_formats(self) -> list[ExportFormat]`

Return list of available export formats.

**Returns:**

`list[ExportFormat]`
