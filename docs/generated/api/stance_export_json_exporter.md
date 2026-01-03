# stance.export.json_exporter

JSON export functionality for Mantissa Stance.

Exports assets, findings, and compliance data to JSON format.

## Contents

### Classes

- [JSONExporter](#jsonexporter)

### Functions

- [export_to_json](#export_to_json)

## JSONExporter

**Inherits from:** BaseExporter

Exports data to JSON format.

Produces API-compatible JSON output with full data fidelity.

### Properties

#### `format(self) -> ExportFormat`

**Returns:**

`ExportFormat`

### Methods

#### `export(self, data: ReportData, options: ExportOptions) -> ExportResult`

Export data to JSON format.

**Parameters:**

- `data` (`ReportData`) - Report data to export
- `options` (`ExportOptions`) - Export options

**Returns:**

`ExportResult` - ExportResult with JSON content

### `export_to_json(data: ReportData, output_path: Path | str | None, report_type: ReportType = "Attribute(value=Name(id='ReportType', ctx=Load()), attr='FULL_REPORT', ctx=Load())", include_raw_data: bool = False) -> ExportResult`

Convenience function to export data to JSON.

**Parameters:**

- `data` (`ReportData`) - Report data to export
- `output_path` (`Path | str | None`) - Optional path to write output
- `report_type` (`ReportType`) - default: `"Attribute(value=Name(id='ReportType', ctx=Load()), attr='FULL_REPORT', ctx=Load())"` - Type of report to generate
- `include_raw_data` (`bool`) - default: `False` - Whether to include raw asset configurations

**Returns:**

`ExportResult` - ExportResult with JSON content
