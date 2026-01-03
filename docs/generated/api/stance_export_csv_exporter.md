# stance.export.csv_exporter

CSV export functionality for Mantissa Stance.

Exports assets, findings, and compliance data to CSV format.

## Contents

### Classes

- [CSVExporter](#csvexporter)

### Functions

- [export_findings_to_csv](#export_findings_to_csv)
- [export_assets_to_csv](#export_assets_to_csv)

## CSVExporter

**Inherits from:** BaseExporter

Exports data to CSV format.

Supports exporting assets, findings, and compliance status
as separate CSV files or combined report.

### Properties

#### `format(self) -> ExportFormat`

**Returns:**

`ExportFormat`

### Methods

#### `export(self, data: ReportData, options: ExportOptions) -> ExportResult`

Export data to CSV format.  For FULL_REPORT, creates a combined CSV with sections. For specific report types, creates focused CSV output.

**Parameters:**

- `data` (`ReportData`) - Report data to export
- `options` (`ExportOptions`) - Export options

**Returns:**

`ExportResult` - ExportResult with CSV content

### `export_findings_to_csv(findings: list[Finding], output_path: Path | str | None) -> ExportResult`

Convenience function to export findings to CSV.

**Parameters:**

- `findings` (`list[Finding]`) - List of findings to export
- `output_path` (`Path | str | None`) - Optional path to write output

**Returns:**

`ExportResult` - ExportResult with CSV content

### `export_assets_to_csv(assets: list[Asset], output_path: Path | str | None) -> ExportResult`

Convenience function to export assets to CSV.

**Parameters:**

- `assets` (`list[Asset]`) - List of assets to export
- `output_path` (`Path | str | None`) - Optional path to write output

**Returns:**

`ExportResult` - ExportResult with CSV content
