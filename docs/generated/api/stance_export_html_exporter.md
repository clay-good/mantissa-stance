# stance.export.html_exporter

HTML export functionality for Mantissa Stance.

Generates styled HTML reports that can be viewed in browsers
or printed to PDF using browser print functionality.

## Contents

### Classes

- [HTMLExporter](#htmlexporter)

### Functions

- [export_to_html](#export_to_html)

## HTMLExporter

**Inherits from:** BaseExporter

Exports data to styled HTML format.

Generates professional, printable HTML reports with embedded
CSS styling. Reports can be printed to PDF using browser
print functionality.

### Properties

#### `format(self) -> ExportFormat`

**Returns:**

`ExportFormat`

### Methods

#### `export(self, data: ReportData, options: ExportOptions) -> ExportResult`

Export data to HTML format.

**Parameters:**

- `data` (`ReportData`) - Report data to export
- `options` (`ExportOptions`) - Export options

**Returns:**

`ExportResult` - ExportResult with HTML content

### `export_to_html(data: ReportData, output_path: Path | str | None, report_type: ReportType = "Attribute(value=Name(id='ReportType', ctx=Load()), attr='FULL_REPORT', ctx=Load())", title: str = Mantissa Stance Security Report) -> ExportResult`

Convenience function to export data to HTML.

**Parameters:**

- `data` (`ReportData`) - Report data to export
- `output_path` (`Path | str | None`) - Optional path to write output
- `report_type` (`ReportType`) - default: `"Attribute(value=Name(id='ReportType', ctx=Load()), attr='FULL_REPORT', ctx=Load())"` - Type of report to generate
- `title` (`str`) - default: `Mantissa Stance Security Report` - Report title

**Returns:**

`ExportResult` - ExportResult with HTML content
