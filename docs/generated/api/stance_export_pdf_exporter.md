# stance.export.pdf_exporter

PDF export functionality for Mantissa Stance.

Generates PDF reports using HTML as an intermediate format.
Uses webbrowser-based print or optional external tools.

## Contents

### Classes

- [PDFExporter](#pdfexporter)

### Functions

- [export_to_pdf](#export_to_pdf)

## PDFExporter

**Inherits from:** BaseExporter

Exports data to PDF format.

Uses HTML as an intermediate format and converts to PDF using
available system tools (wkhtmltopdf, weasyprint, or browser print).

### Properties

#### `format(self) -> ExportFormat`

**Returns:**

`ExportFormat`

### Methods

#### `__init__(self)`

Initialize PDF exporter with HTML exporter.

#### `export(self, data: ReportData, options: ExportOptions) -> ExportResult`

Export data to PDF format.  If no PDF tool is available, generates HTML with print-friendly styling and instructions for manual PDF generation via browser.

**Parameters:**

- `data` (`ReportData`) - Report data to export
- `options` (`ExportOptions`) - Export options

**Returns:**

`ExportResult` - ExportResult with PDF content or fallback HTML

#### `is_pdf_available(self) -> bool`

Check if native PDF generation is available.

**Returns:**

`bool`

#### `get_pdf_tool(self) -> str | None`

Return the name of the detected PDF tool.

**Returns:**

`str | None`

### `export_to_pdf(data: ReportData, output_path: Path | str | None, report_type: ReportType = "Attribute(value=Name(id='ReportType', ctx=Load()), attr='FULL_REPORT', ctx=Load())", title: str = Mantissa Stance Security Report) -> ExportResult`

Convenience function to export data to PDF.

**Parameters:**

- `data` (`ReportData`) - Report data to export
- `output_path` (`Path | str | None`) - Optional path to write output
- `report_type` (`ReportType`) - default: `"Attribute(value=Name(id='ReportType', ctx=Load()), attr='FULL_REPORT', ctx=Load())"` - Type of report to generate
- `title` (`str`) - default: `Mantissa Stance Security Report` - Report title

**Returns:**

`ExportResult` - ExportResult with PDF content (or HTML fallback)
