# stance.export

Export and reporting module for Mantissa Stance.

Provides export functionality for generating reports in various formats
including PDF, CSV, JSON, and HTML.

## Contents

### Functions

- [create_export_manager](#create_export_manager)
- [export_report](#export_report)

### `create_export_manager() -> ExportManager`

Create an export manager with all registered exporters.

**Returns:**

`ExportManager` - ExportManager configured with all available exporters.

### `export_report(assets: list, findings: list, output_path: str | None, format: str = json, report_type: str = full_report, title: str = Mantissa Stance Security Report, compliance_scores: dict | None, **kwargs) -> ExportResult`

Export a security report in the specified format.  This is the main convenience function for generating reports.

**Parameters:**

- `assets` (`list`) - List of Asset objects
- `findings` (`list`) - List of Finding objects
- `output_path` (`str | None`) - Optional path to write the report
- `format` (`str`) - default: `json` - Output format ("json", "csv", "html", "pdf")
- `report_type` (`str`) - default: `full_report` - Type of report ("full_report", "executive_summary", "findings_detail", "compliance_summary", "asset_inventory")
- `title` (`str`) - default: `Mantissa Stance Security Report` - Report title
- `compliance_scores` (`dict | None`) - Optional compliance scores by framework **kwargs: Additional options passed to ExportOptions
- `**kwargs`

**Returns:**

`ExportResult` - ExportResult with the generated report

**Examples:**

```python
from stance.export import export_report

    result = export_report(
        assets=collected_assets,
        findings=detected_findings,
        output_path="report.pdf",
        format="pdf",
        report_type="executive_summary",
        title="Q4 Security Assessment"
    )

    if result.success:
        print(f"Report saved to: {result.output_path}")
    else:
        print(f"Export failed: {result.error}")
```
