"""
PDF export functionality for Mantissa Stance.

Generates PDF reports using HTML as an intermediate format.
Uses webbrowser-based print or optional external tools.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Any

from stance.export.base import (
    BaseExporter,
    ExportFormat,
    ExportOptions,
    ExportResult,
    ReportData,
    ReportType,
)
from stance.export.html_exporter import HTMLExporter


class PDFExporter(BaseExporter):
    """
    Exports data to PDF format.

    Uses HTML as an intermediate format and converts to PDF using
    available system tools (wkhtmltopdf, weasyprint, or browser print).
    """

    @property
    def format(self) -> ExportFormat:
        return ExportFormat.PDF

    def __init__(self):
        """Initialize PDF exporter with HTML exporter."""
        self._html_exporter = HTMLExporter()
        self._pdf_tool: str | None = None
        self._detect_pdf_tool()

    def _detect_pdf_tool(self) -> None:
        """Detect available PDF generation tool."""
        # Check for wkhtmltopdf
        try:
            result = subprocess.run(
                ["wkhtmltopdf", "--version"],
                capture_output=True,
                timeout=5,
            )
            if result.returncode == 0:
                self._pdf_tool = "wkhtmltopdf"
                return
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

        # Check for weasyprint
        try:
            result = subprocess.run(
                ["weasyprint", "--version"],
                capture_output=True,
                timeout=5,
            )
            if result.returncode == 0:
                self._pdf_tool = "weasyprint"
                return
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

        # No tool found - will generate HTML with print instructions
        self._pdf_tool = None

    def export(
        self,
        data: ReportData,
        options: ExportOptions,
    ) -> ExportResult:
        """
        Export data to PDF format.

        If no PDF tool is available, generates HTML with print-friendly
        styling and instructions for manual PDF generation via browser.

        Args:
            data: Report data to export
            options: Export options

        Returns:
            ExportResult with PDF content or fallback HTML
        """
        # Generate HTML first
        html_options = ExportOptions(
            format=ExportFormat.HTML,
            report_type=options.report_type,
            include_charts=options.include_charts,
            include_raw_data=options.include_raw_data,
            severity_filter=options.severity_filter,
            frameworks=options.frameworks,
            title=options.title,
            author=options.author,
        )

        html_result = self._html_exporter.export(data, html_options)

        if not html_result.success:
            return ExportResult(
                success=False,
                format=ExportFormat.PDF,
                error=f"HTML generation failed: {html_result.error}",
            )

        html_content = html_result.content
        if isinstance(html_content, bytes):
            html_content = html_content.decode("utf-8")

        # Try to convert to PDF
        if self._pdf_tool == "wkhtmltopdf":
            return self._convert_with_wkhtmltopdf(html_content, options)
        elif self._pdf_tool == "weasyprint":
            return self._convert_with_weasyprint(html_content, options)
        else:
            # Return HTML with print instructions
            return self._generate_print_ready_html(html_content, options)

    def _convert_with_wkhtmltopdf(
        self,
        html_content: str,
        options: ExportOptions,
    ) -> ExportResult:
        """Convert HTML to PDF using wkhtmltopdf."""
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".html",
                delete=False,
                encoding="utf-8",
            ) as html_file:
                html_file.write(html_content)
                html_path = html_file.name

            if options.output_path:
                pdf_path = str(options.output_path)
            else:
                pdf_file = tempfile.NamedTemporaryFile(
                    suffix=".pdf",
                    delete=False,
                )
                pdf_path = pdf_file.name
                pdf_file.close()

            # Run wkhtmltopdf
            result = subprocess.run(
                [
                    "wkhtmltopdf",
                    "--quiet",
                    "--page-size", "A4",
                    "--margin-top", "20mm",
                    "--margin-bottom", "20mm",
                    "--margin-left", "15mm",
                    "--margin-right", "15mm",
                    "--enable-local-file-access",
                    html_path,
                    pdf_path,
                ],
                capture_output=True,
                timeout=60,
            )

            # Clean up temp HTML
            Path(html_path).unlink(missing_ok=True)

            if result.returncode != 0:
                return ExportResult(
                    success=False,
                    format=ExportFormat.PDF,
                    error=f"wkhtmltopdf failed: {result.stderr.decode()}",
                )

            # Read PDF content if no output path specified
            pdf_content = None
            output_path = None
            if options.output_path:
                output_path = Path(options.output_path)
            else:
                pdf_content = Path(pdf_path).read_bytes()
                Path(pdf_path).unlink(missing_ok=True)

            return ExportResult(
                success=True,
                format=ExportFormat.PDF,
                output_path=output_path,
                content=pdf_content,
                bytes_written=len(pdf_content) if pdf_content else Path(pdf_path).stat().st_size if output_path else 0,
            )

        except Exception as e:
            return ExportResult(
                success=False,
                format=ExportFormat.PDF,
                error=str(e),
            )

    def _convert_with_weasyprint(
        self,
        html_content: str,
        options: ExportOptions,
    ) -> ExportResult:
        """Convert HTML to PDF using weasyprint."""
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".html",
                delete=False,
                encoding="utf-8",
            ) as html_file:
                html_file.write(html_content)
                html_path = html_file.name

            if options.output_path:
                pdf_path = str(options.output_path)
            else:
                pdf_file = tempfile.NamedTemporaryFile(
                    suffix=".pdf",
                    delete=False,
                )
                pdf_path = pdf_file.name
                pdf_file.close()

            # Run weasyprint
            result = subprocess.run(
                ["weasyprint", html_path, pdf_path],
                capture_output=True,
                timeout=60,
            )

            # Clean up temp HTML
            Path(html_path).unlink(missing_ok=True)

            if result.returncode != 0:
                return ExportResult(
                    success=False,
                    format=ExportFormat.PDF,
                    error=f"weasyprint failed: {result.stderr.decode()}",
                )

            # Read PDF content if no output path specified
            pdf_content = None
            output_path = None
            if options.output_path:
                output_path = Path(options.output_path)
            else:
                pdf_content = Path(pdf_path).read_bytes()
                Path(pdf_path).unlink(missing_ok=True)

            return ExportResult(
                success=True,
                format=ExportFormat.PDF,
                output_path=output_path,
                content=pdf_content,
                bytes_written=len(pdf_content) if pdf_content else 0,
            )

        except Exception as e:
            return ExportResult(
                success=False,
                format=ExportFormat.PDF,
                error=str(e),
            )

    def _generate_print_ready_html(
        self,
        html_content: str,
        options: ExportOptions,
    ) -> ExportResult:
        """Generate HTML with print instructions when no PDF tool available."""
        # Add print button and instructions
        print_script = """
        <div class="no-print" style="background: #f5f5f5; padding: 1rem; margin-bottom: 2rem; border: 1px solid #e0e0e0;">
            <h3 style="margin-bottom: 0.5rem;">PDF Export</h3>
            <p style="margin-bottom: 0.5rem;">To save this report as PDF:</p>
            <ol style="margin-left: 1.5rem;">
                <li>Press Ctrl+P (or Cmd+P on Mac) to open print dialog</li>
                <li>Select "Save as PDF" as the destination</li>
                <li>Click Save</li>
            </ol>
            <button onclick="window.print()" style="margin-top: 0.5rem; padding: 0.5rem 1rem; cursor: pointer;">
                Print / Save as PDF
            </button>
        </div>
        """

        # Insert print instructions after body tag
        modified_html = html_content.replace(
            "<body>",
            f"<body>{print_script}",
        )

        # Update output path extension if needed
        output_path = options.output_path
        if output_path:
            path = Path(output_path)
            if path.suffix.lower() == ".pdf":
                output_path = path.with_suffix(".html")

        write_path, content = self._write_output(modified_html, output_path)

        return ExportResult(
            success=True,
            format=ExportFormat.HTML,  # Actually HTML, not PDF
            output_path=write_path,
            content=content,
            bytes_written=len(modified_html.encode("utf-8")),
            error="No PDF tool available. Generated print-ready HTML instead. Install wkhtmltopdf or weasyprint for native PDF generation.",
        )

    def is_pdf_available(self) -> bool:
        """Check if native PDF generation is available."""
        return self._pdf_tool is not None

    def get_pdf_tool(self) -> str | None:
        """Return the name of the detected PDF tool."""
        return self._pdf_tool


def export_to_pdf(
    data: ReportData,
    output_path: Path | str | None = None,
    report_type: ReportType = ReportType.FULL_REPORT,
    title: str = "Mantissa Stance Security Report",
) -> ExportResult:
    """
    Convenience function to export data to PDF.

    Args:
        data: Report data to export
        output_path: Optional path to write output
        report_type: Type of report to generate
        title: Report title

    Returns:
        ExportResult with PDF content (or HTML fallback)
    """
    exporter = PDFExporter()
    options = ExportOptions(
        format=ExportFormat.PDF,
        report_type=report_type,
        output_path=output_path,
        title=title,
    )
    return exporter.export(data, options)
