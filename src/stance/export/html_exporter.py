"""
HTML export functionality for Mantissa Stance.

Generates styled HTML reports that can be viewed in browsers
or printed to PDF using browser print functionality.
"""

from __future__ import annotations

from datetime import datetime
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
from stance.models.finding import Finding, Severity


class HTMLExporter(BaseExporter):
    """
    Exports data to styled HTML format.

    Generates professional, printable HTML reports with embedded
    CSS styling. Reports can be printed to PDF using browser
    print functionality.
    """

    @property
    def format(self) -> ExportFormat:
        return ExportFormat.HTML

    def export(
        self,
        data: ReportData,
        options: ExportOptions,
    ) -> ExportResult:
        """
        Export data to HTML format.

        Args:
            data: Report data to export
            options: Export options

        Returns:
            ExportResult with HTML content
        """
        try:
            if options.report_type == ReportType.EXECUTIVE_SUMMARY:
                content = self._generate_executive_summary(data, options)
            elif options.report_type == ReportType.FINDINGS_DETAIL:
                content = self._generate_findings_report(data, options)
            elif options.report_type == ReportType.COMPLIANCE_SUMMARY:
                content = self._generate_compliance_report(data, options)
            else:
                content = self._generate_full_report(data, options)

            output_path, output_content = self._write_output(
                content, options.output_path
            )

            return ExportResult(
                success=True,
                format=ExportFormat.HTML,
                output_path=output_path,
                content=output_content,
                bytes_written=len(content.encode("utf-8")),
            )

        except Exception as e:
            return ExportResult(
                success=False,
                format=ExportFormat.HTML,
                error=str(e),
            )

    def _get_base_styles(self) -> str:
        """Return base CSS styles for reports."""
        return """
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }

            body {
                font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                line-height: 1.6;
                color: #1a1a1a;
                background: #ffffff;
                padding: 2rem;
                max-width: 1200px;
                margin: 0 auto;
            }

            @media print {
                body { padding: 0; }
                .no-print { display: none; }
                .page-break { page-break-before: always; }
            }

            h1 { font-size: 1.75rem; font-weight: 600; margin-bottom: 0.5rem; }
            h2 { font-size: 1.25rem; font-weight: 600; margin: 2rem 0 1rem; border-bottom: 1px solid #e0e0e0; padding-bottom: 0.5rem; }
            h3 { font-size: 1rem; font-weight: 600; margin: 1.5rem 0 0.75rem; }

            .header { margin-bottom: 2rem; }
            .header p { color: #666; font-size: 0.875rem; }

            .summary-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 1rem;
                margin: 1.5rem 0;
            }

            .summary-card {
                background: #f5f5f5;
                padding: 1rem;
                border-radius: 4px;
            }

            .summary-card .value {
                font-size: 2rem;
                font-weight: 700;
                color: #1a1a1a;
            }

            .summary-card .label {
                font-size: 0.875rem;
                color: #666;
            }

            table {
                width: 100%;
                border-collapse: collapse;
                margin: 1rem 0;
                font-size: 0.875rem;
            }

            th, td {
                text-align: left;
                padding: 0.75rem;
                border-bottom: 1px solid #e0e0e0;
            }

            th {
                background: #f5f5f5;
                font-weight: 600;
            }

            tr:hover { background: #fafafa; }

            .severity-critical { color: #1a1a1a; font-weight: 700; }
            .severity-high { color: #4a4a4a; font-weight: 600; }
            .severity-medium { color: #666; }
            .severity-low { color: #888; }
            .severity-info { color: #aaa; }

            .badge {
                display: inline-block;
                padding: 0.125rem 0.5rem;
                font-size: 0.75rem;
                font-weight: 500;
                border-radius: 2px;
                text-transform: uppercase;
            }

            .badge-critical { background: #1a1a1a; color: #fff; }
            .badge-high { background: #4a4a4a; color: #fff; }
            .badge-medium { background: #888; color: #fff; }
            .badge-low { background: #ccc; color: #333; }
            .badge-info { background: #eee; color: #666; }

            .status-open { color: #1a1a1a; }
            .status-resolved { color: #666; }
            .status-suppressed { color: #999; }

            .score-bar {
                background: #e0e0e0;
                height: 8px;
                border-radius: 4px;
                overflow: hidden;
            }

            .score-fill {
                background: #1a1a1a;
                height: 100%;
            }

            .finding-card {
                border: 1px solid #e0e0e0;
                margin: 1rem 0;
                padding: 1rem;
            }

            .finding-card .title {
                font-weight: 600;
                margin-bottom: 0.5rem;
            }

            .finding-card .meta {
                font-size: 0.875rem;
                color: #666;
            }

            .finding-card .description {
                margin-top: 0.75rem;
                font-size: 0.875rem;
            }

            .footer {
                margin-top: 3rem;
                padding-top: 1rem;
                border-top: 1px solid #e0e0e0;
                font-size: 0.75rem;
                color: #999;
            }
        </style>
        """

    def _generate_header(self, options: ExportOptions, generated_at: datetime) -> str:
        """Generate report header."""
        return f"""
        <div class="header">
            <h1>{self._escape_html(options.title)}</h1>
            <p>Generated: {generated_at.strftime('%Y-%m-%d %H:%M UTC')}</p>
            <p>Author: {self._escape_html(options.author)}</p>
        </div>
        """

    def _generate_footer(self) -> str:
        """Generate report footer."""
        return """
        <div class="footer">
            <p>Generated by Mantissa Stance - Cloud Security Posture Management</p>
        </div>
        """

    def _generate_executive_summary(
        self,
        data: ReportData,
        options: ExportOptions,
    ) -> str:
        """Generate executive summary HTML."""
        findings = data.get_findings_list()
        assets = data.get_assets_list()
        severity_counts = data.get_finding_counts_by_severity()
        compliance_score = data.get_overall_compliance_score()

        # Calculate key metrics
        internet_facing = len([a for a in assets if a.is_internet_facing()])
        critical_high = severity_counts.get("critical", 0) + severity_counts.get("high", 0)

        summary_cards = f"""
        <div class="summary-grid">
            <div class="summary-card">
                <div class="value">{len(assets)}</div>
                <div class="label">Total Assets</div>
            </div>
            <div class="summary-card">
                <div class="value">{internet_facing}</div>
                <div class="label">Internet Facing</div>
            </div>
            <div class="summary-card">
                <div class="value">{len(findings)}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="summary-card">
                <div class="value">{critical_high}</div>
                <div class="label">Critical/High</div>
            </div>
            <div class="summary-card">
                <div class="value">{compliance_score:.0f}%</div>
                <div class="label">Compliance Score</div>
            </div>
        </div>
        """

        # Severity breakdown table
        severity_table = """
        <h2>Findings by Severity</h2>
        <table>
            <thead>
                <tr><th>Severity</th><th>Count</th><th>Percentage</th></tr>
            </thead>
            <tbody>
        """
        total = len(findings) or 1
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            pct = (count / total) * 100
            severity_table += f"""
                <tr>
                    <td><span class="badge badge-{sev}">{sev}</span></td>
                    <td>{count}</td>
                    <td>{pct:.1f}%</td>
                </tr>
            """
        severity_table += "</tbody></table>"

        # Compliance scores
        compliance_section = ""
        if data.compliance_scores:
            compliance_section = "<h2>Compliance Scores</h2>"
            for framework, fw_data in data.compliance_scores.items():
                score = fw_data.get("score", 0)
                compliance_section += f"""
                <div style="margin: 0.5rem 0;">
                    <div style="display: flex; justify-content: space-between;">
                        <span>{self._escape_html(framework)}</span>
                        <span>{score:.0f}%</span>
                    </div>
                    <div class="score-bar">
                        <div class="score-fill" style="width: {score}%;"></div>
                    </div>
                </div>
                """

        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <title>{self._escape_html(options.title)} - Executive Summary</title>
            {self._get_base_styles()}
        </head>
        <body>
            {self._generate_header(options, data.generated_at)}
            <h2>Executive Summary</h2>
            {summary_cards}
            {severity_table}
            {compliance_section}
            {self._generate_footer()}
        </body>
        </html>
        """

    def _generate_findings_report(
        self,
        data: ReportData,
        options: ExportOptions,
    ) -> str:
        """Generate findings detail HTML."""
        findings = self._filter_findings(
            data.get_findings_list(),
            options.severity_filter,
        )

        # Group by severity
        by_severity: dict[str, list[Finding]] = {}
        for f in findings:
            sev = f.severity.value
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(f)

        findings_html = ""
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev not in by_severity:
                continue

            findings_html += f'<h2 class="page-break"><span class="badge badge-{sev}">{sev.upper()}</span> Findings ({len(by_severity[sev])})</h2>'

            for finding in by_severity[sev]:
                findings_html += f"""
                <div class="finding-card">
                    <div class="title">{self._escape_html(finding.title)}</div>
                    <div class="meta">
                        Asset: {self._escape_html(finding.asset_id)} |
                        Rule: {self._escape_html(finding.rule_id or 'N/A')} |
                        Status: <span class="status-{finding.status.value}">{finding.status.value}</span>
                    </div>
                    <div class="description">{self._escape_html(finding.description)}</div>
                </div>
                """

        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <title>{self._escape_html(options.title)} - Findings Detail</title>
            {self._get_base_styles()}
        </head>
        <body>
            {self._generate_header(options, data.generated_at)}
            <h2>Findings Report</h2>
            <p>Total Findings: {len(findings)}</p>
            {findings_html}
            {self._generate_footer()}
        </body>
        </html>
        """

    def _generate_compliance_report(
        self,
        data: ReportData,
        options: ExportOptions,
    ) -> str:
        """Generate compliance summary HTML."""
        frameworks = options.frameworks or list(data.compliance_scores.keys())

        compliance_html = ""
        for framework in frameworks:
            if framework not in data.compliance_scores:
                continue

            fw_data = data.compliance_scores[framework]
            score = fw_data.get("score", 0)
            controls = fw_data.get("controls", [])

            compliance_html += f"""
            <h2 class="page-break">{self._escape_html(framework)}</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <div class="value">{score:.0f}%</div>
                    <div class="label">Overall Score</div>
                </div>
                <div class="summary-card">
                    <div class="value">{len([c for c in controls if c.get('status') == 'pass'])}</div>
                    <div class="label">Passing Controls</div>
                </div>
                <div class="summary-card">
                    <div class="value">{len([c for c in controls if c.get('status') == 'fail'])}</div>
                    <div class="label">Failing Controls</div>
                </div>
            </div>
            """

            if controls:
                compliance_html += """
                <table>
                    <thead>
                        <tr>
                            <th>Control</th>
                            <th>Name</th>
                            <th>Status</th>
                            <th>Resources</th>
                        </tr>
                    </thead>
                    <tbody>
                """
                for control in controls:
                    status = control.get("status", "unknown")
                    status_class = "severity-low" if status == "pass" else "severity-critical"
                    evaluated = control.get("resources_evaluated", 0)
                    compliant = control.get("resources_compliant", 0)

                    compliance_html += f"""
                    <tr>
                        <td>{self._escape_html(control.get('control_id', ''))}</td>
                        <td>{self._escape_html(control.get('control_name', ''))}</td>
                        <td class="{status_class}">{status.upper()}</td>
                        <td>{compliant}/{evaluated}</td>
                    </tr>
                    """
                compliance_html += "</tbody></table>"

        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <title>{self._escape_html(options.title)} - Compliance Report</title>
            {self._get_base_styles()}
        </head>
        <body>
            {self._generate_header(options, data.generated_at)}
            <h2>Compliance Summary</h2>
            <p>Overall Score: {data.get_overall_compliance_score():.0f}%</p>
            {compliance_html}
            {self._generate_footer()}
        </body>
        </html>
        """

    def _generate_full_report(
        self,
        data: ReportData,
        options: ExportOptions,
    ) -> str:
        """Generate full comprehensive HTML report."""
        findings = self._filter_findings(
            data.get_findings_list(),
            options.severity_filter,
        )
        assets = data.get_assets_list()
        severity_counts = data.get_finding_counts_by_severity()
        asset_counts = data.get_asset_counts_by_type()

        # Summary section
        summary_html = f"""
        <h2>Summary</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <div class="value">{len(assets)}</div>
                <div class="label">Total Assets</div>
            </div>
            <div class="summary-card">
                <div class="value">{len(findings)}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="summary-card">
                <div class="value">{severity_counts.get('critical', 0)}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card">
                <div class="value">{severity_counts.get('high', 0)}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card">
                <div class="value">{data.get_overall_compliance_score():.0f}%</div>
                <div class="label">Compliance</div>
            </div>
        </div>
        """

        # Findings table
        findings_table = """
        <h2 class="page-break">Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Title</th>
                    <th>Asset</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
        """
        for finding in sorted(findings, key=lambda f: self._severity_order(f.severity)):
            findings_table += f"""
            <tr>
                <td><span class="badge badge-{finding.severity.value}">{finding.severity.value}</span></td>
                <td>{self._escape_html(finding.title)}</td>
                <td>{self._escape_html(finding.asset_id[:50])}</td>
                <td class="status-{finding.status.value}">{finding.status.value}</td>
            </tr>
            """
        findings_table += "</tbody></table>"

        # Assets table
        assets_table = """
        <h2 class="page-break">Assets</h2>
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Region</th>
                    <th>Exposure</th>
                </tr>
            </thead>
            <tbody>
        """
        for asset in assets:
            assets_table += f"""
            <tr>
                <td>{self._escape_html(asset.name)}</td>
                <td>{self._escape_html(asset.resource_type)}</td>
                <td>{self._escape_html(asset.region)}</td>
                <td>{self._escape_html(asset.network_exposure)}</td>
            </tr>
            """
        assets_table += "</tbody></table>"

        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <title>{self._escape_html(options.title)}</title>
            {self._get_base_styles()}
        </head>
        <body>
            {self._generate_header(options, data.generated_at)}
            {summary_html}
            {findings_table}
            {assets_table}
            {self._generate_footer()}
        </body>
        </html>
        """

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        if not text:
            return ""
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )

    def _severity_order(self, severity: Severity) -> int:
        """Get severity order for sorting."""
        order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return order.get(severity, 5)


def export_to_html(
    data: ReportData,
    output_path: Path | str | None = None,
    report_type: ReportType = ReportType.FULL_REPORT,
    title: str = "Mantissa Stance Security Report",
) -> ExportResult:
    """
    Convenience function to export data to HTML.

    Args:
        data: Report data to export
        output_path: Optional path to write output
        report_type: Type of report to generate
        title: Report title

    Returns:
        ExportResult with HTML content
    """
    exporter = HTMLExporter()
    options = ExportOptions(
        format=ExportFormat.HTML,
        report_type=report_type,
        output_path=output_path,
        title=title,
    )
    return exporter.export(data, options)
