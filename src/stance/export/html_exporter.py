"""
HTML export functionality for Mantissa Stance.

Generates styled, interactive HTML reports using the unified
design system shared with the web dashboard.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from stance.export.base import (
    BaseExporter,
    ExportFormat,
    ExportOptions,
    ExportResult,
    ReportData,
    ReportType,
)
from stance.models.finding import Finding, Severity, FindingStatus
from stance.ui.styles import get_full_stylesheet
from stance.ui.components import (
    render_header,
    render_footer,
    render_metric_grid,
    render_tabs,
    render_tab_content,
    render_section_header,
    render_data_table,
    render_finding_card,
    render_badge,
    render_status_badge,
    render_chart_container,
    render_severity_bar,
    render_status_summary,
    render_progress_bar,
    render_empty_state,
)
from stance.ui.charts import (
    render_severity_bar_chart,
    render_donut_chart,
    render_compliance_gauge,
)
from stance.ui.design_tokens import Colors


class HTMLExporter(BaseExporter):
    """
    Exports data to styled, interactive HTML format.

    Uses the unified Mantissa Stance design system for consistent
    visual appearance with the web dashboard.
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
            elif options.report_type == ReportType.ASSET_INVENTORY:
                content = self._generate_asset_inventory(data, options)
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

    def _get_tab_scripts(self) -> str:
        """Return JavaScript for tab functionality."""
        return """
        <script>
            function showTab(tabId) {
                // Hide all tab contents
                document.querySelectorAll('.stance-tab-content').forEach(el => {
                    el.classList.remove('stance-tab-content--active');
                });
                // Remove active from all tabs
                document.querySelectorAll('.stance-tabs__tab').forEach(el => {
                    el.classList.remove('stance-tabs__tab--active');
                    el.setAttribute('aria-selected', 'false');
                });
                // Show selected tab content
                const tabContent = document.getElementById(tabId);
                if (tabContent) {
                    tabContent.classList.add('stance-tab-content--active');
                }
                // Mark tab as active
                const activeTab = document.querySelector(`[onclick="showTab('${tabId}')"]`);
                if (activeTab) {
                    activeTab.classList.add('stance-tabs__tab--active');
                    activeTab.setAttribute('aria-selected', 'true');
                }
            }

            // Initialize first tab as active on load
            document.addEventListener('DOMContentLoaded', function() {
                const firstTab = document.querySelector('.stance-tabs__tab');
                if (firstTab) {
                    const tabId = firstTab.getAttribute('onclick').match(/'([^']+)'/)[1];
                    showTab(tabId);
                }
            });
        </script>
        """

    def _generate_html_document(
        self,
        title: str,
        body_content: str,
        include_tabs: bool = False,
    ) -> str:
        """Generate complete HTML document with design system styles."""
        scripts = self._get_tab_scripts() if include_tabs else ""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="generator" content="Mantissa Stance">
    <title>{self._escape_html(title)}</title>
    <style>
{get_full_stylesheet()}
    </style>
</head>
<body>
    <div class="stance-container">
        {body_content}
    </div>
    {scripts}
</body>
</html>"""

    def _get_summary_metrics(self, data: ReportData) -> List[Dict[str, Any]]:
        """Get summary metrics for cards."""
        findings = data.get_findings_list()
        assets = data.get_assets_list()
        severity_counts = data.get_finding_counts_by_severity()
        compliance_score = data.get_overall_compliance_score()

        return [
            {"value": len(assets), "label": "Assets Scanned"},
            {"value": len(findings), "label": "Total Findings"},
            {"value": severity_counts.get("critical", 0), "label": "Critical", "variant": "critical"},
            {"value": severity_counts.get("high", 0), "label": "High", "variant": "high"},
            {"value": severity_counts.get("medium", 0), "label": "Medium", "variant": "medium"},
            {"value": f"{compliance_score:.0f}%", "label": "Compliance", "variant": "success"},
        ]

    def _get_status_counts(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by status."""
        counts = {"open": 0, "resolved": 0, "suppressed": 0, "false_positive": 0}
        for f in findings:
            status_key = f.status.value if hasattr(f.status, "value") else str(f.status)
            if status_key in counts:
                counts[status_key] += 1
        return counts

    def _render_findings_table(
        self,
        findings: List[Finding],
        limit: Optional[int] = None,
    ) -> str:
        """Render a findings table."""
        if not findings:
            return render_empty_state(message="No findings to display")

        sorted_findings = sorted(findings, key=lambda f: self._severity_order(f.severity))
        if limit:
            sorted_findings = sorted_findings[:limit]

        columns = [
            {"key": "severity", "label": "Severity", "width": "100px"},
            {"key": "finding", "label": "Finding"},
            {"key": "asset", "label": "Asset", "width": "250px"},
            {"key": "status", "label": "Status", "width": "130px"},
        ]

        rows = []
        for f in sorted_findings:
            sev = f.severity.value
            status = f.status.value if hasattr(f.status, "value") else str(f.status)

            # Build asset context string with available fields
            asset_parts = []
            if f.resource_name:
                asset_parts.append(f.resource_name)
            if f.resource_type:
                asset_parts.append(f.resource_type)
            asset_context = " / ".join(asset_parts) if asset_parts else f.asset_id
            location_parts = []
            if f.cloud_provider:
                location_parts.append(f.cloud_provider)
            if f.region:
                location_parts.append(f.region)
            if f.account_id:
                location_parts.append(f.account_id)
            location_str = " / ".join(location_parts)

            rows.append({
                "severity": render_badge(sev, sev),
                "finding": f"""
                    <div class="stance-table__title">{self._escape_html(f.title)}</div>
                    <div class="stance-table__subtitle">{self._escape_html(f.rule_id or 'N/A')}</div>
                """,
                "asset": f"""
                    <div class="stance-table__title">{self._escape_html(self._truncate(asset_context, 50))}</div>
                    <div class="stance-table__subtitle">{self._escape_html(location_str)}</div>
                """,
                "status": render_status_badge(status),
            })

        return render_data_table(columns, rows)

    def _render_finding_cards(
        self,
        findings: List[Finding],
        severity_filter: Optional[str] = None,
    ) -> str:
        """Render finding detail cards."""
        if severity_filter:
            findings = [f for f in findings if f.severity.value == severity_filter]

        if not findings:
            msg = f"No {severity_filter} findings" if severity_filter else "No findings"
            return render_empty_state(message=msg)

        sorted_findings = sorted(findings, key=lambda f: self._severity_order(f.severity))

        cards = []
        for f in sorted_findings:
            cards.append(render_finding_card(
                title=f.title,
                description=f.description,
                severity=f.severity.value,
                status=f.status.value if hasattr(f.status, "value") else str(f.status),
                rule_id=f.rule_id,
                asset_id=f.asset_id,
                first_seen=f.first_seen,
                remediation=f.remediation_guidance,
            ))

        return "".join(cards)

    def _generate_executive_summary(
        self,
        data: ReportData,
        options: ExportOptions,
    ) -> str:
        """Generate executive summary HTML."""
        findings = data.get_findings_list()
        severity_counts = data.get_finding_counts_by_severity()
        status_counts = self._get_status_counts(findings)
        critical_high = [f for f in findings if f.severity.value in ["critical", "high"]]

        body = f"""
        {render_header(
            title=options.title,
            subtitle="Executive Summary",
            generated_at=data.generated_at,
            author=options.author,
        )}

        {render_metric_grid(self._get_summary_metrics(data))}

        {render_chart_container(
            "Findings by Severity",
            render_severity_bar(severity_counts)
        )}

        {render_chart_container(
            "Findings by Status",
            render_status_summary(status_counts)
        )}

        <section class="stance-section">
            {render_section_header("Priority Findings", count=len(critical_high))}
            {self._render_findings_table(critical_high, limit=20)}
        </section>

        {render_footer("This report contains confidential security information.")}
        """

        return self._generate_html_document(
            title=f"{options.title} - Executive Summary",
            body_content=body,
        )

    def _generate_findings_report(
        self,
        data: ReportData,
        options: ExportOptions,
    ) -> str:
        """Generate detailed findings report HTML."""
        findings = self._filter_findings(
            data.get_findings_list(),
            options.severity_filter,
        )
        severity_counts = data.get_finding_counts_by_severity()
        status_counts = self._get_status_counts(findings)

        tabs = [
            {"id": "all-findings", "label": "All Findings", "count": len(findings)},
            {"id": "critical", "label": "Critical", "count": severity_counts.get("critical", 0)},
            {"id": "high", "label": "High", "count": severity_counts.get("high", 0)},
            {"id": "medium", "label": "Medium", "count": severity_counts.get("medium", 0)},
            {"id": "low", "label": "Low", "count": severity_counts.get("low", 0)},
        ]

        body = f"""
        {render_header(
            title=options.title,
            subtitle="Findings Detail Report",
            generated_at=data.generated_at,
            author=options.author,
        )}

        {render_metric_grid(self._get_summary_metrics(data))}

        {render_chart_container(
            "Findings by Severity",
            render_severity_bar(severity_counts)
        )}

        {render_chart_container(
            "Findings by Status",
            render_status_summary(status_counts)
        )}

        {render_tabs(tabs, active_tab="all-findings")}

        {render_tab_content("all-findings", f'''
            {render_section_header("All Findings", count=len(findings))}
            {self._render_finding_cards(findings)}
        ''', is_active=True)}

        {render_tab_content("critical", f'''
            {render_section_header("Critical Findings", count=severity_counts.get("critical", 0))}
            {self._render_finding_cards(findings, "critical")}
        ''')}

        {render_tab_content("high", f'''
            {render_section_header("High Severity Findings", count=severity_counts.get("high", 0))}
            {self._render_finding_cards(findings, "high")}
        ''')}

        {render_tab_content("medium", f'''
            {render_section_header("Medium Severity Findings", count=severity_counts.get("medium", 0))}
            {self._render_finding_cards(findings, "medium")}
        ''')}

        {render_tab_content("low", f'''
            {render_section_header("Low Severity Findings", count=severity_counts.get("low", 0))}
            {self._render_finding_cards(findings, "low")}
        ''')}

        {render_footer("This report contains confidential security information.")}
        """

        return self._generate_html_document(
            title=f"{options.title} - Findings Detail",
            body_content=body,
            include_tabs=True,
        )

    def _generate_compliance_report(
        self,
        data: ReportData,
        options: ExportOptions,
    ) -> str:
        """Generate compliance summary HTML."""
        compliance_score = data.get_overall_compliance_score()
        frameworks = options.frameworks or list(data.compliance_scores.keys())

        # Build framework sections
        framework_sections = []
        for framework in frameworks:
            if framework not in data.compliance_scores:
                continue

            fw_data = data.compliance_scores[framework]
            score = fw_data.get("score", 0)
            controls = fw_data.get("controls", [])

            # Build controls table if available
            controls_html = ""
            if controls:
                columns = [
                    {"key": "control_id", "label": "Control ID", "width": "120px"},
                    {"key": "control_name", "label": "Control Name"},
                    {"key": "status", "label": "Status", "width": "100px"},
                    {"key": "resources", "label": "Resources", "width": "100px"},
                ]

                rows = []
                for control in controls:
                    status = control.get("status", "unknown")
                    evaluated = control.get("resources_evaluated", 0)
                    compliant = control.get("resources_compliant", 0)

                    rows.append({
                        "control_id": self._escape_html(control.get("control_id", "")),
                        "control_name": self._escape_html(control.get("control_name", "")),
                        "status": render_badge(status.upper(), "success" if status == "pass" else "critical"),
                        "resources": f"{compliant}/{evaluated}",
                    })

                controls_html = render_data_table(columns, rows)

            framework_sections.append(f"""
            <div class="stance-chart">
                <h3 class="stance-chart__title">{self._escape_html(framework)}</h3>
                <div style="margin: 16px 0;">
                    {render_progress_bar(score, label=framework)}
                </div>
                {controls_html}
            </div>
            """)

        body = f"""
        {render_header(
            title=options.title,
            subtitle="Compliance Report",
            generated_at=data.generated_at,
            author=options.author,
        )}

        <div class="stance-summary-grid" style="grid-template-columns: repeat(3, 1fr);">
            <div class="stance-card stance-card--summary">
                {render_compliance_gauge(compliance_score, label="Overall Score")}
            </div>
            <div class="stance-card stance-card--summary">
                <div class="stance-card__value">{len(frameworks)}</div>
                <div class="stance-card__label">Frameworks Evaluated</div>
            </div>
            <div class="stance-card stance-card--summary stance-card--success">
                <div class="stance-card__value">{compliance_score:.0f}%</div>
                <div class="stance-card__label">Average Compliance</div>
            </div>
        </div>

        {render_section_header("Framework Compliance")}
        {"".join(framework_sections) if framework_sections else render_empty_state("No compliance data available")}

        {render_footer("This report contains confidential security information.")}
        """

        return self._generate_html_document(
            title=f"{options.title} - Compliance Report",
            body_content=body,
        )

    def _generate_asset_inventory(
        self,
        data: ReportData,
        options: ExportOptions,
    ) -> str:
        """Generate asset inventory HTML."""
        assets = data.get_assets_list()
        asset_counts = data.get_asset_counts_by_type()

        # Asset type summary table
        type_columns = [
            {"key": "type", "label": "Asset Type"},
            {"key": "count", "label": "Count", "width": "100px"},
        ]
        type_rows = [
            {"type": self._escape_html(t), "count": c}
            for t, c in sorted(asset_counts.items(), key=lambda x: -x[1])
        ]

        # Asset detail table
        asset_columns = [
            {"key": "name", "label": "Name"},
            {"key": "type", "label": "Type", "width": "150px"},
            {"key": "region", "label": "Region", "width": "120px"},
            {"key": "exposure", "label": "Exposure", "width": "100px"},
        ]

        asset_rows = []
        for asset in assets[:100]:
            exposure = getattr(asset, "network_exposure", "N/A")
            asset_rows.append({
                "name": f'<span style="font-weight: 500">{self._escape_html(asset.name)}</span>',
                "type": self._escape_html(asset.resource_type),
                "region": self._escape_html(asset.region),
                "exposure": self._escape_html(str(exposure)),
            })

        tabs = [
            {"id": "summary", "label": "Summary by Type", "count": len(asset_counts)},
            {"id": "details", "label": "Asset Details", "count": len(assets)},
        ]

        body = f"""
        {render_header(
            title=options.title,
            subtitle="Asset Inventory",
            generated_at=data.generated_at,
            author=options.author,
        )}

        {render_metric_grid([
            {"value": len(assets), "label": "Total Assets"},
            {"value": len(asset_counts), "label": "Asset Types"},
        ])}

        {render_tabs(tabs, active_tab="summary")}

        {render_tab_content("summary", f'''
            {render_section_header("Assets by Type", count=len(asset_counts))}
            {render_data_table(type_columns, type_rows)}
        ''', is_active=True)}

        {render_tab_content("details", f'''
            {render_section_header("Asset Details", count=len(assets))}
            {render_data_table(asset_columns, asset_rows)}
            {'<p style="margin-top: 16px; color: var(--color-text-secondary);">Showing first 100 assets.</p>' if len(assets) > 100 else ''}
        ''')}

        {render_footer("This report contains confidential security information.")}
        """

        return self._generate_html_document(
            title=f"{options.title} - Asset Inventory",
            body_content=body,
            include_tabs=True,
        )

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
        status_counts = self._get_status_counts(findings)

        critical_high = [f for f in findings if f.severity.value in ["critical", "high"]]

        tabs = [
            {"id": "overview", "label": "Overview"},
            {"id": "findings", "label": "Findings", "count": len(findings)},
            {"id": "by-status", "label": "By Status"},
            {"id": "assets", "label": "Assets", "count": len(assets)},
        ]

        # Asset table
        asset_columns = [
            {"key": "name", "label": "Name"},
            {"key": "type", "label": "Type", "width": "150px"},
            {"key": "region", "label": "Region", "width": "120px"},
        ]
        asset_rows = []
        for asset in assets[:100]:
            asset_rows.append({
                "name": f'<span style="font-weight: 500">{self._escape_html(asset.name)}</span>',
                "type": self._escape_html(asset.resource_type),
                "region": self._escape_html(asset.region),
            })

        body = f"""
        {render_header(
            title=options.title,
            subtitle="Security Assessment Report",
            generated_at=data.generated_at,
            author=options.author,
        )}

        {render_metric_grid(self._get_summary_metrics(data))}

        {render_tabs(tabs, active_tab="overview")}

        {render_tab_content("overview", f'''
            {render_chart_container("Findings by Severity", render_severity_bar(severity_counts))}
            {render_chart_container("Findings by Status", render_status_summary(status_counts))}
            {render_section_header("Priority Findings", count=len(critical_high))}
            {self._render_findings_table(critical_high, limit=10)}
        ''', is_active=True)}

        {render_tab_content("findings", f'''
            {render_section_header("All Findings", count=len(findings))}
            {self._render_findings_table(findings)}
        ''')}

        {render_tab_content("by-status", f'''
            {render_section_header("Findings by Status")}

            <h3 style="margin: 24px 0 16px; color: var(--color-status-open);">Open ({status_counts["open"]})</h3>
            {self._render_findings_table([f for f in findings if f.status.value == "open"])}

            <h3 style="margin: 24px 0 16px; color: var(--color-status-resolved);">Resolved ({status_counts["resolved"]})</h3>
            {self._render_findings_table([f for f in findings if f.status.value == "resolved"])}

            <h3 style="margin: 24px 0 16px; color: var(--color-status-suppressed);">Suppressed ({status_counts["suppressed"]})</h3>
            {self._render_findings_table([f for f in findings if f.status.value == "suppressed"])}

            <h3 style="margin: 24px 0 16px; color: var(--color-status-false-positive);">False Positive ({status_counts["false_positive"]})</h3>
            {self._render_findings_table([f for f in findings if f.status.value == "false_positive"])}
        ''')}

        {render_tab_content("assets", f'''
            {render_section_header("Assets Scanned", count=len(assets))}
            {render_data_table(asset_columns, asset_rows)}
            {'<p style="margin-top: 16px; color: var(--color-text-secondary);">Showing first 100 assets.</p>' if len(assets) > 100 else ''}
        ''')}

        {render_footer("This report contains confidential security information.")}
        """

        return self._generate_html_document(
            title=options.title,
            body_content=body,
            include_tabs=True,
        )

    def _escape_html(self, text: Any) -> str:
        """Escape HTML special characters."""
        if text is None:
            return ""
        return (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )

    def _truncate(self, text: str, max_length: int = 50) -> str:
        """Truncate text with ellipsis."""
        if not text or len(text) <= max_length:
            return text
        return text[:max_length] + "..."

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
