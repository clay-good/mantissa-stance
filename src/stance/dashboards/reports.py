"""
Report generation and templates for Mantissa Stance.

Provides report templates, section builders, and report generation.

Part of Phase 91: Advanced Reporting & Dashboards
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import time

from stance.dashboards.models import (
    ReportConfig,
    ReportFormat,
    ReportSection,
    GeneratedReport,
    TimeRange,
)
from stance.dashboards.visualizations import (
    ChartData,
    SVGRenderer,
    ASCIIRenderer,
    create_severity_chart,
    create_compliance_chart,
    create_trend_chart,
)


# =============================================================================
# Report Section Builders
# =============================================================================

class SectionBuilder(ABC):
    """Abstract base class for report section builders."""

    def __init__(self, section_id: str, title: str):
        self.section_id = section_id
        self.title = title

    @abstractmethod
    def build(self, data: Dict[str, Any]) -> ReportSection:
        """Build the report section from data."""
        pass

    def _format_number(self, value: float, decimals: int = 0) -> str:
        """Format a number for display."""
        if decimals == 0:
            return f"{value:,.0f}"
        return f"{value:,.{decimals}f}"

    def _format_percentage(self, value: float) -> str:
        """Format a percentage."""
        return f"{value:.1f}%"

    def _format_date(self, dt: datetime) -> str:
        """Format a datetime."""
        return dt.strftime("%Y-%m-%d %H:%M UTC")

    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level."""
        colors = {
            "critical": "#DC2626",
            "high": "#F97316",
            "medium": "#EAB308",
            "low": "#3B82F6",
            "info": "#6B7280",
        }
        return colors.get(severity.lower(), "#6B7280")

    def _get_trend_indicator(self, change: float) -> str:
        """Get trend indicator for a change value."""
        if change > 5:
            return "↑ Increasing"
        elif change < -5:
            return "↓ Decreasing"
        else:
            return "→ Stable"


class ExecutiveSummarySection(SectionBuilder):
    """Builds executive summary section."""

    def __init__(self):
        super().__init__("executive_summary", "Executive Summary")

    def build(self, data: Dict[str, Any]) -> ReportSection:
        """Build executive summary from data."""
        findings = data.get("findings", {})
        assets = data.get("assets", {})
        compliance = data.get("compliance", {})
        trends = data.get("trends", {})

        # Calculate key metrics
        total_findings = findings.get("total", 0)
        critical_findings = findings.get("critical", 0)
        high_findings = findings.get("high", 0)

        total_assets = assets.get("total", 0)
        assets_with_findings = assets.get("with_findings", 0)

        avg_compliance = compliance.get("average_score", 0)

        findings_change = trends.get("findings_change_pct", 0)
        compliance_change = trends.get("compliance_change_pct", 0)

        # Build content
        content = {
            "overview": {
                "report_period": data.get("time_range", "Last 30 days"),
                "generated_at": datetime.utcnow().isoformat(),
            },
            "key_metrics": {
                "total_findings": total_findings,
                "critical_high_findings": critical_findings + high_findings,
                "total_assets": total_assets,
                "assets_at_risk": assets_with_findings,
                "average_compliance_score": avg_compliance,
            },
            "trends": {
                "findings_trend": self._get_trend_indicator(findings_change),
                "findings_change_pct": findings_change,
                "compliance_trend": self._get_trend_indicator(-compliance_change),
                "compliance_change_pct": compliance_change,
            },
            "risk_summary": self._calculate_risk_summary(findings, assets),
            "recommendations": self._generate_recommendations(findings, compliance),
        }

        return ReportSection(
            id=self.section_id,
            title=self.title,
            content_type="executive_summary",
            content=content,
            order=1,
        )

    def _calculate_risk_summary(self, findings: Dict, assets: Dict) -> Dict[str, Any]:
        """Calculate overall risk summary."""
        critical = findings.get("critical", 0)
        high = findings.get("high", 0)
        medium = findings.get("medium", 0)
        total = findings.get("total", 1)

        # Simple risk score calculation
        risk_score = min(100, (critical * 10 + high * 5 + medium * 2) / max(total, 1) * 10)

        if risk_score >= 80:
            level = "Critical"
            color = "#DC2626"
        elif risk_score >= 60:
            level = "High"
            color = "#F97316"
        elif risk_score >= 40:
            level = "Medium"
            color = "#EAB308"
        elif risk_score >= 20:
            level = "Low"
            color = "#3B82F6"
        else:
            level = "Minimal"
            color = "#10B981"

        return {
            "risk_score": risk_score,
            "risk_level": level,
            "risk_color": color,
        }

    def _generate_recommendations(self, findings: Dict, compliance: Dict) -> List[str]:
        """Generate high-level recommendations."""
        recommendations = []

        critical = findings.get("critical", 0)
        high = findings.get("high", 0)

        if critical > 0:
            recommendations.append(
                f"Address {critical} critical finding(s) immediately - "
                "these represent significant security risks."
            )

        if high > 5:
            recommendations.append(
                f"Prioritize remediation of {high} high-severity findings "
                "to reduce attack surface."
            )

        avg_compliance = compliance.get("average_score", 100)
        if avg_compliance < 70:
            recommendations.append(
                f"Compliance score ({avg_compliance:.0f}%) is below target. "
                "Review failing controls and develop remediation plan."
            )

        frameworks = compliance.get("frameworks", {})
        for fw, score in frameworks.items():
            if score < 50:
                recommendations.append(
                    f"{fw} compliance is critically low ({score:.0f}%). "
                    "Immediate attention required."
                )

        if not recommendations:
            recommendations.append(
                "Security posture is strong. Continue monitoring and "
                "maintain current security practices."
            )

        return recommendations[:5]  # Top 5 recommendations


class FindingsSection(SectionBuilder):
    """Builds findings overview section."""

    def __init__(self):
        super().__init__("findings_overview", "Findings Overview")

    def build(self, data: Dict[str, Any]) -> ReportSection:
        """Build findings overview from data."""
        findings = data.get("findings", {})
        findings_list = data.get("findings_list", [])

        content = {
            "summary": {
                "total": findings.get("total", 0),
                "critical": findings.get("critical", 0),
                "high": findings.get("high", 0),
                "medium": findings.get("medium", 0),
                "low": findings.get("low", 0),
                "info": findings.get("info", 0),
            },
            "by_category": findings.get("by_category", {}),
            "by_provider": findings.get("by_provider", {}),
            "top_findings": self._get_top_findings(findings_list),
            "new_findings": findings.get("new_count", 0),
            "resolved_findings": findings.get("resolved_count", 0),
        }

        # Add severity chart
        content["severity_chart"] = create_severity_chart(
            critical=findings.get("critical", 0),
            high=findings.get("high", 0),
            medium=findings.get("medium", 0),
            low=findings.get("low", 0),
            info=findings.get("info", 0),
        ).to_dict()

        return ReportSection(
            id=self.section_id,
            title=self.title,
            content_type="findings",
            content=content,
            order=2,
        )

    def _get_top_findings(self, findings_list: List[Dict],
                         limit: int = 10) -> List[Dict[str, Any]]:
        """Get top findings by severity."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        sorted_findings = sorted(
            findings_list,
            key=lambda f: (
                severity_order.get(f.get("severity", "info").lower(), 5),
                f.get("title", "")
            )
        )

        top = []
        for f in sorted_findings[:limit]:
            top.append({
                "id": f.get("id", ""),
                "title": f.get("title", ""),
                "severity": f.get("severity", ""),
                "asset_id": f.get("asset_id", ""),
                "rule_id": f.get("rule_id", ""),
            })

        return top


class ComplianceSection(SectionBuilder):
    """Builds compliance status section."""

    def __init__(self):
        super().__init__("compliance_status", "Compliance Status")

    def build(self, data: Dict[str, Any]) -> ReportSection:
        """Build compliance section from data."""
        compliance = data.get("compliance", {})
        frameworks = compliance.get("frameworks", {})

        content = {
            "average_score": compliance.get("average_score", 0),
            "frameworks": [],
            "controls_summary": {
                "total": compliance.get("total_controls", 0),
                "passed": compliance.get("passed_controls", 0),
                "failed": compliance.get("failed_controls", 0),
                "not_applicable": compliance.get("na_controls", 0),
            },
            "gaps": [],
        }

        # Framework details
        for fw_name, score in frameworks.items():
            status = "Compliant" if score >= 90 else "Needs Attention" if score >= 70 else "Non-Compliant"
            content["frameworks"].append({
                "name": fw_name,
                "score": score,
                "status": status,
                "color": self._get_compliance_color(score),
            })

        # Add compliance chart
        if frameworks:
            content["compliance_chart"] = create_compliance_chart(
                frameworks, "Framework Compliance Scores"
            ).to_dict()

        # Identify top gaps
        failed_controls = compliance.get("failed_controls_list", [])
        for control in failed_controls[:10]:
            content["gaps"].append({
                "control_id": control.get("id", ""),
                "description": control.get("description", ""),
                "framework": control.get("framework", ""),
                "severity": control.get("severity", "medium"),
            })

        return ReportSection(
            id=self.section_id,
            title=self.title,
            content_type="compliance",
            content=content,
            order=3,
        )

    def _get_compliance_color(self, score: float) -> str:
        """Get color based on compliance score."""
        if score >= 90:
            return "#10B981"  # Green
        elif score >= 70:
            return "#EAB308"  # Yellow
        elif score >= 50:
            return "#F97316"  # Orange
        else:
            return "#DC2626"  # Red


class TrendSection(SectionBuilder):
    """Builds trend analysis section."""

    def __init__(self):
        super().__init__("trends", "Trend Analysis")

    def build(self, data: Dict[str, Any]) -> ReportSection:
        """Build trend section from data."""
        trends = data.get("trends", {})
        history = data.get("scan_history", [])

        content = {
            "summary": {
                "period": data.get("time_range", "Last 30 days"),
                "direction": trends.get("direction", "stable"),
                "findings_velocity": trends.get("findings_velocity", 0),
                "improvement_rate": trends.get("improvement_rate", 0),
            },
            "findings_over_time": self._build_findings_timeline(history),
            "severity_trends": trends.get("severity_trends", {}),
            "forecast": self._build_forecast(trends),
        }

        # Add trend chart
        if history:
            chart_data = []
            for entry in history:
                if isinstance(entry.get("timestamp"), str):
                    ts = datetime.fromisoformat(entry["timestamp"])
                else:
                    ts = entry.get("timestamp", datetime.utcnow())
                chart_data.append((ts, entry.get("findings_total", 0)))

            if chart_data:
                content["trend_chart"] = create_trend_chart(
                    chart_data,
                    title="Findings Over Time",
                    series_name="Total Findings",
                    include_trend_line=True
                ).to_dict()

        return ReportSection(
            id=self.section_id,
            title=self.title,
            content_type="trends",
            content=content,
            order=4,
        )

    def _build_findings_timeline(self, history: List[Dict]) -> List[Dict]:
        """Build findings timeline from scan history."""
        timeline = []
        for entry in history[-30:]:  # Last 30 entries
            timeline.append({
                "date": entry.get("timestamp", ""),
                "total": entry.get("findings_total", 0),
                "critical": entry.get("findings_by_severity", {}).get("critical", 0),
                "high": entry.get("findings_by_severity", {}).get("high", 0),
            })
        return timeline

    def _build_forecast(self, trends: Dict) -> Dict[str, Any]:
        """Build forecast from trend data."""
        forecast = trends.get("forecast", {})
        return {
            "predicted_findings": forecast.get("predicted_value", 0),
            "confidence": forecast.get("confidence", 0),
            "trend": forecast.get("trend", "stable"),
            "days_ahead": forecast.get("days_ahead", 7),
        }


class RecommendationsSection(SectionBuilder):
    """Builds recommendations section."""

    def __init__(self):
        super().__init__("recommendations", "Recommendations")

    def build(self, data: Dict[str, Any]) -> ReportSection:
        """Build recommendations section from data."""
        findings = data.get("findings", {})
        compliance = data.get("compliance", {})
        trends = data.get("trends", {})

        content = {
            "priority_actions": [],
            "quick_wins": [],
            "strategic_initiatives": [],
        }

        # Priority actions (critical/high findings)
        critical = findings.get("critical", 0)
        high = findings.get("high", 0)

        if critical > 0:
            content["priority_actions"].append({
                "action": f"Remediate {critical} critical finding(s)",
                "priority": "critical",
                "impact": "Eliminate critical security risks",
                "effort": "varies",
            })

        if high > 10:
            content["priority_actions"].append({
                "action": f"Create remediation plan for {high} high-severity findings",
                "priority": "high",
                "impact": "Significant risk reduction",
                "effort": "medium",
            })

        # Compliance gaps
        frameworks = compliance.get("frameworks", {})
        for fw, score in frameworks.items():
            if score < 70:
                content["priority_actions"].append({
                    "action": f"Address {fw} compliance gaps (currently {score:.0f}%)",
                    "priority": "high",
                    "impact": "Regulatory compliance",
                    "effort": "high",
                })

        # Quick wins
        low_severity = findings.get("low", 0) + findings.get("info", 0)
        if low_severity > 0 and low_severity < 20:
            content["quick_wins"].append({
                "action": f"Clean up {low_severity} low-priority findings",
                "priority": "low",
                "impact": "Improved security hygiene",
                "effort": "low",
            })

        # Strategic initiatives based on trends
        direction = trends.get("direction", "stable")
        if direction == "increasing":
            content["strategic_initiatives"].append({
                "action": "Review and strengthen preventive controls",
                "priority": "medium",
                "impact": "Reduce new finding generation",
                "effort": "high",
            })

        if compliance.get("average_score", 100) < 90:
            content["strategic_initiatives"].append({
                "action": "Implement automated compliance monitoring",
                "priority": "medium",
                "impact": "Continuous compliance assurance",
                "effort": "high",
            })

        return ReportSection(
            id=self.section_id,
            title=self.title,
            content_type="recommendations",
            content=content,
            order=5,
        )


# =============================================================================
# Report Templates
# =============================================================================

class ReportTemplate(ABC):
    """Abstract base class for report templates."""

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.sections: List[SectionBuilder] = []

    @abstractmethod
    def get_sections(self) -> List[SectionBuilder]:
        """Get the sections for this template."""
        pass

    @abstractmethod
    def render(self, sections: List[ReportSection],
               config: ReportConfig) -> str:
        """Render the report content."""
        pass


class ExecutiveSummaryTemplate(ReportTemplate):
    """Executive summary report template."""

    def __init__(self):
        super().__init__(
            "executive_summary",
            "High-level security overview for executives"
        )

    def get_sections(self) -> List[SectionBuilder]:
        """Get executive summary sections."""
        return [
            ExecutiveSummarySection(),
            FindingsSection(),
            ComplianceSection(),
            RecommendationsSection(),
        ]

    def render(self, sections: List[ReportSection],
               config: ReportConfig) -> str:
        """Render executive summary report."""
        if config.format == ReportFormat.HTML:
            return self._render_html(sections, config)
        elif config.format == ReportFormat.MARKDOWN:
            return self._render_markdown(sections, config)
        elif config.format == ReportFormat.JSON:
            return self._render_json(sections, config)
        else:
            return self._render_markdown(sections, config)

    def _render_html(self, sections: List[ReportSection],
                     config: ReportConfig) -> str:
        """Render as HTML."""
        branding = config.branding
        primary_color = branding.get("primary_color", "#3B82F6")

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{config.title}</title>
    <style>
        body {{ font-family: {branding.get("font_family", "Arial, sans-serif")}; margin: 40px; color: #1F2937; }}
        h1 {{ color: {primary_color}; border-bottom: 2px solid {primary_color}; padding-bottom: 10px; }}
        h2 {{ color: #374151; margin-top: 30px; }}
        .metric {{ display: inline-block; padding: 20px; margin: 10px; background: #F3F4F6; border-radius: 8px; text-align: center; }}
        .metric-value {{ font-size: 32px; font-weight: bold; color: {primary_color}; }}
        .metric-label {{ font-size: 14px; color: #6B7280; }}
        .severity-critical {{ color: #DC2626; }}
        .severity-high {{ color: #F97316; }}
        .severity-medium {{ color: #EAB308; }}
        .severity-low {{ color: #3B82F6; }}
        .recommendation {{ padding: 15px; margin: 10px 0; background: #FEF3C7; border-left: 4px solid #F59E0B; }}
        .priority-critical {{ border-left-color: #DC2626; background: #FEE2E2; }}
        .priority-high {{ border-left-color: #F97316; background: #FFEDD5; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #E5E7EB; padding: 12px; text-align: left; }}
        th {{ background: #F3F4F6; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #E5E7EB; color: #6B7280; font-size: 12px; }}
        .watermark {{ position: fixed; bottom: 20px; right: 20px; opacity: 0.3; font-size: 14px; }}
    </style>
</head>
<body>
    <h1>{config.title}</h1>
    <p><strong>{config.subtitle}</strong></p>
    <p>Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")} | Author: {config.author}</p>
    <p>Confidentiality: {config.confidentiality}</p>
"""

        for section in sorted(sections, key=lambda s: s.order):
            html += self._render_section_html(section)

        html += f"""
    <div class="footer">
        <p>Generated by Mantissa Stance | {config.author}</p>
    </div>
    {f'<div class="watermark">{config.watermark}</div>' if config.watermark else ''}
</body>
</html>"""

        return html

    def _render_section_html(self, section: ReportSection) -> str:
        """Render a section as HTML."""
        content = section.content or {}
        html = f"<h2>{section.title}</h2>\n"

        if section.content_type == "executive_summary":
            # Key metrics
            metrics = content.get("key_metrics", {})
            html += '<div class="metrics-container">\n'
            for key, value in metrics.items():
                label = key.replace("_", " ").title()
                html += f'''<div class="metric">
                    <div class="metric-value">{value:,}</div>
                    <div class="metric-label">{label}</div>
                </div>\n'''
            html += '</div>\n'

            # Risk summary
            risk = content.get("risk_summary", {})
            html += f'''<p><strong>Risk Level:</strong>
                <span style="color: {risk.get("risk_color", "#6B7280")}">
                    {risk.get("risk_level", "Unknown")} ({risk.get("risk_score", 0):.0f}/100)
                </span>
            </p>\n'''

            # Recommendations
            recs = content.get("recommendations", [])
            if recs:
                html += "<h3>Key Recommendations</h3>\n<ul>\n"
                for rec in recs:
                    html += f"<li>{rec}</li>\n"
                html += "</ul>\n"

        elif section.content_type == "findings":
            summary = content.get("summary", {})
            html += '<div class="metrics-container">\n'
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = summary.get(sev, 0)
                html += f'''<div class="metric">
                    <div class="metric-value severity-{sev}">{count}</div>
                    <div class="metric-label">{sev.title()}</div>
                </div>\n'''
            html += '</div>\n'

            # Top findings table
            top = content.get("top_findings", [])
            if top:
                html += "<h3>Top Findings</h3>\n<table>\n"
                html += "<tr><th>Title</th><th>Severity</th><th>Asset</th></tr>\n"
                for f in top:
                    sev = f.get("severity", "").lower()
                    html += f'''<tr>
                        <td>{f.get("title", "")}</td>
                        <td class="severity-{sev}">{f.get("severity", "")}</td>
                        <td>{f.get("asset_id", "")[:30]}</td>
                    </tr>\n'''
                html += "</table>\n"

        elif section.content_type == "compliance":
            html += f'''<p><strong>Average Compliance Score:</strong>
                {content.get("average_score", 0):.1f}%</p>\n'''

            frameworks = content.get("frameworks", [])
            if frameworks:
                html += "<table>\n<tr><th>Framework</th><th>Score</th><th>Status</th></tr>\n"
                for fw in frameworks:
                    html += f'''<tr>
                        <td>{fw.get("name", "")}</td>
                        <td style="color: {fw.get("color", "#6B7280")}">{fw.get("score", 0):.1f}%</td>
                        <td>{fw.get("status", "")}</td>
                    </tr>\n'''
                html += "</table>\n"

        elif section.content_type == "recommendations":
            for category in ["priority_actions", "quick_wins", "strategic_initiatives"]:
                items = content.get(category, [])
                if items:
                    html += f"<h3>{category.replace('_', ' ').title()}</h3>\n"
                    for item in items:
                        priority = item.get("priority", "medium")
                        html += f'''<div class="recommendation priority-{priority}">
                            <strong>{item.get("action", "")}</strong><br>
                            Impact: {item.get("impact", "")} | Effort: {item.get("effort", "")}
                        </div>\n'''

        return html

    def _render_markdown(self, sections: List[ReportSection],
                        config: ReportConfig) -> str:
        """Render as Markdown."""
        md = f"# {config.title}\n\n"
        md += f"**{config.subtitle}**\n\n"
        md += f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n\n"
        md += f"Author: {config.author} | Confidentiality: {config.confidentiality}\n\n"
        md += "---\n\n"

        for section in sorted(sections, key=lambda s: s.order):
            md += self._render_section_markdown(section)

        md += "\n---\n\n*Generated by Mantissa Stance*\n"
        return md

    def _render_section_markdown(self, section: ReportSection) -> str:
        """Render a section as Markdown."""
        content = section.content or {}
        md = f"## {section.title}\n\n"

        if section.content_type == "executive_summary":
            metrics = content.get("key_metrics", {})
            md += "### Key Metrics\n\n"
            md += "| Metric | Value |\n|--------|-------|\n"
            for key, value in metrics.items():
                label = key.replace("_", " ").title()
                md += f"| {label} | {value:,} |\n"
            md += "\n"

            risk = content.get("risk_summary", {})
            md += f"**Risk Level:** {risk.get('risk_level', 'Unknown')} "
            md += f"({risk.get('risk_score', 0):.0f}/100)\n\n"

            recs = content.get("recommendations", [])
            if recs:
                md += "### Key Recommendations\n\n"
                for rec in recs:
                    md += f"- {rec}\n"
                md += "\n"

        elif section.content_type == "findings":
            summary = content.get("summary", {})
            md += "### Summary\n\n"
            md += f"- **Critical:** {summary.get('critical', 0)}\n"
            md += f"- **High:** {summary.get('high', 0)}\n"
            md += f"- **Medium:** {summary.get('medium', 0)}\n"
            md += f"- **Low:** {summary.get('low', 0)}\n"
            md += f"- **Info:** {summary.get('info', 0)}\n\n"

        elif section.content_type == "compliance":
            md += f"**Average Score:** {content.get('average_score', 0):.1f}%\n\n"
            frameworks = content.get("frameworks", [])
            if frameworks:
                md += "| Framework | Score | Status |\n|-----------|-------|--------|\n"
                for fw in frameworks:
                    md += f"| {fw.get('name', '')} | {fw.get('score', 0):.1f}% | {fw.get('status', '')} |\n"
                md += "\n"

        elif section.content_type == "recommendations":
            for category in ["priority_actions", "quick_wins", "strategic_initiatives"]:
                items = content.get(category, [])
                if items:
                    md += f"### {category.replace('_', ' ').title()}\n\n"
                    for item in items:
                        md += f"- **{item.get('action', '')}**\n"
                        md += f"  - Impact: {item.get('impact', '')}\n"
                        md += f"  - Effort: {item.get('effort', '')}\n"
                    md += "\n"

        return md

    def _render_json(self, sections: List[ReportSection],
                    config: ReportConfig) -> str:
        """Render as JSON."""
        report = {
            "title": config.title,
            "subtitle": config.subtitle,
            "author": config.author,
            "generated_at": datetime.utcnow().isoformat(),
            "format": config.format.value,
            "sections": [
                {
                    "id": s.id,
                    "title": s.title,
                    "content_type": s.content_type,
                    "content": s.content,
                }
                for s in sorted(sections, key=lambda x: x.order)
            ]
        }
        return json.dumps(report, indent=2, default=str)


class TechnicalDetailTemplate(ReportTemplate):
    """Technical detail report template."""

    def __init__(self):
        super().__init__(
            "technical_detail",
            "Detailed technical security report"
        )

    def get_sections(self) -> List[SectionBuilder]:
        """Get technical report sections."""
        return [
            FindingsSection(),
            ComplianceSection(),
            TrendSection(),
            RecommendationsSection(),
        ]

    def render(self, sections: List[ReportSection],
               config: ReportConfig) -> str:
        """Render technical report."""
        # Use executive template's render with more detail
        exec_template = ExecutiveSummaryTemplate()
        return exec_template.render(sections, config)


class ComplianceReportTemplate(ReportTemplate):
    """Compliance-focused report template."""

    def __init__(self):
        super().__init__(
            "compliance_report",
            "Detailed compliance status report"
        )

    def get_sections(self) -> List[SectionBuilder]:
        """Get compliance report sections."""
        return [
            ComplianceSection(),
            FindingsSection(),
            RecommendationsSection(),
        ]

    def render(self, sections: List[ReportSection],
               config: ReportConfig) -> str:
        """Render compliance report."""
        exec_template = ExecutiveSummaryTemplate()
        return exec_template.render(sections, config)


class TrendReportTemplate(ReportTemplate):
    """Trend analysis report template."""

    def __init__(self):
        super().__init__(
            "trend_report",
            "Security trend analysis report"
        )

    def get_sections(self) -> List[SectionBuilder]:
        """Get trend report sections."""
        return [
            TrendSection(),
            FindingsSection(),
            RecommendationsSection(),
        ]

    def render(self, sections: List[ReportSection],
               config: ReportConfig) -> str:
        """Render trend report."""
        exec_template = ExecutiveSummaryTemplate()
        return exec_template.render(sections, config)


# =============================================================================
# Report Generator
# =============================================================================

class ReportGenerator:
    """
    Generates reports from security data.

    Supports multiple templates and output formats.
    """

    def __init__(self):
        self.templates: Dict[str, ReportTemplate] = {
            "executive_summary": ExecutiveSummaryTemplate(),
            "technical_detail": TechnicalDetailTemplate(),
            "compliance_report": ComplianceReportTemplate(),
            "trend_report": TrendReportTemplate(),
        }

    def register_template(self, template: ReportTemplate) -> None:
        """Register a custom template."""
        self.templates[template.name] = template

    def get_template(self, name: str) -> Optional[ReportTemplate]:
        """Get a template by name."""
        return self.templates.get(name)

    def list_templates(self) -> List[Dict[str, str]]:
        """List available templates."""
        return [
            {"name": t.name, "description": t.description}
            for t in self.templates.values()
        ]

    def generate(self, data: Dict[str, Any],
                config: ReportConfig) -> GeneratedReport:
        """
        Generate a report.

        Args:
            data: Report data (findings, assets, compliance, trends)
            config: Report configuration

        Returns:
            Generated report
        """
        start_time = time.time()

        # Get template
        template = self.templates.get(config.template, self.templates["executive_summary"])

        # Build sections
        sections = []
        section_builders = template.get_sections()

        for builder in section_builders:
            if builder.section_id in config.include_sections:
                section = builder.build(data)
                sections.append(section)

        # Render report
        content = template.render(sections, config)

        generation_time = time.time() - start_time

        return GeneratedReport(
            id="",  # Will be auto-generated
            schedule_id=None,
            config=config,
            format=config.format,
            content=content,
            file_size=len(content.encode('utf-8')) if isinstance(content, str) else len(content),
            generation_time_seconds=generation_time,
            sections=[s.id for s in sections],
        )

    def generate_to_file(self, data: Dict[str, Any],
                        config: ReportConfig,
                        file_path: str) -> GeneratedReport:
        """Generate a report and save to file."""
        report = self.generate(data, config)

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(report.content)

        report.file_path = file_path
        return report
