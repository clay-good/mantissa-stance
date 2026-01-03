"""
CLI commands for Reporting module.

Provides command-line interface for trend analysis and security reporting:
- Trend analysis (findings, severity, compliance)
- Findings velocity calculation
- Improvement rate tracking
- Period comparison
- Forecasting with linear regression
- Reporting module status and capabilities
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from typing import Any


def add_reporting_parser(subparsers: Any) -> None:
    """Add reporting parser to CLI subparsers."""
    reporting_parser = subparsers.add_parser(
        "reporting",
        help="Trend analysis and security posture reporting",
        description="Analyze security posture trends and generate insights",
    )

    reporting_subparsers = reporting_parser.add_subparsers(
        dest="reporting_action",
        help="Reporting action to perform",
    )

    # analyze - Full trend analysis
    analyze_parser = reporting_subparsers.add_parser(
        "analyze",
        help="Perform full trend analysis",
    )
    analyze_parser.add_argument(
        "--config",
        default="default",
        help="Configuration name to analyze (default: default)",
    )
    analyze_parser.add_argument(
        "--days",
        type=int,
        default=30,
        help="Number of days to analyze (default: 30)",
    )
    analyze_parser.add_argument(
        "--period",
        choices=["daily", "weekly", "monthly", "quarterly"],
        default="daily",
        help="Time period granularity (default: daily)",
    )
    analyze_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # velocity - Get findings velocity
    velocity_parser = reporting_subparsers.add_parser(
        "velocity",
        help="Calculate findings velocity (rate of change)",
    )
    velocity_parser.add_argument(
        "--config",
        default="default",
        help="Configuration name to analyze (default: default)",
    )
    velocity_parser.add_argument(
        "--days",
        type=int,
        default=7,
        help="Number of days to analyze (default: 7)",
    )
    velocity_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # improvement - Get improvement rate
    improvement_parser = reporting_subparsers.add_parser(
        "improvement",
        help="Calculate security improvement rate",
    )
    improvement_parser.add_argument(
        "--config",
        default="default",
        help="Configuration name to analyze (default: default)",
    )
    improvement_parser.add_argument(
        "--days",
        type=int,
        default=30,
        help="Number of days to analyze (default: 30)",
    )
    improvement_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # compare - Compare two time periods
    compare_parser = reporting_subparsers.add_parser(
        "compare",
        help="Compare two time periods",
    )
    compare_parser.add_argument(
        "--config",
        default="default",
        help="Configuration name to analyze (default: default)",
    )
    compare_parser.add_argument(
        "--current-days",
        type=int,
        default=7,
        help="Days in current period (default: 7)",
    )
    compare_parser.add_argument(
        "--previous-days",
        type=int,
        default=7,
        help="Days in previous period (default: 7)",
    )
    compare_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # forecast - Forecast future findings
    forecast_parser = reporting_subparsers.add_parser(
        "forecast",
        help="Forecast future findings using linear regression",
    )
    forecast_parser.add_argument(
        "--config",
        default="default",
        help="Configuration name to analyze (default: default)",
    )
    forecast_parser.add_argument(
        "--history-days",
        type=int,
        default=30,
        help="Days of history for forecast (default: 30)",
    )
    forecast_parser.add_argument(
        "--forecast-days",
        type=int,
        default=7,
        help="Days to forecast ahead (default: 7)",
    )
    forecast_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # directions - List trend directions
    directions_parser = reporting_subparsers.add_parser(
        "directions",
        help="List available trend directions",
    )
    directions_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # periods - List trend periods
    periods_parser = reporting_subparsers.add_parser(
        "periods",
        help="List available trend periods",
    )
    periods_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # severities - List severity levels for trends
    severities_parser = reporting_subparsers.add_parser(
        "severities",
        help="List severity levels tracked in trends",
    )
    severities_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # metrics - Show available metrics
    metrics_parser = reporting_subparsers.add_parser(
        "metrics",
        help="Show available trend metrics",
    )
    metrics_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # stats - Show reporting statistics
    stats_parser = reporting_subparsers.add_parser(
        "stats",
        help="Show reporting module statistics",
    )
    stats_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # status - Show reporting module status
    status_parser = reporting_subparsers.add_parser(
        "status",
        help="Show reporting module status",
    )
    status_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # summary - Get comprehensive reporting module summary
    summary_parser = reporting_subparsers.add_parser(
        "summary",
        help="Get comprehensive reporting module summary",
    )
    summary_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )


def cmd_reporting(args: argparse.Namespace) -> int:
    """Handle reporting commands."""
    action = getattr(args, "reporting_action", None)

    if not action:
        print("No reporting action specified. Use 'stance reporting --help' for options.")
        return 1

    handlers = {
        "analyze": _handle_analyze,
        "velocity": _handle_velocity,
        "improvement": _handle_improvement,
        "compare": _handle_compare,
        "forecast": _handle_forecast,
        "directions": _handle_directions,
        "periods": _handle_periods,
        "severities": _handle_severities,
        "metrics": _handle_metrics,
        "stats": _handle_stats,
        "status": _handle_status,
        "summary": _handle_summary,
    }

    handler = handlers.get(action)
    if handler:
        return handler(args)

    print(f"Unknown action: {action}")
    return 1


def _handle_analyze(args: argparse.Namespace) -> int:
    """Handle analyze command."""
    from stance.reporting import TrendAnalyzer, TrendPeriod

    # Parse period
    period_map = {
        "daily": TrendPeriod.DAILY,
        "weekly": TrendPeriod.WEEKLY,
        "monthly": TrendPeriod.MONTHLY,
        "quarterly": TrendPeriod.QUARTERLY,
    }
    period = period_map.get(args.period, TrendPeriod.DAILY)

    try:
        analyzer = TrendAnalyzer()
        report = analyzer.analyze(
            config_name=args.config,
            days=args.days,
            period=period,
        )

        if args.format == "json":
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print("\nTrend Analysis Report")
            print("=" * 60)
            print(f"Report ID: {report.report_id}")
            print(f"Generated: {report.generated_at.isoformat()}")
            print(f"Period: {report.period.value}")
            print(f"Days Analyzed: {report.days_analyzed}")

            print(f"\nOverall Trend:")
            print(f"  Direction: {report.total_findings.direction.value.upper()}")
            print(f"  Current Findings: {int(report.total_findings.current_value)}")
            print(f"  Previous Findings: {int(report.total_findings.previous_value)}")
            print(f"  Change: {report.total_findings.change:+.0f} ({report.total_findings.change_percent:+.1f}%)")
            print(f"  Velocity: {report.total_findings.velocity:.2f} findings/day")

            if report.severity_trends:
                print(f"\nSeverity Trends:")
                for sev, trend in report.severity_trends.items():
                    direction = trend.metrics.direction.value
                    current = int(trend.metrics.current_value)
                    change = trend.metrics.change
                    print(f"  {sev.upper()}: {current} ({change:+.0f}) - {direction}")

            print(f"\nScan Frequency: {report.scan_frequency:.2f} scans/day")

            if report.summary:
                print(f"\nSummary:")
                for key, value in report.summary.items():
                    if key != "overall_direction":
                        print(f"  {key}: {value}")

            if report.recommendations:
                print(f"\nRecommendations:")
                for rec in report.recommendations:
                    print(f"  - {rec}")

        return 0

    except Exception as e:
        if args.format == "json":
            print(json.dumps({"error": str(e)}))
        else:
            print(f"Error: {e}")
        return 1


def _handle_velocity(args: argparse.Namespace) -> int:
    """Handle velocity command."""
    from stance.reporting import TrendAnalyzer

    try:
        analyzer = TrendAnalyzer()
        velocities = analyzer.get_findings_velocity(
            config_name=args.config,
            days=args.days,
        )

        if args.format == "json":
            result = {
                "config": args.config,
                "days_analyzed": args.days,
                "velocities": {k: round(v, 4) for k, v in velocities.items()},
                "unit": "findings/day",
            }
            print(json.dumps(result, indent=2))
        else:
            print("\nFindings Velocity")
            print("=" * 50)
            print(f"Configuration: {args.config}")
            print(f"Days Analyzed: {args.days}")
            print(f"\nVelocity (findings/day):")
            for category, velocity in velocities.items():
                direction = "increasing" if velocity > 0 else "decreasing" if velocity < 0 else "stable"
                print(f"  {category.upper()}: {velocity:+.4f} ({direction})")

            # Interpretation
            total_vel = velocities.get("total", 0)
            print(f"\nInterpretation:")
            if total_vel > 0.5:
                print("  Security posture is declining - findings increasing rapidly")
            elif total_vel > 0:
                print("  Security posture is declining slightly - findings increasing")
            elif total_vel < -0.5:
                print("  Security posture is improving rapidly - findings decreasing")
            elif total_vel < 0:
                print("  Security posture is improving - findings decreasing")
            else:
                print("  Security posture is stable - no significant change")

        return 0

    except Exception as e:
        if args.format == "json":
            print(json.dumps({"error": str(e)}))
        else:
            print(f"Error: {e}")
        return 1


def _handle_improvement(args: argparse.Namespace) -> int:
    """Handle improvement command."""
    from stance.reporting import TrendAnalyzer

    try:
        analyzer = TrendAnalyzer()
        rate = analyzer.get_improvement_rate(
            config_name=args.config,
            days=args.days,
        )

        if args.format == "json":
            result = {
                "config": args.config,
                "days_analyzed": args.days,
                "improvement_rate": round(rate, 2),
                "unit": "percent",
                "direction": "improving" if rate > 0 else "declining" if rate < 0 else "stable",
            }
            print(json.dumps(result, indent=2))
        else:
            print("\nSecurity Improvement Rate")
            print("=" * 50)
            print(f"Configuration: {args.config}")
            print(f"Days Analyzed: {args.days}")
            print(f"\nImprovement Rate: {rate:+.2f}%")

            print(f"\nInterpretation:")
            if rate > 25:
                print("  Excellent improvement - significant reduction in findings")
            elif rate > 10:
                print("  Good improvement - noticeable reduction in findings")
            elif rate > 0:
                print("  Slight improvement - some reduction in findings")
            elif rate > -10:
                print("  Slight regression - some increase in findings")
            elif rate > -25:
                print("  Notable regression - significant increase in findings")
            else:
                print("  Severe regression - major increase in findings")

        return 0

    except Exception as e:
        if args.format == "json":
            print(json.dumps({"error": str(e)}))
        else:
            print(f"Error: {e}")
        return 1


def _handle_compare(args: argparse.Namespace) -> int:
    """Handle compare command."""
    from stance.reporting import TrendAnalyzer

    try:
        analyzer = TrendAnalyzer()
        comparison = analyzer.compare_periods(
            config_name=args.config,
            current_days=args.current_days,
            previous_days=args.previous_days,
        )

        # Convert TrendDirection enum to string if needed
        def serialize_direction(d):
            if hasattr(d, 'value'):
                return d.value
            return str(d)

        if args.format == "json":
            # Serialize any TrendDirection enums in comparison dict
            comp_copy = dict(comparison)
            if "comparison" in comp_copy and "direction" in comp_copy["comparison"]:
                comp_copy["comparison"]["direction"] = serialize_direction(comp_copy["comparison"]["direction"])
            print(json.dumps(comp_copy, indent=2))
        else:
            print("\nPeriod Comparison")
            print("=" * 60)
            print(f"Configuration: {args.config}")

            current = comparison["current_period"]
            previous = comparison["previous_period"]
            comp = comparison["comparison"]

            print(f"\nCurrent Period ({current['days']} days):")
            print(f"  From: {current['start'][:10]}")
            print(f"  To: {current['end'][:10]}")
            print(f"  Scans: {current['stats']['scans']}")
            print(f"  Avg Findings: {current['stats']['avg_findings']:.1f}")
            print(f"  Min/Max Findings: {current['stats']['min_findings']} / {current['stats']['max_findings']}")

            print(f"\nPrevious Period ({previous['days']} days):")
            print(f"  From: {previous['start'][:10]}")
            print(f"  To: {previous['end'][:10]}")
            print(f"  Scans: {previous['stats']['scans']}")
            print(f"  Avg Findings: {previous['stats']['avg_findings']:.1f}")
            print(f"  Min/Max Findings: {previous['stats']['min_findings']} / {previous['stats']['max_findings']}")

            print(f"\nComparison:")
            print(f"  Findings Change: {comp['avg_findings_change']:+.2f}%")
            print(f"  Scan Count Change: {comp['scan_count_change']:+d}")
            direction_str = serialize_direction(comp['direction'])
            print(f"  Trend Direction: {direction_str.upper()}")

        return 0

    except Exception as e:
        if args.format == "json":
            print(json.dumps({"error": str(e)}))
        else:
            print(f"Error: {e}")
        return 1


def _handle_forecast(args: argparse.Namespace) -> int:
    """Handle forecast command."""
    from stance.reporting import TrendAnalyzer

    try:
        analyzer = TrendAnalyzer()
        forecast = analyzer.forecast(
            config_name=args.config,
            days_history=args.history_days,
            days_forecast=args.forecast_days,
        )

        if args.format == "json":
            print(json.dumps(forecast, indent=2))
        else:
            print("\nFindings Forecast")
            print("=" * 60)
            print(f"Configuration: {args.config}")

            if "error" in forecast:
                print(f"\nError: {forecast['error']}")
                print(f"Data points required: {forecast.get('minimum_required', 2)}")
                print(f"Data points available: {forecast.get('available', 0)}")
                return 0

            print(f"\nModel: {forecast['model']}")
            print(f"Data Points Used: {forecast['data_points']}")
            print(f"Trend Slope: {forecast['trend_slope']:.4f} findings/day")
            print(f"Confidence (R-squared): {forecast['confidence']:.2%}")
            print(f"Trend Direction: {forecast['trend_direction'].upper()}")
            print(f"Current Findings: {forecast['current_findings']}")

            print(f"\nForecasted Findings:")
            print(f"{'Day':<6} {'Date':<12} {'Projected':<12}")
            print("-" * 30)
            for fc in forecast["forecasts"]:
                date_str = fc["date"][:10]
                print(f"{fc['day']:<6} {date_str:<12} {fc['projected_findings']:<12}")

            # Interpretation
            slope = forecast["trend_slope"]
            print(f"\nInterpretation:")
            if slope > 1:
                print(f"  Warning: Findings expected to increase by ~{abs(slope):.1f}/day")
            elif slope > 0:
                print(f"  Caution: Findings expected to increase slightly")
            elif slope < -1:
                print(f"  Positive: Findings expected to decrease by ~{abs(slope):.1f}/day")
            elif slope < 0:
                print(f"  Positive: Findings expected to decrease slightly")
            else:
                print(f"  Stable: Findings expected to remain constant")

        return 0

    except Exception as e:
        if args.format == "json":
            print(json.dumps({"error": str(e)}))
        else:
            print(f"Error: {e}")
        return 1


def _handle_directions(args: argparse.Namespace) -> int:
    """Handle directions command."""
    directions = [
        {
            "direction": "improving",
            "description": "Security posture getting better (fewer findings or higher compliance)",
            "indicator": "Positive trend",
            "action": "Continue current practices",
        },
        {
            "direction": "declining",
            "description": "Security posture getting worse (more findings or lower compliance)",
            "indicator": "Negative trend",
            "action": "Investigate and remediate",
        },
        {
            "direction": "stable",
            "description": "No significant change in security posture",
            "indicator": "Neutral trend",
            "action": "Monitor and maintain",
        },
        {
            "direction": "insufficient_data",
            "description": "Not enough data points for reliable trend analysis",
            "indicator": "Unknown trend",
            "action": "Collect more scan data",
        },
    ]

    if args.format == "json":
        print(json.dumps({"total": len(directions), "directions": directions}, indent=2))
    else:
        print("\nTrend Directions")
        print("=" * 60)
        for d in directions:
            print(f"\n{d['direction'].upper()}")
            print(f"  {d['description']}")
            print(f"  Indicator: {d['indicator']}")
            print(f"  Recommended Action: {d['action']}")

    return 0


def _handle_periods(args: argparse.Namespace) -> int:
    """Handle periods command."""
    periods = [
        {
            "period": "daily",
            "description": "Day-by-day trend analysis",
            "use_case": "Short-term monitoring and rapid response",
            "recommended_history": "7-14 days",
        },
        {
            "period": "weekly",
            "description": "Week-over-week trend analysis",
            "use_case": "Sprint-level tracking and weekly reports",
            "recommended_history": "4-8 weeks",
        },
        {
            "period": "monthly",
            "description": "Month-over-month trend analysis",
            "use_case": "Executive reporting and long-term planning",
            "recommended_history": "3-6 months",
        },
        {
            "period": "quarterly",
            "description": "Quarter-over-quarter trend analysis",
            "use_case": "Strategic planning and compliance reporting",
            "recommended_history": "4+ quarters",
        },
    ]

    if args.format == "json":
        print(json.dumps({"total": len(periods), "periods": periods}, indent=2))
    else:
        print("\nTrend Periods")
        print("=" * 60)
        for p in periods:
            print(f"\n{p['period'].upper()}")
            print(f"  {p['description']}")
            print(f"  Use Case: {p['use_case']}")
            print(f"  Recommended History: {p['recommended_history']}")

    return 0


def _handle_severities(args: argparse.Namespace) -> int:
    """Handle severities command."""
    severities = [
        {
            "severity": "critical",
            "description": "Most severe security issues",
            "trend_priority": "Highest - track closely",
            "velocity_threshold": 0.5,
        },
        {
            "severity": "high",
            "description": "Significant security issues",
            "trend_priority": "High - monitor weekly",
            "velocity_threshold": 1.0,
        },
        {
            "severity": "medium",
            "description": "Moderate security issues",
            "trend_priority": "Medium - review monthly",
            "velocity_threshold": 2.0,
        },
        {
            "severity": "low",
            "description": "Minor security issues",
            "trend_priority": "Low - opportunistic",
            "velocity_threshold": 5.0,
        },
        {
            "severity": "info",
            "description": "Informational findings",
            "trend_priority": "Informational only",
            "velocity_threshold": 10.0,
        },
    ]

    if args.format == "json":
        print(json.dumps({"total": len(severities), "severities": severities}, indent=2))
    else:
        print("\nSeverity Levels for Trend Tracking")
        print("=" * 60)
        for s in severities:
            print(f"\n{s['severity'].upper()}")
            print(f"  {s['description']}")
            print(f"  Trend Priority: {s['trend_priority']}")
            print(f"  Velocity Alert Threshold: {s['velocity_threshold']} findings/day")

    return 0


def _handle_metrics(args: argparse.Namespace) -> int:
    """Handle metrics command."""
    metrics = [
        {
            "metric": "current_value",
            "description": "Most recent value from scans",
            "type": "float",
        },
        {
            "metric": "previous_value",
            "description": "Value from previous period",
            "type": "float",
        },
        {
            "metric": "average",
            "description": "Average value over the analysis period",
            "type": "float",
        },
        {
            "metric": "min_value",
            "description": "Minimum value observed",
            "type": "float",
        },
        {
            "metric": "max_value",
            "description": "Maximum value observed",
            "type": "float",
        },
        {
            "metric": "change",
            "description": "Absolute change from previous value",
            "type": "float",
        },
        {
            "metric": "change_percent",
            "description": "Percentage change from previous value",
            "type": "float",
        },
        {
            "metric": "direction",
            "description": "Trend direction (improving/declining/stable)",
            "type": "enum",
        },
        {
            "metric": "data_points",
            "description": "Number of data points analyzed",
            "type": "integer",
        },
        {
            "metric": "velocity",
            "description": "Rate of change per day",
            "type": "float",
        },
    ]

    if args.format == "json":
        print(json.dumps({"total": len(metrics), "metrics": metrics}, indent=2))
    else:
        print("\nAvailable Trend Metrics")
        print("=" * 60)
        print(f"{'Metric':<20} {'Type':<10} Description")
        print("-" * 60)
        for m in metrics:
            print(f"{m['metric']:<20} {m['type']:<10} {m['description']}")

    return 0


def _handle_stats(args: argparse.Namespace) -> int:
    """Handle stats command."""
    stats = {
        "trend_directions": 4,
        "trend_periods": 4,
        "severity_levels": 5,
        "metrics_tracked": 10,
        "analysis_methods": ["velocity", "improvement_rate", "period_comparison", "forecast"],
        "forecast_model": "linear_regression",
        "change_threshold_percent": 5.0,
        "critical_velocity_threshold": 0.5,
    }

    if args.format == "json":
        print(json.dumps(stats, indent=2))
    else:
        print("\nReporting Module Statistics")
        print("=" * 50)
        print(f"Trend Directions: {stats['trend_directions']}")
        print(f"Trend Periods: {stats['trend_periods']}")
        print(f"Severity Levels: {stats['severity_levels']}")
        print(f"Metrics Tracked: {stats['metrics_tracked']}")
        print(f"Forecast Model: {stats['forecast_model']}")
        print(f"Change Threshold: {stats['change_threshold_percent']}%")
        print(f"Critical Velocity Threshold: {stats['critical_velocity_threshold']} findings/day")
        print(f"\nAnalysis Methods:")
        for method in stats["analysis_methods"]:
            print(f"  - {method}")

    return 0


def _handle_status(args: argparse.Namespace) -> int:
    """Handle status command."""
    status = {
        "module": "reporting",
        "status": "operational",
        "components": {
            "TrendAnalyzer": "available",
            "TrendReport": "available",
            "TrendMetrics": "available",
            "SeverityTrend": "available",
            "ComplianceTrend": "available",
            "ScanHistoryManager": "available",
        },
        "capabilities": [
            "trend_analysis",
            "velocity_calculation",
            "improvement_rate",
            "period_comparison",
            "linear_regression_forecast",
            "severity_tracking",
            "compliance_tracking",
            "recommendation_generation",
        ],
    }

    if args.format == "json":
        print(json.dumps(status, indent=2))
    else:
        print("\nReporting Module Status")
        print("=" * 50)
        print(f"Module: {status['module']}")
        print(f"Status: {status['status']}")
        print(f"\nComponents:")
        for comp, state in status["components"].items():
            print(f"  {comp}: {state}")
        print(f"\nCapabilities:")
        for cap in status["capabilities"]:
            print(f"  - {cap}")

    return 0


def _handle_summary(args: argparse.Namespace) -> int:
    """Handle summary command."""
    summary = {
        "module": "reporting",
        "version": "1.0.0",
        "description": "Security posture trend analysis and reporting",
        "features": [
            "Full trend analysis with configurable periods",
            "Findings velocity calculation (rate of change)",
            "Security improvement rate tracking",
            "Period-over-period comparison",
            "Linear regression forecasting",
            "Severity-level trend breakdown",
            "Compliance score trend tracking",
            "Automatic recommendation generation",
            "JSON and table output formats",
        ],
        "analysis_types": {
            "analyze": "Comprehensive trend analysis with recommendations",
            "velocity": "Rate of findings change per day",
            "improvement": "Percentage improvement over time",
            "compare": "Compare current vs previous period",
            "forecast": "Project future findings using regression",
        },
        "data_requirements": {
            "minimum_scans": 2,
            "recommended_scans": 10,
            "default_history_days": 30,
        },
    }

    if args.format == "json":
        print(json.dumps(summary, indent=2))
    else:
        print("\nReporting Module Summary")
        print("=" * 60)
        print(f"Module: {summary['module']}")
        print(f"Version: {summary['version']}")
        print(f"Description: {summary['description']}")

        print(f"\nFeatures:")
        for feature in summary["features"]:
            print(f"  - {feature}")

        print(f"\nAnalysis Types:")
        for atype, desc in summary["analysis_types"].items():
            print(f"  {atype}: {desc}")

        print(f"\nData Requirements:")
        for req, value in summary["data_requirements"].items():
            print(f"  {req.replace('_', ' ').title()}: {value}")

    return 0
