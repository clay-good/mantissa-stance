"""
CLI commands for CIS Benchmarks.

Provides command-line interface for:
- CIS benchmark status checks
- Benchmark control listing
- Policy-to-benchmark mapping

Note: For compliance frameworks (SOC 2, PCI-DSS, HIPAA, NIST 800-53),
use Attestful (https://github.com/clay-good/attestful).
"""

import argparse
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def add_benchmark_parser(subparsers: Any) -> None:
    """Add benchmark command parser."""
    benchmark_parser = subparsers.add_parser(
        "benchmark",
        help="CIS benchmark commands",
    )

    benchmark_subparsers = benchmark_parser.add_subparsers(dest="benchmark_action")

    # benchmark status
    status_parser = benchmark_subparsers.add_parser(
        "status",
        help="Show benchmark status",
    )
    status_parser.add_argument(
        "--benchmark",
        "-b",
        choices=["cis-aws", "cis-gcp", "cis-azure", "all"],
        default="all",
        help="CIS benchmark (default: all)",
    )
    status_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # benchmark list
    list_parser = benchmark_subparsers.add_parser(
        "list",
        help="List supported CIS benchmarks",
    )
    list_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # benchmark controls
    controls_parser = benchmark_subparsers.add_parser(
        "controls",
        help="List controls for a benchmark",
    )
    controls_parser.add_argument(
        "--benchmark",
        "-b",
        required=True,
        choices=["cis-aws", "cis-gcp", "cis-azure"],
        help="CIS benchmark",
    )
    controls_parser.add_argument(
        "--status",
        choices=["pass", "fail", "unknown"],
        help="Filter by status",
    )
    controls_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # benchmark gaps
    gaps_parser = benchmark_subparsers.add_parser(
        "gaps",
        help="Show failing CIS controls",
    )
    gaps_parser.add_argument(
        "--benchmark",
        "-b",
        required=True,
        choices=["cis-aws", "cis-gcp", "cis-azure"],
        help="CIS benchmark",
    )
    gaps_parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low"],
        help="Minimum severity to show",
    )
    gaps_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )


def cmd_benchmark(args: argparse.Namespace) -> int:
    """Handle benchmark commands."""
    action = getattr(args, "benchmark_action", None)

    if action == "status":
        return _benchmark_status(args)
    elif action == "list":
        return _list_benchmarks(args)
    elif action == "controls":
        return _list_controls(args)
    elif action == "gaps":
        return _show_gaps(args)
    else:
        print("Usage: stance benchmark <command>")
        print("")
        print("Commands:")
        print("  status     Show benchmark status (scores)")
        print("  list       List supported CIS benchmarks")
        print("  controls   List controls for a benchmark")
        print("  gaps       Show failing CIS controls")
        print("")
        print("Note: For compliance frameworks (SOC 2, PCI-DSS, HIPAA, NIST 800-53),")
        print("use Attestful: https://github.com/clay-good/attestful")
        return 1


def _benchmark_status(args: argparse.Namespace) -> int:
    """Show benchmark status."""
    benchmark_id = getattr(args, "benchmark", "all")
    output_format = getattr(args, "format", "table")

    try:
        from stance.engine.benchmark import BenchmarkCalculator
        from stance.storage import get_storage
        from stance.engine.loader import PolicyLoader

        storage = get_storage()
        findings = storage.get_findings()
        assets = storage.get_assets()

        loader = PolicyLoader()
        policies = loader.load_all()

        calculator = BenchmarkCalculator()

        if benchmark_id == "all":
            report = calculator.calculate_scores(
                policies=policies,
                findings=findings,
                assets=assets,
            )
            results = [
                {
                    "benchmark": b.benchmark_id,
                    "name": b.benchmark_name,
                    "version": b.version,
                    "score": b.score_percentage,
                    "passed": b.controls_passed,
                    "failed": b.controls_failed,
                    "total": b.controls_total,
                }
                for b in report.benchmarks
            ]
        else:
            score = calculator.get_benchmark_score(
                benchmark_id=benchmark_id,
                policies=policies,
                findings=findings,
                assets=assets,
            )
            results = [{
                "benchmark": score.benchmark_id,
                "name": score.benchmark_name,
                "version": score.version,
                "score": score.score_percentage,
                "passed": score.controls_passed,
                "failed": score.controls_failed,
                "total": score.controls_total,
            }]

        if output_format == "json":
            print(json.dumps({"benchmarks": results}, indent=2))
        else:
            print("\nCIS Benchmark Status")
            print("=" * 70)
            print(f"{'Benchmark':<15} {'Name':<30} {'Score':<10} {'Pass/Total':<12}")
            print("-" * 70)
            for r in results:
                print(
                    f"{r['benchmark']:<15} "
                    f"{r['name'][:29]:<30} "
                    f"{r['score']:.1f}%{'':<5} "
                    f"{r['passed']}/{r['total']}"
                )

        return 0

    except Exception as e:
        logger.error(f"Error getting benchmark status: {e}")
        print(f"Error: {e}")
        return 1


def _list_benchmarks(args: argparse.Namespace) -> int:
    """List supported CIS benchmarks."""
    output_format = getattr(args, "format", "table")

    benchmarks = [
        {
            "id": "cis-aws",
            "name": "CIS AWS Foundations Benchmark",
            "version": "1.5.0",
            "controls": 60,
        },
        {
            "id": "cis-gcp",
            "name": "CIS GCP Foundations Benchmark",
            "version": "1.3.0",
            "controls": 68,
        },
        {
            "id": "cis-azure",
            "name": "CIS Azure Foundations Benchmark",
            "version": "1.5.0",
            "controls": 88,
        },
    ]

    if output_format == "json":
        print(json.dumps({"benchmarks": benchmarks}, indent=2))
    else:
        print("\nSupported CIS Benchmarks")
        print("=" * 70)
        print(f"{'ID':<12} {'Name':<40} {'Version':<10} {'Controls':<10}")
        print("-" * 70)
        for bm in benchmarks:
            print(f"{bm['id']:<12} {bm['name']:<40} {bm['version']:<10} {bm['controls']:<10}")
        print("")
        print("Note: For compliance frameworks (SOC 2, PCI-DSS, HIPAA, NIST 800-53),")
        print("use Attestful: https://github.com/clay-good/attestful")

    return 0


def _list_controls(args: argparse.Namespace) -> int:
    """List controls for a benchmark."""
    benchmark_id = args.benchmark
    status_filter = getattr(args, "status", None)
    output_format = getattr(args, "format", "table")

    try:
        from stance.engine.benchmark import BenchmarkCalculator
        from stance.storage import get_storage
        from stance.engine.loader import PolicyLoader

        storage = get_storage()
        findings = storage.get_findings()
        assets = storage.get_assets()

        loader = PolicyLoader()
        policies = loader.load_all()

        calculator = BenchmarkCalculator()
        score = calculator.get_benchmark_score(
            benchmark_id=benchmark_id,
            policies=policies,
            findings=findings,
            assets=assets,
        )

        controls = score.control_statuses

        if status_filter:
            controls = [c for c in controls if c.status == status_filter]

        if output_format == "json":
            print(json.dumps({
                "benchmark": benchmark_id,
                "controls": [
                    {
                        "id": c.control_id,
                        "name": c.control_name,
                        "status": c.status,
                        "resources_evaluated": c.resources_evaluated,
                        "findings": len(c.findings),
                    }
                    for c in controls
                ]
            }, indent=2))
        else:
            print(f"\nControls for {benchmark_id.upper()}")
            print("=" * 80)
            print(f"{'Control':<12} {'Name':<50} {'Status':<10}")
            print("-" * 80)
            for control in controls[:50]:
                status_str = "PASS" if control.status == "pass" else "FAIL"
                print(
                    f"{control.control_id:<12} "
                    f"{control.control_name[:49]:<50} "
                    f"{status_str:<10}"
                )
            if len(controls) > 50:
                print(f"\n... and {len(controls) - 50} more controls")

        return 0

    except Exception as e:
        logger.error(f"Error listing controls: {e}")
        print(f"Error: {e}")
        return 1


def _show_gaps(args: argparse.Namespace) -> int:
    """Show failing CIS controls."""
    benchmark_id = args.benchmark
    severity_filter = getattr(args, "severity", None)
    output_format = getattr(args, "format", "table")

    try:
        from stance.engine.benchmark import BenchmarkCalculator
        from stance.storage import get_storage
        from stance.engine.loader import PolicyLoader

        storage = get_storage()
        findings = storage.get_findings()
        assets = storage.get_assets()

        loader = PolicyLoader()
        policies = loader.load_all()

        calculator = BenchmarkCalculator()
        score = calculator.get_benchmark_score(
            benchmark_id=benchmark_id,
            policies=policies,
            findings=findings,
            assets=assets,
        )

        # Get failing controls
        failing_controls = [c for c in score.control_statuses if c.status == "fail"]

        gaps = []
        for control in failing_controls:
            for finding_id in control.findings:
                # Get finding details
                finding = next((f for f in findings if f.id == finding_id), None)
                if finding:
                    if severity_filter and finding.severity.value.lower() != severity_filter:
                        continue
                    gaps.append({
                        "control_id": control.control_id,
                        "control_name": control.control_name,
                        "finding_id": finding.id,
                        "title": finding.title,
                        "severity": finding.severity.value,
                        "resource": finding.resource_id,
                    })

        if output_format == "json":
            print(json.dumps({"benchmark": benchmark_id, "gaps": gaps}, indent=2))
        else:
            print(f"\nCIS Benchmark Gaps for {benchmark_id.upper()}")
            print("=" * 100)
            if gaps:
                print(f"{'Control':<10} {'Severity':<10} {'Finding':<40} {'Resource':<30}")
                print("-" * 100)
                for gap in gaps[:50]:
                    print(
                        f"{gap['control_id']:<10} "
                        f"{gap['severity']:<10} "
                        f"{gap['title'][:39]:<40} "
                        f"{gap['resource'][:29]:<30}"
                    )
                if len(gaps) > 50:
                    print(f"\n... and {len(gaps) - 50} more gaps")
            else:
                print("No benchmark gaps found - all controls passing!")

        return 0

    except Exception as e:
        logger.error(f"Error showing gaps: {e}")
        print(f"Error: {e}")
        return 1
