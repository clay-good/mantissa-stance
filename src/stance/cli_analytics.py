"""
CLI command handlers for Vulnerability Analytics.

Provides commands for:
- Attack path analysis
- Risk scoring
- Blast radius calculation
- MITRE ATT&CK mapping
"""

from __future__ import annotations

import argparse
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def cmd_analytics(args: argparse.Namespace) -> int:
    """
    Route analytics subcommands to appropriate handlers.

    Returns:
        Exit code (0 success, 1 error)
    """
    action = getattr(args, "analytics_action", None)

    if action is None:
        print("Usage: stance analytics <command>")
        print("")
        print("Commands:")
        print("  attack-paths   Analyze attack paths in the environment")
        print("  risk-score     Calculate risk scores for assets")
        print("  blast-radius   Calculate blast radius for findings")
        print("  mitre          Map findings to MITRE ATT&CK framework")
        print("")
        print("Run 'stance analytics <command> --help' for more information")
        return 0

    handlers = {
        "attack-paths": _cmd_attack_paths,
        "risk-score": _cmd_risk_score,
        "blast-radius": _cmd_blast_radius,
        "mitre": _cmd_mitre,
    }

    handler = handlers.get(action)
    if handler:
        return handler(args)

    print(f"Unknown analytics command: {action}")
    return 1


def _cmd_attack_paths(args: argparse.Namespace) -> int:
    """
    Analyze attack paths in the cloud environment.

    Identifies potential attack paths through the asset graph based on
    network connectivity, IAM relationships, and security findings.
    """
    from stance.analytics.attack_paths import AttackPathAnalyzer, AttackPathType
    from stance.analytics.asset_graph import AssetGraph
    from stance.models.finding import FindingCollection
    from stance.storage import get_storage

    output_format = getattr(args, "format", "table")
    path_type_filter = getattr(args, "type", None)
    min_severity = getattr(args, "severity", None)
    limit = getattr(args, "limit", 20)

    try:
        # Load data from storage
        storage = get_storage()
        assets = storage.load_assets()
        findings_data = storage.load_findings()

        if not assets or not assets.assets:
            print("No assets found. Run 'stance scan' first.")
            return 1

        # Build asset graph
        print("Building asset graph...")
        graph = AssetGraph()
        graph.build_from_assets(assets)

        # Create findings collection if available
        findings = None
        if findings_data and findings_data.findings:
            findings = findings_data

        # Run attack path analysis
        print("Analyzing attack paths...")
        analyzer = AttackPathAnalyzer(graph, findings)
        paths = analyzer.analyze()

        # Filter by path type if specified
        if path_type_filter:
            try:
                filter_type = AttackPathType(path_type_filter)
                paths = [p for p in paths if p.path_type == filter_type]
            except ValueError:
                print(f"Warning: Unknown path type '{path_type_filter}'")

        # Filter by severity if specified
        if min_severity:
            from stance.models.finding import Severity
            severity_order = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "info": Severity.INFO,
            }
            min_sev = severity_order.get(min_severity.lower())
            if min_sev:
                paths = [p for p in paths if p.severity.value <= min_sev.value]

        # Limit results
        paths = paths[:limit]

        # Output results
        if output_format == "json":
            output = {
                "total_paths": len(paths),
                "paths": [p.to_dict() for p in paths],
            }
            print(json.dumps(output, indent=2))
        else:
            # Table format
            print("")
            print(f"Attack Paths Found: {len(paths)}")
            print("=" * 100)

            if not paths:
                print("No attack paths identified.")
                return 0

            for i, path in enumerate(paths):
                print(f"\n[{i+1}] {path.path_type.value.upper()}")
                print(f"    Severity: {path.severity.value}")
                print(f"    Steps: {path.length}")
                print(f"    Description: {path.description}")

                if path.steps:
                    print("    Path:")
                    for j, step in enumerate(path.steps):
                        arrow = "  -> " if j > 0 else "     "
                        print(f"    {arrow}{step.asset_name} ({step.resource_type})")
                        print(f"         Action: {step.action}")
                        if step.findings:
                            print(f"         Findings: {len(step.findings)}")

                if path.mitigation:
                    print(f"    Mitigation: {path.mitigation[:100]}...")

                print("-" * 100)

        return 0

    except Exception as e:
        logger.error(f"Attack path analysis failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_risk_score(args: argparse.Namespace) -> int:
    """
    Calculate risk scores for assets.

    Considers exposure, findings, compliance status, relationships,
    and resource age to compute comprehensive risk scores.
    """
    from stance.analytics.risk_scoring import RiskScorer
    from stance.analytics.asset_graph import AssetGraph
    from stance.models.finding import FindingCollection
    from stance.storage import get_storage

    output_format = getattr(args, "format", "table")
    asset_id = getattr(args, "asset_id", None)
    min_score = getattr(args, "min_score", None)
    risk_level = getattr(args, "level", None)
    limit = getattr(args, "limit", 20)

    try:
        # Load data from storage
        storage = get_storage()
        assets = storage.load_assets()
        findings_data = storage.load_findings()

        if not assets or not assets.assets:
            print("No assets found. Run 'stance scan' first.")
            return 1

        # Build asset graph for relationship analysis
        graph = AssetGraph()
        graph.build_from_assets(assets)

        # Create findings collection if available
        findings = None
        if findings_data and findings_data.findings:
            findings = findings_data

        # Initialize risk scorer
        scorer = RiskScorer(graph, findings)

        # Score single asset or all assets
        if asset_id:
            asset = assets.get_by_id(asset_id)
            if not asset:
                print(f"Asset not found: {asset_id}")
                return 1
            scores = [scorer.score_asset(asset)]
        else:
            scores = scorer.score_collection(assets)

        # Filter by minimum score
        if min_score is not None:
            scores = [s for s in scores if s.overall_score >= min_score]

        # Filter by risk level
        if risk_level:
            scores = [s for s in scores if s.risk_level == risk_level.lower()]

        # Limit results
        scores = scores[:limit]

        # Output results
        if output_format == "json":
            output = {
                "total_scored": len(scores),
                "aggregate": scorer.aggregate_risk(assets) if not asset_id else None,
                "scores": [s.to_dict() for s in scores],
            }
            print(json.dumps(output, indent=2, default=str))
        else:
            # Table format
            print("")
            print(f"Risk Scores for {len(scores)} Assets")
            print("=" * 100)

            if not scores:
                print("No assets match the specified filters.")
                return 0

            # Print aggregate summary if scoring all assets
            if not asset_id:
                agg = scorer.aggregate_risk(assets)
                print(f"\nAggregate Summary:")
                print(f"  Total Assets: {agg['total_assets']}")
                print(f"  Average Score: {agg['average_score']}")
                print(f"  Highest Score: {agg['max_score']}")
                print(f"  By Level: {agg['by_level']}")
                print("")

            print(f"{'Asset ID':<40} {'Score':<8} {'Level':<10} {'Top Risk'}")
            print("-" * 100)

            for score in scores:
                asset_short = score.asset_id[:37] + "..." if len(score.asset_id) > 40 else score.asset_id
                top_risk = score.top_risks[0] if score.top_risks else "N/A"
                top_risk = top_risk[:40] + "..." if len(top_risk) > 43 else top_risk
                print(f"{asset_short:<40} {score.overall_score:<8.1f} {score.risk_level:<10} {top_risk}")

            # Show detailed view for single asset
            if asset_id and scores:
                score = scores[0]
                print("\nDetailed Risk Factors:")
                print(f"  Exposure Score:     {score.factors.exposure_score:.1f}")
                print(f"  Finding Score:      {score.factors.finding_score:.1f}")
                print(f"  Compliance Score:   {score.factors.compliance_score:.1f}")
                print(f"  Relationship Score: {score.factors.relationship_score:.1f}")
                print(f"  Age Score:          {score.factors.age_score:.1f}")
                print("\nTop Risks:")
                for risk in score.top_risks:
                    print(f"  - {risk}")
                print("\nRecommendations:")
                for rec in score.recommendations:
                    print(f"  - {rec}")

        return 0

    except Exception as e:
        logger.error(f"Risk scoring failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_blast_radius(args: argparse.Namespace) -> int:
    """
    Calculate blast radius for security findings.

    Analyzes the potential downstream impact of findings by examining
    asset relationships and affected resources.
    """
    from stance.analytics.blast_radius import BlastRadiusCalculator, ImpactCategory
    from stance.analytics.asset_graph import AssetGraph
    from stance.models.finding import FindingCollection
    from stance.storage import get_storage

    output_format = getattr(args, "format", "table")
    finding_id = getattr(args, "finding_id", None)
    category_filter = getattr(args, "category", None)
    min_score = getattr(args, "min_score", None)
    limit = getattr(args, "limit", 20)

    try:
        # Load data from storage
        storage = get_storage()
        assets = storage.load_assets()
        findings_data = storage.load_findings()

        if not assets or not assets.assets:
            print("No assets found. Run 'stance scan' first.")
            return 1

        if not findings_data or not findings_data.findings:
            print("No findings found. Run 'stance scan' first.")
            return 1

        # Build asset graph
        print("Building asset graph...")
        graph = AssetGraph()
        graph.build_from_assets(assets)

        # Initialize calculator
        calculator = BlastRadiusCalculator(graph, findings_data)

        # Calculate for single finding or all findings
        if finding_id:
            finding = findings_data.get_by_id(finding_id)
            if not finding:
                print(f"Finding not found: {finding_id}")
                return 1
            results = [calculator.calculate(finding)]
        else:
            print("Calculating blast radius for all findings...")
            results = calculator.calculate_all()

        # Filter by impact category
        if category_filter:
            try:
                filter_cat = ImpactCategory(category_filter)
                results = [r for r in results if filter_cat in r.impact_categories]
            except ValueError:
                print(f"Warning: Unknown category '{category_filter}'")

        # Filter by minimum score
        if min_score is not None:
            results = [r for r in results if r.blast_radius_score >= min_score]

        # Limit results
        results = results[:limit]

        # Output results
        if output_format == "json":
            output = {
                "total_analyzed": len(results),
                "results": [r.to_dict() for r in results],
            }
            print(json.dumps(output, indent=2))
        else:
            # Table format
            print("")
            print(f"Blast Radius Analysis for {len(results)} Findings")
            print("=" * 100)

            if not results:
                print("No findings match the specified filters.")
                return 0

            print(f"{'Finding ID':<30} {'Score':<8} {'Severity':<10} {'Adjusted':<10} {'Affected':<10} {'Data Risk'}")
            print("-" * 100)

            for result in results:
                finding_short = result.finding_id[:27] + "..." if len(result.finding_id) > 30 else result.finding_id
                print(
                    f"{finding_short:<30} "
                    f"{result.blast_radius_score:<8.1f} "
                    f"{result.finding_severity.value:<10} "
                    f"{result.adjusted_severity.value:<10} "
                    f"{result.total_affected_count:<10} "
                    f"{result.data_exposure_risk}"
                )

            # Show detailed view for single finding
            if finding_id and results:
                result = results[0]
                print("\nDetailed Blast Radius:")
                print(f"  Source Asset: {result.source_asset_name}")
                print(f"  Original Severity: {result.finding_severity.value}")
                print(f"  Adjusted Severity: {result.adjusted_severity.value}")
                print(f"  Blast Radius Score: {result.blast_radius_score:.1f}")
                print(f"\n  Impact Categories:")
                for cat in result.impact_categories:
                    print(f"    - {cat.value}")
                print(f"\n  Data Exposure Risk: {result.data_exposure_risk}")
                print(f"  Service Disruption Risk: {result.service_disruption_risk}")
                print(f"\n  Compliance Implications:")
                for framework in result.compliance_implications:
                    print(f"    - {framework}")
                print(f"\n  Directly Affected ({len(result.directly_affected)}):")
                for affected in result.directly_affected[:5]:
                    print(f"    - {affected.asset_name} ({affected.impact_type})")
                if len(result.directly_affected) > 5:
                    print(f"    ... and {len(result.directly_affected) - 5} more")
                print(f"\n  Indirectly Affected ({len(result.indirectly_affected)}):")
                for affected in result.indirectly_affected[:5]:
                    print(f"    - {affected.asset_name} ({affected.impact_type})")
                if len(result.indirectly_affected) > 5:
                    print(f"    ... and {len(result.indirectly_affected) - 5} more")

        return 0

    except Exception as e:
        logger.error(f"Blast radius calculation failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_mitre(args: argparse.Namespace) -> int:
    """
    Map findings to MITRE ATT&CK framework.

    Provides mapping of security findings to MITRE ATT&CK tactics,
    techniques, and kill chain phases with detection recommendations.
    """
    from stance.analytics.mitre_attack import MitreAttackMapper, MitreTactic
    from stance.models.finding import FindingCollection
    from stance.storage import get_storage

    output_format = getattr(args, "format", "table")
    finding_id = getattr(args, "finding_id", None)
    tactic_filter = getattr(args, "tactic", None)
    technique_id = getattr(args, "technique", None)
    show_coverage = getattr(args, "coverage", False)
    limit = getattr(args, "limit", 20)

    try:
        # Initialize mapper
        mapper = MitreAttackMapper()

        # Show specific technique info
        if technique_id:
            technique = mapper.get_technique(technique_id.upper())
            if not technique:
                print(f"Technique not found: {technique_id}")
                return 1

            if output_format == "json":
                print(json.dumps(technique.to_dict(), indent=2))
            else:
                print("")
                print(f"MITRE ATT&CK Technique: {technique.id}")
                print("=" * 60)
                print(f"Name: {technique.name}")
                print(f"Tactic: {technique.tactic.value}")
                print(f"Description: {technique.description}")
                print(f"Cloud Platforms: {', '.join(technique.cloud_platforms)}")
                if technique.sub_techniques:
                    print(f"Sub-techniques: {', '.join(technique.sub_techniques)}")

                # Show detection recommendations
                detection_recs = mapper.DETECTION_RECOMMENDATIONS.get(technique.id, [])
                if detection_recs:
                    print("\nDetection Recommendations:")
                    for rec in detection_recs:
                        print(f"  - {rec}")

                # Show mitigation strategies
                mitigation_strats = mapper.MITIGATION_STRATEGIES.get(technique.id, [])
                if mitigation_strats:
                    print("\nMitigation Strategies:")
                    for strat in mitigation_strats:
                        print(f"  - {strat}")

            return 0

        # Load findings
        storage = get_storage()
        findings_data = storage.load_findings()

        if not findings_data or not findings_data.findings:
            print("No findings found. Run 'stance scan' first.")
            return 1

        # Map single finding or all findings
        if finding_id:
            finding = findings_data.get_by_id(finding_id)
            if not finding:
                print(f"Finding not found: {finding_id}")
                return 1
            mappings = [mapper.map_finding(finding)]
        else:
            print("Mapping findings to MITRE ATT&CK...")
            mappings = mapper.map_findings(findings_data)

        # Filter by tactic
        if tactic_filter:
            try:
                filter_tactic = MitreTactic(tactic_filter.lower())
                mappings = [m for m in mappings if filter_tactic in m.tactics]
            except ValueError:
                print(f"Warning: Unknown tactic '{tactic_filter}'")

        # Filter out mappings with no techniques
        mappings = [m for m in mappings if m.techniques]

        # Show coverage summary
        if show_coverage:
            coverage = mapper.get_coverage_summary(mappings)
            if output_format == "json":
                print(json.dumps(coverage, indent=2))
            else:
                print("")
                print("MITRE ATT&CK Coverage Summary")
                print("=" * 60)
                print(f"Total Mappings: {coverage['total_mappings']}")
                print(f"Tactics Covered: {coverage['tactics_covered']}/{len(MitreTactic)}")
                print(f"Techniques Covered: {coverage['techniques_covered']}")
                print(f"Kill Chain Phases: {coverage['kill_chain_phases_covered']}")
                print("\nTactics Covered:")
                for tactic in coverage['tactics_covered_list']:
                    print(f"  - {tactic}")
                print("\nTactic Distribution:")
                for tactic, count in sorted(coverage['tactic_distribution'].items(), key=lambda x: -x[1]):
                    print(f"  {tactic}: {count}")
            return 0

        # Limit results
        mappings = mappings[:limit]

        # Output results
        if output_format == "json":
            output = {
                "total_mappings": len(mappings),
                "mappings": [m.to_dict() for m in mappings],
            }
            print(json.dumps(output, indent=2))
        else:
            # Table format
            print("")
            print(f"MITRE ATT&CK Mappings for {len(mappings)} Findings")
            print("=" * 100)

            if not mappings:
                print("No findings could be mapped to MITRE ATT&CK.")
                return 0

            print(f"{'Finding ID':<30} {'Techniques':<20} {'Tactics':<25} {'Confidence'}")
            print("-" * 100)

            for mapping in mappings:
                finding_short = mapping.finding_id[:27] + "..." if len(mapping.finding_id) > 30 else mapping.finding_id
                techniques = ", ".join(mapping.technique_ids[:3])
                if len(mapping.technique_ids) > 3:
                    techniques += f" +{len(mapping.technique_ids) - 3}"
                tactics = ", ".join(t.value for t in mapping.tactics[:2])
                if len(mapping.tactics) > 2:
                    tactics += f" +{len(mapping.tactics) - 2}"
                print(f"{finding_short:<30} {techniques:<20} {tactics:<25} {mapping.confidence:.0%}")

            # Show detailed view for single finding
            if finding_id and mappings:
                mapping = mappings[0]
                print("\nDetailed MITRE ATT&CK Mapping:")
                print(f"  Finding: {mapping.finding_id}")
                print(f"  Confidence: {mapping.confidence:.0%}")
                print("\n  Techniques:")
                for tech in mapping.techniques:
                    print(f"    - {tech.id}: {tech.name}")
                    print(f"      Tactic: {tech.tactic.value}")
                print("\n  Kill Chain Phases:")
                for phase in mapping.kill_chain_phases:
                    print(f"    - {phase.value}")
                print("\n  Detection Recommendations:")
                for rec in mapping.detection_recommendations[:5]:
                    print(f"    - {rec}")
                print("\n  Mitigation Strategies:")
                for strat in mapping.mitigation_strategies[:5]:
                    print(f"    - {strat}")

        return 0

    except Exception as e:
        logger.error(f"MITRE ATT&CK mapping failed: {e}")
        print(f"Error: {e}")
        return 1
