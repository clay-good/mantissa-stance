"""
Analytics handlers for the Stance web API.

This module handles all /api/analytics/* endpoints for attack path analysis,
risk scoring, blast radius calculation, and MITRE ATT&CK mapping.
"""

from __future__ import annotations

import logging
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


class AnalyticsHandler(RoutedHandler):
    """
    Handler for analytics API endpoints.

    Handles:
    - Attack path analysis
    - Risk scoring
    - Blast radius calculation
    - MITRE ATT&CK framework mapping
    """

    base_path = "/api/analytics/"

    # =========================================================================
    # Attack Path Analysis endpoints
    # =========================================================================

    @route("attack-paths")
    def analytics_attack_paths(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Analyze attack paths in the environment.

        Query params:
            type: Filter by attack path type
            severity: Minimum severity to include
            limit: Maximum number of paths to return (default: 20)
        """
        try:
            path_type = self.get_param(params, "type", "")
            severity = self.get_param(params, "severity", "")
            limit = self.get_param_int(params, "limit", 20)

            # Try to use real analytics if available
            try:
                from stance.analytics.attack_paths import AttackPathAnalyzer, AttackPathType
                from stance.analytics.asset_graph import AssetGraph
                from stance.storage import get_storage

                storage = get_storage()
                assets = storage.get_assets()
                findings_data = storage.get_findings()

                if not assets or not assets.assets:
                    return HandlerResponse.success(self._get_demo_attack_paths(path_type, severity, limit))

                graph = AssetGraph()
                graph.build_from_assets(assets)

                analyzer = AttackPathAnalyzer(graph, findings_data)
                paths = analyzer.analyze()

                if path_type:
                    try:
                        filter_type = AttackPathType(path_type)
                        paths = [p for p in paths if p.path_type == filter_type]
                    except ValueError:
                        pass

                if severity:
                    from stance.models.finding import Severity
                    severity_order = {
                        "critical": Severity.CRITICAL,
                        "high": Severity.HIGH,
                        "medium": Severity.MEDIUM,
                        "low": Severity.LOW,
                        "info": Severity.INFO,
                    }
                    min_sev = severity_order.get(severity.lower())
                    if min_sev:
                        paths = [p for p in paths if p.severity.value <= min_sev.value]

                paths = paths[:limit]

                return HandlerResponse.success({
                    "total_paths": len(paths),
                    "paths": [
                        {
                            "id": getattr(p, "id", None),
                            "path_type": p.path_type.value if p.path_type else None,
                            "severity": p.severity.value if p.severity else None,
                            "length": p.length,
                            "description": p.description,
                            "mitigation": p.mitigation,
                            "steps": [
                                {
                                    "asset_id": s.asset_id,
                                    "asset_name": s.asset_name,
                                    "resource_type": s.resource_type,
                                    "action": s.action,
                                    "finding_count": len(s.findings) if s.findings else 0,
                                }
                                for s in (p.steps or [])
                            ],
                        }
                        for p in paths
                    ],
                })
            except Exception:
                # Fall back to demo data
                return HandlerResponse.success(self._get_demo_attack_paths(path_type, severity, limit))

        except Exception as e:
            logger.exception("Failed to analyze attack paths")
            return HandlerResponse.server_error(str(e))

    def _get_demo_attack_paths(self, path_type: str, severity: str, limit: int) -> dict[str, Any]:
        """Get demo attack path data."""
        paths = [
            {
                "id": "path-001",
                "path_type": "internet_to_internal",
                "severity": "critical",
                "length": 4,
                "description": "Internet-exposed S3 bucket leads to EC2 instance with admin credentials",
                "mitigation": "Enable S3 bucket encryption and restrict public access",
                "steps": [
                    {"asset_id": "s3-001", "asset_name": "public-data-bucket", "resource_type": "aws_s3_bucket", "action": "read", "finding_count": 2},
                    {"asset_id": "lambda-001", "asset_name": "data-processor", "resource_type": "aws_lambda_function", "action": "invoke", "finding_count": 1},
                    {"asset_id": "ec2-001", "asset_name": "app-server", "resource_type": "aws_ec2_instance", "action": "access", "finding_count": 3},
                ],
            },
            {
                "id": "path-002",
                "path_type": "privilege_escalation",
                "severity": "high",
                "length": 3,
                "description": "Overly permissive IAM role allows privilege escalation to admin",
                "mitigation": "Apply least privilege principle to IAM policies",
                "steps": [
                    {"asset_id": "iam-001", "asset_name": "developer-role", "resource_type": "aws_iam_role", "action": "assume", "finding_count": 1},
                    {"asset_id": "iam-002", "asset_name": "admin-role", "resource_type": "aws_iam_role", "action": "assume", "finding_count": 2},
                ],
            },
            {
                "id": "path-003",
                "path_type": "lateral_movement",
                "severity": "high",
                "length": 5,
                "description": "Compromised workload can move laterally through VPC peering",
                "mitigation": "Implement network segmentation and security groups",
                "steps": [
                    {"asset_id": "ec2-002", "asset_name": "web-server", "resource_type": "aws_ec2_instance", "action": "compromise", "finding_count": 2},
                    {"asset_id": "vpc-001", "asset_name": "prod-vpc", "resource_type": "aws_vpc", "action": "traverse", "finding_count": 0},
                    {"asset_id": "ec2-003", "asset_name": "db-server", "resource_type": "aws_ec2_instance", "action": "access", "finding_count": 1},
                ],
            },
            {
                "id": "path-004",
                "path_type": "data_exfiltration",
                "severity": "critical",
                "length": 3,
                "description": "Sensitive data can be exfiltrated via public S3 bucket",
                "mitigation": "Enable S3 bucket policies to prevent public access",
                "steps": [
                    {"asset_id": "rds-001", "asset_name": "customer-db", "resource_type": "aws_rds_instance", "action": "query", "finding_count": 1},
                    {"asset_id": "s3-002", "asset_name": "backup-bucket", "resource_type": "aws_s3_bucket", "action": "upload", "finding_count": 2},
                ],
            },
        ]

        # Apply filters
        if path_type:
            paths = [p for p in paths if p["path_type"] == path_type]
        if severity:
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            min_sev = severity_order.get(severity.lower(), 4)
            paths = [p for p in paths if severity_order.get(p["severity"], 4) <= min_sev]

        paths = paths[:limit]

        return {
            "total_paths": len(paths),
            "paths": paths,
        }

    # =========================================================================
    # Risk Scoring endpoints
    # =========================================================================

    @route("risk-score")
    def analytics_risk_score(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Calculate risk scores for assets.

        Query params:
            asset_id: Specific asset ID to score
            min_score: Minimum risk score to include
            level: Filter by risk level (critical, high, medium, low, minimal)
            limit: Maximum number of assets to return (default: 20)
        """
        try:
            asset_id = self.get_param(params, "asset_id", "")
            min_score = self.get_param(params, "min_score", "")
            level = self.get_param(params, "level", "")
            limit = self.get_param_int(params, "limit", 20)

            # Try to use real analytics if available
            try:
                from stance.analytics.risk_scoring import RiskScorer
                from stance.analytics.asset_graph import AssetGraph
                from stance.storage import get_storage

                storage = get_storage()
                assets = storage.get_assets()
                findings_data = storage.get_findings()

                if not assets or not assets.assets:
                    return HandlerResponse.success(self._get_demo_risk_scores(asset_id, min_score, level, limit))

                graph = AssetGraph()
                graph.build_from_assets(assets)

                scorer = RiskScorer(graph, findings_data)

                if asset_id:
                    asset = assets.get_by_id(asset_id)
                    if not asset:
                        return HandlerResponse.error(f"Asset not found: {asset_id}", HttpStatus.NOT_FOUND)
                    scores = [scorer.score_asset(asset)]
                    aggregate = None
                else:
                    scores = scorer.score_collection(assets)
                    aggregate = scorer.aggregate_risk(assets)

                if min_score:
                    min_score_val = float(min_score)
                    scores = [s for s in scores if s.overall_score >= min_score_val]

                if level:
                    scores = [s for s in scores if s.risk_level == level.lower()]

                scores = scores[:limit]

                return HandlerResponse.success({
                    "total_scored": len(scores),
                    "aggregate": aggregate,
                    "scores": [
                        {
                            "asset_id": s.asset_id,
                            "overall_score": s.overall_score,
                            "risk_level": s.risk_level,
                            "factors": s.factors.to_dict() if s.factors else {},
                            "top_risks": s.top_risks,
                            "recommendations": s.recommendations,
                            "last_updated": s.last_updated.isoformat() if s.last_updated else None,
                        }
                        for s in scores
                    ],
                })
            except Exception:
                return HandlerResponse.success(self._get_demo_risk_scores(asset_id, min_score, level, limit))

        except Exception as e:
            logger.exception("Failed to calculate risk scores")
            return HandlerResponse.server_error(str(e))

    def _get_demo_risk_scores(self, asset_id: str, min_score: str, level: str, limit: int) -> dict[str, Any]:
        """Get demo risk score data."""
        scores = [
            {
                "asset_id": "s3-001",
                "overall_score": 92.5,
                "risk_level": "critical",
                "factors": {"exposure": 0.95, "sensitivity": 0.90, "vulnerability": 0.85},
                "top_risks": ["Public access enabled", "No encryption", "No versioning"],
                "recommendations": ["Enable encryption", "Restrict public access", "Enable versioning"],
                "last_updated": "2024-12-29T12:00:00Z",
            },
            {
                "asset_id": "ec2-001",
                "overall_score": 78.0,
                "risk_level": "high",
                "factors": {"exposure": 0.80, "sensitivity": 0.75, "vulnerability": 0.70},
                "top_risks": ["Exposed to internet", "Missing patches", "Weak IAM role"],
                "recommendations": ["Apply security patches", "Restrict security groups", "Review IAM policies"],
                "last_updated": "2024-12-29T12:00:00Z",
            },
            {
                "asset_id": "rds-001",
                "overall_score": 65.0,
                "risk_level": "medium",
                "factors": {"exposure": 0.60, "sensitivity": 0.85, "vulnerability": 0.50},
                "top_risks": ["Publicly accessible", "Backup retention too short"],
                "recommendations": ["Disable public accessibility", "Increase backup retention"],
                "last_updated": "2024-12-29T12:00:00Z",
            },
            {
                "asset_id": "lambda-001",
                "overall_score": 45.0,
                "risk_level": "low",
                "factors": {"exposure": 0.40, "sensitivity": 0.50, "vulnerability": 0.40},
                "top_risks": ["Overly permissive execution role"],
                "recommendations": ["Apply least privilege to execution role"],
                "last_updated": "2024-12-29T12:00:00Z",
            },
        ]

        # Apply filters
        if asset_id:
            scores = [s for s in scores if s["asset_id"] == asset_id]
        if min_score:
            min_score_val = float(min_score)
            scores = [s for s in scores if s["overall_score"] >= min_score_val]
        if level:
            scores = [s for s in scores if s["risk_level"] == level.lower()]

        scores = scores[:limit]

        return {
            "total_scored": len(scores),
            "aggregate": {
                "average_score": sum(s["overall_score"] for s in scores) / len(scores) if scores else 0,
                "critical_count": len([s for s in scores if s["risk_level"] == "critical"]),
                "high_count": len([s for s in scores if s["risk_level"] == "high"]),
                "medium_count": len([s for s in scores if s["risk_level"] == "medium"]),
                "low_count": len([s for s in scores if s["risk_level"] == "low"]),
            },
            "scores": scores,
        }

    # =========================================================================
    # Blast Radius endpoints
    # =========================================================================

    @route("blast-radius")
    def analytics_blast_radius(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Calculate blast radius for security findings.

        Query params:
            finding_id: Specific finding ID to analyze
            category: Filter by impact category
            min_score: Minimum blast radius score to include
            limit: Maximum number of findings to return (default: 20)
        """
        try:
            finding_id = self.get_param(params, "finding_id", "")
            category = self.get_param(params, "category", "")
            min_score = self.get_param(params, "min_score", "")
            limit = self.get_param_int(params, "limit", 20)

            # Try to use real analytics if available
            try:
                from stance.analytics.blast_radius import BlastRadiusCalculator, ImpactCategory
                from stance.analytics.asset_graph import AssetGraph
                from stance.storage import get_storage

                storage = get_storage()
                assets = storage.get_assets()
                findings_data = storage.get_findings()

                if not assets or not assets.assets or not findings_data or not findings_data.findings:
                    return HandlerResponse.success(self._get_demo_blast_radius(finding_id, category, min_score, limit))

                graph = AssetGraph()
                graph.build_from_assets(assets)

                calculator = BlastRadiusCalculator(graph, findings_data)

                if finding_id:
                    finding = findings_data.get_by_id(finding_id)
                    if not finding:
                        return HandlerResponse.error(f"Finding not found: {finding_id}", HttpStatus.NOT_FOUND)
                    results = [calculator.calculate(finding)]
                else:
                    results = calculator.calculate_all()

                if category:
                    try:
                        filter_cat = ImpactCategory(category)
                        results = [r for r in results if filter_cat in r.impact_categories]
                    except ValueError:
                        pass

                if min_score:
                    min_score_val = float(min_score)
                    results = [r for r in results if r.blast_radius_score >= min_score_val]

                results = results[:limit]

                return HandlerResponse.success({
                    "total_analyzed": len(results),
                    "results": [
                        {
                            "finding_id": r.finding_id,
                            "blast_radius_score": r.blast_radius_score,
                            "finding_severity": r.finding_severity.value if r.finding_severity else None,
                            "adjusted_severity": r.adjusted_severity.value if r.adjusted_severity else None,
                            "source_asset_name": r.source_asset_name,
                            "total_affected_count": r.total_affected_count,
                            "data_exposure_risk": r.data_exposure_risk,
                            "service_disruption_risk": r.service_disruption_risk,
                            "impact_categories": [c.value for c in r.impact_categories] if r.impact_categories else [],
                            "compliance_implications": r.compliance_implications or [],
                            "directly_affected": [
                                {
                                    "asset_id": a.asset_id,
                                    "asset_name": a.asset_name,
                                    "impact_type": a.impact_type,
                                }
                                for a in (r.directly_affected or [])[:10]
                            ],
                            "indirectly_affected_count": len(r.indirectly_affected) if r.indirectly_affected else 0,
                        }
                        for r in results
                    ],
                })
            except Exception:
                return HandlerResponse.success(self._get_demo_blast_radius(finding_id, category, min_score, limit))

        except Exception as e:
            logger.exception("Failed to calculate blast radius")
            return HandlerResponse.server_error(str(e))

    def _get_demo_blast_radius(self, finding_id: str, category: str, min_score: str, limit: int) -> dict[str, Any]:
        """Get demo blast radius data."""
        results = [
            {
                "finding_id": "finding-001",
                "blast_radius_score": 95.0,
                "finding_severity": "critical",
                "adjusted_severity": "critical",
                "source_asset_name": "public-data-bucket",
                "total_affected_count": 15,
                "data_exposure_risk": 0.95,
                "service_disruption_risk": 0.60,
                "impact_categories": ["data_exposure", "compliance_violation"],
                "compliance_implications": ["PCI-DSS", "SOC2", "HIPAA"],
                "directly_affected": [
                    {"asset_id": "lambda-001", "asset_name": "data-processor", "impact_type": "data_access"},
                    {"asset_id": "ec2-001", "asset_name": "app-server", "impact_type": "service_dependency"},
                ],
                "indirectly_affected_count": 12,
            },
            {
                "finding_id": "finding-002",
                "blast_radius_score": 78.0,
                "finding_severity": "high",
                "adjusted_severity": "critical",
                "source_asset_name": "app-server",
                "total_affected_count": 8,
                "data_exposure_risk": 0.70,
                "service_disruption_risk": 0.85,
                "impact_categories": ["service_disruption", "lateral_movement"],
                "compliance_implications": ["SOC2"],
                "directly_affected": [
                    {"asset_id": "rds-001", "asset_name": "customer-db", "impact_type": "data_access"},
                ],
                "indirectly_affected_count": 6,
            },
            {
                "finding_id": "finding-003",
                "blast_radius_score": 55.0,
                "finding_severity": "medium",
                "adjusted_severity": "high",
                "source_asset_name": "developer-role",
                "total_affected_count": 5,
                "data_exposure_risk": 0.40,
                "service_disruption_risk": 0.30,
                "impact_categories": ["privilege_escalation"],
                "compliance_implications": ["SOC2"],
                "directly_affected": [
                    {"asset_id": "iam-002", "asset_name": "admin-role", "impact_type": "privilege_escalation"},
                ],
                "indirectly_affected_count": 3,
            },
        ]

        # Apply filters
        if finding_id:
            results = [r for r in results if r["finding_id"] == finding_id]
        if category:
            results = [r for r in results if category in r["impact_categories"]]
        if min_score:
            min_score_val = float(min_score)
            results = [r for r in results if r["blast_radius_score"] >= min_score_val]

        results = results[:limit]

        return {
            "total_analyzed": len(results),
            "results": results,
        }

    # =========================================================================
    # MITRE ATT&CK endpoints
    # =========================================================================

    @route("mitre")
    def analytics_mitre(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Map findings to MITRE ATT&CK framework.

        Query params:
            finding_id: Specific finding ID to map
            tactic: Filter by MITRE ATT&CK tactic
            limit: Maximum number of mappings to return (default: 20)
        """
        try:
            finding_id = self.get_param(params, "finding_id", "")
            tactic = self.get_param(params, "tactic", "")
            limit = self.get_param_int(params, "limit", 20)

            # Try to use real analytics if available
            try:
                from stance.analytics.mitre_attack import MitreAttackMapper, MitreTactic
                from stance.storage import get_storage

                mapper = MitreAttackMapper()
                storage = get_storage()
                findings_data = storage.get_findings()

                if not findings_data or not findings_data.findings:
                    return HandlerResponse.success(self._get_demo_mitre_mappings(finding_id, tactic, limit))

                if finding_id:
                    finding = findings_data.get_by_id(finding_id)
                    if not finding:
                        return HandlerResponse.error(f"Finding not found: {finding_id}", HttpStatus.NOT_FOUND)
                    mappings = [mapper.map_finding(finding)]
                else:
                    mappings = mapper.map_findings(findings_data)

                if tactic:
                    try:
                        filter_tactic = MitreTactic(tactic.lower())
                        mappings = [m for m in mappings if filter_tactic in m.tactics]
                    except ValueError:
                        pass

                mappings = [m for m in mappings if m.techniques]
                mappings = mappings[:limit]

                return HandlerResponse.success({
                    "total_mappings": len(mappings),
                    "mappings": [
                        {
                            "finding_id": m.finding_id,
                            "confidence": m.confidence,
                            "techniques": [
                                {
                                    "id": t.id,
                                    "name": t.name,
                                    "tactic": t.tactic.value if t.tactic else None,
                                    "description": t.description,
                                }
                                for t in m.techniques
                            ],
                            "tactics": [t.value for t in m.tactics],
                            "kill_chain_phases": [p.value for p in m.kill_chain_phases],
                            "detection_recommendations": m.detection_recommendations[:5],
                            "mitigation_strategies": m.mitigation_strategies[:5],
                        }
                        for m in mappings
                    ],
                })
            except Exception:
                return HandlerResponse.success(self._get_demo_mitre_mappings(finding_id, tactic, limit))

        except Exception as e:
            logger.exception("Failed to map to MITRE ATT&CK")
            return HandlerResponse.server_error(str(e))

    def _get_demo_mitre_mappings(self, finding_id: str, tactic: str, limit: int) -> dict[str, Any]:
        """Get demo MITRE ATT&CK mapping data."""
        mappings = [
            {
                "finding_id": "finding-001",
                "confidence": 0.95,
                "techniques": [
                    {"id": "T1078", "name": "Valid Accounts", "tactic": "initial_access", "description": "Adversaries may obtain and abuse credentials of existing accounts"},
                    {"id": "T1530", "name": "Data from Cloud Storage Object", "tactic": "collection", "description": "Adversaries may access data objects from improperly secured cloud storage"},
                ],
                "tactics": ["initial_access", "collection"],
                "kill_chain_phases": ["exploitation", "actions_on_objectives"],
                "detection_recommendations": ["Monitor for unusual S3 access patterns", "Enable CloudTrail logging"],
                "mitigation_strategies": ["Enable MFA", "Apply least privilege", "Enable bucket encryption"],
            },
            {
                "finding_id": "finding-002",
                "confidence": 0.85,
                "techniques": [
                    {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "privilege_escalation", "description": "Adversaries may exploit software vulnerabilities to gain elevated privileges"},
                ],
                "tactics": ["privilege_escalation"],
                "kill_chain_phases": ["exploitation"],
                "detection_recommendations": ["Monitor for privilege escalation attempts", "Enable IAM Access Analyzer"],
                "mitigation_strategies": ["Apply patches", "Use security groups"],
            },
            {
                "finding_id": "finding-003",
                "confidence": 0.75,
                "techniques": [
                    {"id": "T1021", "name": "Remote Services", "tactic": "lateral_movement", "description": "Adversaries may use remote services to move laterally within a network"},
                ],
                "tactics": ["lateral_movement"],
                "kill_chain_phases": ["exploitation"],
                "detection_recommendations": ["Monitor network connections", "Enable VPC flow logs"],
                "mitigation_strategies": ["Implement network segmentation", "Use security groups"],
            },
        ]

        # Apply filters
        if finding_id:
            mappings = [m for m in mappings if m["finding_id"] == finding_id]
        if tactic:
            mappings = [m for m in mappings if tactic.lower() in m["tactics"]]

        mappings = mappings[:limit]

        return {
            "total_mappings": len(mappings),
            "mappings": mappings,
        }

    @route("mitre/technique")
    def analytics_mitre_technique(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Get details for a specific MITRE ATT&CK technique.

        Query params:
            technique_id: MITRE technique ID (e.g., T1078)
        """
        try:
            technique_id = self.get_param(params, "technique_id", "")

            if not technique_id:
                return HandlerResponse.error(
                    "technique_id parameter is required",
                    HttpStatus.BAD_REQUEST
                )

            # Try to use real analytics if available
            try:
                from stance.analytics.mitre_attack import MitreAttackMapper

                mapper = MitreAttackMapper()
                technique = mapper.get_technique(technique_id.upper())

                if not technique:
                    return HandlerResponse.error(
                        f"Technique not found: {technique_id}",
                        HttpStatus.NOT_FOUND
                    )

                detection_recs = mapper.DETECTION_RECOMMENDATIONS.get(technique.id, [])
                mitigation_strats = mapper.MITIGATION_STRATEGIES.get(technique.id, [])

                return HandlerResponse.success({
                    "technique": {
                        "id": technique.id,
                        "name": technique.name,
                        "tactic": technique.tactic.value if technique.tactic else None,
                        "description": technique.description,
                        "cloud_platforms": technique.cloud_platforms,
                        "sub_techniques": technique.sub_techniques,
                    },
                    "detection_recommendations": detection_recs,
                    "mitigation_strategies": mitigation_strats,
                })
            except Exception:
                return HandlerResponse.success(self._get_demo_technique(technique_id))

        except Exception as e:
            logger.exception("Failed to get MITRE technique")
            return HandlerResponse.server_error(str(e))

    def _get_demo_technique(self, technique_id: str) -> dict[str, Any]:
        """Get demo MITRE technique data."""
        techniques = {
            "T1078": {
                "technique": {
                    "id": "T1078",
                    "name": "Valid Accounts",
                    "tactic": "initial_access",
                    "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
                    "cloud_platforms": ["AWS", "Azure", "GCP"],
                    "sub_techniques": ["T1078.001", "T1078.002", "T1078.003", "T1078.004"],
                },
                "detection_recommendations": [
                    "Monitor for unusual account activity",
                    "Enable MFA and monitor bypass attempts",
                    "Alert on failed login attempts",
                ],
                "mitigation_strategies": [
                    "Enable multi-factor authentication",
                    "Use strong password policies",
                    "Regularly rotate credentials",
                ],
            },
            "T1530": {
                "technique": {
                    "id": "T1530",
                    "name": "Data from Cloud Storage Object",
                    "tactic": "collection",
                    "description": "Adversaries may access data objects from improperly secured cloud storage.",
                    "cloud_platforms": ["AWS", "Azure", "GCP"],
                    "sub_techniques": [],
                },
                "detection_recommendations": [
                    "Monitor for unusual S3/GCS/Azure Blob access",
                    "Enable CloudTrail/Cloud Audit Logs",
                ],
                "mitigation_strategies": [
                    "Enable bucket encryption",
                    "Restrict public access",
                    "Use IAM policies",
                ],
            },
        }

        tid = technique_id.upper()
        if tid in techniques:
            return techniques[tid]

        return {
            "technique": {
                "id": tid,
                "name": f"Technique {tid}",
                "tactic": "unknown",
                "description": f"MITRE ATT&CK technique {tid}",
                "cloud_platforms": [],
                "sub_techniques": [],
            },
            "detection_recommendations": [],
            "mitigation_strategies": [],
        }

    @route("mitre/coverage")
    def analytics_mitre_coverage(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Get MITRE ATT&CK coverage summary for all findings.

        Shows which tactics and techniques are covered by current findings.
        """
        try:
            # Try to use real analytics if available
            try:
                from stance.analytics.mitre_attack import MitreAttackMapper, MitreTactic
                from stance.storage import get_storage

                mapper = MitreAttackMapper()
                storage = get_storage()
                findings_data = storage.get_findings()

                if not findings_data or not findings_data.findings:
                    return HandlerResponse.success(self._get_demo_mitre_coverage())

                mappings = mapper.map_findings(findings_data)
                mappings = [m for m in mappings if m.techniques]
                coverage = mapper.get_coverage_summary(mappings)

                return HandlerResponse.success({
                    "total_mappings": coverage["total_mappings"],
                    "total_tactics": len(MitreTactic),
                    "tactics_covered": coverage["tactics_covered"],
                    "tactics_covered_list": coverage["tactics_covered_list"],
                    "techniques_covered": coverage["techniques_covered"],
                    "techniques_covered_list": coverage["techniques_covered_list"],
                    "kill_chain_phases_covered": coverage["kill_chain_phases_covered"],
                    "kill_chain_phases_list": coverage.get("kill_chain_phases_list", []),
                    "tactic_distribution": coverage["tactic_distribution"],
                })
            except Exception:
                return HandlerResponse.success(self._get_demo_mitre_coverage())

        except Exception as e:
            logger.exception("Failed to get MITRE coverage")
            return HandlerResponse.server_error(str(e))

    def _get_demo_mitre_coverage(self) -> dict[str, Any]:
        """Get demo MITRE coverage data."""
        return {
            "total_mappings": 15,
            "total_tactics": 14,
            "tactics_covered": 8,
            "tactics_covered_list": [
                "initial_access", "execution", "persistence",
                "privilege_escalation", "credential_access",
                "discovery", "lateral_movement", "collection"
            ],
            "techniques_covered": 12,
            "techniques_covered_list": [
                "T1078", "T1530", "T1068", "T1021",
                "T1059", "T1098", "T1087", "T1110",
                "T1552", "T1580", "T1528", "T1538"
            ],
            "kill_chain_phases_covered": 5,
            "kill_chain_phases_list": [
                "reconnaissance", "weaponization", "delivery",
                "exploitation", "actions_on_objectives"
            ],
            "tactic_distribution": {
                "initial_access": 3,
                "execution": 2,
                "persistence": 2,
                "privilege_escalation": 2,
                "credential_access": 2,
                "discovery": 1,
                "lateral_movement": 2,
                "collection": 1,
            },
        }

    # =========================================================================
    # Summary endpoints
    # =========================================================================

    @route("summary")
    def analytics_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get analytics summary and available features."""
        try:
            return HandlerResponse.success({
                "available_features": [
                    {
                        "name": "attack-paths",
                        "description": "Analyze attack paths in the environment",
                        "params": ["type", "severity", "limit"],
                    },
                    {
                        "name": "risk-score",
                        "description": "Calculate risk scores for assets",
                        "params": ["asset_id", "min_score", "level", "limit"],
                    },
                    {
                        "name": "blast-radius",
                        "description": "Calculate blast radius for findings",
                        "params": ["finding_id", "category", "min_score", "limit"],
                    },
                    {
                        "name": "mitre",
                        "description": "Map findings to MITRE ATT&CK framework",
                        "params": ["finding_id", "tactic", "limit"],
                    },
                    {
                        "name": "mitre/technique",
                        "description": "Get details for a specific MITRE technique",
                        "params": ["technique_id"],
                    },
                    {
                        "name": "mitre/coverage",
                        "description": "Get MITRE ATT&CK coverage summary",
                        "params": [],
                    },
                ],
                "attack_path_types": [
                    "internet_to_internal",
                    "privilege_escalation",
                    "lateral_movement",
                    "data_exfiltration",
                    "credential_exposure",
                    "data_theft",
                    "ransomware_spread",
                    "crypto_mining",
                    "identity_theft",
                ],
                "risk_levels": ["critical", "high", "medium", "low", "minimal"],
                "impact_categories": [
                    "data_exposure",
                    "service_disruption",
                    "credential_compromise",
                    "compliance_violation",
                    "lateral_movement",
                    "privilege_escalation",
                ],
                "mitre_tactics": [
                    "reconnaissance",
                    "resource_development",
                    "initial_access",
                    "execution",
                    "persistence",
                    "privilege_escalation",
                    "defense_evasion",
                    "credential_access",
                    "discovery",
                    "lateral_movement",
                    "collection",
                    "exfiltration",
                    "impact",
                ],
            })
        except Exception as e:
            logger.exception("Failed to get analytics summary")
            return HandlerResponse.server_error(str(e))
