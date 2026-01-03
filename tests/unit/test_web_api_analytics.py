"""
Unit tests for the Analytics Web API endpoints.

Tests for:
- /api/analytics/attack-paths
- /api/analytics/risk-score
- /api/analytics/blast-radius
- /api/analytics/mitre
- /api/analytics/mitre/technique
- /api/analytics/mitre/coverage
- /api/analytics/summary
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest


class TestAnalyticsAttackPathsAPI:
    """Tests for /api/analytics/attack-paths endpoint."""

    def test_no_assets_returns_error(self):
        """Test that no assets returns appropriate error."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler.storage = MagicMock()

        with patch("stance.web.server.get_storage") as mock_storage:
            mock_store = MagicMock()
            mock_store.load_assets.return_value = None
            mock_storage.return_value = mock_store

            result = StanceRequestHandler._analytics_attack_paths(handler, {})

            assert "error" in result
            assert "No assets found" in result["error"]

    def test_attack_paths_success(self):
        """Test successful attack paths analysis."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.get_storage") as mock_storage, \
             patch("stance.web.server.AssetGraph") as mock_graph_class, \
             patch("stance.web.server.AttackPathAnalyzer") as mock_analyzer_class:
            # Setup storage mock
            mock_store = MagicMock()
            mock_assets = MagicMock()
            mock_assets.assets = [MagicMock()]
            mock_store.load_assets.return_value = mock_assets
            mock_store.load_findings.return_value = None
            mock_storage.return_value = mock_store

            # Setup graph mock
            mock_graph = MagicMock()
            mock_graph_class.return_value = mock_graph

            # Setup analyzer mock
            mock_analyzer = MagicMock()
            mock_path = MagicMock()
            mock_path.path_type = MagicMock()
            mock_path.path_type.value = "internet_to_internal"
            mock_path.severity = MagicMock()
            mock_path.severity.value = "high"
            mock_path.length = 3
            mock_path.description = "Test path"
            mock_path.mitigation = "Fix it"
            mock_path.steps = []
            mock_analyzer.analyze.return_value = [mock_path]
            mock_analyzer_class.return_value = mock_analyzer

            result = StanceRequestHandler._analytics_attack_paths(handler, {})

            assert "total_paths" in result
            assert "paths" in result
            assert result["total_paths"] == 1

    def test_attack_paths_with_type_filter(self):
        """Test attack paths with type filter."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.get_storage") as mock_storage, \
             patch("stance.web.server.AssetGraph") as mock_graph_class, \
             patch("stance.web.server.AttackPathAnalyzer") as mock_analyzer_class, \
             patch("stance.web.server.AttackPathType") as mock_type:
            # Setup storage mock
            mock_store = MagicMock()
            mock_assets = MagicMock()
            mock_assets.assets = [MagicMock()]
            mock_store.load_assets.return_value = mock_assets
            mock_store.load_findings.return_value = None
            mock_storage.return_value = mock_store

            # Setup graph mock
            mock_graph = MagicMock()
            mock_graph_class.return_value = mock_graph

            # Setup analyzer mock
            mock_analyzer = MagicMock()
            mock_path = MagicMock()
            mock_path.path_type = mock_type("privilege_escalation")
            mock_path.severity = MagicMock()
            mock_path.severity.value = "high"
            mock_path.steps = []
            mock_analyzer.analyze.return_value = [mock_path]
            mock_analyzer_class.return_value = mock_analyzer

            result = StanceRequestHandler._analytics_attack_paths(
                handler, {"type": ["privilege_escalation"]}
            )

            assert "total_paths" in result

    def test_attack_paths_with_limit(self):
        """Test attack paths with limit parameter."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.get_storage") as mock_storage, \
             patch("stance.web.server.AssetGraph") as mock_graph_class, \
             patch("stance.web.server.AttackPathAnalyzer") as mock_analyzer_class:
            # Setup storage mock
            mock_store = MagicMock()
            mock_assets = MagicMock()
            mock_assets.assets = [MagicMock()]
            mock_store.load_assets.return_value = mock_assets
            mock_store.load_findings.return_value = None
            mock_storage.return_value = mock_store

            # Setup graph mock
            mock_graph = MagicMock()
            mock_graph_class.return_value = mock_graph

            # Setup analyzer mock - return many paths
            mock_analyzer = MagicMock()
            mock_paths = []
            for i in range(10):
                mock_path = MagicMock()
                mock_path.path_type = MagicMock()
                mock_path.path_type.value = "lateral_movement"
                mock_path.severity = MagicMock()
                mock_path.severity.value = "medium"
                mock_path.steps = []
                mock_paths.append(mock_path)
            mock_analyzer.analyze.return_value = mock_paths
            mock_analyzer_class.return_value = mock_analyzer

            result = StanceRequestHandler._analytics_attack_paths(
                handler, {"limit": ["5"]}
            )

            assert len(result["paths"]) == 5


class TestAnalyticsRiskScoreAPI:
    """Tests for /api/analytics/risk-score endpoint."""

    def test_no_assets_returns_error(self):
        """Test that no assets returns appropriate error."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.get_storage") as mock_storage:
            mock_store = MagicMock()
            mock_store.load_assets.return_value = None
            mock_storage.return_value = mock_store

            result = StanceRequestHandler._analytics_risk_score(handler, {})

            assert "error" in result
            assert "No assets found" in result["error"]

    def test_risk_score_success(self):
        """Test successful risk score calculation."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.get_storage") as mock_storage, \
             patch("stance.web.server.AssetGraph") as mock_graph_class, \
             patch("stance.web.server.RiskScorer") as mock_scorer_class:
            # Setup storage mock
            mock_store = MagicMock()
            mock_assets = MagicMock()
            mock_assets.assets = [MagicMock()]
            mock_store.load_assets.return_value = mock_assets
            mock_store.load_findings.return_value = None
            mock_storage.return_value = mock_store

            # Setup graph mock
            mock_graph = MagicMock()
            mock_graph_class.return_value = mock_graph

            # Setup scorer mock
            mock_scorer = MagicMock()
            mock_score = MagicMock()
            mock_score.asset_id = "test-asset"
            mock_score.overall_score = 75.5
            mock_score.risk_level = "high"
            mock_score.factors = MagicMock()
            mock_score.factors.to_dict.return_value = {}
            mock_score.top_risks = []
            mock_score.recommendations = []
            mock_score.last_updated = None
            mock_scorer.score_collection.return_value = [mock_score]
            mock_scorer.aggregate_risk.return_value = {"average_score": 75.5}
            mock_scorer_class.return_value = mock_scorer

            result = StanceRequestHandler._analytics_risk_score(handler, {})

            assert "total_scored" in result
            assert "scores" in result
            assert "aggregate" in result

    def test_risk_score_single_asset(self):
        """Test risk score for a single asset."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.get_storage") as mock_storage, \
             patch("stance.web.server.AssetGraph") as mock_graph_class, \
             patch("stance.web.server.RiskScorer") as mock_scorer_class:
            # Setup storage mock
            mock_store = MagicMock()
            mock_assets = MagicMock()
            mock_asset = MagicMock()
            mock_assets.assets = [mock_asset]
            mock_assets.get_by_id.return_value = mock_asset
            mock_store.load_assets.return_value = mock_assets
            mock_store.load_findings.return_value = None
            mock_storage.return_value = mock_store

            # Setup graph mock
            mock_graph = MagicMock()
            mock_graph_class.return_value = mock_graph

            # Setup scorer mock
            mock_scorer = MagicMock()
            mock_score = MagicMock()
            mock_score.asset_id = "specific-asset"
            mock_score.overall_score = 85.0
            mock_score.risk_level = "high"
            mock_score.factors = MagicMock()
            mock_score.factors.to_dict.return_value = {}
            mock_score.top_risks = []
            mock_score.recommendations = []
            mock_score.last_updated = None
            mock_scorer.score_asset.return_value = mock_score
            mock_scorer_class.return_value = mock_scorer

            result = StanceRequestHandler._analytics_risk_score(
                handler, {"asset_id": ["specific-asset"]}
            )

            assert result["aggregate"] is None  # No aggregate for single asset
            assert len(result["scores"]) == 1

    def test_risk_score_asset_not_found(self):
        """Test risk score for non-existent asset."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.get_storage") as mock_storage, \
             patch("stance.web.server.AssetGraph") as mock_graph_class:
            # Setup storage mock
            mock_store = MagicMock()
            mock_assets = MagicMock()
            mock_assets.assets = [MagicMock()]
            mock_assets.get_by_id.return_value = None
            mock_store.load_assets.return_value = mock_assets
            mock_store.load_findings.return_value = None
            mock_storage.return_value = mock_store

            # Setup graph mock
            mock_graph = MagicMock()
            mock_graph_class.return_value = mock_graph

            result = StanceRequestHandler._analytics_risk_score(
                handler, {"asset_id": ["non-existent"]}
            )

            assert "error" in result
            assert "Asset not found" in result["error"]

    def test_risk_score_with_level_filter(self):
        """Test risk score with level filter."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.get_storage") as mock_storage, \
             patch("stance.web.server.AssetGraph") as mock_graph_class, \
             patch("stance.web.server.RiskScorer") as mock_scorer_class:
            # Setup storage mock
            mock_store = MagicMock()
            mock_assets = MagicMock()
            mock_assets.assets = [MagicMock()]
            mock_store.load_assets.return_value = mock_assets
            mock_store.load_findings.return_value = None
            mock_storage.return_value = mock_store

            # Setup graph mock
            mock_graph = MagicMock()
            mock_graph_class.return_value = mock_graph

            # Setup scorer mock
            mock_scorer = MagicMock()
            mock_score1 = MagicMock()
            mock_score1.overall_score = 95.0
            mock_score1.risk_level = "critical"
            mock_score1.factors = MagicMock()
            mock_score1.factors.to_dict.return_value = {}
            mock_score2 = MagicMock()
            mock_score2.overall_score = 30.0
            mock_score2.risk_level = "low"
            mock_score2.factors = MagicMock()
            mock_score2.factors.to_dict.return_value = {}
            mock_scorer.score_collection.return_value = [mock_score1, mock_score2]
            mock_scorer.aggregate_risk.return_value = {}
            mock_scorer_class.return_value = mock_scorer

            result = StanceRequestHandler._analytics_risk_score(
                handler, {"level": ["critical"]}
            )

            assert len(result["scores"]) == 1


class TestAnalyticsBlastRadiusAPI:
    """Tests for /api/analytics/blast-radius endpoint."""

    def test_no_assets_returns_error(self):
        """Test that no assets returns appropriate error."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.get_storage") as mock_storage:
            mock_store = MagicMock()
            mock_store.load_assets.return_value = None
            mock_storage.return_value = mock_store

            result = StanceRequestHandler._analytics_blast_radius(handler, {})

            assert "error" in result
            assert "No assets found" in result["error"]

    def test_no_findings_returns_error(self):
        """Test that no findings returns appropriate error."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.get_storage") as mock_storage:
            mock_store = MagicMock()
            mock_assets = MagicMock()
            mock_assets.assets = [MagicMock()]
            mock_store.load_assets.return_value = mock_assets
            mock_store.load_findings.return_value = None
            mock_storage.return_value = mock_store

            result = StanceRequestHandler._analytics_blast_radius(handler, {})

            assert "error" in result
            assert "No findings found" in result["error"]

    def test_blast_radius_success(self):
        """Test successful blast radius calculation."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.get_storage") as mock_storage, \
             patch("stance.web.server.AssetGraph") as mock_graph_class, \
             patch("stance.web.server.BlastRadiusCalculator") as mock_calc_class:
            # Setup storage mock
            mock_store = MagicMock()
            mock_assets = MagicMock()
            mock_assets.assets = [MagicMock()]
            mock_findings = MagicMock()
            mock_findings.findings = [MagicMock()]
            mock_store.load_assets.return_value = mock_assets
            mock_store.load_findings.return_value = mock_findings
            mock_storage.return_value = mock_store

            # Setup graph mock
            mock_graph = MagicMock()
            mock_graph_class.return_value = mock_graph

            # Setup calculator mock
            mock_calc = MagicMock()
            mock_result = MagicMock()
            mock_result.finding_id = "finding-123"
            mock_result.blast_radius_score = 75.0
            mock_result.finding_severity = MagicMock()
            mock_result.finding_severity.value = "high"
            mock_result.adjusted_severity = MagicMock()
            mock_result.adjusted_severity.value = "critical"
            mock_result.source_asset_name = "test-asset"
            mock_result.total_affected_count = 5
            mock_result.data_exposure_risk = "high"
            mock_result.service_disruption_risk = "medium"
            mock_result.impact_categories = []
            mock_result.compliance_implications = []
            mock_result.directly_affected = []
            mock_result.indirectly_affected = []
            mock_calc.calculate_all.return_value = [mock_result]
            mock_calc_class.return_value = mock_calc

            result = StanceRequestHandler._analytics_blast_radius(handler, {})

            assert "total_analyzed" in result
            assert "results" in result
            assert result["total_analyzed"] == 1

    def test_blast_radius_single_finding(self):
        """Test blast radius for a single finding."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.get_storage") as mock_storage, \
             patch("stance.web.server.AssetGraph") as mock_graph_class, \
             patch("stance.web.server.BlastRadiusCalculator") as mock_calc_class:
            # Setup storage mock
            mock_store = MagicMock()
            mock_assets = MagicMock()
            mock_assets.assets = [MagicMock()]
            mock_finding = MagicMock()
            mock_findings = MagicMock()
            mock_findings.findings = [mock_finding]
            mock_findings.get_by_id.return_value = mock_finding
            mock_store.load_assets.return_value = mock_assets
            mock_store.load_findings.return_value = mock_findings
            mock_storage.return_value = mock_store

            # Setup graph mock
            mock_graph = MagicMock()
            mock_graph_class.return_value = mock_graph

            # Setup calculator mock
            mock_calc = MagicMock()
            mock_result = MagicMock()
            mock_result.finding_id = "specific-finding"
            mock_result.blast_radius_score = 90.0
            mock_result.finding_severity = MagicMock()
            mock_result.finding_severity.value = "critical"
            mock_result.adjusted_severity = MagicMock()
            mock_result.adjusted_severity.value = "critical"
            mock_result.source_asset_name = "test-asset"
            mock_result.total_affected_count = 10
            mock_result.data_exposure_risk = "critical"
            mock_result.service_disruption_risk = "high"
            mock_result.impact_categories = []
            mock_result.compliance_implications = []
            mock_result.directly_affected = []
            mock_result.indirectly_affected = []
            mock_calc.calculate.return_value = mock_result
            mock_calc_class.return_value = mock_calc

            result = StanceRequestHandler._analytics_blast_radius(
                handler, {"finding_id": ["specific-finding"]}
            )

            assert result["total_analyzed"] == 1

    def test_blast_radius_finding_not_found(self):
        """Test blast radius for non-existent finding."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.get_storage") as mock_storage, \
             patch("stance.web.server.AssetGraph") as mock_graph_class:
            # Setup storage mock
            mock_store = MagicMock()
            mock_assets = MagicMock()
            mock_assets.assets = [MagicMock()]
            mock_findings = MagicMock()
            mock_findings.findings = [MagicMock()]
            mock_findings.get_by_id.return_value = None
            mock_store.load_assets.return_value = mock_assets
            mock_store.load_findings.return_value = mock_findings
            mock_storage.return_value = mock_store

            # Setup graph mock
            mock_graph = MagicMock()
            mock_graph_class.return_value = mock_graph

            result = StanceRequestHandler._analytics_blast_radius(
                handler, {"finding_id": ["non-existent"]}
            )

            assert "error" in result
            assert "Finding not found" in result["error"]


class TestAnalyticsMitreAPI:
    """Tests for /api/analytics/mitre endpoint."""

    def test_no_findings_returns_error(self):
        """Test that no findings returns appropriate error."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.MitreAttackMapper") as mock_mapper_class, \
             patch("stance.web.server.get_storage") as mock_storage:
            mock_mapper = MagicMock()
            mock_mapper_class.return_value = mock_mapper

            mock_store = MagicMock()
            mock_store.load_findings.return_value = None
            mock_storage.return_value = mock_store

            result = StanceRequestHandler._analytics_mitre(handler, {})

            assert "error" in result
            assert "No findings found" in result["error"]

    def test_mitre_mapping_success(self):
        """Test successful MITRE ATT&CK mapping."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.MitreAttackMapper") as mock_mapper_class, \
             patch("stance.web.server.get_storage") as mock_storage:
            # Setup storage mock
            mock_store = MagicMock()
            mock_findings = MagicMock()
            mock_findings.findings = [MagicMock()]
            mock_store.load_findings.return_value = mock_findings
            mock_storage.return_value = mock_store

            # Setup mapper mock
            mock_mapper = MagicMock()
            mock_technique = MagicMock()
            mock_technique.id = "T1078"
            mock_technique.name = "Valid Accounts"
            mock_technique.tactic = MagicMock()
            mock_technique.tactic.value = "initial_access"
            mock_technique.description = "Test"
            mock_mapping = MagicMock()
            mock_mapping.finding_id = "finding-abc"
            mock_mapping.confidence = 0.8
            mock_mapping.techniques = [mock_technique]
            mock_mapping.tactics = [MagicMock(value="initial_access")]
            mock_mapping.kill_chain_phases = [MagicMock(value="delivery")]
            mock_mapping.detection_recommendations = ["Monitor logins"]
            mock_mapping.mitigation_strategies = ["Enable MFA"]
            mock_mapper.map_findings.return_value = [mock_mapping]
            mock_mapper_class.return_value = mock_mapper

            result = StanceRequestHandler._analytics_mitre(handler, {})

            assert "total_mappings" in result
            assert "mappings" in result
            assert result["total_mappings"] == 1

    def test_mitre_mapping_single_finding(self):
        """Test MITRE ATT&CK mapping for a single finding."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.MitreAttackMapper") as mock_mapper_class, \
             patch("stance.web.server.get_storage") as mock_storage:
            # Setup storage mock
            mock_store = MagicMock()
            mock_finding = MagicMock()
            mock_findings = MagicMock()
            mock_findings.findings = [mock_finding]
            mock_findings.get_by_id.return_value = mock_finding
            mock_store.load_findings.return_value = mock_findings
            mock_storage.return_value = mock_store

            # Setup mapper mock
            mock_mapper = MagicMock()
            mock_mapping = MagicMock()
            mock_mapping.finding_id = "specific-finding"
            mock_mapping.confidence = 0.9
            mock_mapping.techniques = [MagicMock()]
            mock_mapping.tactics = []
            mock_mapping.kill_chain_phases = []
            mock_mapping.detection_recommendations = []
            mock_mapping.mitigation_strategies = []
            mock_mapper.map_finding.return_value = mock_mapping
            mock_mapper_class.return_value = mock_mapper

            result = StanceRequestHandler._analytics_mitre(
                handler, {"finding_id": ["specific-finding"]}
            )

            assert result["total_mappings"] == 1

    def test_mitre_mapping_finding_not_found(self):
        """Test MITRE mapping for non-existent finding."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.MitreAttackMapper") as mock_mapper_class, \
             patch("stance.web.server.get_storage") as mock_storage:
            # Setup storage mock
            mock_store = MagicMock()
            mock_findings = MagicMock()
            mock_findings.findings = [MagicMock()]
            mock_findings.get_by_id.return_value = None
            mock_store.load_findings.return_value = mock_findings
            mock_storage.return_value = mock_store

            # Setup mapper mock
            mock_mapper = MagicMock()
            mock_mapper_class.return_value = mock_mapper

            result = StanceRequestHandler._analytics_mitre(
                handler, {"finding_id": ["non-existent"]}
            )

            assert "error" in result
            assert "Finding not found" in result["error"]


class TestAnalyticsMitreTechniqueAPI:
    """Tests for /api/analytics/mitre/technique endpoint."""

    def test_technique_id_required(self):
        """Test that technique_id parameter is required."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        result = StanceRequestHandler._analytics_mitre_technique(handler, {})

        assert "error" in result
        assert "technique_id parameter is required" in result["error"]

    def test_technique_found(self):
        """Test looking up a valid technique."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.MitreAttackMapper") as mock_mapper_class:
            mock_mapper = MagicMock()
            mock_technique = MagicMock()
            mock_technique.id = "T1078"
            mock_technique.name = "Valid Accounts"
            mock_technique.tactic = MagicMock()
            mock_technique.tactic.value = "initial_access"
            mock_technique.description = "Use valid accounts"
            mock_technique.cloud_platforms = ["AWS", "Azure", "GCP"]
            mock_technique.sub_techniques = ["T1078.001"]
            mock_mapper.get_technique.return_value = mock_technique
            mock_mapper.DETECTION_RECOMMENDATIONS = {
                "T1078": ["Monitor logins"],
            }
            mock_mapper.MITIGATION_STRATEGIES = {
                "T1078": ["Enable MFA"],
            }
            mock_mapper_class.return_value = mock_mapper

            result = StanceRequestHandler._analytics_mitre_technique(
                handler, {"technique_id": ["T1078"]}
            )

            assert "technique" in result
            assert result["technique"]["id"] == "T1078"
            assert "detection_recommendations" in result
            assert "mitigation_strategies" in result

    def test_technique_not_found(self):
        """Test looking up non-existent technique."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.MitreAttackMapper") as mock_mapper_class:
            mock_mapper = MagicMock()
            mock_mapper.get_technique.return_value = None
            mock_mapper_class.return_value = mock_mapper

            result = StanceRequestHandler._analytics_mitre_technique(
                handler, {"technique_id": ["T9999"]}
            )

            assert "error" in result
            assert "Technique not found" in result["error"]


class TestAnalyticsMitreCoverageAPI:
    """Tests for /api/analytics/mitre/coverage endpoint."""

    def test_coverage_no_findings(self):
        """Test coverage with no findings."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.MitreAttackMapper") as mock_mapper_class, \
             patch("stance.web.server.get_storage") as mock_storage:
            mock_mapper = MagicMock()
            mock_mapper_class.return_value = mock_mapper

            mock_store = MagicMock()
            mock_store.load_findings.return_value = None
            mock_storage.return_value = mock_store

            result = StanceRequestHandler._analytics_mitre_coverage(handler, {})

            assert result["total_mappings"] == 0
            assert result["tactics_covered"] == 0
            assert result["techniques_covered"] == 0

    def test_coverage_success(self):
        """Test successful coverage calculation."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.MitreAttackMapper") as mock_mapper_class, \
             patch("stance.web.server.MitreTactic") as mock_tactic_class, \
             patch("stance.web.server.get_storage") as mock_storage:
            # Setup storage mock
            mock_store = MagicMock()
            mock_findings = MagicMock()
            mock_findings.findings = [MagicMock()]
            mock_store.load_findings.return_value = mock_findings
            mock_storage.return_value = mock_store

            # Setup tactic class
            mock_tactic_class.__len__ = lambda self: 13

            # Setup mapper mock
            mock_mapper = MagicMock()
            mock_mapping = MagicMock()
            mock_mapping.techniques = [MagicMock()]
            mock_mapper.map_findings.return_value = [mock_mapping]
            mock_mapper.get_coverage_summary.return_value = {
                "total_mappings": 5,
                "tactics_covered": 3,
                "tactics_covered_list": ["initial_access", "persistence", "discovery"],
                "techniques_covered": 8,
                "techniques_covered_list": ["T1078", "T1190"],
                "kill_chain_phases_covered": 4,
                "kill_chain_phases_list": ["delivery", "exploitation"],
                "tactic_distribution": {"initial_access": 3},
            }
            mock_mapper_class.return_value = mock_mapper

            result = StanceRequestHandler._analytics_mitre_coverage(handler, {})

            assert "total_mappings" in result
            assert "tactics_covered" in result
            assert "techniques_covered" in result
            assert "tactic_distribution" in result


class TestAnalyticsSummaryAPI:
    """Tests for /api/analytics/summary endpoint."""

    def test_summary_returns_features(self):
        """Test that summary returns available features."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        result = StanceRequestHandler._analytics_summary(handler, {})

        assert "available_features" in result
        assert len(result["available_features"]) == 6  # All 6 analytics features

        # Check feature names
        feature_names = [f["name"] for f in result["available_features"]]
        assert "attack-paths" in feature_names
        assert "risk-score" in feature_names
        assert "blast-radius" in feature_names
        assert "mitre" in feature_names
        assert "mitre/technique" in feature_names
        assert "mitre/coverage" in feature_names

    def test_summary_returns_options(self):
        """Test that summary returns valid options."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)

        result = StanceRequestHandler._analytics_summary(handler, {})

        assert "attack_path_types" in result
        assert "risk_levels" in result
        assert "impact_categories" in result
        assert "mitre_tactics" in result

        # Check some values
        assert "internet_to_internal" in result["attack_path_types"]
        assert "critical" in result["risk_levels"]
        assert "data_exposure" in result["impact_categories"]
        assert "initial_access" in result["mitre_tactics"]


class TestAnalyticsAPIIntegration:
    """Integration tests for analytics API endpoints."""

    def test_api_routing_attack_paths(self):
        """Test that attack-paths endpoint is properly routed."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._analytics_attack_paths = MagicMock(return_value={"test": True})
        handler._send_json = MagicMock()
        handler._send_error = MagicMock()

        # Simulate routing
        path = "/api/analytics/attack-paths"
        assert path.startswith("/api/analytics/")

    def test_api_routing_risk_score(self):
        """Test that risk-score endpoint is properly routed."""
        path = "/api/analytics/risk-score"
        assert path.startswith("/api/analytics/")

    def test_api_routing_blast_radius(self):
        """Test that blast-radius endpoint is properly routed."""
        path = "/api/analytics/blast-radius"
        assert path.startswith("/api/analytics/")

    def test_api_routing_mitre(self):
        """Test that mitre endpoint is properly routed."""
        path = "/api/analytics/mitre"
        assert path.startswith("/api/analytics/")

    def test_api_routing_mitre_technique(self):
        """Test that mitre/technique endpoint is properly routed."""
        path = "/api/analytics/mitre/technique"
        assert path.startswith("/api/analytics/")

    def test_api_routing_mitre_coverage(self):
        """Test that mitre/coverage endpoint is properly routed."""
        path = "/api/analytics/mitre/coverage"
        assert path.startswith("/api/analytics/")

    def test_api_routing_summary(self):
        """Test that summary endpoint is properly routed."""
        path = "/api/analytics/summary"
        assert path.startswith("/api/analytics/")
