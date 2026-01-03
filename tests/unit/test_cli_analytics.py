"""
Unit tests for the Analytics CLI commands.

Tests for:
- Attack path analysis CLI
- Risk score calculation CLI
- Blast radius calculation CLI
- MITRE ATT&CK mapping CLI
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from stance.cli_analytics import (
    cmd_analytics,
    _cmd_attack_paths,
    _cmd_risk_score,
    _cmd_blast_radius,
    _cmd_mitre,
)


class TestCmdAnalytics:
    """Tests for cmd_analytics routing function."""

    def test_no_action_shows_help(self, capsys):
        """Test that no action shows help text."""
        args = argparse.Namespace(analytics_action=None)

        result = cmd_analytics(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Usage: stance analytics" in captured.out
        assert "attack-paths" in captured.out
        assert "risk-score" in captured.out
        assert "blast-radius" in captured.out
        assert "mitre" in captured.out

    def test_unknown_action_fails(self, capsys):
        """Test that unknown action returns error."""
        args = argparse.Namespace(analytics_action="unknown")

        result = cmd_analytics(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Unknown" in captured.out

    def test_routes_to_attack_paths(self):
        """Test routing to attack-paths command."""
        with patch("stance.cli_analytics._cmd_attack_paths") as mock_cmd:
            mock_cmd.return_value = 0
            args = argparse.Namespace(analytics_action="attack-paths")

            result = cmd_analytics(args)

            mock_cmd.assert_called_once_with(args)
            assert result == 0

    def test_routes_to_risk_score(self):
        """Test routing to risk-score command."""
        with patch("stance.cli_analytics._cmd_risk_score") as mock_cmd:
            mock_cmd.return_value = 0
            args = argparse.Namespace(analytics_action="risk-score")

            result = cmd_analytics(args)

            mock_cmd.assert_called_once_with(args)
            assert result == 0

    def test_routes_to_blast_radius(self):
        """Test routing to blast-radius command."""
        with patch("stance.cli_analytics._cmd_blast_radius") as mock_cmd:
            mock_cmd.return_value = 0
            args = argparse.Namespace(analytics_action="blast-radius")

            result = cmd_analytics(args)

            mock_cmd.assert_called_once_with(args)
            assert result == 0

    def test_routes_to_mitre(self):
        """Test routing to mitre command."""
        with patch("stance.cli_analytics._cmd_mitre") as mock_cmd:
            mock_cmd.return_value = 0
            args = argparse.Namespace(analytics_action="mitre")

            result = cmd_analytics(args)

            mock_cmd.assert_called_once_with(args)
            assert result == 0


class TestCmdAttackPaths:
    """Tests for _cmd_attack_paths function."""

    def test_no_assets_shows_message(self, capsys):
        """Test that no assets shows appropriate message."""
        with patch("stance.cli_analytics.get_storage") as mock_storage:
            mock_store = MagicMock()
            mock_store.load_assets.return_value = None
            mock_storage.return_value = mock_store

            args = argparse.Namespace(
                format="table",
                type=None,
                severity=None,
                limit=20,
            )

            result = _cmd_attack_paths(args)

            assert result == 1
            captured = capsys.readouterr()
            assert "No assets found" in captured.out

    def test_attack_paths_table_output(self, capsys):
        """Test attack paths with table output."""
        with patch("stance.cli_analytics.get_storage") as mock_storage, \
             patch("stance.cli_analytics.AssetGraph") as mock_graph_class, \
             patch("stance.cli_analytics.AttackPathAnalyzer") as mock_analyzer_class:
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
            mock_path.description = "Test attack path"
            mock_path.steps = [
                MagicMock(asset_name="entry-point", resource_type="aws_ec2_instance", action="Initial access", findings=[]),
                MagicMock(asset_name="target", resource_type="aws_s3_bucket", action="Target reached", findings=[]),
            ]
            mock_path.mitigation = "Restrict access"
            mock_analyzer.analyze.return_value = [mock_path]
            mock_analyzer_class.return_value = mock_analyzer

            args = argparse.Namespace(
                format="table",
                type=None,
                severity=None,
                limit=20,
            )

            result = _cmd_attack_paths(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "Attack Paths Found" in captured.out
            assert "INTERNET_TO_INTERNAL" in captured.out

    def test_attack_paths_json_output(self, capsys):
        """Test attack paths with JSON output."""
        with patch("stance.cli_analytics.get_storage") as mock_storage, \
             patch("stance.cli_analytics.AssetGraph") as mock_graph_class, \
             patch("stance.cli_analytics.AttackPathAnalyzer") as mock_analyzer_class:
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
            mock_path.to_dict.return_value = {
                "id": "test-path-1",
                "path_type": "internet_to_internal",
                "severity": "high",
            }
            mock_analyzer.analyze.return_value = [mock_path]
            mock_analyzer_class.return_value = mock_analyzer

            args = argparse.Namespace(
                format="json",
                type=None,
                severity=None,
                limit=20,
            )

            result = _cmd_attack_paths(args)

            assert result == 0
            captured = capsys.readouterr()
            output = json.loads(captured.out)
            assert "total_paths" in output
            assert "paths" in output

    def test_attack_paths_filter_by_type(self, capsys):
        """Test attack paths filtered by type."""
        with patch("stance.cli_analytics.get_storage") as mock_storage, \
             patch("stance.cli_analytics.AssetGraph") as mock_graph_class, \
             patch("stance.cli_analytics.AttackPathAnalyzer") as mock_analyzer_class, \
             patch("stance.cli_analytics.AttackPathType") as mock_type:
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
            mock_analyzer.analyze.return_value = [mock_path]
            mock_analyzer_class.return_value = mock_analyzer

            args = argparse.Namespace(
                format="table",
                type="privilege_escalation",
                severity=None,
                limit=20,
            )

            result = _cmd_attack_paths(args)

            assert result == 0

    def test_attack_paths_error_handling(self, capsys):
        """Test attack paths error handling."""
        with patch("stance.cli_analytics.get_storage") as mock_storage:
            mock_storage.side_effect = Exception("Test error")

            args = argparse.Namespace(
                format="table",
                type=None,
                severity=None,
                limit=20,
            )

            result = _cmd_attack_paths(args)

            assert result == 1
            captured = capsys.readouterr()
            assert "Error" in captured.out


class TestCmdRiskScore:
    """Tests for _cmd_risk_score function."""

    def test_no_assets_shows_message(self, capsys):
        """Test that no assets shows appropriate message."""
        with patch("stance.cli_analytics.get_storage") as mock_storage:
            mock_store = MagicMock()
            mock_store.load_assets.return_value = None
            mock_storage.return_value = mock_store

            args = argparse.Namespace(
                format="table",
                asset_id=None,
                min_score=None,
                level=None,
                limit=20,
            )

            result = _cmd_risk_score(args)

            assert result == 1
            captured = capsys.readouterr()
            assert "No assets found" in captured.out

    def test_risk_score_table_output(self, capsys):
        """Test risk scoring with table output."""
        with patch("stance.cli_analytics.get_storage") as mock_storage, \
             patch("stance.cli_analytics.AssetGraph") as mock_graph_class, \
             patch("stance.cli_analytics.RiskScorer") as mock_scorer_class:
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
            mock_score.asset_id = "test-asset-123"
            mock_score.overall_score = 75.5
            mock_score.risk_level = "high"
            mock_score.top_risks = ["Internet-facing resource"]
            mock_score.factors = MagicMock()
            mock_score.factors.exposure_score = 100.0
            mock_score.factors.finding_score = 50.0
            mock_score.factors.compliance_score = 30.0
            mock_score.factors.relationship_score = 20.0
            mock_score.factors.age_score = 10.0
            mock_score.recommendations = ["Review access"]
            mock_scorer.score_collection.return_value = [mock_score]
            mock_scorer.aggregate_risk.return_value = {
                "total_assets": 1,
                "average_score": 75.5,
                "max_score": 75.5,
                "by_level": {"high": 1},
            }
            mock_scorer_class.return_value = mock_scorer

            args = argparse.Namespace(
                format="table",
                asset_id=None,
                min_score=None,
                level=None,
                limit=20,
            )

            result = _cmd_risk_score(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "Risk Scores" in captured.out
            assert "test-asset-123" in captured.out

    def test_risk_score_json_output(self, capsys):
        """Test risk scoring with JSON output."""
        with patch("stance.cli_analytics.get_storage") as mock_storage, \
             patch("stance.cli_analytics.AssetGraph") as mock_graph_class, \
             patch("stance.cli_analytics.RiskScorer") as mock_scorer_class:
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
            mock_score.to_dict.return_value = {
                "asset_id": "test-asset",
                "overall_score": 60.0,
                "risk_level": "medium",
            }
            mock_scorer.score_collection.return_value = [mock_score]
            mock_scorer.aggregate_risk.return_value = {"total_assets": 1}
            mock_scorer_class.return_value = mock_scorer

            args = argparse.Namespace(
                format="json",
                asset_id=None,
                min_score=None,
                level=None,
                limit=20,
            )

            result = _cmd_risk_score(args)

            assert result == 0
            captured = capsys.readouterr()
            output = json.loads(captured.out)
            assert "total_scored" in output
            assert "scores" in output

    def test_risk_score_single_asset(self, capsys):
        """Test risk scoring for a single asset."""
        with patch("stance.cli_analytics.get_storage") as mock_storage, \
             patch("stance.cli_analytics.AssetGraph") as mock_graph_class, \
             patch("stance.cli_analytics.RiskScorer") as mock_scorer_class:
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
            mock_score.top_risks = ["Risk 1", "Risk 2"]
            mock_score.factors = MagicMock()
            mock_score.factors.exposure_score = 100.0
            mock_score.factors.finding_score = 80.0
            mock_score.factors.compliance_score = 50.0
            mock_score.factors.relationship_score = 30.0
            mock_score.factors.age_score = 20.0
            mock_score.recommendations = ["Rec 1", "Rec 2"]
            mock_scorer.score_asset.return_value = mock_score
            mock_scorer_class.return_value = mock_scorer

            args = argparse.Namespace(
                format="table",
                asset_id="specific-asset",
                min_score=None,
                level=None,
                limit=20,
            )

            result = _cmd_risk_score(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "Detailed Risk Factors" in captured.out

    def test_risk_score_asset_not_found(self, capsys):
        """Test risk scoring for non-existent asset."""
        with patch("stance.cli_analytics.get_storage") as mock_storage, \
             patch("stance.cli_analytics.AssetGraph") as mock_graph_class:
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

            args = argparse.Namespace(
                format="table",
                asset_id="non-existent",
                min_score=None,
                level=None,
                limit=20,
            )

            result = _cmd_risk_score(args)

            assert result == 1
            captured = capsys.readouterr()
            assert "Asset not found" in captured.out

    def test_risk_score_filter_by_level(self, capsys):
        """Test risk scoring filtered by level."""
        with patch("stance.cli_analytics.get_storage") as mock_storage, \
             patch("stance.cli_analytics.AssetGraph") as mock_graph_class, \
             patch("stance.cli_analytics.RiskScorer") as mock_scorer_class:
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
            mock_score1.risk_level = "critical"
            mock_score1.asset_id = "critical-asset"
            mock_score1.overall_score = 95.0
            mock_score1.top_risks = []
            mock_score2 = MagicMock()
            mock_score2.risk_level = "low"
            mock_score2.asset_id = "low-asset"
            mock_score2.overall_score = 20.0
            mock_score2.top_risks = []
            mock_scorer.score_collection.return_value = [mock_score1, mock_score2]
            mock_scorer.aggregate_risk.return_value = {"total_assets": 2}
            mock_scorer_class.return_value = mock_scorer

            args = argparse.Namespace(
                format="table",
                asset_id=None,
                min_score=None,
                level="critical",
                limit=20,
            )

            result = _cmd_risk_score(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "critical-asset" in captured.out


class TestCmdBlastRadius:
    """Tests for _cmd_blast_radius function."""

    def test_no_assets_shows_message(self, capsys):
        """Test that no assets shows appropriate message."""
        with patch("stance.cli_analytics.get_storage") as mock_storage:
            mock_store = MagicMock()
            mock_store.load_assets.return_value = None
            mock_storage.return_value = mock_store

            args = argparse.Namespace(
                format="table",
                finding_id=None,
                category=None,
                min_score=None,
                limit=20,
            )

            result = _cmd_blast_radius(args)

            assert result == 1
            captured = capsys.readouterr()
            assert "No assets found" in captured.out

    def test_no_findings_shows_message(self, capsys):
        """Test that no findings shows appropriate message."""
        with patch("stance.cli_analytics.get_storage") as mock_storage:
            mock_store = MagicMock()
            mock_assets = MagicMock()
            mock_assets.assets = [MagicMock()]
            mock_store.load_assets.return_value = mock_assets
            mock_store.load_findings.return_value = None
            mock_storage.return_value = mock_store

            args = argparse.Namespace(
                format="table",
                finding_id=None,
                category=None,
                min_score=None,
                limit=20,
            )

            result = _cmd_blast_radius(args)

            assert result == 1
            captured = capsys.readouterr()
            assert "No findings found" in captured.out

    def test_blast_radius_table_output(self, capsys):
        """Test blast radius with table output."""
        with patch("stance.cli_analytics.get_storage") as mock_storage, \
             patch("stance.cli_analytics.AssetGraph") as mock_graph_class, \
             patch("stance.cli_analytics.BlastRadiusCalculator") as mock_calc_class:
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
            mock_result.total_affected_count = 5
            mock_result.data_exposure_risk = "high"
            mock_result.impact_categories = []
            mock_calc.calculate_all.return_value = [mock_result]
            mock_calc_class.return_value = mock_calc

            args = argparse.Namespace(
                format="table",
                finding_id=None,
                category=None,
                min_score=None,
                limit=20,
            )

            result = _cmd_blast_radius(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "Blast Radius Analysis" in captured.out
            assert "finding-123" in captured.out

    def test_blast_radius_json_output(self, capsys):
        """Test blast radius with JSON output."""
        with patch("stance.cli_analytics.get_storage") as mock_storage, \
             patch("stance.cli_analytics.AssetGraph") as mock_graph_class, \
             patch("stance.cli_analytics.BlastRadiusCalculator") as mock_calc_class:
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
            mock_result.to_dict.return_value = {
                "finding_id": "finding-456",
                "blast_radius_score": 80.0,
            }
            mock_result.impact_categories = []
            mock_calc.calculate_all.return_value = [mock_result]
            mock_calc_class.return_value = mock_calc

            args = argparse.Namespace(
                format="json",
                finding_id=None,
                category=None,
                min_score=None,
                limit=20,
            )

            result = _cmd_blast_radius(args)

            assert result == 0
            captured = capsys.readouterr()
            output = json.loads(captured.out)
            assert "total_analyzed" in output
            assert "results" in output

    def test_blast_radius_single_finding(self, capsys):
        """Test blast radius for a single finding."""
        with patch("stance.cli_analytics.get_storage") as mock_storage, \
             patch("stance.cli_analytics.AssetGraph") as mock_graph_class, \
             patch("stance.cli_analytics.BlastRadiusCalculator") as mock_calc_class:
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
            mock_result.impact_categories = [MagicMock(value="data_exposure")]
            mock_result.compliance_implications = ["PCI-DSS", "SOC2"]
            mock_result.directly_affected = [
                MagicMock(asset_name="affected-1", impact_type="data_exposure"),
            ]
            mock_result.indirectly_affected = [
                MagicMock(asset_name="indirect-1", impact_type="lateral_movement"),
            ]
            mock_calc.calculate.return_value = mock_result
            mock_calc_class.return_value = mock_calc

            args = argparse.Namespace(
                format="table",
                finding_id="specific-finding",
                category=None,
                min_score=None,
                limit=20,
            )

            result = _cmd_blast_radius(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "Detailed Blast Radius" in captured.out
            assert "specific-finding" in captured.out

    def test_blast_radius_finding_not_found(self, capsys):
        """Test blast radius for non-existent finding."""
        with patch("stance.cli_analytics.get_storage") as mock_storage, \
             patch("stance.cli_analytics.AssetGraph") as mock_graph_class:
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

            args = argparse.Namespace(
                format="table",
                finding_id="non-existent",
                category=None,
                min_score=None,
                limit=20,
            )

            result = _cmd_blast_radius(args)

            assert result == 1
            captured = capsys.readouterr()
            assert "Finding not found" in captured.out


class TestCmdMitre:
    """Tests for _cmd_mitre function."""

    def test_technique_lookup(self, capsys):
        """Test looking up a specific MITRE technique."""
        with patch("stance.cli_analytics.MitreAttackMapper") as mock_mapper_class:
            mock_mapper = MagicMock()
            mock_technique = MagicMock()
            mock_technique.id = "T1078"
            mock_technique.name = "Valid Accounts"
            mock_technique.tactic = MagicMock()
            mock_technique.tactic.value = "initial_access"
            mock_technique.description = "Test description"
            mock_technique.cloud_platforms = ["AWS", "Azure", "GCP"]
            mock_technique.sub_techniques = ["T1078.001"]
            mock_mapper.get_technique.return_value = mock_technique
            mock_mapper.DETECTION_RECOMMENDATIONS = {
                "T1078": ["Monitor for unusual logins"],
            }
            mock_mapper.MITIGATION_STRATEGIES = {
                "T1078": ["Enforce MFA"],
            }
            mock_mapper_class.return_value = mock_mapper

            args = argparse.Namespace(
                format="table",
                finding_id=None,
                technique="T1078",
                tactic=None,
                coverage=False,
                limit=20,
            )

            result = _cmd_mitre(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "T1078" in captured.out
            assert "Valid Accounts" in captured.out

    def test_technique_lookup_json(self, capsys):
        """Test looking up a specific MITRE technique with JSON output."""
        with patch("stance.cli_analytics.MitreAttackMapper") as mock_mapper_class:
            mock_mapper = MagicMock()
            mock_technique = MagicMock()
            mock_technique.to_dict.return_value = {
                "id": "T1078",
                "name": "Valid Accounts",
                "tactic": "initial_access",
            }
            mock_mapper.get_technique.return_value = mock_technique
            mock_mapper_class.return_value = mock_mapper

            args = argparse.Namespace(
                format="json",
                finding_id=None,
                technique="T1078",
                tactic=None,
                coverage=False,
                limit=20,
            )

            result = _cmd_mitre(args)

            assert result == 0
            captured = capsys.readouterr()
            output = json.loads(captured.out)
            assert output["id"] == "T1078"

    def test_technique_not_found(self, capsys):
        """Test looking up non-existent technique."""
        with patch("stance.cli_analytics.MitreAttackMapper") as mock_mapper_class:
            mock_mapper = MagicMock()
            mock_mapper.get_technique.return_value = None
            mock_mapper_class.return_value = mock_mapper

            args = argparse.Namespace(
                format="table",
                finding_id=None,
                technique="T9999",
                tactic=None,
                coverage=False,
                limit=20,
            )

            result = _cmd_mitre(args)

            assert result == 1
            captured = capsys.readouterr()
            assert "Technique not found" in captured.out

    def test_mitre_no_findings(self, capsys):
        """Test MITRE mapping with no findings."""
        with patch("stance.cli_analytics.MitreAttackMapper") as mock_mapper_class, \
             patch("stance.cli_analytics.get_storage") as mock_storage:
            mock_mapper = MagicMock()
            mock_mapper.get_technique.return_value = None
            mock_mapper_class.return_value = mock_mapper

            mock_store = MagicMock()
            mock_store.load_findings.return_value = None
            mock_storage.return_value = mock_store

            args = argparse.Namespace(
                format="table",
                finding_id=None,
                technique=None,
                tactic=None,
                coverage=False,
                limit=20,
            )

            result = _cmd_mitre(args)

            assert result == 1
            captured = capsys.readouterr()
            assert "No findings found" in captured.out

    def test_mitre_mapping_table_output(self, capsys):
        """Test MITRE mapping with table output."""
        with patch("stance.cli_analytics.MitreAttackMapper") as mock_mapper_class, \
             patch("stance.cli_analytics.get_storage") as mock_storage:
            # Setup storage mock
            mock_store = MagicMock()
            mock_findings = MagicMock()
            mock_findings.findings = [MagicMock()]
            mock_store.load_findings.return_value = mock_findings
            mock_storage.return_value = mock_store

            # Setup mapper mock
            mock_mapper = MagicMock()
            mock_mapper.get_technique.return_value = None
            mock_mapping = MagicMock()
            mock_mapping.finding_id = "finding-abc"
            mock_mapping.technique_ids = ["T1078", "T1190"]
            mock_mapping.tactics = [MagicMock(value="initial_access")]
            mock_mapping.confidence = 0.8
            mock_mapping.techniques = [MagicMock()]  # Not empty
            mock_mapper.map_findings.return_value = [mock_mapping]
            mock_mapper_class.return_value = mock_mapper

            args = argparse.Namespace(
                format="table",
                finding_id=None,
                technique=None,
                tactic=None,
                coverage=False,
                limit=20,
            )

            result = _cmd_mitre(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "MITRE ATT&CK Mappings" in captured.out

    def test_mitre_mapping_json_output(self, capsys):
        """Test MITRE mapping with JSON output."""
        with patch("stance.cli_analytics.MitreAttackMapper") as mock_mapper_class, \
             patch("stance.cli_analytics.get_storage") as mock_storage:
            # Setup storage mock
            mock_store = MagicMock()
            mock_findings = MagicMock()
            mock_findings.findings = [MagicMock()]
            mock_store.load_findings.return_value = mock_findings
            mock_storage.return_value = mock_store

            # Setup mapper mock
            mock_mapper = MagicMock()
            mock_mapper.get_technique.return_value = None
            mock_mapping = MagicMock()
            mock_mapping.to_dict.return_value = {
                "finding_id": "finding-xyz",
                "techniques": [],
            }
            mock_mapping.techniques = [MagicMock()]  # Not empty
            mock_mapper.map_findings.return_value = [mock_mapping]
            mock_mapper_class.return_value = mock_mapper

            args = argparse.Namespace(
                format="json",
                finding_id=None,
                technique=None,
                tactic=None,
                coverage=False,
                limit=20,
            )

            result = _cmd_mitre(args)

            assert result == 0
            captured = capsys.readouterr()
            output = json.loads(captured.out)
            assert "total_mappings" in output
            assert "mappings" in output

    def test_mitre_coverage_summary(self, capsys):
        """Test MITRE coverage summary."""
        with patch("stance.cli_analytics.MitreAttackMapper") as mock_mapper_class, \
             patch("stance.cli_analytics.get_storage") as mock_storage:
            # Setup storage mock
            mock_store = MagicMock()
            mock_findings = MagicMock()
            mock_findings.findings = [MagicMock()]
            mock_store.load_findings.return_value = mock_findings
            mock_storage.return_value = mock_store

            # Setup mapper mock
            mock_mapper = MagicMock()
            mock_mapper.get_technique.return_value = None
            mock_mapping = MagicMock()
            mock_mapping.techniques = [MagicMock()]
            mock_mapper.map_findings.return_value = [mock_mapping]
            mock_mapper.get_coverage_summary.return_value = {
                "total_mappings": 5,
                "tactics_covered": 3,
                "tactics_covered_list": ["initial_access", "persistence", "discovery"],
                "techniques_covered": 8,
                "kill_chain_phases_covered": 4,
                "tactic_distribution": {"initial_access": 3, "persistence": 2},
            }
            mock_mapper_class.return_value = mock_mapper

            args = argparse.Namespace(
                format="table",
                finding_id=None,
                technique=None,
                tactic=None,
                coverage=True,
                limit=20,
            )

            result = _cmd_mitre(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "Coverage Summary" in captured.out
            assert "Tactics Covered" in captured.out

    def test_mitre_single_finding(self, capsys):
        """Test MITRE mapping for a single finding."""
        with patch("stance.cli_analytics.MitreAttackMapper") as mock_mapper_class, \
             patch("stance.cli_analytics.get_storage") as mock_storage:
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
            mock_mapper.get_technique.return_value = None
            mock_technique = MagicMock()
            mock_technique.id = "T1078"
            mock_technique.name = "Valid Accounts"
            mock_technique.tactic = MagicMock()
            mock_technique.tactic.value = "initial_access"
            mock_mapping = MagicMock()
            mock_mapping.finding_id = "specific-finding"
            mock_mapping.confidence = 0.9
            mock_mapping.techniques = [mock_technique]
            mock_mapping.technique_ids = ["T1078"]
            mock_mapping.tactics = [MagicMock(value="initial_access")]
            mock_mapping.kill_chain_phases = [MagicMock(value="delivery")]
            mock_mapping.detection_recommendations = ["Monitor logins"]
            mock_mapping.mitigation_strategies = ["Enable MFA"]
            mock_mapper.map_finding.return_value = mock_mapping
            mock_mapper_class.return_value = mock_mapper

            args = argparse.Namespace(
                format="table",
                finding_id="specific-finding",
                technique=None,
                tactic=None,
                coverage=False,
                limit=20,
            )

            result = _cmd_mitre(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "Detailed MITRE ATT&CK Mapping" in captured.out
            assert "specific-finding" in captured.out

    def test_mitre_finding_not_found(self, capsys):
        """Test MITRE mapping for non-existent finding."""
        with patch("stance.cli_analytics.MitreAttackMapper") as mock_mapper_class, \
             patch("stance.cli_analytics.get_storage") as mock_storage:
            # Setup storage mock
            mock_store = MagicMock()
            mock_findings = MagicMock()
            mock_findings.findings = [MagicMock()]
            mock_findings.get_by_id.return_value = None
            mock_store.load_findings.return_value = mock_findings
            mock_storage.return_value = mock_store

            # Setup mapper mock
            mock_mapper = MagicMock()
            mock_mapper.get_technique.return_value = None
            mock_mapper_class.return_value = mock_mapper

            args = argparse.Namespace(
                format="table",
                finding_id="non-existent",
                technique=None,
                tactic=None,
                coverage=False,
                limit=20,
            )

            result = _cmd_mitre(args)

            assert result == 1
            captured = capsys.readouterr()
            assert "Finding not found" in captured.out


class TestAnalyticsIntegration:
    """Integration tests for analytics CLI commands."""

    def test_all_commands_have_format_option(self):
        """Test that all analytics commands support format option."""
        from stance.cli import create_parser

        parser = create_parser()

        # Parse analytics commands
        for cmd in ["attack-paths", "risk-score", "blast-radius", "mitre"]:
            args = parser.parse_args(["analytics", cmd, "--format", "json"])
            assert args.format == "json"

    def test_all_commands_have_limit_option(self):
        """Test that all analytics commands support limit option."""
        from stance.cli import create_parser

        parser = create_parser()

        for cmd in ["attack-paths", "risk-score", "blast-radius", "mitre"]:
            args = parser.parse_args(["analytics", cmd, "--limit", "50"])
            assert args.limit == 50

    def test_attack_paths_type_filter_options(self):
        """Test attack paths type filter options."""
        from stance.cli import create_parser

        parser = create_parser()

        valid_types = [
            "internet_to_internal",
            "privilege_escalation",
            "lateral_movement",
            "data_exfiltration",
            "credential_exposure",
            "data_theft",
            "ransomware_spread",
            "crypto_mining",
            "identity_theft",
        ]

        for path_type in valid_types:
            args = parser.parse_args(["analytics", "attack-paths", "--type", path_type])
            assert args.type == path_type

    def test_blast_radius_category_filter_options(self):
        """Test blast radius category filter options."""
        from stance.cli import create_parser

        parser = create_parser()

        valid_categories = [
            "data_exposure",
            "service_disruption",
            "credential_compromise",
            "compliance_violation",
            "lateral_movement",
            "privilege_escalation",
        ]

        for category in valid_categories:
            args = parser.parse_args(["analytics", "blast-radius", "--category", category])
            assert args.category == category

    def test_mitre_tactic_filter_options(self):
        """Test MITRE tactic filter options."""
        from stance.cli import create_parser

        parser = create_parser()

        valid_tactics = [
            "reconnaissance",
            "initial_access",
            "persistence",
            "privilege_escalation",
            "defense_evasion",
            "credential_access",
            "discovery",
            "lateral_movement",
            "collection",
            "exfiltration",
            "impact",
        ]

        for tactic in valid_tactics:
            args = parser.parse_args(["analytics", "mitre", "--tactic", tactic])
            assert args.tactic == tactic

    def test_risk_score_level_filter_options(self):
        """Test risk score level filter options."""
        from stance.cli import create_parser

        parser = create_parser()

        valid_levels = ["critical", "high", "medium", "low", "minimal"]

        for level in valid_levels:
            args = parser.parse_args(["analytics", "risk-score", "--level", level])
            assert args.level == level
