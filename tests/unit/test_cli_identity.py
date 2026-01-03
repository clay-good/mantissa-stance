"""
Unit tests for the Identity CLI commands.
"""

from __future__ import annotations

import argparse
import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from stance.cli_identity import (
    cmd_identity,
    _cmd_identity_who_can_access,
    _cmd_identity_exposure,
    _cmd_identity_overprivileged,
)


class TestCmdIdentity:
    """Tests for cmd_identity routing function."""

    def test_no_action_shows_help(self, capsys):
        """Test that no action shows help text."""
        args = argparse.Namespace(identity_action=None)

        result = cmd_identity(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Usage: stance identity" in captured.out
        assert "who-can-access" in captured.out
        assert "exposure" in captured.out
        assert "overprivileged" in captured.out

    def test_unknown_action_fails(self, capsys):
        """Test that unknown action returns error."""
        args = argparse.Namespace(identity_action="unknown")

        result = cmd_identity(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Unknown" in captured.out

    def test_routes_to_who_can_access(self):
        """Test routing to who-can-access command."""
        with patch("stance.cli_identity._cmd_identity_who_can_access") as mock_wca:
            mock_wca.return_value = 0
            args = argparse.Namespace(identity_action="who-can-access")

            result = cmd_identity(args)

            mock_wca.assert_called_once_with(args)
            assert result == 0

    def test_routes_to_exposure(self):
        """Test routing to exposure command."""
        with patch("stance.cli_identity._cmd_identity_exposure") as mock_exposure:
            mock_exposure.return_value = 0
            args = argparse.Namespace(identity_action="exposure")

            result = cmd_identity(args)

            mock_exposure.assert_called_once_with(args)
            assert result == 0

    def test_routes_to_overprivileged(self):
        """Test routing to overprivileged command."""
        with patch("stance.cli_identity._cmd_identity_overprivileged") as mock_op:
            mock_op.return_value = 0
            args = argparse.Namespace(identity_action="overprivileged")

            result = cmd_identity(args)

            mock_op.assert_called_once_with(args)
            assert result == 0


class TestCmdIdentityWhoCanAccess:
    """Tests for _cmd_identity_who_can_access function."""

    def test_who_can_access_aws_table_output(self, capsys):
        """Test who-can-access for AWS with table output."""
        with patch("stance.cli_identity.AWSDataAccessMapper") as mock_mapper_class:
            mock_mapper = MagicMock()
            mock_result = MagicMock()
            mock_result.resource_id = "arn:aws:s3:::my-bucket"
            mock_result.cloud_provider = "aws"
            mock_result.access_list = []
            mock_mapper.who_can_access.return_value = mock_result
            mock_mapper_class.return_value = mock_mapper

            args = argparse.Namespace(
                resource="arn:aws:s3:::my-bucket",
                cloud="aws",
                format="table",
                include_users=True,
                include_roles=True,
                include_groups=True,
                include_service_accounts=True,
            )

            result = _cmd_identity_who_can_access(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "my-bucket" in captured.out
            assert "aws" in captured.out

    def test_who_can_access_gcp_json_output(self, capsys):
        """Test who-can-access for GCP with JSON output."""
        with patch("stance.cli_identity.GCPDataAccessMapper") as mock_mapper_class:
            mock_mapper = MagicMock()
            mock_result = MagicMock()
            mock_result.resource_id = "gs://gcs-bucket"
            mock_result.cloud_provider = "gcp"

            mock_access = MagicMock()
            mock_access.principal = MagicMock()
            mock_access.principal.id = "user:test@example.com"
            mock_access.principal.type = MagicMock()
            mock_access.principal.type.value = "user"
            mock_access.principal.name = "test@example.com"
            mock_access.permission_level = MagicMock()
            mock_access.permission_level.value = "read"
            mock_access.source = "IAM"

            mock_result.access_list = [mock_access]
            mock_mapper.who_can_access.return_value = mock_result
            mock_mapper_class.return_value = mock_mapper

            args = argparse.Namespace(
                resource="gs://gcs-bucket",
                cloud="gcp",
                format="json",
                include_users=True,
                include_roles=True,
                include_groups=True,
                include_service_accounts=True,
            )

            result = _cmd_identity_who_can_access(args)

            assert result == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["resource"] == "gs://gcs-bucket"
            assert data["cloud"] == "gcp"
            assert len(data["principals"]) == 1

    def test_who_can_access_azure(self, capsys):
        """Test who-can-access for Azure."""
        with patch("stance.cli_identity.AzureDataAccessMapper") as mock_mapper_class:
            mock_mapper = MagicMock()
            mock_result = MagicMock()
            mock_result.resource_id = "/subscriptions/.../storageAccounts/test"
            mock_result.cloud_provider = "azure"
            mock_result.access_list = []
            mock_mapper.who_can_access.return_value = mock_result
            mock_mapper_class.return_value = mock_mapper

            args = argparse.Namespace(
                resource="/subscriptions/.../storageAccounts/test",
                cloud="azure",
                format="table",
                include_users=True,
                include_roles=True,
                include_groups=True,
                include_service_accounts=True,
            )

            result = _cmd_identity_who_can_access(args)

            assert result == 0

    def test_who_can_access_unknown_cloud_fails(self, capsys):
        """Test who-can-access with unknown cloud fails."""
        args = argparse.Namespace(
            resource="bucket",
            cloud="unknown",
            format="table",
            include_users=True,
            include_roles=True,
            include_groups=True,
            include_service_accounts=True,
        )

        result = _cmd_identity_who_can_access(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Unknown cloud provider" in captured.out

    def test_who_can_access_with_principals(self, capsys):
        """Test who-can-access shows principal details."""
        with patch("stance.cli_identity.AWSDataAccessMapper") as mock_mapper_class:
            mock_mapper = MagicMock()
            mock_result = MagicMock()
            mock_result.resource_id = "arn:aws:s3:::my-bucket"
            mock_result.cloud_provider = "aws"

            mock_access1 = MagicMock()
            mock_access1.principal = MagicMock()
            mock_access1.principal.id = "arn:aws:iam::123456789012:user/admin"
            mock_access1.principal.type = MagicMock()
            mock_access1.principal.type.value = "user"
            mock_access1.principal.name = "admin"
            mock_access1.permission_level = MagicMock()
            mock_access1.permission_level.value = "full_control"
            mock_access1.source = "bucket_policy"

            mock_access2 = MagicMock()
            mock_access2.principal = MagicMock()
            mock_access2.principal.id = "arn:aws:iam::123456789012:role/developer"
            mock_access2.principal.type = MagicMock()
            mock_access2.principal.type.value = "role"
            mock_access2.principal.name = "developer"
            mock_access2.permission_level = MagicMock()
            mock_access2.permission_level.value = "read"
            mock_access2.source = "IAM"

            mock_result.access_list = [mock_access1, mock_access2]
            mock_mapper.who_can_access.return_value = mock_result
            mock_mapper_class.return_value = mock_mapper

            args = argparse.Namespace(
                resource="arn:aws:s3:::my-bucket",
                cloud="aws",
                format="table",
                include_users=True,
                include_roles=True,
                include_groups=True,
                include_service_accounts=True,
            )

            result = _cmd_identity_who_can_access(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "Principals with Access" in captured.out
            assert "admin" in captured.out
            assert "Total: 2 principals" in captured.out


class TestCmdIdentityExposure:
    """Tests for _cmd_identity_exposure function."""

    def test_exposure_table_output(self, capsys):
        """Test exposure analysis with table output."""
        with patch("stance.cli_identity.PrincipalExposureAnalyzer") as mock_analyzer_class:
            mock_analyzer = MagicMock()
            mock_result = MagicMock()
            mock_result.principal_id = "arn:aws:iam::123456789012:user/admin"
            mock_result.summary = MagicMock()
            mock_result.summary.total_resources = 100
            mock_result.summary.sensitive_resources = 25
            mock_result.summary.critical_exposures = 5
            mock_result.summary.high_exposures = 10
            mock_result.risk_score = 75
            mock_result.exposures = []
            mock_analyzer.analyze_principal_exposure.return_value = mock_result
            mock_analyzer_class.return_value = mock_analyzer

            args = argparse.Namespace(
                principal="arn:aws:iam::123456789012:user/admin",
                format="table",
                classification=None,
            )

            result = _cmd_identity_exposure(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "admin" in captured.out
            assert "75" in captured.out  # risk score

    def test_exposure_json_output(self, capsys):
        """Test exposure analysis with JSON output."""
        with patch("stance.cli_identity.PrincipalExposureAnalyzer") as mock_analyzer_class:
            mock_analyzer = MagicMock()
            mock_result = MagicMock()
            mock_result.principal_id = "user:test@example.com"
            mock_result.summary = MagicMock()
            mock_result.summary.total_resources = 50
            mock_result.summary.sensitive_resources = 10
            mock_result.summary.critical_exposures = 2
            mock_result.summary.high_exposures = 5
            mock_result.risk_score = 45
            mock_result.exposures = []
            mock_analyzer.analyze_principal_exposure.return_value = mock_result
            mock_analyzer_class.return_value = mock_analyzer

            args = argparse.Namespace(
                principal="user:test@example.com",
                format="json",
                classification=None,
            )

            result = _cmd_identity_exposure(args)

            assert result == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["principal"] == "user:test@example.com"
            assert data["risk_score"] == 45
            assert "summary" in data

    def test_exposure_with_findings(self, capsys):
        """Test exposure with exposure findings."""
        with patch("stance.cli_identity.PrincipalExposureAnalyzer") as mock_analyzer_class:
            mock_analyzer = MagicMock()
            mock_result = MagicMock()
            mock_result.principal_id = "admin-user"
            mock_result.summary = MagicMock()
            mock_result.summary.total_resources = 20
            mock_result.summary.sensitive_resources = 5
            mock_result.summary.critical_exposures = 2
            mock_result.summary.high_exposures = 3
            mock_result.risk_score = 80

            mock_exposure = MagicMock()
            mock_exposure.resource = MagicMock()
            mock_exposure.resource.resource_id = "s3://sensitive-bucket"
            mock_exposure.resource.classification = MagicMock()
            mock_exposure.resource.classification.value = "confidential"
            mock_exposure.resource.categories = []
            mock_exposure.severity = MagicMock()
            mock_exposure.severity.value = "critical"
            mock_exposure.permission_level = MagicMock()
            mock_exposure.permission_level.value = "full_control"

            mock_result.exposures = [mock_exposure]
            mock_analyzer.analyze_principal_exposure.return_value = mock_result
            mock_analyzer_class.return_value = mock_analyzer

            args = argparse.Namespace(
                principal="admin-user",
                format="table",
                classification=None,
            )

            result = _cmd_identity_exposure(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "Sensitive Data Exposures" in captured.out
            assert "sensitive-bucket" in captured.out


class TestCmdIdentityOverprivileged:
    """Tests for _cmd_identity_overprivileged function."""

    def test_overprivileged_aws_table_output(self, capsys):
        """Test overprivileged analysis for AWS with table output."""
        with patch("stance.cli_identity.OverPrivilegedAnalyzer") as mock_analyzer_class:
            mock_analyzer = MagicMock()
            mock_result = MagicMock()
            mock_result.cloud_provider = "aws"
            mock_result.analysis_period_days = 90
            mock_result.summary = MagicMock()
            mock_result.summary.total_principals = 100
            mock_result.summary.over_privileged_count = 15
            mock_result.summary.unused_admin_count = 5
            mock_result.summary.stale_elevated_count = 10
            mock_result.findings = []
            mock_analyzer.analyze.return_value = mock_result
            mock_analyzer_class.return_value = mock_analyzer

            args = argparse.Namespace(
                cloud="aws",
                format="table",
                days=90,
            )

            result = _cmd_identity_overprivileged(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "aws" in captured.out
            assert "90 days" in captured.out

    def test_overprivileged_gcp_json_output(self, capsys):
        """Test overprivileged analysis for GCP with JSON output."""
        with patch("stance.cli_identity.OverPrivilegedAnalyzer") as mock_analyzer_class:
            mock_analyzer = MagicMock()
            mock_result = MagicMock()
            mock_result.cloud_provider = "gcp"
            mock_result.analysis_period_days = 60
            mock_result.summary = MagicMock()
            mock_result.summary.total_principals = 50
            mock_result.summary.over_privileged_count = 8
            mock_result.summary.unused_admin_count = 3
            mock_result.summary.stale_elevated_count = 5
            mock_result.findings = []
            mock_analyzer.analyze.return_value = mock_result
            mock_analyzer_class.return_value = mock_analyzer

            args = argparse.Namespace(
                cloud="gcp",
                format="json",
                days=60,
            )

            result = _cmd_identity_overprivileged(args)

            assert result == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["cloud"] == "gcp"
            assert data["analysis_period_days"] == 60
            assert "summary" in data

    def test_overprivileged_with_findings(self, capsys):
        """Test overprivileged with findings."""
        with patch("stance.cli_identity.OverPrivilegedAnalyzer") as mock_analyzer_class:
            mock_analyzer = MagicMock()
            mock_result = MagicMock()
            mock_result.cloud_provider = "aws"
            mock_result.analysis_period_days = 90
            mock_result.summary = MagicMock()
            mock_result.summary.total_principals = 100
            mock_result.summary.over_privileged_count = 2
            mock_result.summary.unused_admin_count = 1
            mock_result.summary.stale_elevated_count = 1

            mock_finding = MagicMock()
            mock_finding.principal = "arn:aws:iam::123456789012:user/admin"
            mock_finding.principal_type = MagicMock()
            mock_finding.principal_type.value = "user"
            mock_finding.finding_type = MagicMock()
            mock_finding.finding_type.value = "unused_admin"
            mock_finding.granted_permission = MagicMock()
            mock_finding.granted_permission.value = "admin"
            mock_finding.observed_permission = MagicMock()
            mock_finding.observed_permission.value = "read"
            mock_finding.days_inactive = 120
            mock_finding.risk_score = 85
            mock_finding.recommendation = "Remove admin privileges"

            mock_result.findings = [mock_finding]
            mock_analyzer.analyze.return_value = mock_result
            mock_analyzer_class.return_value = mock_analyzer

            args = argparse.Namespace(
                cloud="aws",
                format="table",
                days=90,
            )

            result = _cmd_identity_overprivileged(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "Over-Privileged Access Findings" in captured.out
            assert "admin" in captured.out

    def test_overprivileged_handles_exception(self, capsys):
        """Test overprivileged handles exceptions gracefully."""
        with patch("stance.cli_identity.OverPrivilegedAnalyzer") as mock_analyzer_class:
            mock_analyzer_class.side_effect = Exception("API error")

            args = argparse.Namespace(
                cloud="aws",
                format="table",
                days=90,
            )

            result = _cmd_identity_overprivileged(args)

            assert result == 1
            captured = capsys.readouterr()
            assert "Error" in captured.out
