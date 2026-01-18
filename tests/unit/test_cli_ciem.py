"""
Unit tests for CIEM CLI commands.

Tests the CLI interface for Cloud Infrastructure Entitlement Management:
- Effective permissions calculation
- Overprivileged identity detection
- Cross-account trust analysis
- Privilege escalation path detection
- CIEM summary command
"""

from __future__ import annotations

import argparse
import json
import sys
from unittest.mock import MagicMock, patch

import pytest

from stance.cli_ciem import (
    add_ciem_parser,
    cmd_ciem,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_storage():
    """Create mock storage with sample assets."""
    storage = MagicMock()

    # Create sample assets
    iam_user = MagicMock()
    iam_user.id = "arn:aws:iam::123456789012:user/admin-user"
    iam_user.name = "admin-user"
    iam_user.resource_type = "aws_iam_user"
    iam_user.raw_config = {"attached_policies": ["arn:aws:iam::aws:policy/AdministratorAccess"]}

    iam_role = MagicMock()
    iam_role.id = "arn:aws:iam::123456789012:role/LambdaRole"
    iam_role.name = "LambdaRole"
    iam_role.resource_type = "aws_iam_role"
    iam_role.raw_config = {
        "attached_policies": [],
        "assume_role_policy": {
            "Statement": [{
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }]
        }
    }

    iam_policy = MagicMock()
    iam_policy.id = "arn:aws:iam::aws:policy/AdministratorAccess"
    iam_policy.name = "AdministratorAccess"
    iam_policy.resource_type = "aws_iam_policy"
    iam_policy.raw_config = {
        "arn": "arn:aws:iam::aws:policy/AdministratorAccess",
        "PolicyDocument": {
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }]
        }
    }

    storage.get_assets.return_value = [iam_user, iam_role, iam_policy]
    return storage


@pytest.fixture
def mock_effective_access():
    """Create mock effective access result."""
    result = MagicMock()
    result.identity_name = "admin-user"
    result.identity_type = "user"
    result.is_admin = True
    result.risk_score = 9.5
    result.permission_set = MagicMock()
    result.permission_set.service_count = 150
    result.to_dict.return_value = {
        "identity_name": "admin-user",
        "identity_type": "user",
        "is_admin": True,
        "risk_score": 9.5,
    }
    return result


@pytest.fixture
def mock_overprivileged_finding():
    """Create mock overprivileged finding."""
    finding = MagicMock()
    finding.identity_name = "dev-user"
    finding.identity_type = "user"
    finding.unused_percentage = 45.5
    finding.unused_permissions = ["s3:DeleteBucket", "ec2:TerminateInstances"]
    finding.severity = MagicMock()
    finding.severity.value = "medium"
    finding.to_dict.return_value = {
        "identity_name": "dev-user",
        "unused_percentage": 45.5,
        "severity": "medium",
    }
    return finding


@pytest.fixture
def mock_trust_relationship():
    """Create mock trust relationship."""
    trust = MagicMock()
    trust.source_name = "CrossAccountRole"
    trust.target_principal = "arn:aws:iam::999888777666:root"
    trust.trust_type = MagicMock()
    trust.trust_type.value = "cross_account"
    trust.risk = MagicMock()
    trust.risk.value = "high"
    trust.is_cross_account = True
    trust.to_dict.return_value = {
        "source_name": "CrossAccountRole",
        "target_principal": "arn:aws:iam::999888777666:root",
        "trust_type": "cross_account",
        "risk": "high",
    }
    return trust


@pytest.fixture
def mock_escalation_path():
    """Create mock privilege escalation path."""
    path = MagicMock()
    path.identity_name = "limited-user"
    path.escalation_type = MagicMock()
    path.escalation_type.value = "iam:PassRole"
    path.final_access = "AdministratorAccess"
    path.severity = MagicMock()
    path.severity.value = "critical"
    path.to_dict.return_value = {
        "identity_name": "limited-user",
        "escalation_type": "iam:PassRole",
        "final_access": "AdministratorAccess",
        "severity": "critical",
    }
    return path


# =============================================================================
# Parser Tests
# =============================================================================


class TestCIEMParser:
    """Tests for CIEM argument parser setup."""

    def test_add_ciem_parser(self):
        """Test CIEM parser is added correctly."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        add_ciem_parser(subparsers)

        args = parser.parse_args(["ciem", "permissions"])
        assert args.ciem_action == "permissions"

    def test_permissions_subcommand_args(self):
        """Test permissions subcommand arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_ciem_parser(subparsers)

        args = parser.parse_args([
            "ciem", "permissions",
            "--identity", "admin-user",
            "--provider", "gcp",
            "--admin-only",
            "--format", "json",
        ])

        assert args.ciem_action == "permissions"
        assert args.identity == "admin-user"
        assert args.provider == "gcp"
        assert args.admin_only is True
        assert args.format == "json"

    def test_overprivileged_subcommand_args(self):
        """Test overprivileged subcommand arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_ciem_parser(subparsers)

        args = parser.parse_args([
            "ciem", "overprivileged",
            "--provider", "azure",
            "--min-unused", "30.0",
            "--lookback-days", "60",
            "--format", "json",
        ])

        assert args.ciem_action == "overprivileged"
        assert args.provider == "azure"
        assert args.min_unused == 30.0
        assert args.lookback_days == 60
        assert args.format == "json"

    def test_trust_subcommand_args(self):
        """Test trust subcommand arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_ciem_parser(subparsers)

        args = parser.parse_args([
            "ciem", "trust",
            "--provider", "aws",
            "--external-only",
            "--high-risk",
            "--format", "table",
        ])

        assert args.ciem_action == "trust"
        assert args.provider == "aws"
        assert args.external_only is True
        assert args.high_risk is True
        assert args.format == "table"

    def test_privesc_subcommand_args(self):
        """Test privesc subcommand arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_ciem_parser(subparsers)

        args = parser.parse_args([
            "ciem", "privesc",
            "--provider", "gcp",
            "--identity", "user@example.com",
            "--format", "json",
        ])

        assert args.ciem_action == "privesc"
        assert args.provider == "gcp"
        assert args.identity == "user@example.com"
        assert args.format == "json"

    def test_summary_subcommand_args(self):
        """Test summary subcommand arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_ciem_parser(subparsers)

        args = parser.parse_args([
            "ciem", "summary",
            "--provider", "azure",
            "--format", "json",
        ])

        assert args.ciem_action == "summary"
        assert args.provider == "azure"
        assert args.format == "json"


# =============================================================================
# Command Dispatch Tests
# =============================================================================


class TestCIEMCommandDispatch:
    """Tests for CIEM command routing."""

    def test_cmd_ciem_no_action(self, capsys):
        """Test cmd_ciem with no action shows usage."""
        args = argparse.Namespace(ciem_action=None)

        result = cmd_ciem(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Usage:" in captured.out
        assert "permissions" in captured.out

    @patch("stance.cli_ciem._ciem_permissions")
    def test_cmd_ciem_permissions_dispatch(self, mock_fn):
        """Test cmd_ciem dispatches to permissions handler."""
        mock_fn.return_value = 0
        args = argparse.Namespace(ciem_action="permissions")

        result = cmd_ciem(args)

        mock_fn.assert_called_once_with(args)
        assert result == 0

    @patch("stance.cli_ciem._ciem_overprivileged")
    def test_cmd_ciem_overprivileged_dispatch(self, mock_fn):
        """Test cmd_ciem dispatches to overprivileged handler."""
        mock_fn.return_value = 0
        args = argparse.Namespace(ciem_action="overprivileged")

        result = cmd_ciem(args)

        mock_fn.assert_called_once_with(args)
        assert result == 0

    @patch("stance.cli_ciem._ciem_trust")
    def test_cmd_ciem_trust_dispatch(self, mock_fn):
        """Test cmd_ciem dispatches to trust handler."""
        mock_fn.return_value = 0
        args = argparse.Namespace(ciem_action="trust")

        result = cmd_ciem(args)

        mock_fn.assert_called_once_with(args)
        assert result == 0

    @patch("stance.cli_ciem._ciem_privesc")
    def test_cmd_ciem_privesc_dispatch(self, mock_fn):
        """Test cmd_ciem dispatches to privesc handler."""
        mock_fn.return_value = 0
        args = argparse.Namespace(ciem_action="privesc")

        result = cmd_ciem(args)

        mock_fn.assert_called_once_with(args)
        assert result == 0

    @patch("stance.cli_ciem._ciem_summary")
    def test_cmd_ciem_summary_dispatch(self, mock_fn):
        """Test cmd_ciem dispatches to summary handler."""
        mock_fn.return_value = 0
        args = argparse.Namespace(ciem_action="summary")

        result = cmd_ciem(args)

        mock_fn.assert_called_once_with(args)
        assert result == 0


# =============================================================================
# Permissions Command Tests
# =============================================================================


class TestCIEMPermissions:
    """Tests for CIEM permissions command."""

    @patch("stance.storage.get_storage")
    @patch("stance.ciem.EffectivePermissionsCalculator")
    def test_permissions_table_output(
        self, mock_calc_class, mock_get_storage, mock_storage, mock_effective_access, capsys
    ):
        """Test permissions command with table output."""
        from stance.cli_ciem import _ciem_permissions

        mock_get_storage.return_value = mock_storage
        mock_calc = MagicMock()
        mock_calc.calculate_all.return_value = [mock_effective_access]
        mock_calc_class.return_value = mock_calc

        args = argparse.Namespace(
            provider="aws",
            identity=None,
            admin_only=False,
            format="table",
        )

        result = _ciem_permissions(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Effective Permissions Analysis" in captured.out
        assert "admin-user" in captured.out

    @patch("stance.storage.get_storage")
    @patch("stance.ciem.EffectivePermissionsCalculator")
    def test_permissions_json_output(
        self, mock_calc_class, mock_get_storage, mock_storage, mock_effective_access, capsys
    ):
        """Test permissions command with JSON output."""
        from stance.cli_ciem import _ciem_permissions

        mock_get_storage.return_value = mock_storage
        mock_calc = MagicMock()
        mock_calc.calculate_all.return_value = [mock_effective_access]
        mock_calc_class.return_value = mock_calc

        args = argparse.Namespace(
            provider="aws",
            identity=None,
            admin_only=False,
            format="json",
        )

        result = _ciem_permissions(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "identities" in output
        assert len(output["identities"]) == 1

    @patch("stance.storage.get_storage")
    @patch("stance.ciem.EffectivePermissionsCalculator")
    def test_permissions_admin_only_filter(
        self, mock_calc_class, mock_get_storage, mock_storage, mock_effective_access, capsys
    ):
        """Test permissions command with admin-only filter."""
        from stance.cli_ciem import _ciem_permissions

        mock_get_storage.return_value = mock_storage
        mock_calc = MagicMock()

        # Add non-admin user
        non_admin = MagicMock()
        non_admin.is_admin = False
        non_admin.to_dict.return_value = {"is_admin": False}

        mock_calc.calculate_all.return_value = [mock_effective_access, non_admin]
        mock_calc_class.return_value = mock_calc

        args = argparse.Namespace(
            provider="aws",
            identity=None,
            admin_only=True,
            format="json",
        )

        result = _ciem_permissions(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        # Only admin should be in results
        assert len(output["identities"]) == 1
        assert output["identities"][0]["is_admin"] is True

    @patch("stance.storage.get_storage")
    def test_permissions_error_handling(self, mock_get_storage, capsys):
        """Test permissions command error handling."""
        from stance.cli_ciem import _ciem_permissions

        mock_get_storage.side_effect = Exception("Storage error")

        args = argparse.Namespace(
            provider="aws",
            identity=None,
            admin_only=False,
            format="table",
        )

        result = _ciem_permissions(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Error" in captured.out


# =============================================================================
# Overprivileged Command Tests
# =============================================================================


class TestCIEMOverprivileged:
    """Tests for CIEM overprivileged command."""

    @patch("stance.storage.get_storage")
    @patch("stance.ciem.EffectivePermissionsCalculator")
    @patch("stance.ciem.OverprivilegedDetector")
    def test_overprivileged_table_output(
        self, mock_detector_class, mock_calc_class, mock_get_storage,
        mock_storage, mock_overprivileged_finding, capsys
    ):
        """Test overprivileged command with table output."""
        from stance.cli_ciem import _ciem_overprivileged

        mock_get_storage.return_value = mock_storage
        mock_calc_class.return_value.calculate_all.return_value = []
        mock_detector_class.return_value.detect_all.return_value = [mock_overprivileged_finding]

        args = argparse.Namespace(
            provider="aws",
            min_unused=20.0,
            lookback_days=90,
            format="table",
        )

        result = _ciem_overprivileged(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Overprivileged Identities" in captured.out
        assert "dev-user" in captured.out

    @patch("stance.storage.get_storage")
    @patch("stance.ciem.EffectivePermissionsCalculator")
    @patch("stance.ciem.OverprivilegedDetector")
    def test_overprivileged_json_output(
        self, mock_detector_class, mock_calc_class, mock_get_storage,
        mock_storage, mock_overprivileged_finding, capsys
    ):
        """Test overprivileged command with JSON output."""
        from stance.cli_ciem import _ciem_overprivileged

        mock_get_storage.return_value = mock_storage
        mock_calc_class.return_value.calculate_all.return_value = []
        mock_detector_class.return_value.detect_all.return_value = [mock_overprivileged_finding]

        args = argparse.Namespace(
            provider="aws",
            min_unused=20.0,
            lookback_days=90,
            format="json",
        )

        result = _ciem_overprivileged(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "overprivileged" in output

    @patch("stance.storage.get_storage")
    @patch("stance.ciem.EffectivePermissionsCalculator")
    @patch("stance.ciem.OverprivilegedDetector")
    def test_overprivileged_no_results(
        self, mock_detector_class, mock_calc_class, mock_get_storage, mock_storage, capsys
    ):
        """Test overprivileged command with no results."""
        from stance.cli_ciem import _ciem_overprivileged

        mock_get_storage.return_value = mock_storage
        mock_calc_class.return_value.calculate_all.return_value = []
        mock_detector_class.return_value.detect_all.return_value = []

        args = argparse.Namespace(
            provider="aws",
            min_unused=20.0,
            lookback_days=90,
            format="table",
        )

        result = _ciem_overprivileged(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "No overprivileged identities found" in captured.out


# =============================================================================
# Trust Command Tests
# =============================================================================


class TestCIEMTrust:
    """Tests for CIEM trust command."""

    @patch("stance.storage.get_storage")
    @patch("stance.ciem.TrustAnalyzer")
    @patch("stance.ciem.TrustRisk")
    def test_trust_table_output(
        self, mock_risk_class, mock_analyzer_class, mock_get_storage,
        mock_storage, mock_trust_relationship, capsys
    ):
        """Test trust command with table output."""
        from stance.cli_ciem import _ciem_trust

        mock_get_storage.return_value = mock_storage
        mock_analyzer_class.return_value.analyze_all.return_value = [mock_trust_relationship]
        mock_risk_class.CRITICAL = mock_trust_relationship.risk
        mock_risk_class.HIGH = MagicMock()

        args = argparse.Namespace(
            provider="aws",
            external_only=False,
            high_risk=False,
            format="table",
        )

        result = _ciem_trust(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Trust Relationships" in captured.out
        assert "CrossAccountRole" in captured.out

    @patch("stance.storage.get_storage")
    @patch("stance.ciem.TrustAnalyzer")
    @patch("stance.ciem.TrustRisk")
    def test_trust_json_output(
        self, mock_risk_class, mock_analyzer_class, mock_get_storage,
        mock_storage, mock_trust_relationship, capsys
    ):
        """Test trust command with JSON output."""
        from stance.cli_ciem import _ciem_trust

        mock_get_storage.return_value = mock_storage
        mock_analyzer_class.return_value.analyze_all.return_value = [mock_trust_relationship]
        mock_risk_class.CRITICAL = MagicMock()
        mock_risk_class.HIGH = MagicMock()

        args = argparse.Namespace(
            provider="aws",
            external_only=False,
            high_risk=False,
            format="json",
        )

        result = _ciem_trust(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "trust_relationships" in output

    @patch("stance.storage.get_storage")
    @patch("stance.ciem.TrustAnalyzer")
    @patch("stance.ciem.TrustRisk")
    def test_trust_external_only_filter(
        self, mock_risk_class, mock_analyzer_class, mock_get_storage,
        mock_storage, mock_trust_relationship, capsys
    ):
        """Test trust command with external-only filter."""
        from stance.cli_ciem import _ciem_trust

        mock_get_storage.return_value = mock_storage

        internal_trust = MagicMock()
        internal_trust.is_cross_account = False

        mock_analyzer_class.return_value.analyze_all.return_value = [
            mock_trust_relationship, internal_trust
        ]
        mock_risk_class.CRITICAL = MagicMock()
        mock_risk_class.HIGH = MagicMock()

        args = argparse.Namespace(
            provider="aws",
            external_only=True,
            high_risk=False,
            format="json",
        )

        result = _ciem_trust(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        # Only external trust should be in results
        assert len(output["trust_relationships"]) == 1


# =============================================================================
# Privesc Command Tests
# =============================================================================


class TestCIEMPrivesc:
    """Tests for CIEM privesc command."""

    @patch("stance.storage.get_storage")
    @patch("stance.ciem.PrivilegeEscalationAnalyzer")
    @patch("stance.ciem.EffectivePermissionsCalculator")
    def test_privesc_table_output(
        self, mock_calc_class, mock_analyzer_class, mock_get_storage,
        mock_storage, mock_escalation_path, capsys
    ):
        """Test privesc command with table output."""
        from stance.cli_ciem import _ciem_privesc

        mock_get_storage.return_value = mock_storage

        # Mock calculator
        mock_calc = MagicMock()
        mock_access = MagicMock()
        mock_access.permission_set.permissions = []
        mock_calc.calculate_effective_permissions.return_value = mock_access
        mock_calc_class.return_value = mock_calc

        # Mock analyzer
        mock_analyzer_class.return_value.analyze_all.return_value = [mock_escalation_path]

        args = argparse.Namespace(
            provider="aws",
            identity=None,
            format="table",
        )

        result = _ciem_privesc(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Privilege Escalation Paths" in captured.out

    @patch("stance.storage.get_storage")
    @patch("stance.ciem.PrivilegeEscalationAnalyzer")
    @patch("stance.ciem.EffectivePermissionsCalculator")
    def test_privesc_json_output(
        self, mock_calc_class, mock_analyzer_class, mock_get_storage,
        mock_storage, mock_escalation_path, capsys
    ):
        """Test privesc command with JSON output."""
        from stance.cli_ciem import _ciem_privesc

        mock_get_storage.return_value = mock_storage

        # Mock calculator
        mock_calc = MagicMock()
        mock_access = MagicMock()
        mock_access.permission_set.permissions = []
        mock_calc.calculate_effective_permissions.return_value = mock_access
        mock_calc_class.return_value = mock_calc

        # Mock analyzer
        mock_analyzer_class.return_value.analyze_all.return_value = [mock_escalation_path]

        args = argparse.Namespace(
            provider="aws",
            identity=None,
            format="json",
        )

        result = _ciem_privesc(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "escalation_paths" in output

    @patch("stance.storage.get_storage")
    @patch("stance.ciem.PrivilegeEscalationAnalyzer")
    @patch("stance.ciem.EffectivePermissionsCalculator")
    def test_privesc_no_paths_found(
        self, mock_calc_class, mock_analyzer_class, mock_get_storage, mock_storage, capsys
    ):
        """Test privesc command with no escalation paths."""
        from stance.cli_ciem import _ciem_privesc

        mock_get_storage.return_value = mock_storage

        # Mock calculator
        mock_calc = MagicMock()
        mock_access = MagicMock()
        mock_access.permission_set.permissions = []
        mock_calc.calculate_effective_permissions.return_value = mock_access
        mock_calc_class.return_value = mock_calc

        # Mock analyzer
        mock_analyzer_class.return_value.analyze_all.return_value = []

        args = argparse.Namespace(
            provider="aws",
            identity=None,
            format="table",
        )

        result = _ciem_privesc(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "No privilege escalation paths found" in captured.out


# =============================================================================
# Summary Command Tests
# =============================================================================


class TestCIEMSummary:
    """Tests for CIEM summary command."""

    @patch("stance.storage.get_storage")
    @patch("stance.ciem.EffectivePermissionsCalculator")
    @patch("stance.ciem.OverprivilegedDetector")
    @patch("stance.ciem.TrustAnalyzer")
    @patch("stance.ciem.PrivilegeEscalationAnalyzer")
    def test_summary_table_output(
        self, mock_privesc_class, mock_trust_class, mock_overpriv_class,
        mock_calc_class, mock_get_storage, mock_storage,
        mock_effective_access, mock_overprivileged_finding,
        mock_trust_relationship, mock_escalation_path, capsys
    ):
        """Test summary command with table output."""
        from stance.cli_ciem import _ciem_summary

        mock_get_storage.return_value = mock_storage
        mock_calc_class.return_value.calculate_all.return_value = [mock_effective_access]
        mock_overpriv_class.return_value.detect_all.return_value = [mock_overprivileged_finding]
        mock_trust_class.return_value.analyze_all.return_value = [mock_trust_relationship]
        mock_privesc_class.return_value.analyze_all.return_value = [mock_escalation_path]

        args = argparse.Namespace(
            provider="aws",
            format="table",
        )

        result = _ciem_summary(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "CIEM Summary" in captured.out

    @patch("stance.storage.get_storage")
    @patch("stance.ciem.EffectivePermissionsCalculator")
    @patch("stance.ciem.OverprivilegedDetector")
    @patch("stance.ciem.TrustAnalyzer")
    @patch("stance.ciem.PrivilegeEscalationAnalyzer")
    def test_summary_json_output(
        self, mock_privesc_class, mock_trust_class, mock_overpriv_class,
        mock_calc_class, mock_get_storage, mock_storage,
        mock_effective_access, mock_overprivileged_finding,
        mock_trust_relationship, mock_escalation_path, capsys
    ):
        """Test summary command with JSON output."""
        from stance.cli_ciem import _ciem_summary

        mock_get_storage.return_value = mock_storage
        mock_calc_class.return_value.calculate_all.return_value = [mock_effective_access]
        mock_overpriv_class.return_value.detect_all.return_value = [mock_overprivileged_finding]
        mock_trust_class.return_value.analyze_all.return_value = [mock_trust_relationship]
        mock_privesc_class.return_value.analyze_all.return_value = [mock_escalation_path]

        args = argparse.Namespace(
            provider="aws",
            format="json",
        )

        result = _ciem_summary(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        # The summary JSON output contains provider and counts at top level
        assert "provider" in output
        assert "total_identities" in output


# =============================================================================
# Provider Tests
# =============================================================================


class TestCIEMProviders:
    """Tests for CIEM provider support."""

    def test_provider_choices(self):
        """Test provider choices are aws, gcp, azure."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_ciem_parser(subparsers)

        # Valid choices should work
        for provider in ["aws", "gcp", "azure"]:
            args = parser.parse_args(["ciem", "permissions", "--provider", provider])
            assert args.provider == provider

    def test_default_provider_is_aws(self):
        """Test default provider is AWS."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_ciem_parser(subparsers)

        args = parser.parse_args(["ciem", "permissions"])
        assert args.provider == "aws"
