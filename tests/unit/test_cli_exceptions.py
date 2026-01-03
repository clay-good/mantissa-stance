"""
Unit tests for CLI exceptions commands.

Tests the Policy Exceptions CLI commands including listing,
creating, showing, revoking, and deleting exceptions.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone, timedelta
from io import StringIO
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


class TestExceptionsListCommand:
    """Tests for 'stance exceptions list' command."""

    def test_list_all_exceptions(self):
        """Test listing all exceptions."""
        from stance.cli_exceptions import _handle_exceptions_list

        args = argparse.Namespace(
            format='table',
            status=None,
            type=None,
            scope=None,
            active=False,
            include_expired=False,
        )

        with patch('stance.cli_exceptions.get_exception_manager') as mock_manager:
            mock_manager.return_value.list_exceptions.return_value = [
                MagicMock(
                    id='exc-001',
                    exception_type=MagicMock(value='suppression'),
                    scope=MagicMock(value='finding'),
                    status=MagicMock(value='approved'),
                    reason='Test reason',
                    created_at=datetime.now(timezone.utc),
                    expires_at=None,
                    is_expired=False,
                    days_until_expiry=None,
                ),
            ]

            result = _handle_exceptions_list(args)
            assert result == 0

    def test_list_exceptions_json_format(self):
        """Test listing exceptions in JSON format."""
        from stance.cli_exceptions import _handle_exceptions_list

        args = argparse.Namespace(
            format='json',
            status=None,
            type=None,
            scope=None,
            active=False,
            include_expired=False,
        )

        with patch('stance.cli_exceptions.get_exception_manager') as mock_manager:
            mock_exc = MagicMock()
            mock_exc.to_dict.return_value = {'id': 'exc-001', 'reason': 'Test'}
            mock_manager.return_value.list_exceptions.return_value = [mock_exc]

            result = _handle_exceptions_list(args)
            assert result == 0

    def test_list_exceptions_filter_by_status(self):
        """Test filtering exceptions by status."""
        from stance.cli_exceptions import _handle_exceptions_list
        from stance.exceptions import ExceptionStatus

        args = argparse.Namespace(
            format='table',
            status='approved',
            type=None,
            scope=None,
            active=False,
            include_expired=False,
        )

        with patch('stance.cli_exceptions.get_exception_manager') as mock_manager:
            mock_manager.return_value.list_exceptions.return_value = []

            result = _handle_exceptions_list(args)
            assert result == 0
            mock_manager.return_value.list_exceptions.assert_called_once()

    def test_list_active_only(self):
        """Test listing only active exceptions."""
        from stance.cli_exceptions import _handle_exceptions_list

        args = argparse.Namespace(
            format='table',
            status=None,
            type=None,
            scope=None,
            active=True,
            include_expired=False,
        )

        with patch('stance.cli_exceptions.get_exception_manager') as mock_manager:
            mock_manager.return_value.get_active_exceptions.return_value = []

            result = _handle_exceptions_list(args)
            assert result == 0


class TestExceptionsShowCommand:
    """Tests for 'stance exceptions show' command."""

    def test_show_exception(self):
        """Test showing exception details."""
        from stance.cli_exceptions import _handle_exceptions_show

        args = argparse.Namespace(
            exception_id='exc-001',
            format='text',
            verbose=False,
        )

        with patch('stance.cli_exceptions.get_exception_manager') as mock_manager:
            mock_exc = MagicMock()
            mock_exc.id = 'exc-001'
            mock_exc.exception_type = MagicMock(value='suppression')
            mock_exc.scope = MagicMock(value='finding')
            mock_exc.status = MagicMock(value='approved')
            mock_exc.reason = 'Test reason'
            mock_exc.created_by = 'tester'
            mock_exc.created_at = datetime.now(timezone.utc)
            mock_exc.approved_by = None
            mock_exc.expires_at = None
            mock_exc.is_active = True
            mock_exc.policy_id = None
            mock_exc.asset_id = None
            mock_exc.finding_id = None
            mock_exc.resource_type = None
            mock_exc.account_id = None
            mock_exc.tag_key = None
            mock_exc.jira_ticket = None
            mock_exc.days_until_expiry = None
            mock_exc.conditions = {}
            mock_exc.metadata = {}
            mock_exc.notes = ''

            mock_manager.return_value.list_exceptions.return_value = [mock_exc]

            result = _handle_exceptions_show(args)
            assert result == 0

    def test_show_exception_not_found(self):
        """Test showing non-existent exception."""
        from stance.cli_exceptions import _handle_exceptions_show

        args = argparse.Namespace(
            exception_id='nonexistent',
            format='text',
            verbose=False,
        )

        with patch('stance.cli_exceptions.get_exception_manager') as mock_manager:
            mock_manager.return_value.list_exceptions.return_value = []

            result = _handle_exceptions_show(args)
            assert result == 1

    def test_show_exception_json_format(self):
        """Test showing exception in JSON format."""
        from stance.cli_exceptions import _handle_exceptions_show

        args = argparse.Namespace(
            exception_id='exc-001',
            format='json',
            verbose=False,
        )

        with patch('stance.cli_exceptions.get_exception_manager') as mock_manager:
            mock_exc = MagicMock()
            mock_exc.id = 'exc-001'
            mock_exc.to_dict.return_value = {'id': 'exc-001'}
            mock_manager.return_value.list_exceptions.return_value = [mock_exc]

            result = _handle_exceptions_show(args)
            assert result == 0


class TestExceptionsCreateCommand:
    """Tests for 'stance exceptions create' command."""

    def test_create_exception(self):
        """Test creating an exception."""
        from stance.cli_exceptions import _handle_exceptions_create

        args = argparse.Namespace(
            type='suppression',
            scope='finding',
            reason='Test suppression',
            created_by='tester',
            policy=None,
            asset=None,
            finding='finding-123',
            resource_type=None,
            account=None,
            tag=None,
            days=None,
            jira='JIRA-123',
            format='text',
        )

        with patch('stance.cli_exceptions.get_exception_manager') as mock_manager:
            mock_store = MagicMock()
            mock_manager.return_value.store = mock_store

            result = _handle_exceptions_create(args)
            assert result == 0

    def test_create_exception_missing_reason(self):
        """Test creating exception without reason."""
        from stance.cli_exceptions import _handle_exceptions_create

        args = argparse.Namespace(
            type='suppression',
            scope='finding',
            reason='',
            created_by='tester',
            policy=None,
            asset=None,
            finding=None,
            resource_type=None,
            account=None,
            tag=None,
            days=None,
            jira=None,
            format='text',
        )

        result = _handle_exceptions_create(args)
        assert result == 1

    def test_create_temporary_exception(self):
        """Test creating a temporary exception."""
        from stance.cli_exceptions import _handle_exceptions_create

        args = argparse.Namespace(
            type='temporary',
            scope='asset',
            reason='Temporary exception',
            created_by='tester',
            policy=None,
            asset='asset-123',
            finding=None,
            resource_type=None,
            account=None,
            tag=None,
            days=30,
            jira=None,
            format='text',
        )

        with patch('stance.cli_exceptions.get_exception_manager') as mock_manager:
            mock_store = MagicMock()
            mock_manager.return_value.store = mock_store

            result = _handle_exceptions_create(args)
            assert result == 0


class TestExceptionsSuppressCommand:
    """Tests for 'stance exceptions suppress' command."""

    def test_create_suppression(self):
        """Test creating a suppression."""
        from stance.cli_exceptions import _handle_exceptions_suppress

        args = argparse.Namespace(
            scope='policy',
            reason='Suppress for known issue',
            created_by='tester',
            policy='aws-iam-001',
            asset=None,
            finding=None,
            resource_type=None,
            account=None,
            jira=None,
            format='text',
        )

        with patch('stance.cli_exceptions.get_exception_manager') as mock_manager:
            mock_exc = MagicMock()
            mock_exc.id = 'exc-001'
            mock_manager.return_value.create_suppression.return_value = mock_exc

            result = _handle_exceptions_suppress(args)
            assert result == 0


class TestExceptionsFalsePositiveCommand:
    """Tests for 'stance exceptions false-positive' command."""

    def test_mark_false_positive(self):
        """Test marking as false positive."""
        from stance.cli_exceptions import _handle_exceptions_false_positive

        args = argparse.Namespace(
            finding_id='finding-123',
            reason='This is a false positive',
            created_by='analyst',
            jira=None,
            format='text',
        )

        with patch('stance.cli_exceptions.get_exception_manager') as mock_manager:
            mock_exc = MagicMock()
            mock_exc.id = 'exc-fp-001'
            mock_manager.return_value.mark_false_positive.return_value = mock_exc

            result = _handle_exceptions_false_positive(args)
            assert result == 0

    def test_false_positive_missing_finding(self):
        """Test false positive without finding ID."""
        from stance.cli_exceptions import _handle_exceptions_false_positive

        args = argparse.Namespace(
            finding_id=None,
            reason='This is a false positive',
            created_by='analyst',
            jira=None,
            format='text',
        )

        result = _handle_exceptions_false_positive(args)
        assert result == 1


class TestExceptionsAcceptRiskCommand:
    """Tests for 'stance exceptions accept-risk' command."""

    def test_accept_risk(self):
        """Test accepting risk."""
        from stance.cli_exceptions import _handle_exceptions_accept_risk

        args = argparse.Namespace(
            scope='policy',
            reason='Business requires this configuration',
            approved_by='ciso@example.com',
            created_by='app-team',
            policy='aws-s3-002',
            asset=None,
            resource_type=None,
            account=None,
            days=365,
            jira='RISK-001',
            notes='Annual review required',
            format='text',
        )

        with patch('stance.cli_exceptions.get_exception_manager') as mock_manager:
            mock_exc = MagicMock()
            mock_exc.id = 'exc-risk-001'
            mock_manager.return_value.accept_risk.return_value = mock_exc

            result = _handle_exceptions_accept_risk(args)
            assert result == 0

    def test_accept_risk_missing_approver(self):
        """Test accepting risk without approver."""
        from stance.cli_exceptions import _handle_exceptions_accept_risk

        args = argparse.Namespace(
            scope='policy',
            reason='Business requires this configuration',
            approved_by=None,
            created_by='app-team',
            policy='aws-s3-002',
            asset=None,
            resource_type=None,
            account=None,
            days=365,
            jira=None,
            notes='',
            format='text',
        )

        result = _handle_exceptions_accept_risk(args)
        assert result == 1


class TestExceptionsRevokeCommand:
    """Tests for 'stance exceptions revoke' command."""

    def test_revoke_exception(self):
        """Test revoking an exception."""
        from stance.cli_exceptions import _handle_exceptions_revoke

        args = argparse.Namespace(
            exception_id='exc-001',
            reason='No longer needed',
        )

        with patch('stance.cli_exceptions.get_exception_manager') as mock_manager:
            mock_exc = MagicMock()
            mock_exc.id = 'exc-001'
            mock_manager.return_value.list_exceptions.return_value = [mock_exc]
            mock_manager.return_value.revoke_exception.return_value = True

            result = _handle_exceptions_revoke(args)
            assert result == 0

    def test_revoke_not_found(self):
        """Test revoking non-existent exception."""
        from stance.cli_exceptions import _handle_exceptions_revoke

        args = argparse.Namespace(
            exception_id='nonexistent',
            reason='',
        )

        with patch('stance.cli_exceptions.get_exception_manager') as mock_manager:
            mock_manager.return_value.list_exceptions.return_value = []

            result = _handle_exceptions_revoke(args)
            assert result == 1


class TestExceptionsDeleteCommand:
    """Tests for 'stance exceptions delete' command."""

    def test_delete_exception(self):
        """Test deleting an exception."""
        from stance.cli_exceptions import _handle_exceptions_delete

        args = argparse.Namespace(
            exception_id='exc-001',
            force=False,
        )

        with patch('stance.cli_exceptions.get_exception_manager') as mock_manager:
            mock_exc = MagicMock()
            mock_exc.id = 'exc-001'
            mock_exc.is_active = False
            mock_manager.return_value.list_exceptions.return_value = [mock_exc]
            mock_manager.return_value.delete_exception.return_value = True

            result = _handle_exceptions_delete(args)
            assert result == 0

    def test_delete_active_without_force(self):
        """Test deleting active exception without force."""
        from stance.cli_exceptions import _handle_exceptions_delete

        args = argparse.Namespace(
            exception_id='exc-001',
            force=False,
        )

        with patch('stance.cli_exceptions.get_exception_manager') as mock_manager:
            mock_exc = MagicMock()
            mock_exc.id = 'exc-001'
            mock_exc.is_active = True
            mock_manager.return_value.list_exceptions.return_value = [mock_exc]

            result = _handle_exceptions_delete(args)
            assert result == 1

    def test_delete_active_with_force(self):
        """Test deleting active exception with force."""
        from stance.cli_exceptions import _handle_exceptions_delete

        args = argparse.Namespace(
            exception_id='exc-001',
            force=True,
        )

        with patch('stance.cli_exceptions.get_exception_manager') as mock_manager:
            mock_exc = MagicMock()
            mock_exc.id = 'exc-001'
            mock_exc.is_active = True
            mock_manager.return_value.list_exceptions.return_value = [mock_exc]
            mock_manager.return_value.delete_exception.return_value = True

            result = _handle_exceptions_delete(args)
            assert result == 0


class TestExceptionsExpireCommand:
    """Tests for 'stance exceptions expire' command."""

    def test_expire_outdated(self):
        """Test expiring outdated exceptions."""
        from stance.cli_exceptions import _handle_exceptions_expire

        args = argparse.Namespace()

        with patch('stance.cli_exceptions.get_exception_manager') as mock_manager:
            mock_manager.return_value.expire_outdated.return_value = 5

            result = _handle_exceptions_expire(args)
            assert result == 0


class TestExceptionsTypesCommand:
    """Tests for 'stance exceptions types' command."""

    def test_list_types(self):
        """Test listing exception types."""
        from stance.cli_exceptions import _handle_exceptions_types

        args = argparse.Namespace(format='table')

        result = _handle_exceptions_types(args)
        assert result == 0

    def test_list_types_json(self):
        """Test listing exception types in JSON format."""
        from stance.cli_exceptions import _handle_exceptions_types

        args = argparse.Namespace(format='json')

        result = _handle_exceptions_types(args)
        assert result == 0


class TestExceptionsScopesCommand:
    """Tests for 'stance exceptions scopes' command."""

    def test_list_scopes(self):
        """Test listing exception scopes."""
        from stance.cli_exceptions import _handle_exceptions_scopes

        args = argparse.Namespace(format='table')

        result = _handle_exceptions_scopes(args)
        assert result == 0


class TestExceptionsStatusCommand:
    """Tests for 'stance exceptions status' command."""

    def test_get_status(self):
        """Test getting exceptions status."""
        from stance.cli_exceptions import _handle_exceptions_status

        args = argparse.Namespace(format='text')

        with patch('stance.cli_exceptions.get_exception_manager') as mock_manager:
            mock_exc1 = MagicMock()
            mock_exc1.exception_type = MagicMock(value='suppression')
            mock_exc1.scope = MagicMock(value='finding')
            mock_exc1.status = MagicMock(value='approved')
            mock_exc1.is_active = True
            mock_exc1.expires_at = None
            mock_exc1.days_until_expiry = None

            mock_manager.return_value.list_exceptions.return_value = [mock_exc1]
            mock_manager.return_value.get_active_exceptions.return_value = [mock_exc1]

            result = _handle_exceptions_status(args)
            assert result == 0


class TestCmdExceptions:
    """Tests for main cmd_exceptions function."""

    def test_cmd_exceptions_no_action(self):
        """Test cmd_exceptions with no action shows help."""
        from stance.cli_exceptions import cmd_exceptions

        args = argparse.Namespace(
            exceptions_action=None,
        )

        result = cmd_exceptions(args)
        assert result == 0

    def test_cmd_exceptions_unknown_action(self):
        """Test cmd_exceptions with unknown action."""
        from stance.cli_exceptions import cmd_exceptions

        args = argparse.Namespace(
            exceptions_action='unknown_action',
        )

        result = cmd_exceptions(args)
        assert result == 1


class TestAddExceptionsParser:
    """Tests for add_exceptions_parser function."""

    def test_add_exceptions_parser(self):
        """Test adding exceptions parser to subparsers."""
        from stance.cli_exceptions import add_exceptions_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        add_exceptions_parser(subparsers)

        # Parse a valid exceptions command
        args = parser.parse_args(['exceptions', 'list'])
        assert args.exceptions_action == 'list'

    def test_exceptions_create_parser(self):
        """Test exceptions create subparser."""
        from stance.cli_exceptions import add_exceptions_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_exceptions_parser(subparsers)

        args = parser.parse_args([
            'exceptions', 'create',
            '--type', 'suppression',
            '--scope', 'finding',
            '--reason', 'Test reason',
        ])
        assert args.exceptions_action == 'create'
        assert args.type == 'suppression'
        assert args.scope == 'finding'
        assert args.reason == 'Test reason'

    def test_exceptions_suppress_parser(self):
        """Test exceptions suppress subparser."""
        from stance.cli_exceptions import add_exceptions_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_exceptions_parser(subparsers)

        args = parser.parse_args([
            'exceptions', 'suppress',
            '--reason', 'Test suppression',
            '--policy', 'aws-iam-001',
        ])
        assert args.exceptions_action == 'suppress'
        assert args.policy == 'aws-iam-001'

    def test_exceptions_false_positive_parser(self):
        """Test exceptions false-positive subparser."""
        from stance.cli_exceptions import add_exceptions_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_exceptions_parser(subparsers)

        args = parser.parse_args([
            'exceptions', 'false-positive', 'finding-123',
            '--reason', 'Not applicable',
        ])
        assert args.exceptions_action == 'false-positive'
        assert args.finding_id == 'finding-123'

    def test_exceptions_accept_risk_parser(self):
        """Test exceptions accept-risk subparser."""
        from stance.cli_exceptions import add_exceptions_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_exceptions_parser(subparsers)

        args = parser.parse_args([
            'exceptions', 'accept-risk',
            '--reason', 'Business need',
            '--approved-by', 'ciso@example.com',
            '--days', '365',
        ])
        assert args.exceptions_action == 'accept-risk'
        assert args.approved_by == 'ciso@example.com'
        assert args.days == 365


class TestFormatFunctions:
    """Tests for formatting helper functions."""

    def test_format_exception_table(self):
        """Test formatting exceptions as table."""
        from stance.cli_exceptions import _format_exception_table

        mock_exc = MagicMock()
        mock_exc.id = 'exc-001'
        mock_exc.exception_type = MagicMock(value='suppression')
        mock_exc.scope = MagicMock(value='finding')
        mock_exc.status = MagicMock(value='approved')
        mock_exc.reason = 'Test reason'
        mock_exc.created_at = datetime.now(timezone.utc)
        mock_exc.expires_at = None
        mock_exc.days_until_expiry = None

        result = _format_exception_table([mock_exc])
        assert 'exc-001' in result

    def test_format_exception_table_empty(self):
        """Test formatting empty exception list."""
        from stance.cli_exceptions import _format_exception_table

        result = _format_exception_table([])
        assert 'No exceptions found' in result

    def test_format_exception_detail(self):
        """Test formatting exception details."""
        from stance.cli_exceptions import _format_exception_detail

        mock_exc = MagicMock()
        mock_exc.id = 'exc-001'
        mock_exc.exception_type = MagicMock(value='suppression')
        mock_exc.scope = MagicMock(value='finding')
        mock_exc.status = MagicMock(value='approved')
        mock_exc.reason = 'Test reason'
        mock_exc.created_by = 'tester'
        mock_exc.created_at = datetime.now(timezone.utc)
        mock_exc.approved_by = None
        mock_exc.expires_at = None
        mock_exc.is_active = True
        mock_exc.policy_id = None
        mock_exc.asset_id = None
        mock_exc.finding_id = None
        mock_exc.resource_type = None
        mock_exc.account_id = None
        mock_exc.tag_key = None
        mock_exc.jira_ticket = None
        mock_exc.days_until_expiry = None
        mock_exc.conditions = {}
        mock_exc.metadata = {}
        mock_exc.notes = ''

        result = _format_exception_detail(mock_exc)
        assert 'exc-001' in result
        assert 'suppression' in result

    def test_format_exception_with_expiry(self):
        """Test formatting exception with expiry."""
        from stance.cli_exceptions import _format_exception_table

        mock_exc = MagicMock()
        mock_exc.id = 'exc-002'
        mock_exc.exception_type = MagicMock(value='temporary')
        mock_exc.scope = MagicMock(value='asset')
        mock_exc.status = MagicMock(value='approved')
        mock_exc.reason = 'Temporary exception'
        mock_exc.created_at = datetime.now(timezone.utc)
        mock_exc.expires_at = datetime.now(timezone.utc) + timedelta(days=10)
        mock_exc.days_until_expiry = 10

        result = _format_exception_table([mock_exc])
        assert 'exc-002' in result
        assert '10d' in result
