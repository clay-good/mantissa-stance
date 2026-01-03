"""
Unit tests for Web API exceptions endpoints.

Tests the Policy Exceptions REST API endpoints including listing,
creating, showing, revoking, and deleting exceptions.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


class TestExceptionsListEndpoint:
    """Tests for GET /api/exceptions/list endpoint."""

    def test_list_all_exceptions(self):
        """Test listing all exceptions."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_exceptions = StanceRequestHandler._get_sample_exceptions.__get__(handler)
        handler._exceptions_list = StanceRequestHandler._exceptions_list.__get__(handler)

        result = handler._exceptions_list({})

        assert 'exceptions' in result
        assert 'total' in result
        assert 'active_count' in result
        assert result['total'] == len(result['exceptions'])

    def test_list_exceptions_filter_by_status(self):
        """Test filtering exceptions by status."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_exceptions = StanceRequestHandler._get_sample_exceptions.__get__(handler)
        handler._exceptions_list = StanceRequestHandler._exceptions_list.__get__(handler)

        result = handler._exceptions_list({'status': ['approved']})

        assert all(e.get('status') == 'approved' for e in result['exceptions'])

    def test_list_exceptions_filter_by_type(self):
        """Test filtering exceptions by type."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_exceptions = StanceRequestHandler._get_sample_exceptions.__get__(handler)
        handler._exceptions_list = StanceRequestHandler._exceptions_list.__get__(handler)

        result = handler._exceptions_list({'type': ['suppression']})

        assert all(e.get('exception_type') == 'suppression' for e in result['exceptions'])

    def test_list_exceptions_active_only(self):
        """Test filtering only active exceptions."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_exceptions = StanceRequestHandler._get_sample_exceptions.__get__(handler)
        handler._exceptions_list = StanceRequestHandler._exceptions_list.__get__(handler)

        result = handler._exceptions_list({'active': ['true']})

        assert all(e.get('is_active', False) for e in result['exceptions'])

    def test_list_exceptions_include_expired(self):
        """Test including expired exceptions."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_exceptions = StanceRequestHandler._get_sample_exceptions.__get__(handler)
        handler._exceptions_list = StanceRequestHandler._exceptions_list.__get__(handler)

        result = handler._exceptions_list({'include_expired': ['true']})

        # Should include expired exceptions
        assert 'exceptions' in result


class TestExceptionsShowEndpoint:
    """Tests for GET /api/exceptions/show endpoint."""

    def test_show_exception(self):
        """Test showing exception details."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_exceptions = StanceRequestHandler._get_sample_exceptions.__get__(handler)
        handler._exceptions_show = StanceRequestHandler._exceptions_show.__get__(handler)

        result = handler._exceptions_show({'id': ['exc-001']})

        assert 'id' in result
        assert result['id'].startswith('exc-001')

    def test_show_exception_not_found(self):
        """Test showing non-existent exception."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_exceptions = StanceRequestHandler._get_sample_exceptions.__get__(handler)
        handler._exceptions_show = StanceRequestHandler._exceptions_show.__get__(handler)

        result = handler._exceptions_show({'id': ['nonexistent']})

        assert 'error' in result

    def test_show_exception_missing_id(self):
        """Test showing exception without ID."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._exceptions_show = StanceRequestHandler._exceptions_show.__get__(handler)

        result = handler._exceptions_show({})

        assert 'error' in result


class TestExceptionsCreateEndpoint:
    """Tests for GET /api/exceptions/create endpoint."""

    def test_create_exception(self):
        """Test creating an exception."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._exceptions_create = StanceRequestHandler._exceptions_create.__get__(handler)

        result = handler._exceptions_create({
            'type': ['suppression'],
            'scope': ['finding'],
            'reason': ['Test suppression'],
            'finding': ['finding-123'],
        })

        assert result['success'] is True
        assert 'id' in result
        assert result['exception_type'] == 'suppression'

    def test_create_exception_missing_reason(self):
        """Test creating exception without reason."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._exceptions_create = StanceRequestHandler._exceptions_create.__get__(handler)

        result = handler._exceptions_create({
            'type': ['suppression'],
            'scope': ['finding'],
        })

        assert 'error' in result

    def test_create_temporary_exception(self):
        """Test creating temporary exception with expiry."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._exceptions_create = StanceRequestHandler._exceptions_create.__get__(handler)

        result = handler._exceptions_create({
            'type': ['temporary'],
            'scope': ['asset'],
            'reason': ['Temporary exception'],
            'days': ['30'],
        })

        assert result['success'] is True
        assert result['expires_at'] is not None


class TestExceptionsSuppressEndpoint:
    """Tests for GET /api/exceptions/suppress endpoint."""

    def test_create_suppression(self):
        """Test creating a suppression."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._exceptions_create = StanceRequestHandler._exceptions_create.__get__(handler)
        handler._exceptions_suppress = StanceRequestHandler._exceptions_suppress.__get__(handler)

        result = handler._exceptions_suppress({
            'reason': ['Suppress this finding'],
            'policy': ['aws-iam-001'],
        })

        assert result['success'] is True
        assert result['exception_type'] == 'suppression'


class TestExceptionsFalsePositiveEndpoint:
    """Tests for GET /api/exceptions/false-positive endpoint."""

    def test_mark_false_positive(self):
        """Test marking as false positive."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._exceptions_create = StanceRequestHandler._exceptions_create.__get__(handler)
        handler._exceptions_false_positive = StanceRequestHandler._exceptions_false_positive.__get__(handler)

        result = handler._exceptions_false_positive({
            'finding': ['finding-123'],
            'reason': ['Not applicable'],
        })

        assert result['success'] is True
        assert result['exception_type'] == 'false_positive'

    def test_false_positive_missing_finding(self):
        """Test false positive without finding ID."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._exceptions_false_positive = StanceRequestHandler._exceptions_false_positive.__get__(handler)

        result = handler._exceptions_false_positive({
            'reason': ['Not applicable'],
        })

        assert 'error' in result

    def test_false_positive_missing_reason(self):
        """Test false positive without reason."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._exceptions_false_positive = StanceRequestHandler._exceptions_false_positive.__get__(handler)

        result = handler._exceptions_false_positive({
            'finding': ['finding-123'],
        })

        assert 'error' in result


class TestExceptionsAcceptRiskEndpoint:
    """Tests for GET /api/exceptions/accept-risk endpoint."""

    def test_accept_risk(self):
        """Test accepting risk."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._exceptions_create = StanceRequestHandler._exceptions_create.__get__(handler)
        handler._exceptions_accept_risk = StanceRequestHandler._exceptions_accept_risk.__get__(handler)

        result = handler._exceptions_accept_risk({
            'reason': ['Business requirement'],
            'approved_by': ['ciso@example.com'],
            'policy': ['aws-s3-002'],
        })

        assert result['success'] is True
        assert result['exception_type'] == 'risk_accepted'
        assert result['approved_by'] == 'ciso@example.com'

    def test_accept_risk_missing_approver(self):
        """Test accepting risk without approver."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._exceptions_accept_risk = StanceRequestHandler._exceptions_accept_risk.__get__(handler)

        result = handler._exceptions_accept_risk({
            'reason': ['Business requirement'],
        })

        assert 'error' in result

    def test_accept_risk_default_days(self):
        """Test accepting risk with default expiry."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._exceptions_create = StanceRequestHandler._exceptions_create.__get__(handler)
        handler._exceptions_accept_risk = StanceRequestHandler._exceptions_accept_risk.__get__(handler)

        result = handler._exceptions_accept_risk({
            'reason': ['Business requirement'],
            'approved_by': ['ciso@example.com'],
        })

        assert result['success'] is True
        assert result['expires_at'] is not None


class TestExceptionsRevokeEndpoint:
    """Tests for GET /api/exceptions/revoke endpoint."""

    def test_revoke_exception(self):
        """Test revoking an exception."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._exceptions_revoke = StanceRequestHandler._exceptions_revoke.__get__(handler)

        result = handler._exceptions_revoke({
            'id': ['exc-001'],
            'reason': ['No longer needed'],
        })

        assert result['success'] is True
        assert result['status'] == 'revoked'

    def test_revoke_exception_missing_id(self):
        """Test revoking without ID."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._exceptions_revoke = StanceRequestHandler._exceptions_revoke.__get__(handler)

        result = handler._exceptions_revoke({})

        assert 'error' in result


class TestExceptionsDeleteEndpoint:
    """Tests for GET /api/exceptions/delete endpoint."""

    def test_delete_exception(self):
        """Test deleting an exception."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._exceptions_delete = StanceRequestHandler._exceptions_delete.__get__(handler)

        result = handler._exceptions_delete({
            'id': ['exc-001'],
        })

        assert result['success'] is True

    def test_delete_exception_with_force(self):
        """Test force deleting an exception."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._exceptions_delete = StanceRequestHandler._exceptions_delete.__get__(handler)

        result = handler._exceptions_delete({
            'id': ['exc-001'],
            'force': ['true'],
        })

        assert result['success'] is True
        assert result['force'] is True


class TestExceptionsExpireEndpoint:
    """Tests for GET /api/exceptions/expire endpoint."""

    def test_expire_outdated(self):
        """Test expiring outdated exceptions."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._exceptions_expire = StanceRequestHandler._exceptions_expire.__get__(handler)

        result = handler._exceptions_expire({})

        assert result['success'] is True
        assert 'expired_count' in result


class TestExceptionsTypesEndpoint:
    """Tests for GET /api/exceptions/types endpoint."""

    def test_list_types(self):
        """Test listing exception types."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._exceptions_types = StanceRequestHandler._exceptions_types.__get__(handler)

        result = handler._exceptions_types({})

        assert 'types' in result
        assert 'total' in result
        assert result['total'] == 5

        type_names = [t['type'] for t in result['types']]
        assert 'suppression' in type_names
        assert 'temporary' in type_names
        assert 'false_positive' in type_names
        assert 'risk_accepted' in type_names
        assert 'compensating_control' in type_names


class TestExceptionsScopesEndpoint:
    """Tests for GET /api/exceptions/scopes endpoint."""

    def test_list_scopes(self):
        """Test listing exception scopes."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._exceptions_scopes = StanceRequestHandler._exceptions_scopes.__get__(handler)

        result = handler._exceptions_scopes({})

        assert 'scopes' in result
        assert 'total' in result
        assert result['total'] == 8

        scope_names = [s['scope'] for s in result['scopes']]
        assert 'finding' in scope_names
        assert 'asset' in scope_names
        assert 'policy' in scope_names
        assert 'global' in scope_names


class TestExceptionsStatusEndpoint:
    """Tests for GET /api/exceptions/status endpoint."""

    def test_get_status(self):
        """Test getting exceptions status."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_exceptions = StanceRequestHandler._get_sample_exceptions.__get__(handler)
        handler._exceptions_status = StanceRequestHandler._exceptions_status.__get__(handler)

        result = handler._exceptions_status({})

        assert result['module'] == 'exceptions'
        assert 'version' in result
        assert 'total_exceptions' in result
        assert 'active_exceptions' in result
        assert 'expiring_soon' in result
        assert 'exceptions_by_type' in result
        assert 'exceptions_by_status' in result
        assert 'capabilities' in result

    def test_status_capabilities(self):
        """Test status includes capabilities."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_exceptions = StanceRequestHandler._get_sample_exceptions.__get__(handler)
        handler._exceptions_status = StanceRequestHandler._exceptions_status.__get__(handler)

        result = handler._exceptions_status({})

        caps = result['capabilities']
        assert caps['suppression'] is True
        assert caps['temporary_exceptions'] is True
        assert caps['false_positive_marking'] is True
        assert caps['risk_acceptance'] is True


class TestSampleExceptionsData:
    """Tests for sample exception data."""

    def test_sample_exceptions_structure(self):
        """Test sample exceptions have correct structure."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_exceptions = StanceRequestHandler._get_sample_exceptions.__get__(handler)

        exceptions = handler._get_sample_exceptions()

        assert len(exceptions) > 0
        for exc in exceptions:
            assert 'id' in exc
            assert 'exception_type' in exc
            assert 'scope' in exc
            assert 'status' in exc
            assert 'reason' in exc
            assert 'is_active' in exc

    def test_sample_exceptions_have_all_types(self):
        """Test sample data includes all exception types."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_exceptions = StanceRequestHandler._get_sample_exceptions.__get__(handler)

        exceptions = handler._get_sample_exceptions()
        types = set(e.get('exception_type') for e in exceptions)

        assert 'suppression' in types
        assert 'temporary' in types
        assert 'false_positive' in types
        assert 'risk_accepted' in types
        assert 'compensating_control' in types

    def test_sample_exceptions_have_different_statuses(self):
        """Test sample data includes different statuses."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_exceptions = StanceRequestHandler._get_sample_exceptions.__get__(handler)

        exceptions = handler._get_sample_exceptions()
        statuses = set(e.get('status') for e in exceptions)

        assert 'approved' in statuses
        assert 'expired' in statuses
        assert 'revoked' in statuses


class TestEndpointRouting:
    """Tests for endpoint routing."""

    def test_exceptions_endpoints_registered(self):
        """Test that exception endpoints are in the routing."""
        import stance.web.server as server_module
        import inspect

        source = inspect.getsource(server_module.StanceRequestHandler._handle_api)

        endpoints = [
            '/api/exceptions/list',
            '/api/exceptions/show',
            '/api/exceptions/create',
            '/api/exceptions/suppress',
            '/api/exceptions/false-positive',
            '/api/exceptions/accept-risk',
            '/api/exceptions/revoke',
            '/api/exceptions/delete',
            '/api/exceptions/expire',
            '/api/exceptions/types',
            '/api/exceptions/scopes',
            '/api/exceptions/status',
        ]

        for endpoint in endpoints:
            assert endpoint in source, f"Missing endpoint routing: {endpoint}"

    def test_exceptions_methods_exist(self):
        """Test that exception handler methods exist."""
        from stance.web.server import StanceRequestHandler

        methods = [
            '_exceptions_list',
            '_exceptions_show',
            '_exceptions_create',
            '_exceptions_suppress',
            '_exceptions_false_positive',
            '_exceptions_accept_risk',
            '_exceptions_revoke',
            '_exceptions_delete',
            '_exceptions_expire',
            '_exceptions_types',
            '_exceptions_scopes',
            '_exceptions_status',
        ]

        for method in methods:
            assert hasattr(StanceRequestHandler, method), f"Missing method: {method}"


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_params(self):
        """Test handling of empty parameters."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._get_sample_exceptions = StanceRequestHandler._get_sample_exceptions.__get__(handler)
        handler._exceptions_list = StanceRequestHandler._exceptions_list.__get__(handler)

        result = handler._exceptions_list(None)

        assert 'exceptions' in result

    def test_invalid_days_value(self):
        """Test creating exception with invalid days value."""
        from stance.web.server import StanceRequestHandler

        handler = MagicMock(spec=StanceRequestHandler)
        handler._exceptions_create = StanceRequestHandler._exceptions_create.__get__(handler)

        result = handler._exceptions_create({
            'type': ['temporary'],
            'scope': ['finding'],
            'reason': ['Test'],
            'days': ['not-a-number'],
        })

        assert 'error' in result
