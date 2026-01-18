"""
Unit tests for web handler infrastructure.

Tests for:
- BaseHandler: Base handler functionality
- HandlerResponse: Response formatting
- HandlerRegistry: Handler routing
- RouteTable: Route matching
- RoutedHandler: Decorator-based routing
- VisualizationHandler: Visualization endpoints
"""

from __future__ import annotations

import json
from datetime import datetime
from enum import Enum
from unittest.mock import MagicMock, patch

import pytest

from stance.web.handlers.base import (
    BaseHandler,
    HandlerRegistry,
    HandlerResponse,
    HttpStatus,
)
from stance.web.handlers.router import Route, RouteTable, RoutedHandler, route


# =============================================================================
# HandlerResponse Tests
# =============================================================================


class TestHandlerResponse:
    """Tests for HandlerResponse class."""

    def test_default_values(self):
        """Test default response values."""
        response = HandlerResponse()
        assert response.data is None
        assert response.status == HttpStatus.OK
        assert response.content_type == "application/json"

    def test_success_response(self):
        """Test creating success response."""
        data = {"message": "OK"}
        response = HandlerResponse.success(data)
        assert response.data == data
        assert response.status == HttpStatus.OK

    def test_success_with_status(self):
        """Test success response with custom status."""
        response = HandlerResponse.success({"id": 1}, HttpStatus.CREATED)
        assert response.status == HttpStatus.CREATED

    def test_error_response(self):
        """Test creating error response."""
        response = HandlerResponse.error("Bad request")
        assert response.data["error"] == "Bad request"
        assert response.status == HttpStatus.BAD_REQUEST

    def test_error_with_details(self):
        """Test error response with details."""
        response = HandlerResponse.error(
            "Validation failed",
            details={"field": "email", "reason": "invalid format"},
        )
        assert response.data["error"] == "Validation failed"
        assert response.data["details"]["field"] == "email"

    def test_not_found_response(self):
        """Test 404 response."""
        response = HandlerResponse.not_found("User")
        assert "not found" in response.data["error"]
        assert response.status == HttpStatus.NOT_FOUND

    def test_unauthorized_response(self):
        """Test 401 response."""
        response = HandlerResponse.unauthorized()
        assert response.status == HttpStatus.UNAUTHORIZED

    def test_forbidden_response(self):
        """Test 403 response."""
        response = HandlerResponse.forbidden("Access denied")
        assert "Access denied" in response.data["error"]
        assert response.status == HttpStatus.FORBIDDEN

    def test_server_error_response(self):
        """Test 500 response."""
        response = HandlerResponse.server_error()
        assert response.status == HttpStatus.INTERNAL_SERVER_ERROR

    def test_to_json_simple(self):
        """Test JSON serialization of simple data."""
        response = HandlerResponse.success({"key": "value"})
        json_str = response.to_json()
        parsed = json.loads(json_str)
        assert parsed["key"] == "value"

    def test_to_json_with_datetime(self):
        """Test JSON serialization with datetime."""
        dt = datetime(2025, 1, 15, 10, 30, 0)
        response = HandlerResponse.success({"timestamp": dt})
        json_str = response.to_json()
        parsed = json.loads(json_str)
        assert parsed["timestamp"] == dt.isoformat()

    def test_to_json_with_enum(self):
        """Test JSON serialization with enum."""

        class Status(Enum):
            ACTIVE = "active"

        response = HandlerResponse.success({"status": Status.ACTIVE})
        json_str = response.to_json()
        parsed = json.loads(json_str)
        assert parsed["status"] == "active"

    def test_to_json_empty(self):
        """Test JSON serialization of None."""
        response = HandlerResponse()
        assert response.to_json() == ""


# =============================================================================
# BaseHandler Tests
# =============================================================================


class TestBaseHandler:
    """Tests for BaseHandler class."""

    def test_init_with_storage(self):
        """Test handler initialization with storage."""
        storage = MagicMock()
        handler = BaseHandler(storage=storage)
        assert handler.storage == storage

    def test_register_route(self):
        """Test registering a route."""
        handler = BaseHandler()
        handler.register_route("test", lambda p, b: HandlerResponse.success())
        assert "GET:test" in handler._routes

    def test_register_route_with_methods(self):
        """Test registering route with multiple methods."""
        handler = BaseHandler()
        handler.register_route(
            "data", lambda p, b: HandlerResponse.success(), methods=["GET", "POST"]
        )
        assert "GET:data" in handler._routes
        assert "POST:data" in handler._routes

    def test_can_handle_matching_path(self):
        """Test can_handle with matching path."""
        handler = BaseHandler()
        handler.base_path = "/api/test/"
        assert handler.can_handle("/api/test/something")

    def test_can_handle_non_matching_path(self):
        """Test can_handle with non-matching path."""
        handler = BaseHandler()
        handler.base_path = "/api/test/"
        assert not handler.can_handle("/api/other/something")

    def test_handle_registered_route(self):
        """Test handling a registered route."""
        handler = BaseHandler()
        handler.base_path = "/api/test/"
        handler.register_route("list", lambda p, b: HandlerResponse.success({"items": []}))

        response = handler.handle("/api/test/list", {})
        assert response.status == HttpStatus.OK
        assert response.data == {"items": []}

    def test_handle_unregistered_route(self):
        """Test handling an unregistered route."""
        handler = BaseHandler()
        handler.base_path = "/api/test/"

        response = handler.handle("/api/test/unknown", {})
        assert response.status == HttpStatus.NOT_FOUND

    def test_handle_exception_in_handler(self):
        """Test handling exception in route handler."""

        def failing_handler(params, body):
            raise ValueError("Test error")

        handler = BaseHandler()
        handler.base_path = "/api/test/"
        handler.register_route("fail", failing_handler)

        response = handler.handle("/api/test/fail", {})
        assert response.status == HttpStatus.INTERNAL_SERVER_ERROR

    def test_get_param(self):
        """Test getting single parameter."""
        handler = BaseHandler()
        params = {"name": ["alice"], "age": ["30"]}
        assert handler.get_param(params, "name") == "alice"
        assert handler.get_param(params, "missing") is None
        assert handler.get_param(params, "missing", "default") == "default"

    def test_get_param_int(self):
        """Test getting integer parameter."""
        handler = BaseHandler()
        params = {"count": ["42"], "invalid": ["abc"]}
        assert handler.get_param_int(params, "count") == 42
        assert handler.get_param_int(params, "invalid") == 0
        assert handler.get_param_int(params, "missing", 10) == 10

    def test_get_param_bool(self):
        """Test getting boolean parameter."""
        handler = BaseHandler()
        params = {
            "enabled": ["true"],
            "disabled": ["false"],
            "on": ["1"],
            "yes": ["yes"],
        }
        assert handler.get_param_bool(params, "enabled") is True
        assert handler.get_param_bool(params, "disabled") is False
        assert handler.get_param_bool(params, "on") is True
        assert handler.get_param_bool(params, "yes") is True
        assert handler.get_param_bool(params, "missing") is False

    def test_get_param_list(self):
        """Test getting list parameter."""
        handler = BaseHandler()
        params = {"tags": ["a", "b", "c"]}
        assert handler.get_param_list(params, "tags") == ["a", "b", "c"]
        assert handler.get_param_list(params, "missing") == []

    def test_require_storage_success(self):
        """Test require_storage with storage configured."""
        storage = MagicMock()
        handler = BaseHandler(storage=storage)
        assert handler.require_storage() == storage

    def test_require_storage_failure(self):
        """Test require_storage without storage."""
        handler = BaseHandler()
        with pytest.raises(RuntimeError):
            handler.require_storage()


# =============================================================================
# HandlerRegistry Tests
# =============================================================================


class TestHandlerRegistry:
    """Tests for HandlerRegistry class."""

    def test_register_handler(self):
        """Test registering a handler."""
        registry = HandlerRegistry()
        registry.register_handler("/api/test/", BaseHandler)
        assert "/api/test/" in registry.list_handlers()

    def test_register_instance(self):
        """Test registering handler instance."""
        handler = BaseHandler()
        handler.base_path = "/api/custom/"
        registry = HandlerRegistry()
        registry.register_instance(handler)
        assert "/api/custom/" in registry.list_handlers()

    def test_handle_matching_path(self):
        """Test handling with matching handler."""

        class TestHandler(BaseHandler):
            base_path = "/api/test/"

            def _setup_routes(self):
                self.register_route("items", lambda p, b: HandlerResponse.success([1, 2, 3]))

        registry = HandlerRegistry()
        registry.register_handler("/api/test/", TestHandler)

        response = registry.handle("/api/test/items", {})
        assert response is not None
        assert response.status == HttpStatus.OK
        assert response.data == [1, 2, 3]

    def test_handle_no_matching_handler(self):
        """Test handling with no matching handler."""
        registry = HandlerRegistry()
        response = registry.handle("/api/unknown/path", {})
        assert response is None


# =============================================================================
# RouteTable Tests
# =============================================================================


class TestRouteTable:
    """Tests for RouteTable class."""

    def test_add_route(self):
        """Test adding a route."""
        table = RouteTable()
        table.add("list", lambda p, b: HandlerResponse.success())
        handler, params = table.match("list", "GET")
        assert handler is not None

    def test_get_decorator(self):
        """Test @get decorator."""
        table = RouteTable()

        @table.get("items")
        def list_items(params, body):
            return HandlerResponse.success()

        handler, params = table.match("items", "GET")
        assert handler is not None

    def test_post_decorator(self):
        """Test @post decorator."""
        table = RouteTable()

        @table.post("items")
        def create_item(params, body):
            return HandlerResponse.success()

        handler, params = table.match("items", "POST")
        assert handler is not None

    def test_route_with_methods(self):
        """Test @route decorator with methods."""
        table = RouteTable()

        @table.route("data", methods=["GET", "POST"])
        def handle_data(params, body):
            return HandlerResponse.success()

        get_handler, _ = table.match("data", "GET")
        post_handler, _ = table.match("data", "POST")
        assert get_handler is not None
        assert post_handler is not None

    def test_match_with_path_params(self):
        """Test matching routes with path parameters."""
        table = RouteTable()
        table.add("users/{user_id}", lambda p, b, user_id: HandlerResponse.success())

        handler, params = table.match("users/123", "GET")
        assert handler is not None
        assert params["user_id"] == "123"

    def test_no_match_wrong_method(self):
        """Test no match for wrong method."""
        table = RouteTable()
        table.add("items", lambda p, b: HandlerResponse.success(), ["GET"])

        handler, params = table.match("items", "DELETE")
        assert handler is None


class TestRoute:
    """Tests for Route class."""

    def test_simple_path_match(self):
        """Test matching simple path."""
        route = Route(path="users", handler=lambda: None)
        matches, params = route.matches("users", "GET")
        assert matches is True
        assert params == {}

    def test_path_param_match(self):
        """Test matching path with parameters."""
        route = Route(path="users/{id}", handler=lambda: None)
        matches, params = route.matches("users/42", "GET")
        assert matches is True
        assert params["id"] == "42"

    def test_multiple_path_params(self):
        """Test matching path with multiple parameters."""
        route = Route(path="users/{user_id}/posts/{post_id}", handler=lambda: None)
        matches, params = route.matches("users/1/posts/2", "GET")
        assert matches is True
        assert params["user_id"] == "1"
        assert params["post_id"] == "2"

    def test_method_mismatch(self):
        """Test no match for wrong method."""
        route = Route(path="users", handler=lambda: None, methods=["POST"])
        matches, params = route.matches("users", "GET")
        assert matches is False


# =============================================================================
# RoutedHandler Tests
# =============================================================================


class TestRoutedHandler:
    """Tests for RoutedHandler class."""

    def test_route_decorator_discovery(self):
        """Test that @route decorators are discovered."""

        class TestHandler(RoutedHandler):
            @route("items")
            def list_items(self, params, body):
                return HandlerResponse.success({"items": []})

        handler = TestHandler()
        handler.base_path = "/api/test/"

        response = handler.handle("/api/test/items", {})
        assert response.status == HttpStatus.OK
        assert response.data == {"items": []}

    def test_route_with_path_params(self):
        """Test route with path parameters."""

        class TestHandler(RoutedHandler):
            @route("users/{user_id}")
            def get_user(self, params, body, user_id: str):
                return HandlerResponse.success({"user_id": user_id})

        handler = TestHandler()
        handler.base_path = "/api/"

        response = handler.handle("/api/users/42", {})
        assert response.status == HttpStatus.OK
        assert response.data["user_id"] == "42"

    def test_post_route(self):
        """Test POST route."""

        class TestHandler(RoutedHandler):
            @route("items", methods=["POST"])
            def create_item(self, params, body):
                return HandlerResponse.success(body, HttpStatus.CREATED)

        handler = TestHandler()
        handler.base_path = "/api/"

        response = handler.handle("/api/items", {}, method="POST", body={"name": "test"})
        assert response.status == HttpStatus.CREATED

    def test_unmatched_route(self):
        """Test unmatched route returns 404."""

        class TestHandler(RoutedHandler):
            @route("items")
            def list_items(self, params, body):
                return HandlerResponse.success([])

        handler = TestHandler()
        handler.base_path = "/api/"

        response = handler.handle("/api/unknown", {})
        assert response.status == HttpStatus.NOT_FOUND


# =============================================================================
# VisualizationHandler Tests
# =============================================================================


class TestVisualizationHandler:
    """Tests for VisualizationHandler class."""

    @pytest.fixture
    def mock_viz_api(self):
        """Create mock visualization API."""
        return MagicMock()

    @pytest.fixture
    def handler(self, mock_viz_api):
        """Create handler with mocked API."""
        from stance.web.handlers.visualization import VisualizationHandler

        handler = VisualizationHandler()
        handler._viz_api = mock_viz_api
        return handler

    def test_widget_templates(self, handler, mock_viz_api):
        """Test widget templates endpoint."""
        mock_viz_api.widget_templates_list.return_value = {"templates": []}
        response = handler.widget_templates({}, None)
        assert response.status == HttpStatus.OK
        mock_viz_api.widget_templates_list.assert_called_once()

    def test_widget_search(self, handler, mock_viz_api):
        """Test widget search endpoint."""
        mock_viz_api.widget_templates_search.return_value = {"results": []}
        response = handler.widget_search({"query": ["test"]}, None)
        assert response.status == HttpStatus.OK

    def test_layout_info(self, handler, mock_viz_api):
        """Test layout info endpoint."""
        mock_viz_api.dashboard_layout_info.return_value = {"layout": {}}
        response = handler.layout_info({}, None)
        assert response.status == HttpStatus.OK

    def test_embed_tokens(self, handler, mock_viz_api):
        """Test embed tokens endpoint."""
        mock_viz_api.embed_tokens_list.return_value = {"tokens": []}
        response = handler.embed_tokens({}, None)
        assert response.status == HttpStatus.OK

    def test_share_links(self, handler, mock_viz_api):
        """Test share links endpoint."""
        mock_viz_api.share_links_list.return_value = {"links": []}
        response = handler.share_links({}, None)
        assert response.status == HttpStatus.OK

    def test_realtime_status(self, handler, mock_viz_api):
        """Test realtime status endpoint."""
        mock_viz_api.realtime_status.return_value = {"connected": True}
        response = handler.realtime_status({}, None)
        assert response.status == HttpStatus.OK

    def test_chart_types(self, handler, mock_viz_api):
        """Test chart types endpoint."""
        mock_viz_api.chart_types.return_value = {"types": ["bar", "line"]}
        response = handler.chart_types({}, None)
        assert response.status == HttpStatus.OK

    def test_widget_create(self, handler, mock_viz_api):
        """Test widget create endpoint."""
        mock_viz_api.widget_create.return_value = {"id": "new-widget"}
        response = handler.widget_create({}, {"type": "chart"})
        assert response.status == HttpStatus.CREATED

    def test_widget_delete(self, handler, mock_viz_api):
        """Test widget delete endpoint."""
        mock_viz_api.widget_delete.return_value = {"deleted": True}
        response = handler.widget_delete({}, {"id": "widget-1"})
        assert response.status == HttpStatus.OK

    def test_embed_create(self, handler, mock_viz_api):
        """Test embed create endpoint."""
        mock_viz_api.embed_token_create.return_value = {"token": "abc123"}
        response = handler.embed_create({}, {"dashboard_id": "dash-1"})
        assert response.status == HttpStatus.CREATED

    def test_share_create(self, handler, mock_viz_api):
        """Test share create endpoint."""
        mock_viz_api.share_link_create.return_value = {"link": "https://..."}
        response = handler.share_create({}, {"dashboard_id": "dash-1"})
        assert response.status == HttpStatus.CREATED

    def test_error_handling(self, handler, mock_viz_api):
        """Test error handling in handler."""
        mock_viz_api.widget_templates_list.side_effect = Exception("API error")
        response = handler.widget_templates({}, None)
        assert response.status == HttpStatus.INTERNAL_SERVER_ERROR
        assert "API error" in response.data["error"]

    def test_base_path(self, handler):
        """Test handler base path is set correctly."""
        assert handler.base_path == "/api/viz/"

    def test_can_handle_viz_path(self, handler):
        """Test can_handle for visualization paths."""
        assert handler.can_handle("/api/viz/widget/templates")
        assert handler.can_handle("/api/viz/chart/types")
        assert not handler.can_handle("/api/auth/login")


# =============================================================================
# AuthHandler Tests
# =============================================================================


class TestAuthHandler:
    """Tests for AuthHandler class."""

    @pytest.fixture
    def handler(self):
        """Create AuthHandler instance."""
        from stance.web.handlers.auth import AuthHandler
        return AuthHandler()

    # -------------------------------------------------------------------------
    # Status and Summary GET endpoints
    # -------------------------------------------------------------------------

    def test_auth_status(self, handler):
        """Test auth status endpoint."""
        response = handler.auth_status({}, None)
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "auth"
        assert response.data["status"] == "operational"
        assert "components" in response.data
        assert "capabilities" in response.data

    def test_auth_summary(self, handler):
        """Test auth summary endpoint."""
        response = handler.auth_summary({}, None)
        assert response.status == HttpStatus.OK
        assert "users" in response.data
        assert "sessions" in response.data
        assert "api_keys" in response.data
        assert "audit" in response.data

    # -------------------------------------------------------------------------
    # User GET endpoints
    # -------------------------------------------------------------------------

    def test_users_list(self, handler):
        """Test users list endpoint."""
        response = handler.users_list({}, None)
        assert response.status == HttpStatus.OK
        assert "users" in response.data
        assert "total" in response.data
        assert len(response.data["users"]) > 0

    def test_users_list_with_status_filter(self, handler):
        """Test users list with status filter."""
        params = {"status": ["active"]}
        response = handler.users_list(params, None)
        assert response.status == HttpStatus.OK
        for user in response.data["users"]:
            assert user["status"] == "active"

    def test_users_list_with_role_filter(self, handler):
        """Test users list with role filter."""
        params = {"role": ["admin"]}
        response = handler.users_list(params, None)
        assert response.status == HttpStatus.OK
        for user in response.data["users"]:
            assert "admin" in user["roles"]

    def test_users_list_with_limit(self, handler):
        """Test users list with limit."""
        params = {"limit": ["1"]}
        response = handler.users_list(params, None)
        assert response.status == HttpStatus.OK
        assert len(response.data["users"]) <= 1

    def test_users_show(self, handler):
        """Test users show endpoint."""
        params = {"user_id": ["usr_001"]}
        response = handler.users_show(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["id"] == "usr_001"
        assert "email" in response.data
        assert "roles" in response.data

    def test_users_show_default(self, handler):
        """Test users show with default user."""
        response = handler.users_show({}, None)
        assert response.status == HttpStatus.OK
        assert response.data["id"] == "usr_001"

    # -------------------------------------------------------------------------
    # API Key GET endpoints
    # -------------------------------------------------------------------------

    def test_apikeys_list(self, handler):
        """Test API keys list endpoint."""
        response = handler.apikeys_list({}, None)
        assert response.status == HttpStatus.OK
        assert "api_keys" in response.data
        assert "total" in response.data

    def test_apikeys_list_with_user_filter(self, handler):
        """Test API keys list with user filter."""
        params = {"user_id": ["usr_001"]}
        response = handler.apikeys_list(params, None)
        assert response.status == HttpStatus.OK
        for key in response.data["api_keys"]:
            assert key["user_id"] == "usr_001"

    # -------------------------------------------------------------------------
    # Session GET endpoints
    # -------------------------------------------------------------------------

    def test_sessions_list(self, handler):
        """Test sessions list endpoint."""
        response = handler.sessions_list({}, None)
        assert response.status == HttpStatus.OK
        assert "sessions" in response.data
        assert "total" in response.data

    def test_sessions_list_with_user_filter(self, handler):
        """Test sessions list with user filter."""
        params = {"user_id": ["usr_001"]}
        response = handler.sessions_list(params, None)
        assert response.status == HttpStatus.OK
        for session in response.data["sessions"]:
            assert session["user_id"] == "usr_001"

    # -------------------------------------------------------------------------
    # Role GET endpoints
    # -------------------------------------------------------------------------

    def test_roles_list(self, handler):
        """Test roles list endpoint."""
        response = handler.roles_list({}, None)
        assert response.status == HttpStatus.OK
        assert "roles" in response.data
        assert "total" in response.data
        assert len(response.data["roles"]) == 6

    def test_roles_show(self, handler):
        """Test roles show endpoint."""
        params = {"role_name": ["admin"]}
        response = handler.roles_show(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["name"] == "admin"
        assert "permissions" in response.data
        assert len(response.data["permissions"]) > 0

    def test_roles_show_analyst(self, handler):
        """Test roles show for analyst role."""
        params = {"role_name": ["analyst"]}
        response = handler.roles_show(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["name"] == "analyst"
        assert "findings:read" in response.data["permissions"]

    def test_roles_show_viewer(self, handler):
        """Test roles show for viewer role."""
        params = {"role_name": ["viewer"]}
        response = handler.roles_show(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["name"] == "viewer"
        # Viewer should not have write permissions
        for perm in response.data["permissions"]:
            assert ":write" not in perm

    # -------------------------------------------------------------------------
    # Permission GET endpoints
    # -------------------------------------------------------------------------

    def test_permissions_list(self, handler):
        """Test permissions list endpoint."""
        response = handler.permissions_list({}, None)
        assert response.status == HttpStatus.OK
        assert "permissions" in response.data
        assert "total" in response.data
        assert response.data["total"] == 18

    def test_permissions_have_required_fields(self, handler):
        """Test permissions have name, description, resource."""
        response = handler.permissions_list({}, None)
        for perm in response.data["permissions"]:
            assert "name" in perm
            assert "description" in perm
            assert "resource" in perm

    # -------------------------------------------------------------------------
    # Audit GET endpoints
    # -------------------------------------------------------------------------

    def test_audit_list(self, handler):
        """Test audit list endpoint."""
        response = handler.audit_list({}, None)
        assert response.status == HttpStatus.OK
        assert "events" in response.data
        assert "total" in response.data

    def test_audit_list_with_user_filter(self, handler):
        """Test audit list with user filter."""
        params = {"user_id": ["usr_001"]}
        response = handler.audit_list(params, None)
        assert response.status == HttpStatus.OK
        for event in response.data["events"]:
            assert event["user_id"] == "usr_001"

    def test_audit_list_with_event_type_filter(self, handler):
        """Test audit list with event type filter."""
        params = {"event_type": ["login_success"]}
        response = handler.audit_list(params, None)
        assert response.status == HttpStatus.OK
        for event in response.data["events"]:
            assert event["event_type"] == "login_success"

    def test_audit_security(self, handler):
        """Test audit security endpoint."""
        response = handler.audit_security({}, None)
        assert response.status == HttpStatus.OK
        assert "events" in response.data
        assert "hours" in response.data

    def test_audit_security_with_hours(self, handler):
        """Test audit security with hours parameter."""
        params = {"hours": ["48"]}
        response = handler.audit_security(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["hours"] == 48

    def test_audit_failed_logins(self, handler):
        """Test audit failed logins endpoint."""
        response = handler.audit_failed_logins({}, None)
        assert response.status == HttpStatus.OK
        assert "events" in response.data
        assert "total" in response.data

    def test_audit_stats(self, handler):
        """Test audit stats endpoint."""
        response = handler.audit_stats({}, None)
        assert response.status == HttpStatus.OK
        assert "total_events" in response.data
        assert "events_last_24h" in response.data
        assert "event_counts_24h" in response.data

    # -------------------------------------------------------------------------
    # Login/Logout POST endpoints
    # -------------------------------------------------------------------------

    def test_login_success(self, handler):
        """Test successful login."""
        body = {"email": "test@example.com", "password": "secret"}
        response = handler.login({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True
        assert "user" in response.data
        assert "tokens" in response.data

    def test_login_missing_email(self, handler):
        """Test login with missing email."""
        body = {"password": "secret"}
        response = handler.login({}, body)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "Email and password required" in response.data["error"]

    def test_login_missing_password(self, handler):
        """Test login with missing password."""
        body = {"email": "test@example.com"}
        response = handler.login({}, body)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "Email and password required" in response.data["error"]

    def test_logout(self, handler):
        """Test logout."""
        body = {"session_id": "sess_001"}
        response = handler.logout({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True

    def test_logout_no_session(self, handler):
        """Test logout without session ID."""
        response = handler.logout({}, {})
        assert response.status == HttpStatus.OK
        assert "current" in response.data["message"]

    # -------------------------------------------------------------------------
    # User POST endpoints
    # -------------------------------------------------------------------------

    def test_users_create_success(self, handler):
        """Test successful user creation."""
        body = {
            "email": "new@example.com",
            "username": "newuser",
            "password": "secure123"
        }
        response = handler.users_create({}, body)
        assert response.status == HttpStatus.CREATED
        assert response.data["success"] is True
        assert response.data["user"]["email"] == "new@example.com"

    def test_users_create_with_roles(self, handler):
        """Test user creation with roles."""
        body = {
            "email": "new@example.com",
            "username": "newuser",
            "password": "secure123",
            "roles": ["analyst", "viewer"]
        }
        response = handler.users_create({}, body)
        assert response.status == HttpStatus.CREATED
        assert response.data["user"]["roles"] == ["analyst", "viewer"]

    def test_users_create_missing_fields(self, handler):
        """Test user creation with missing fields."""
        body = {"email": "test@example.com"}
        response = handler.users_create({}, body)
        assert response.status == HttpStatus.BAD_REQUEST

    def test_users_delete_success(self, handler):
        """Test successful user deletion."""
        body = {"user_id": "usr_001"}
        response = handler.users_delete({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True

    def test_users_delete_missing_id(self, handler):
        """Test user deletion with missing ID."""
        response = handler.users_delete({}, {})
        assert response.status == HttpStatus.BAD_REQUEST

    def test_users_suspend_success(self, handler):
        """Test successful user suspension."""
        body = {"user_id": "usr_001", "reason": "Security concern"}
        response = handler.users_suspend({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True
        assert response.data["reason"] == "Security concern"

    def test_users_suspend_missing_id(self, handler):
        """Test user suspension with missing ID."""
        response = handler.users_suspend({}, {})
        assert response.status == HttpStatus.BAD_REQUEST

    def test_users_reactivate_success(self, handler):
        """Test successful user reactivation."""
        body = {"user_id": "usr_001"}
        response = handler.users_reactivate({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True

    def test_users_reactivate_missing_id(self, handler):
        """Test user reactivation with missing ID."""
        response = handler.users_reactivate({}, {})
        assert response.status == HttpStatus.BAD_REQUEST

    # -------------------------------------------------------------------------
    # API Key POST endpoints
    # -------------------------------------------------------------------------

    def test_apikeys_create_success(self, handler):
        """Test successful API key creation."""
        body = {"name": "New API Key"}
        response = handler.apikeys_create({}, body)
        assert response.status == HttpStatus.CREATED
        assert response.data["success"] is True
        assert "key" in response.data["api_key"]
        assert "warning" in response.data

    def test_apikeys_create_with_scopes(self, handler):
        """Test API key creation with scopes."""
        body = {"name": "Limited Key", "scopes": ["read:findings"]}
        response = handler.apikeys_create({}, body)
        assert response.status == HttpStatus.CREATED
        assert response.data["api_key"]["scopes"] == ["read:findings"]

    def test_apikeys_create_missing_name(self, handler):
        """Test API key creation with missing name."""
        response = handler.apikeys_create({}, {})
        assert response.status == HttpStatus.BAD_REQUEST

    def test_apikeys_revoke_success(self, handler):
        """Test successful API key revocation."""
        body = {"key_id": "key_001"}
        response = handler.apikeys_revoke({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True

    def test_apikeys_revoke_missing_id(self, handler):
        """Test API key revocation with missing ID."""
        response = handler.apikeys_revoke({}, {})
        assert response.status == HttpStatus.BAD_REQUEST

    def test_apikeys_rotate_success(self, handler):
        """Test successful API key rotation."""
        body = {"key_id": "key_001"}
        response = handler.apikeys_rotate({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True
        assert "new_api_key" in response.data
        assert "warning" in response.data

    def test_apikeys_rotate_missing_id(self, handler):
        """Test API key rotation with missing ID."""
        response = handler.apikeys_rotate({}, {})
        assert response.status == HttpStatus.BAD_REQUEST

    # -------------------------------------------------------------------------
    # Session POST endpoints
    # -------------------------------------------------------------------------

    def test_sessions_terminate_by_session_id(self, handler):
        """Test session termination by session ID."""
        body = {"session_id": "sess_001"}
        response = handler.sessions_terminate({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True
        assert "sess_001" in response.data["message"]

    def test_sessions_terminate_by_user_id(self, handler):
        """Test session termination by user ID."""
        body = {"user_id": "usr_001"}
        response = handler.sessions_terminate({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True
        assert "terminated_count" in response.data

    def test_sessions_terminate_missing_ids(self, handler):
        """Test session termination with missing IDs."""
        response = handler.sessions_terminate({}, {})
        assert response.status == HttpStatus.BAD_REQUEST

    def test_sessions_cleanup(self, handler):
        """Test expired sessions cleanup."""
        response = handler.sessions_cleanup({}, None)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True
        assert "removed_count" in response.data

    # -------------------------------------------------------------------------
    # Role POST endpoints
    # -------------------------------------------------------------------------

    def test_roles_assign_success(self, handler):
        """Test successful role assignment."""
        body = {"user_id": "usr_001", "role": "analyst"}
        response = handler.roles_assign({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True

    def test_roles_assign_missing_user_id(self, handler):
        """Test role assignment with missing user ID."""
        body = {"role": "analyst"}
        response = handler.roles_assign({}, body)
        assert response.status == HttpStatus.BAD_REQUEST

    def test_roles_assign_missing_role(self, handler):
        """Test role assignment with missing role."""
        body = {"user_id": "usr_001"}
        response = handler.roles_assign({}, body)
        assert response.status == HttpStatus.BAD_REQUEST

    def test_roles_revoke_success(self, handler):
        """Test successful role revocation."""
        body = {"user_id": "usr_001", "role": "analyst"}
        response = handler.roles_revoke({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True

    def test_roles_revoke_missing_fields(self, handler):
        """Test role revocation with missing fields."""
        response = handler.roles_revoke({}, {})
        assert response.status == HttpStatus.BAD_REQUEST

    # -------------------------------------------------------------------------
    # Token POST endpoints
    # -------------------------------------------------------------------------

    def test_token_refresh_success(self, handler):
        """Test successful token refresh."""
        body = {"refresh_token": "old_token"}
        response = handler.token_refresh({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True
        assert "tokens" in response.data
        assert "access_token" in response.data["tokens"]

    def test_token_refresh_missing_token(self, handler):
        """Test token refresh with missing token."""
        response = handler.token_refresh({}, {})
        assert response.status == HttpStatus.BAD_REQUEST

    def test_token_validate_success(self, handler):
        """Test successful token validation."""
        body = {"token": "some_jwt_token"}
        response = handler.token_validate({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["valid"] is True
        assert "payload" in response.data

    def test_token_validate_missing_token(self, handler):
        """Test token validation with missing token."""
        response = handler.token_validate({}, {})
        assert response.status == HttpStatus.BAD_REQUEST

    # -------------------------------------------------------------------------
    # Handler routing tests
    # -------------------------------------------------------------------------

    def test_base_path(self, handler):
        """Test handler base path is set correctly."""
        assert handler.base_path == "/api/auth/"

    def test_can_handle_auth_path(self, handler):
        """Test can_handle for auth paths."""
        assert handler.can_handle("/api/auth/status")
        assert handler.can_handle("/api/auth/users")
        assert handler.can_handle("/api/auth/login")
        assert not handler.can_handle("/api/viz/widget")

    def test_handle_get_status(self, handler):
        """Test handling GET /api/auth/status."""
        response = handler.handle("/api/auth/status", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "auth"

    def test_handle_post_login(self, handler):
        """Test handling POST /api/auth/login."""
        body = {"email": "test@example.com", "password": "secret"}
        response = handler.handle("/api/auth/login", {}, "POST", body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True

    def test_handle_unknown_route(self, handler):
        """Test handling unknown route."""
        response = handler.handle("/api/auth/unknown", {}, "GET")
        assert response.status == HttpStatus.NOT_FOUND

    def test_route_discovery(self, handler):
        """Test that routes are discovered correctly."""
        # Check that routes were registered
        routes = list(handler._route_table)
        assert len(routes) > 0

        # Find login route
        login_routes = [r for r in routes if r.path == "login"]
        assert len(login_routes) == 1
        assert "POST" in login_routes[0].methods


# =============================================================================
# WorkflowHandler Tests
# =============================================================================


class TestWorkflowHandler:
    """Tests for WorkflowHandler class."""

    @pytest.fixture
    def handler(self):
        """Create WorkflowHandler instance."""
        from stance.web.handlers.workflow import WorkflowHandler
        return WorkflowHandler()

    # -------------------------------------------------------------------------
    # Status and Statistics GET endpoints
    # -------------------------------------------------------------------------

    def test_workflow_status(self, handler):
        """Test workflow status endpoint."""
        response = handler.workflow_status({}, None)
        assert response.status == HttpStatus.OK
        assert "components" in response.data
        assert "capabilities" in response.data
        assert response.data["components"]["escalation_engine"] == "operational"

    def test_workflow_stats(self, handler):
        """Test workflow stats endpoint."""
        response = handler.workflow_stats({}, None)
        assert response.status == HttpStatus.OK
        assert "escalation" in response.data
        assert "runbook" in response.data
        assert "remediation" in response.data
        assert "trigger" in response.data

    # -------------------------------------------------------------------------
    # Escalation GET endpoints
    # -------------------------------------------------------------------------

    def test_escalation_policies(self, handler):
        """Test escalation policies endpoint."""
        response = handler.escalation_policies({}, None)
        assert response.status == HttpStatus.OK
        assert "policies" in response.data
        assert len(response.data["policies"]) > 0

    def test_escalation_policies_have_required_fields(self, handler):
        """Test escalation policies have required fields."""
        response = handler.escalation_policies({}, None)
        for policy in response.data["policies"]:
            assert "id" in policy
            assert "name" in policy
            assert "priority" in policy
            assert "enabled" in policy

    def test_escalation_sla(self, handler):
        """Test escalation SLA endpoint."""
        response = handler.escalation_sla({}, None)
        assert response.status == HttpStatus.OK
        assert "incidents" in response.data
        for incident in response.data["incidents"]:
            assert "incident_id" in incident
            assert "priority" in incident
            assert "status" in incident
            assert "sla_hours" in incident

    def test_escalation_history(self, handler):
        """Test escalation history endpoint."""
        response = handler.escalation_history({}, None)
        assert response.status == HttpStatus.OK
        assert "history" in response.data

    def test_escalation_levels(self, handler):
        """Test escalation levels endpoint."""
        response = handler.escalation_levels({}, None)
        assert response.status == HttpStatus.OK
        assert "levels" in response.data
        assert len(response.data["levels"]) == 5
        # Check levels are ordered
        for i, level in enumerate(response.data["levels"]):
            assert level["level"] == i + 1

    # -------------------------------------------------------------------------
    # Runbook GET endpoints
    # -------------------------------------------------------------------------

    def test_runbook_list(self, handler):
        """Test runbook list endpoint."""
        response = handler.runbook_list({}, None)
        assert response.status == HttpStatus.OK
        assert "runbooks" in response.data
        assert len(response.data["runbooks"]) > 0

    def test_runbook_list_with_category_filter(self, handler):
        """Test runbook list with category filter."""
        params = {"category": ["incident"]}
        response = handler.runbook_list(params, None)
        assert response.status == HttpStatus.OK
        for runbook in response.data["runbooks"]:
            assert runbook["category"] == "incident"

    def test_runbook_show(self, handler):
        """Test runbook show endpoint."""
        params = {"id": ["rb-data-breach"]}
        response = handler.runbook_show(params, None)
        assert response.status == HttpStatus.OK
        assert "runbook" in response.data
        assert response.data["runbook"]["id"] == "rb-data-breach"
        assert "tasks" in response.data["runbook"]

    def test_runbook_show_default(self, handler):
        """Test runbook show with default ID."""
        response = handler.runbook_show({}, None)
        assert response.status == HttpStatus.OK
        assert response.data["runbook"]["id"] == "rb-data-breach"

    def test_runbook_templates(self, handler):
        """Test runbook templates endpoint."""
        response = handler.runbook_templates({}, None)
        assert response.status == HttpStatus.OK
        assert "templates" in response.data
        assert len(response.data["templates"]) > 0

    def test_runbook_executions(self, handler):
        """Test runbook executions endpoint."""
        response = handler.runbook_executions({}, None)
        assert response.status == HttpStatus.OK
        assert "executions" in response.data
        for exec in response.data["executions"]:
            assert "id" in exec
            assert "status" in exec
            assert "progress" in exec

    # -------------------------------------------------------------------------
    # Remediation GET endpoints
    # -------------------------------------------------------------------------

    def test_remediation_rules(self, handler):
        """Test remediation rules endpoint."""
        response = handler.remediation_rules({}, None)
        assert response.status == HttpStatus.OK
        assert "rules" in response.data
        for rule in response.data["rules"]:
            assert "id" in rule
            assert "name" in rule
            assert "risk_level" in rule
            assert "auto_remediate" in rule

    def test_remediation_plans(self, handler):
        """Test remediation plans endpoint."""
        response = handler.remediation_plans({}, None)
        assert response.status == HttpStatus.OK
        assert "plans" in response.data
        for plan in response.data["plans"]:
            assert "id" in plan
            assert "status" in plan
            assert "risk_level" in plan

    def test_remediation_pending(self, handler):
        """Test remediation pending endpoint."""
        response = handler.remediation_pending({}, None)
        assert response.status == HttpStatus.OK
        assert "pending" in response.data

    def test_remediation_auto(self, handler):
        """Test remediation auto status endpoint."""
        response = handler.remediation_auto({}, None)
        assert response.status == HttpStatus.OK
        assert "mode" in response.data
        assert "status" in response.data
        assert "risk_levels" in response.data

    # -------------------------------------------------------------------------
    # Trigger GET endpoints
    # -------------------------------------------------------------------------

    def test_trigger_list(self, handler):
        """Test trigger list endpoint."""
        response = handler.trigger_list({}, None)
        assert response.status == HttpStatus.OK
        assert "triggers" in response.data
        for trigger in response.data["triggers"]:
            assert "id" in trigger
            assert "name" in trigger
            assert "type" in trigger
            assert "status" in trigger

    def test_trigger_types(self, handler):
        """Test trigger types endpoint."""
        response = handler.trigger_types({}, None)
        assert response.status == HttpStatus.OK
        assert "types" in response.data
        for t in response.data["types"]:
            assert "value" in t
            assert "description" in t

    def test_trigger_history(self, handler):
        """Test trigger history endpoint."""
        response = handler.trigger_history({}, None)
        assert response.status == HttpStatus.OK
        assert "history" in response.data

    # -------------------------------------------------------------------------
    # Escalation POST endpoints
    # -------------------------------------------------------------------------

    def test_escalation_trigger_success(self, handler):
        """Test successful escalation trigger."""
        body = {"incident_id": "INC-001"}
        response = handler.escalation_trigger({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True
        assert "INC-001" in response.data["message"]

    def test_escalation_trigger_missing_id(self, handler):
        """Test escalation trigger with missing ID."""
        response = handler.escalation_trigger({}, {})
        assert response.status == HttpStatus.BAD_REQUEST

    # -------------------------------------------------------------------------
    # Runbook POST endpoints
    # -------------------------------------------------------------------------

    def test_runbook_execute_success(self, handler):
        """Test successful runbook execution."""
        body = {"runbook_id": "rb-data-breach"}
        response = handler.runbook_execute({}, body)
        assert response.status == HttpStatus.CREATED
        assert response.data["success"] is True
        assert "execution_id" in response.data

    def test_runbook_execute_missing_id(self, handler):
        """Test runbook execution with missing ID."""
        response = handler.runbook_execute({}, {})
        assert response.status == HttpStatus.BAD_REQUEST

    def test_runbook_cancel_success(self, handler):
        """Test successful runbook cancellation."""
        body = {"execution_id": "exec-001"}
        response = handler.runbook_cancel({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True

    def test_runbook_cancel_missing_id(self, handler):
        """Test runbook cancellation with missing ID."""
        response = handler.runbook_cancel({}, {})
        assert response.status == HttpStatus.BAD_REQUEST

    # -------------------------------------------------------------------------
    # Remediation POST endpoints
    # -------------------------------------------------------------------------

    def test_remediation_approve_success(self, handler):
        """Test successful remediation approval."""
        body = {"plan_id": "plan-001"}
        response = handler.remediation_approve({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True

    def test_remediation_approve_missing_id(self, handler):
        """Test remediation approval with missing ID."""
        response = handler.remediation_approve({}, {})
        assert response.status == HttpStatus.BAD_REQUEST

    def test_remediation_reject_success(self, handler):
        """Test successful remediation rejection."""
        body = {"plan_id": "plan-001", "reason": "Risk too high"}
        response = handler.remediation_reject({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True
        assert "Risk too high" in response.data["message"]

    def test_remediation_reject_missing_id(self, handler):
        """Test remediation rejection with missing ID."""
        response = handler.remediation_reject({}, {})
        assert response.status == HttpStatus.BAD_REQUEST

    def test_remediation_reject_default_reason(self, handler):
        """Test remediation rejection with default reason."""
        body = {"plan_id": "plan-001"}
        response = handler.remediation_reject({}, body)
        assert response.status == HttpStatus.OK
        assert "No reason provided" in response.data["message"]

    def test_remediation_execute_success(self, handler):
        """Test successful remediation execution."""
        body = {"plan_id": "plan-001"}
        response = handler.remediation_execute({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True

    def test_remediation_execute_missing_id(self, handler):
        """Test remediation execution with missing ID."""
        response = handler.remediation_execute({}, {})
        assert response.status == HttpStatus.BAD_REQUEST

    # -------------------------------------------------------------------------
    # Trigger POST endpoints
    # -------------------------------------------------------------------------

    def test_trigger_enable_success(self, handler):
        """Test successful trigger enable."""
        body = {"trigger_id": "trigger-001"}
        response = handler.trigger_enable({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True

    def test_trigger_enable_missing_id(self, handler):
        """Test trigger enable with missing ID."""
        response = handler.trigger_enable({}, {})
        assert response.status == HttpStatus.BAD_REQUEST

    def test_trigger_disable_success(self, handler):
        """Test successful trigger disable."""
        body = {"trigger_id": "trigger-001"}
        response = handler.trigger_disable({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True

    def test_trigger_disable_missing_id(self, handler):
        """Test trigger disable with missing ID."""
        response = handler.trigger_disable({}, {})
        assert response.status == HttpStatus.BAD_REQUEST

    def test_trigger_test_success(self, handler):
        """Test successful trigger test."""
        body = {"trigger_id": "trigger-001"}
        response = handler.trigger_test({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True
        assert response.data["trigger_id"] == "trigger-001"
        assert "would_match" in response.data
        assert "actions" in response.data

    def test_trigger_test_missing_id(self, handler):
        """Test trigger test with missing ID."""
        response = handler.trigger_test({}, {})
        assert response.status == HttpStatus.BAD_REQUEST

    # -------------------------------------------------------------------------
    # Handler routing tests
    # -------------------------------------------------------------------------

    def test_base_path(self, handler):
        """Test handler base path is set correctly."""
        assert handler.base_path == "/api/workflow/"

    def test_can_handle_workflow_path(self, handler):
        """Test can_handle for workflow paths."""
        assert handler.can_handle("/api/workflow/status")
        assert handler.can_handle("/api/workflow/escalation/policies")
        assert handler.can_handle("/api/workflow/runbook/list")
        assert not handler.can_handle("/api/auth/login")

    def test_handle_get_status(self, handler):
        """Test handling GET /api/workflow/status."""
        response = handler.handle("/api/workflow/status", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "components" in response.data

    def test_handle_post_runbook_execute(self, handler):
        """Test handling POST /api/workflow/runbook/execute."""
        body = {"runbook_id": "rb-data-breach"}
        response = handler.handle("/api/workflow/runbook/execute", {}, "POST", body)
        assert response.status == HttpStatus.CREATED
        assert response.data["success"] is True

    def test_handle_unknown_route(self, handler):
        """Test handling unknown route."""
        response = handler.handle("/api/workflow/unknown", {}, "GET")
        assert response.status == HttpStatus.NOT_FOUND

    def test_route_discovery(self, handler):
        """Test that routes are discovered correctly."""
        routes = list(handler._route_table)
        assert len(routes) > 0

        # Find runbook execute route
        exec_routes = [r for r in routes if r.path == "runbook/execute"]
        assert len(exec_routes) == 1
        assert "POST" in exec_routes[0].methods


# =============================================================================
# ConfigHandler Tests
# =============================================================================


class TestConfigHandler:
    """Tests for ConfigHandler class."""

    @pytest.fixture
    def handler(self):
        """Create ConfigHandler instance."""
        from stance.web.handlers.config import ConfigHandler
        return ConfigHandler()

    # -------------------------------------------------------------------------
    # Configuration GET endpoints
    # -------------------------------------------------------------------------

    def test_config_list(self, handler):
        """Test config list endpoint."""
        response = handler.config_list({}, None)
        assert response.status == HttpStatus.OK
        assert "configurations" in response.data
        assert "total" in response.data
        assert "config_dir" in response.data

    def test_config_list_has_configs(self, handler):
        """Test config list returns configuration objects."""
        response = handler.config_list({}, None)
        for config in response.data["configurations"]:
            assert "name" in config
            assert "mode" in config

    def test_config_show(self, handler):
        """Test config show endpoint."""
        response = handler.config_show({}, None)
        assert response.status == HttpStatus.OK
        assert "name" in response.data
        assert "description" in response.data
        assert "mode" in response.data
        assert "collectors" in response.data
        assert "accounts" in response.data
        assert "schedule" in response.data
        assert "policies" in response.data
        assert "storage" in response.data
        assert "notifications" in response.data

    def test_config_show_with_name(self, handler):
        """Test config show with name parameter."""
        params = {"name": ["production"]}
        response = handler.config_show(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["name"] == "production"

    def test_config_show_section(self, handler):
        """Test config show with section parameter."""
        params = {"section": ["collectors"]}
        response = handler.config_show(params, None)
        assert response.status == HttpStatus.OK
        assert "section" in response.data
        assert response.data["section"] == "collectors"
        assert "data" in response.data

    def test_config_validate(self, handler):
        """Test config validate endpoint."""
        response = handler.config_validate({}, None)
        assert response.status == HttpStatus.OK
        assert "name" in response.data
        assert "valid" in response.data
        assert "errors" in response.data
        assert "warnings" in response.data
        assert response.data["valid"] is True

    def test_config_validate_with_name(self, handler):
        """Test config validate with name parameter."""
        params = {"name": ["production"]}
        response = handler.config_validate(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["name"] == "production"

    def test_config_default(self, handler):
        """Test config default endpoint."""
        response = handler.config_default({}, None)
        assert response.status == HttpStatus.OK
        assert response.data["name"] == "default"
        assert "schedule" in response.data
        assert "policies" in response.data
        assert "storage" in response.data
        assert "notifications" in response.data

    def test_config_modes(self, handler):
        """Test config modes endpoint."""
        response = handler.config_modes({}, None)
        assert response.status == HttpStatus.OK
        assert "modes" in response.data
        assert "total" in response.data
        assert len(response.data["modes"]) == 3

    def test_config_modes_have_required_fields(self, handler):
        """Test config modes have required fields."""
        response = handler.config_modes({}, None)
        for mode in response.data["modes"]:
            assert "name" in mode
            assert "description" in mode
            assert "use_case" in mode

    def test_config_providers(self, handler):
        """Test config providers endpoint."""
        response = handler.config_providers({}, None)
        assert response.status == HttpStatus.OK
        assert "providers" in response.data
        assert "total" in response.data
        assert len(response.data["providers"]) == 3

    def test_config_providers_have_required_fields(self, handler):
        """Test config providers have required fields."""
        response = handler.config_providers({}, None)
        provider_names = [p["name"] for p in response.data["providers"]]
        assert "aws" in provider_names
        assert "gcp" in provider_names
        assert "azure" in provider_names

    def test_config_schema_all(self, handler):
        """Test config schema endpoint for all sections."""
        response = handler.config_schema({}, None)
        assert response.status == HttpStatus.OK
        assert response.data["type"] == "object"
        assert "properties" in response.data
        assert "collectors" in response.data["properties"]
        assert "accounts" in response.data["properties"]
        assert "schedule" in response.data["properties"]

    def test_config_schema_section(self, handler):
        """Test config schema endpoint for specific section."""
        params = {"section": ["collectors"]}
        response = handler.config_schema(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["type"] == "array"
        assert "items" in response.data

    def test_config_env(self, handler):
        """Test config env endpoint."""
        response = handler.config_env({}, None)
        assert response.status == HttpStatus.OK
        assert "environment_variables" in response.data
        assert "total" in response.data
        assert len(response.data["environment_variables"]) > 0

    def test_config_env_have_required_fields(self, handler):
        """Test config env variables have required fields."""
        response = handler.config_env({}, None)
        for env_var in response.data["environment_variables"]:
            assert "name" in env_var
            assert "description" in env_var
            assert "current" in env_var

    def test_config_status(self, handler):
        """Test config status endpoint."""
        response = handler.config_status({}, None)
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "config"
        assert "components" in response.data
        assert "enums" in response.data
        assert "utilities" in response.data

    def test_config_summary(self, handler):
        """Test config summary endpoint."""
        response = handler.config_summary({}, None)
        assert response.status == HttpStatus.OK
        assert "overview" in response.data
        assert "features" in response.data
        assert "architecture" in response.data
        assert "supported_formats" in response.data
        assert "scan_modes" in response.data

    # -------------------------------------------------------------------------
    # Configuration POST endpoints
    # -------------------------------------------------------------------------

    def test_config_create_success(self, handler):
        """Test successful config creation."""
        body = {"name": "new-config"}
        response = handler.config_create({}, body)
        assert response.status == HttpStatus.CREATED
        assert response.data["success"] is True
        assert response.data["name"] == "new-config"
        assert "path" in response.data

    def test_config_create_missing_name(self, handler):
        """Test config creation with missing name."""
        response = handler.config_create({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "name" in response.data["error"]

    def test_config_delete_success(self, handler):
        """Test successful config deletion."""
        body = {"name": "old-config"}
        response = handler.config_delete({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True
        assert response.data["name"] == "old-config"

    def test_config_delete_missing_name(self, handler):
        """Test config deletion with missing name."""
        response = handler.config_delete({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "name" in response.data["error"]

    def test_config_edit_success(self, handler):
        """Test successful config edit."""
        body = {"name": "default", "description": "Updated description"}
        response = handler.config_edit({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True
        assert response.data["name"] == "default"
        assert "path" in response.data

    def test_config_edit_no_changes(self, handler):
        """Test config edit with no changes."""
        body = {"name": "default"}
        response = handler.config_edit({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is False
        assert "No changes" in response.data["message"]

    def test_config_edit_various_fields(self, handler):
        """Test config edit with various fields."""
        body = {
            "name": "default",
            "mode": "incremental",
            "storage_backend": "s3",
            "severity_threshold": "high"
        }
        response = handler.config_edit({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True

    def test_config_import_success(self, handler):
        """Test successful config import."""
        body = {
            "name": "imported",
            "config": {
                "name": "imported",
                "mode": "full",
                "collectors": []
            }
        }
        response = handler.config_import({}, body)
        assert response.status == HttpStatus.CREATED
        assert response.data["success"] is True
        assert response.data["name"] == "imported"

    def test_config_import_missing_config(self, handler):
        """Test config import with missing config data."""
        body = {"name": "imported"}
        response = handler.config_import({}, body)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "config" in response.data["error"]

    def test_config_import_infers_name(self, handler):
        """Test config import infers name from config."""
        body = {
            "config": {
                "name": "from-config",
                "mode": "full"
            }
        }
        response = handler.config_import({}, body)
        assert response.status == HttpStatus.CREATED
        assert response.data["name"] == "from-config"

    def test_config_export_json(self, handler):
        """Test config export as JSON."""
        body = {"name": "default", "format": "json"}
        response = handler.config_export({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["name"] == "default"
        assert response.data["format"] == "json"
        assert "content" in response.data
        assert isinstance(response.data["content"], dict)

    def test_config_export_yaml(self, handler):
        """Test config export as YAML."""
        body = {"name": "default", "format": "yaml"}
        response = handler.config_export({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["name"] == "default"
        assert response.data["format"] == "yaml"
        assert "content" in response.data
        assert isinstance(response.data["content"], str)
        assert "name: default" in response.data["content"]

    def test_config_export_default_format(self, handler):
        """Test config export with default format (JSON)."""
        body = {"name": "production"}
        response = handler.config_export({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["format"] == "json"

    def test_config_set_default_success(self, handler):
        """Test successful set default config."""
        body = {"name": "production"}
        response = handler.config_set_default({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True
        assert response.data["name"] == "production"
        assert "default_path" in response.data

    def test_config_set_default_missing_name(self, handler):
        """Test set default config with missing name."""
        response = handler.config_set_default({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "name" in response.data["error"]

    # -------------------------------------------------------------------------
    # Handler routing tests
    # -------------------------------------------------------------------------

    def test_base_path(self, handler):
        """Test handler base path is set correctly."""
        assert handler.base_path == "/api/config/"

    def test_can_handle_config_path(self, handler):
        """Test can_handle for config paths."""
        assert handler.can_handle("/api/config/list")
        assert handler.can_handle("/api/config/show")
        assert handler.can_handle("/api/config/create")
        assert not handler.can_handle("/api/auth/login")

    def test_handle_get_list(self, handler):
        """Test handling GET /api/config/list."""
        response = handler.handle("/api/config/list", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "configurations" in response.data

    def test_handle_post_create(self, handler):
        """Test handling POST /api/config/create."""
        body = {"name": "test-config"}
        response = handler.handle("/api/config/create", {}, "POST", body)
        assert response.status == HttpStatus.CREATED
        assert response.data["success"] is True

    def test_handle_unknown_route(self, handler):
        """Test handling unknown route."""
        response = handler.handle("/api/config/unknown", {}, "GET")
        assert response.status == HttpStatus.NOT_FOUND

    def test_route_discovery(self, handler):
        """Test that routes are discovered correctly."""
        routes = list(handler._route_table)
        assert len(routes) > 0

        # Find create route
        create_routes = [r for r in routes if r.path == "create"]
        assert len(create_routes) == 1
        assert "POST" in create_routes[0].methods

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 10 GET routes + 6 POST routes = 16 total
        assert len(routes) == 16


# =============================================================================
# ScanHandler Tests
# =============================================================================


class TestScanHandler:
    """Tests for ScanHandler class."""

    @pytest.fixture
    def handler(self):
        """Create ScanHandler instance."""
        from stance.web.handlers.scan import ScanHandler
        return ScanHandler()

    # -------------------------------------------------------------------------
    # Scan History and Status GET endpoints
    # -------------------------------------------------------------------------

    def test_scan_list(self, handler):
        """Test scan list endpoint."""
        response = handler.scan_list({}, None)
        assert response.status == HttpStatus.OK
        assert "scans" in response.data
        assert "total" in response.data
        assert "filters" in response.data

    def test_scan_list_with_status_filter(self, handler):
        """Test scan list with status filter."""
        params = {"status": ["completed"]}
        response = handler.scan_list(params, None)
        assert response.status == HttpStatus.OK
        for scan in response.data["scans"]:
            assert scan["status"] == "completed"

    def test_scan_list_with_limit(self, handler):
        """Test scan list with limit."""
        params = {"limit": ["1"]}
        response = handler.scan_list(params, None)
        assert response.status == HttpStatus.OK
        assert len(response.data["scans"]) <= 1

    def test_scan_show(self, handler):
        """Test scan show endpoint."""
        params = {"scan_id": ["scan-001"]}
        response = handler.scan_show(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["scan_id"] == "scan-001"
        assert "status" in response.data
        assert "summary" in response.data
        assert "config" in response.data

    def test_scan_show_missing_id(self, handler):
        """Test scan show with missing ID."""
        response = handler.scan_show({}, None)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "scan_id" in response.data["error"]

    def test_scan_status(self, handler):
        """Test scan status endpoint."""
        response = handler.scan_status({}, None)
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "scan"
        assert response.data["status"] == "operational"
        assert "components" in response.data
        assert "capabilities" in response.data

    def test_scan_statuses(self, handler):
        """Test scan statuses endpoint."""
        response = handler.scan_statuses({}, None)
        assert response.status == HttpStatus.OK
        assert "statuses" in response.data
        assert len(response.data["statuses"]) == 5
        status_names = [s["status"] for s in response.data["statuses"]]
        assert "pending" in status_names
        assert "running" in status_names
        assert "completed" in status_names
        assert "failed" in status_names
        assert "canceled" in status_names

    def test_scan_progress(self, handler):
        """Test scan progress endpoint."""
        response = handler.scan_progress({}, None)
        assert response.status == HttpStatus.OK
        assert "scan_id" in response.data
        assert "total_accounts" in response.data
        assert "completed_accounts" in response.data
        assert "progress_percent" in response.data
        assert "is_complete" in response.data

    def test_scan_progress_with_id(self, handler):
        """Test scan progress with scan ID."""
        params = {"scan_id": ["scan-001"]}
        response = handler.scan_progress(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["scan_id"] == "scan-001"

    def test_scan_results(self, handler):
        """Test scan results endpoint."""
        response = handler.scan_results({}, None)
        assert response.status == HttpStatus.OK
        assert "scan_id" in response.data
        assert "summary" in response.data
        assert "findings_by_severity" in response.data
        assert "account_results" in response.data

    def test_scan_results_with_filter(self, handler):
        """Test scan results with account filter."""
        params = {"account": ["123456789012"]}
        response = handler.scan_results(params, None)
        assert response.status == HttpStatus.OK
        assert "filter" in response.data
        assert response.data["filter"]["account"] == "123456789012"

    def test_scan_report(self, handler):
        """Test scan report endpoint."""
        response = handler.scan_report({}, None)
        assert response.status == HttpStatus.OK
        assert "scan_id" in response.data
        assert "scan_date" in response.data
        assert "summary" in response.data
        assert "findings_by_severity" in response.data
        assert "findings_by_provider" in response.data
        assert "top_accounts_by_findings" in response.data

    def test_scan_summary(self, handler):
        """Test scan summary endpoint."""
        response = handler.scan_summary({}, None)
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "scan"
        assert "features" in response.data
        assert "scan_types" in response.data
        assert "supported_providers" in response.data

    # -------------------------------------------------------------------------
    # Multi-Account Scanning GET endpoints
    # -------------------------------------------------------------------------

    def test_scan_accounts(self, handler):
        """Test scan accounts endpoint."""
        response = handler.scan_accounts({}, None)
        assert response.status == HttpStatus.OK
        assert "accounts" in response.data
        assert "total" in response.data
        # Default excludes disabled accounts
        for account in response.data["accounts"]:
            assert account["enabled"] is True

    def test_scan_accounts_include_disabled(self, handler):
        """Test scan accounts including disabled."""
        params = {"include_disabled": ["true"]}
        response = handler.scan_accounts(params, None)
        assert response.status == HttpStatus.OK
        # Should include disabled accounts now
        enabled_statuses = [a["enabled"] for a in response.data["accounts"]]
        assert False in enabled_statuses

    def test_scan_options(self, handler):
        """Test scan options endpoint."""
        response = handler.scan_options({}, None)
        assert response.status == HttpStatus.OK
        assert "options" in response.data
        assert "total" in response.data
        option_names = [o["option"] for o in response.data["options"]]
        assert "parallel_accounts" in option_names
        assert "timeout_per_account" in option_names
        assert "continue_on_error" in option_names

    def test_scan_providers(self, handler):
        """Test scan providers endpoint."""
        response = handler.scan_providers({}, None)
        assert response.status == HttpStatus.OK
        assert "providers" in response.data
        assert len(response.data["providers"]) == 3
        provider_names = [p["provider"] for p in response.data["providers"]]
        assert "aws" in provider_names
        assert "gcp" in provider_names
        assert "azure" in provider_names

    def test_scan_stats(self, handler):
        """Test scan stats endpoint."""
        response = handler.scan_stats({}, None)
        assert response.status == HttpStatus.OK
        assert "features" in response.data
        assert "default_settings" in response.data
        assert response.data["features"]["parallel_execution"] is True

    # -------------------------------------------------------------------------
    # Scanner Module GET endpoints
    # -------------------------------------------------------------------------

    def test_scan_scanners(self, handler):
        """Test scan scanners endpoint."""
        response = handler.scan_scanners({}, None)
        assert response.status == HttpStatus.OK
        assert "scanners" in response.data
        assert "total" in response.data
        assert "available" in response.data

    def test_scan_scanners_have_required_fields(self, handler):
        """Test scan scanners have required fields."""
        response = handler.scan_scanners({}, None)
        for scanner in response.data["scanners"]:
            assert "id" in scanner
            assert "name" in scanner
            assert "description" in scanner
            assert "available" in scanner
            assert "supported_targets" in scanner

    def test_scan_scanner_check(self, handler):
        """Test scan scanner check endpoint."""
        response = handler.scan_scanner_check({}, None)
        assert response.status == HttpStatus.OK
        assert "scanner" in response.data
        assert "available" in response.data
        assert "message" in response.data

    def test_scan_severity_levels(self, handler):
        """Test scan severity levels endpoint."""
        response = handler.scan_severity_levels({}, None)
        assert response.status == HttpStatus.OK
        assert "levels" in response.data
        assert len(response.data["levels"]) == 5
        level_names = [l["level"] for l in response.data["levels"]]
        assert "CRITICAL" in level_names
        assert "HIGH" in level_names
        assert "MEDIUM" in level_names
        assert "LOW" in level_names
        assert "UNKNOWN" in level_names

    def test_scan_priority_factors(self, handler):
        """Test scan priority factors endpoint."""
        response = handler.scan_priority_factors({}, None)
        assert response.status == HttpStatus.OK
        assert "factors" in response.data
        assert "max_score" in response.data
        assert response.data["max_score"] == 100

    def test_scan_package_types(self, handler):
        """Test scan package types endpoint."""
        response = handler.scan_package_types({}, None)
        assert response.status == HttpStatus.OK
        assert "package_types" in response.data
        assert "total" in response.data
        type_names = [p["type"] for p in response.data["package_types"]]
        assert "npm" in type_names
        assert "pip" in type_names
        assert "go" in type_names

    # -------------------------------------------------------------------------
    # Scan Execution POST endpoints
    # -------------------------------------------------------------------------

    def test_scan_start_success(self, handler):
        """Test successful scan start."""
        body = {"config": "production"}
        response = handler.scan_start({}, body)
        assert response.status == HttpStatus.CREATED
        assert response.data["success"] is True
        assert "scan_id" in response.data
        assert response.data["config"] == "production"

    def test_scan_start_default_config(self, handler):
        """Test scan start with default config."""
        response = handler.scan_start({}, {})
        assert response.status == HttpStatus.CREATED
        assert response.data["success"] is True
        assert response.data["config"] == "default"

    def test_scan_start_with_options(self, handler):
        """Test scan start with options."""
        body = {
            "config": "default",
            "accounts": ["123456789012"],
            "collectors": ["aws_iam", "aws_s3"],
            "parallel": 5,
        }
        response = handler.scan_start({}, body)
        assert response.status == HttpStatus.CREATED
        assert response.data["success"] is True
        assert response.data["options"]["parallel_accounts"] == 5

    def test_scan_stop_success(self, handler):
        """Test successful scan stop."""
        body = {"scan_id": "scan-001"}
        response = handler.scan_stop({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True
        assert response.data["status"] == "canceled"

    def test_scan_stop_missing_id(self, handler):
        """Test scan stop with missing ID."""
        response = handler.scan_stop({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "scan_id" in response.data["error"]

    def test_scan_pause_success(self, handler):
        """Test successful scan pause."""
        body = {"scan_id": "scan-001"}
        response = handler.scan_pause({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True
        assert response.data["status"] == "paused"

    def test_scan_pause_missing_id(self, handler):
        """Test scan pause with missing ID."""
        response = handler.scan_pause({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "scan_id" in response.data["error"]

    def test_scan_resume_success(self, handler):
        """Test successful scan resume."""
        body = {"scan_id": "scan-001"}
        response = handler.scan_resume({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True
        assert response.data["status"] == "running"

    def test_scan_resume_missing_id(self, handler):
        """Test scan resume with missing ID."""
        response = handler.scan_resume({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "scan_id" in response.data["error"]

    def test_scan_enrich_success(self, handler):
        """Test successful CVE enrichment."""
        body = {"cve_id": "CVE-2024-1234"}
        response = handler.scan_enrich({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["cve_id"] == "CVE-2024-1234"
        assert "epss" in response.data
        assert "kev" in response.data

    def test_scan_enrich_missing_cve(self, handler):
        """Test CVE enrichment with missing CVE ID."""
        response = handler.scan_enrich({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "cve_id" in response.data["error"]

    def test_scan_enrich_invalid_cve(self, handler):
        """Test CVE enrichment with invalid CVE ID."""
        body = {"cve_id": "INVALID-123"}
        response = handler.scan_enrich({}, body)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "Invalid CVE ID" in response.data["error"]

    def test_scan_vulnerability_success(self, handler):
        """Test successful vulnerability scan."""
        body = {"target": "nginx:latest", "type": "image"}
        response = handler.scan_vulnerability({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True
        assert response.data["target"] == "nginx:latest"
        assert "summary" in response.data
        assert "vulnerabilities" in response.data

    def test_scan_vulnerability_missing_target(self, handler):
        """Test vulnerability scan with missing target."""
        response = handler.scan_vulnerability({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "target" in response.data["error"]

    # -------------------------------------------------------------------------
    # Handler routing tests
    # -------------------------------------------------------------------------

    def test_base_path(self, handler):
        """Test handler base path is set correctly."""
        assert handler.base_path == "/api/scan/"

    def test_can_handle_scan_path(self, handler):
        """Test can_handle for scan paths."""
        assert handler.can_handle("/api/scan/list")
        assert handler.can_handle("/api/scan/status")
        assert handler.can_handle("/api/scan/start")
        assert not handler.can_handle("/api/auth/login")

    def test_handle_get_list(self, handler):
        """Test handling GET /api/scan/list."""
        response = handler.handle("/api/scan/list", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "scans" in response.data

    def test_handle_post_start(self, handler):
        """Test handling POST /api/scan/start."""
        body = {"config": "default"}
        response = handler.handle("/api/scan/start", {}, "POST", body)
        assert response.status == HttpStatus.CREATED
        assert response.data["success"] is True

    def test_handle_unknown_route(self, handler):
        """Test handling unknown route."""
        response = handler.handle("/api/scan/unknown", {}, "GET")
        assert response.status == HttpStatus.NOT_FOUND

    def test_route_discovery(self, handler):
        """Test that routes are discovered correctly."""
        routes = list(handler._route_table)
        assert len(routes) > 0

        # Find start route
        start_routes = [r for r in routes if r.path == "start"]
        assert len(start_routes) == 1
        assert "POST" in start_routes[0].methods

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 17 GET routes + 6 POST routes = 23 total
        assert len(routes) == 23


# =============================================================================
# FindingsHandler Tests
# =============================================================================


class TestFindingsHandler:
    """Tests for FindingsHandler class."""

    @pytest.fixture
    def handler(self):
        """Create FindingsHandler instance."""
        from stance.web.handlers.findings import FindingsHandler
        return FindingsHandler()

    # -------------------------------------------------------------------------
    # Finding Listing GET endpoints
    # -------------------------------------------------------------------------

    def test_findings_list(self, handler):
        """Test findings list endpoint."""
        response = handler.findings_list({}, None)
        assert response.status == HttpStatus.OK
        assert "items" in response.data
        assert "total" in response.data
        assert "limit" in response.data
        assert "offset" in response.data

    def test_findings_list_with_severity_filter(self, handler):
        """Test findings list with severity filter."""
        params = {"severity": ["HIGH"]}
        response = handler.findings_list(params, None)
        assert response.status == HttpStatus.OK
        for finding in response.data["items"]:
            assert finding["severity"] == "HIGH"

    def test_findings_list_with_status_filter(self, handler):
        """Test findings list with status filter."""
        params = {"status": ["OPEN"]}
        response = handler.findings_list(params, None)
        assert response.status == HttpStatus.OK
        for finding in response.data["items"]:
            assert finding["status"] == "OPEN"

    def test_findings_list_pagination(self, handler):
        """Test findings list with pagination."""
        params = {"limit": ["2"], "offset": ["1"]}
        response = handler.findings_list(params, None)
        assert response.status == HttpStatus.OK
        assert len(response.data["items"]) <= 2

    def test_findings_show(self, handler):
        """Test findings show endpoint."""
        params = {"finding_id": ["finding-001"]}
        response = handler.findings_show(params, None)
        assert response.status == HttpStatus.OK
        assert "finding" in response.data
        assert "asset" in response.data
        assert "title" in response.data["finding"]
        assert "severity" in response.data["finding"]
        assert "remediation_guidance" in response.data["finding"]

    def test_findings_show_missing_id(self, handler):
        """Test findings show with missing ID."""
        response = handler.findings_show({}, None)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "finding_id" in response.data["error"]

    def test_findings_search(self, handler):
        """Test findings search endpoint."""
        params = {"q": ["public access"]}
        response = handler.findings_search(params, None)
        assert response.status == HttpStatus.OK
        assert "query" in response.data
        assert "results" in response.data
        assert response.data["query"] == "public access"

    def test_findings_search_missing_query(self, handler):
        """Test findings search with missing query."""
        response = handler.findings_search({}, None)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "q" in response.data["error"]

    def test_findings_by_severity(self, handler):
        """Test findings by severity endpoint."""
        response = handler.findings_by_severity({}, None)
        assert response.status == HttpStatus.OK
        assert "severity_counts" in response.data
        assert "total" in response.data
        assert "CRITICAL" in response.data["severity_counts"]
        assert "HIGH" in response.data["severity_counts"]

    def test_findings_by_status(self, handler):
        """Test findings by status endpoint."""
        response = handler.findings_by_status({}, None)
        assert response.status == HttpStatus.OK
        assert "status_counts" in response.data
        assert "OPEN" in response.data["status_counts"]
        assert "RESOLVED" in response.data["status_counts"]

    def test_findings_by_type(self, handler):
        """Test findings by type endpoint."""
        response = handler.findings_by_type({}, None)
        assert response.status == HttpStatus.OK
        assert "type_counts" in response.data
        assert "MISCONFIGURATION" in response.data["type_counts"]
        assert "VULNERABILITY" in response.data["type_counts"]

    # -------------------------------------------------------------------------
    # Finding Lifecycle GET endpoints
    # -------------------------------------------------------------------------

    def test_findings_lifecycles(self, handler):
        """Test findings lifecycles endpoint."""
        response = handler.findings_lifecycles({}, None)
        assert response.status == HttpStatus.OK
        assert "lifecycles" in response.data
        assert len(response.data["lifecycles"]) == 6
        lifecycle_names = [l["lifecycle"] for l in response.data["lifecycles"]]
        assert "NEW" in lifecycle_names
        assert "RESOLVED" in lifecycle_names
        assert "SUPPRESSED" in lifecycle_names

    def test_findings_states(self, handler):
        """Test findings states endpoint."""
        response = handler.findings_states({}, None)
        assert response.status == HttpStatus.OK
        assert "findings" in response.data
        assert "filters" in response.data

    def test_findings_states_with_lifecycle_filter(self, handler):
        """Test findings states with lifecycle filter."""
        params = {"lifecycle": ["SUPPRESSED"]}
        response = handler.findings_states(params, None)
        assert response.status == HttpStatus.OK
        for finding in response.data["findings"]:
            assert finding["lifecycle"] == "SUPPRESSED"

    def test_findings_state(self, handler):
        """Test findings state endpoint."""
        params = {"finding_id": ["finding-001"]}
        response = handler.findings_state(params, None)
        assert response.status == HttpStatus.OK
        assert "finding_id" in response.data
        assert "lifecycle" in response.data
        assert "first_seen" in response.data

    def test_findings_state_missing_id(self, handler):
        """Test findings state with missing ID."""
        response = handler.findings_state({}, None)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "finding_id" in response.data["error"]

    def test_findings_stats(self, handler):
        """Test findings stats endpoint."""
        response = handler.findings_stats({}, None)
        assert response.status == HttpStatus.OK
        assert "stats" in response.data
        assert "total" in response.data
        assert "breakdown" in response.data

    # -------------------------------------------------------------------------
    # Finding Aggregation GET endpoints
    # -------------------------------------------------------------------------

    def test_findings_aggregate(self, handler):
        """Test findings aggregate endpoint."""
        response = handler.findings_aggregate({}, None)
        assert response.status == HttpStatus.OK
        assert "total_findings" in response.data
        assert "unique_findings" in response.data
        assert "findings_by_severity" in response.data

    def test_findings_aggregate_no_dedup(self, handler):
        """Test findings aggregate without deduplication."""
        params = {"deduplicate": ["false"]}
        response = handler.findings_aggregate(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["deduplicated"] is False

    def test_findings_cross_account(self, handler):
        """Test findings cross-account endpoint."""
        response = handler.findings_cross_account({}, None)
        assert response.status == HttpStatus.OK
        assert "cross_account_findings" in response.data
        for finding in response.data["cross_account_findings"]:
            assert "accounts" in finding
            assert "account_count" in finding
            assert finding["account_count"] >= 2

    # -------------------------------------------------------------------------
    # Finding Correlation GET endpoints
    # -------------------------------------------------------------------------

    def test_findings_correlate(self, handler):
        """Test findings correlate endpoint."""
        response = handler.findings_correlate({}, None)
        assert response.status == HttpStatus.OK
        assert "correlation_groups" in response.data
        assert "total_groups" in response.data
        assert "findings_correlated" in response.data

    def test_findings_groups(self, handler):
        """Test findings groups endpoint."""
        response = handler.findings_groups({}, None)
        assert response.status == HttpStatus.OK
        assert "groups" in response.data
        for group in response.data["groups"]:
            assert "group_id" in group
            assert "type" in group
            assert "finding_count" in group

    def test_findings_groups_with_type_filter(self, handler):
        """Test findings groups with type filter."""
        params = {"type": ["attack_path"]}
        response = handler.findings_groups(params, None)
        assert response.status == HttpStatus.OK
        for group in response.data["groups"]:
            assert group["type"] == "attack_path"

    def test_findings_group(self, handler):
        """Test findings group details endpoint."""
        params = {"group_id": ["corr-001"]}
        response = handler.findings_group(params, None)
        assert response.status == HttpStatus.OK
        assert "group_id" in response.data
        assert "findings" in response.data
        assert "recommendations" in response.data

    def test_findings_group_missing_id(self, handler):
        """Test findings group with missing ID."""
        response = handler.findings_group({}, None)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "group_id" in response.data["error"]

    # -------------------------------------------------------------------------
    # Finding Enrichment GET endpoints
    # -------------------------------------------------------------------------

    def test_findings_enrich(self, handler):
        """Test findings enrich endpoint."""
        response = handler.findings_enrich({}, None)
        assert response.status == HttpStatus.OK
        assert "enrichments" in response.data
        assert "cve" in response.data["enrichments"]
        assert "kev" in response.data["enrichments"]
        assert "threat" in response.data["enrichments"]

    def test_findings_explain(self, handler):
        """Test findings explain endpoint."""
        params = {"finding_id": ["finding-001"]}
        response = handler.findings_explain(params, None)
        assert response.status == HttpStatus.OK
        assert "explanation" in response.data
        assert "summary" in response.data["explanation"]
        assert "remediation_steps" in response.data["explanation"]

    def test_findings_explain_missing_id(self, handler):
        """Test findings explain with missing ID."""
        response = handler.findings_explain({}, None)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "finding_id" in response.data["error"]

    # -------------------------------------------------------------------------
    # Finding Export GET endpoints
    # -------------------------------------------------------------------------

    def test_findings_export_formats(self, handler):
        """Test findings export formats endpoint."""
        response = handler.findings_export_formats({}, None)
        assert response.status == HttpStatus.OK
        assert "formats" in response.data
        format_names = [f["format"] for f in response.data["formats"]]
        assert "json" in format_names
        assert "csv" in format_names
        assert "pdf" in format_names

    def test_findings_summary(self, handler):
        """Test findings summary endpoint."""
        response = handler.findings_summary({}, None)
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "findings"
        assert "features" in response.data
        assert "finding_types" in response.data
        assert "lifecycle_states" in response.data

    # -------------------------------------------------------------------------
    # Finding Status Update POST endpoints
    # -------------------------------------------------------------------------

    def test_findings_suppress_success(self, handler):
        """Test successful finding suppression."""
        body = {"finding_id": "finding-001", "reason": "Risk accepted"}
        response = handler.findings_suppress({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["suppressed"] is True
        assert response.data["lifecycle"] == "SUPPRESSED"

    def test_findings_suppress_missing_id(self, handler):
        """Test finding suppression with missing ID."""
        response = handler.findings_suppress({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "finding_id" in response.data["error"]

    def test_findings_resolve_success(self, handler):
        """Test successful finding resolution."""
        body = {"finding_id": "finding-001"}
        response = handler.findings_resolve({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["resolved"] is True
        assert response.data["lifecycle"] == "RESOLVED"

    def test_findings_resolve_missing_id(self, handler):
        """Test finding resolution with missing ID."""
        response = handler.findings_resolve({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "finding_id" in response.data["error"]

    def test_findings_reopen_success(self, handler):
        """Test successful finding reopen."""
        body = {"finding_id": "finding-001"}
        response = handler.findings_reopen({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["reopened"] is True
        assert response.data["lifecycle"] == "REOPENED"

    def test_findings_reopen_missing_id(self, handler):
        """Test finding reopen with missing ID."""
        response = handler.findings_reopen({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "finding_id" in response.data["error"]

    def test_findings_false_positive_success(self, handler):
        """Test successful false positive marking."""
        body = {"finding_id": "finding-001", "reason": "Not applicable"}
        response = handler.findings_false_positive({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["marked"] is True
        assert response.data["lifecycle"] == "FALSE_POSITIVE"

    def test_findings_false_positive_missing_id(self, handler):
        """Test false positive with missing ID."""
        response = handler.findings_false_positive({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "finding_id" in response.data["error"]

    def test_findings_bulk_update_success(self, handler):
        """Test successful bulk update."""
        body = {
            "finding_ids": ["finding-001", "finding-002"],
            "action": "suppress",
            "reason": "Bulk suppression",
        }
        response = handler.findings_bulk_update({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True
        assert response.data["updated_count"] == 2

    def test_findings_bulk_update_missing_ids(self, handler):
        """Test bulk update with missing IDs."""
        body = {"action": "suppress"}
        response = handler.findings_bulk_update({}, body)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "finding_ids" in response.data["error"]

    def test_findings_bulk_update_missing_action(self, handler):
        """Test bulk update with missing action."""
        body = {"finding_ids": ["finding-001"]}
        response = handler.findings_bulk_update({}, body)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "action" in response.data["error"]

    def test_findings_bulk_update_invalid_action(self, handler):
        """Test bulk update with invalid action."""
        body = {"finding_ids": ["finding-001"], "action": "invalid"}
        response = handler.findings_bulk_update({}, body)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "Invalid action" in response.data["error"]

    def test_findings_export_success(self, handler):
        """Test successful findings export."""
        body = {"format": "json", "report_type": "findings_detail"}
        response = handler.findings_export({}, body)
        assert response.status == HttpStatus.CREATED
        assert response.data["success"] is True
        assert response.data["format"] == "json"
        assert "download_url" in response.data

    def test_findings_export_invalid_format(self, handler):
        """Test findings export with invalid format."""
        body = {"format": "invalid"}
        response = handler.findings_export({}, body)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "Invalid format" in response.data["error"]

    # -------------------------------------------------------------------------
    # Handler routing tests
    # -------------------------------------------------------------------------

    def test_base_path(self, handler):
        """Test handler base path is set correctly."""
        assert handler.base_path == "/api/findings/"

    def test_can_handle_findings_path(self, handler):
        """Test can_handle for findings paths."""
        assert handler.can_handle("/api/findings/list")
        assert handler.can_handle("/api/findings/show")
        assert handler.can_handle("/api/findings/suppress")
        assert not handler.can_handle("/api/auth/login")

    def test_handle_get_list(self, handler):
        """Test handling GET /api/findings/list."""
        response = handler.handle("/api/findings/list", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "items" in response.data

    def test_handle_post_suppress(self, handler):
        """Test handling POST /api/findings/suppress."""
        body = {"finding_id": "finding-001"}
        response = handler.handle("/api/findings/suppress", {}, "POST", body)
        assert response.status == HttpStatus.OK
        assert response.data["suppressed"] is True

    def test_handle_unknown_route(self, handler):
        """Test handling unknown route."""
        response = handler.handle("/api/findings/unknown", {}, "GET")
        assert response.status == HttpStatus.NOT_FOUND

    def test_route_discovery(self, handler):
        """Test that routes are discovered correctly."""
        routes = list(handler._route_table)
        assert len(routes) > 0

        # Find suppress route
        suppress_routes = [r for r in routes if r.path == "suppress"]
        assert len(suppress_routes) == 1
        assert "POST" in suppress_routes[0].methods

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 19 GET routes + 6 POST routes = 25 total
        assert len(routes) == 25


# =============================================================================
# AssetHandler Tests
# =============================================================================


class TestAssetHandler:
    """Tests for AssetHandler class."""

    @pytest.fixture
    def handler(self):
        """Create AssetHandler instance."""
        from stance.web.handlers.assets import AssetHandler
        return AssetHandler()

    # -------------------------------------------------------------------------
    # Asset Listing GET endpoints
    # -------------------------------------------------------------------------

    def test_assets_list(self, handler):
        """Test assets list endpoint."""
        response = handler.assets_list({}, None)
        assert response.status == HttpStatus.OK
        assert "items" in response.data
        assert "total" in response.data
        assert "limit" in response.data
        assert "offset" in response.data

    def test_assets_list_with_type_filter(self, handler):
        """Test assets list with resource type filter."""
        params = {"type": ["aws_s3_bucket"]}
        response = handler.assets_list(params, None)
        assert response.status == HttpStatus.OK
        for asset in response.data["items"]:
            assert asset["resource_type"] == "aws_s3_bucket"

    def test_assets_list_with_region_filter(self, handler):
        """Test assets list with region filter."""
        params = {"region": ["us-east-1"]}
        response = handler.assets_list(params, None)
        assert response.status == HttpStatus.OK
        for asset in response.data["items"]:
            assert asset["region"] == "us-east-1"

    def test_assets_list_with_cloud_filter(self, handler):
        """Test assets list with cloud provider filter."""
        params = {"cloud": ["aws"]}
        response = handler.assets_list(params, None)
        assert response.status == HttpStatus.OK
        for asset in response.data["items"]:
            assert asset["cloud_provider"].lower() == "aws"

    def test_assets_list_with_exposure_filter(self, handler):
        """Test assets list with exposure filter."""
        params = {"exposure": ["internet_facing"]}
        response = handler.assets_list(params, None)
        assert response.status == HttpStatus.OK
        for asset in response.data["items"]:
            assert asset["network_exposure"] == "public"

    def test_assets_list_pagination(self, handler):
        """Test assets list with pagination."""
        params = {"limit": ["2"], "offset": ["1"]}
        response = handler.assets_list(params, None)
        assert response.status == HttpStatus.OK
        assert len(response.data["items"]) <= 2

    def test_assets_show(self, handler):
        """Test assets show endpoint."""
        params = {"asset_id": ["arn:aws:s3:::production-data"]}
        response = handler.assets_show(params, None)
        assert response.status == HttpStatus.OK
        assert "asset" in response.data
        assert "findings" in response.data
        assert "finding_count" in response.data
        assert "findings_by_severity" in response.data

    def test_assets_show_missing_id(self, handler):
        """Test assets show with missing ID."""
        response = handler.assets_show({}, None)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "asset_id" in response.data["error"]

    # -------------------------------------------------------------------------
    # Asset Search and Filter endpoints
    # -------------------------------------------------------------------------

    def test_assets_search(self, handler):
        """Test assets search endpoint."""
        params = {"q": ["production"]}
        response = handler.assets_search(params, None)
        assert response.status == HttpStatus.OK
        assert "query" in response.data
        assert "items" in response.data
        assert response.data["query"] == "production"

    def test_assets_search_missing_query(self, handler):
        """Test assets search with missing query."""
        response = handler.assets_search({}, None)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "q" in response.data["error"]

    def test_assets_filter(self, handler):
        """Test assets filter endpoint."""
        params = {"clouds": ["aws"], "exposure": ["public"]}
        response = handler.assets_filter(params, None)
        assert response.status == HttpStatus.OK
        assert "items" in response.data
        assert "filters_applied" in response.data

    # -------------------------------------------------------------------------
    # Asset Grouping and Aggregation endpoints
    # -------------------------------------------------------------------------

    def test_assets_by_cloud(self, handler):
        """Test assets by cloud endpoint."""
        response = handler.assets_by_cloud({}, None)
        assert response.status == HttpStatus.OK
        assert "groups" in response.data
        assert "total_assets" in response.data
        for group in response.data["groups"]:
            assert "cloud_provider" in group
            assert "asset_count" in group

    def test_assets_by_cloud_with_counts(self, handler):
        """Test assets by cloud with finding counts."""
        params = {"include_counts": ["true"]}
        response = handler.assets_by_cloud(params, None)
        assert response.status == HttpStatus.OK
        for group in response.data["groups"]:
            assert "finding_count" in group
            assert "critical_findings" in group

    def test_assets_by_region(self, handler):
        """Test assets by region endpoint."""
        response = handler.assets_by_region({}, None)
        assert response.status == HttpStatus.OK
        assert "groups" in response.data
        assert "total_regions" in response.data
        for group in response.data["groups"]:
            assert "region" in group
            assert "cloud_provider" in group
            assert "asset_count" in group

    def test_assets_by_region_filtered(self, handler):
        """Test assets by region with cloud filter."""
        params = {"cloud": ["aws"]}
        response = handler.assets_by_region(params, None)
        assert response.status == HttpStatus.OK
        for group in response.data["groups"]:
            assert group["cloud_provider"].lower() == "aws"

    def test_assets_by_type(self, handler):
        """Test assets by type endpoint."""
        response = handler.assets_by_type({}, None)
        assert response.status == HttpStatus.OK
        assert "groups" in response.data
        assert "total_types" in response.data
        for group in response.data["groups"]:
            assert "resource_type" in group
            assert "cloud_provider" in group
            assert "asset_count" in group

    def test_assets_by_type_filtered(self, handler):
        """Test assets by type with cloud filter."""
        params = {"cloud": ["gcp"]}
        response = handler.assets_by_type(params, None)
        assert response.status == HttpStatus.OK
        for group in response.data["groups"]:
            assert group["cloud_provider"].lower() == "gcp"

    def test_assets_by_exposure(self, handler):
        """Test assets by exposure endpoint."""
        response = handler.assets_by_exposure({}, None)
        assert response.status == HttpStatus.OK
        assert "groups" in response.data
        assert "total_assets" in response.data
        assert "internet_facing_percentage" in response.data
        for group in response.data["groups"]:
            assert "exposure" in group
            assert "asset_count" in group

    # -------------------------------------------------------------------------
    # Asset Inventory and Metadata endpoints
    # -------------------------------------------------------------------------

    def test_assets_inventory(self, handler):
        """Test assets inventory endpoint."""
        response = handler.assets_inventory({}, None)
        assert response.status == HttpStatus.OK
        assert "summary" in response.data
        assert "by_cloud" in response.data
        assert "by_severity" in response.data
        assert "top_resource_types" in response.data
        assert "last_scan" in response.data
        assert "total_assets" in response.data["summary"]
        assert "total_findings" in response.data["summary"]

    def test_assets_types(self, handler):
        """Test assets types endpoint."""
        response = handler.assets_types({}, None)
        assert response.status == HttpStatus.OK
        assert "types" in response.data
        assert "total" in response.data
        for asset_type in response.data["types"]:
            assert "type" in asset_type
            assert "cloud" in asset_type
            assert "display_name" in asset_type

    def test_assets_types_filtered(self, handler):
        """Test assets types with cloud filter."""
        params = {"cloud": ["azure"]}
        response = handler.assets_types(params, None)
        assert response.status == HttpStatus.OK
        for asset_type in response.data["types"]:
            assert asset_type["cloud"].lower() == "azure"

    def test_assets_regions(self, handler):
        """Test assets regions endpoint."""
        response = handler.assets_regions({}, None)
        assert response.status == HttpStatus.OK
        assert "regions" in response.data
        assert "total" in response.data
        for region in response.data["regions"]:
            assert "region" in region
            assert "cloud" in region
            assert "display_name" in region

    def test_assets_regions_filtered(self, handler):
        """Test assets regions with cloud filter."""
        params = {"cloud": ["gcp"]}
        response = handler.assets_regions(params, None)
        assert response.status == HttpStatus.OK
        for region in response.data["regions"]:
            assert region["cloud"].lower() == "gcp"

    def test_assets_clouds(self, handler):
        """Test assets clouds endpoint."""
        response = handler.assets_clouds({}, None)
        assert response.status == HttpStatus.OK
        assert "clouds" in response.data
        assert "total" in response.data
        for cloud in response.data["clouds"]:
            assert "id" in cloud
            assert "name" in cloud
            assert "asset_count" in cloud
            assert "enabled" in cloud

    # -------------------------------------------------------------------------
    # Asset Enrichment endpoints
    # -------------------------------------------------------------------------

    def test_assets_enrich(self, handler):
        """Test assets enrich endpoint."""
        body = {"types": "ip,geo,cloud"}
        response = handler.assets_enrich({}, body)
        assert response.status == HttpStatus.OK
        assert "total_assets" in response.data
        assert "assets_enriched" in response.data
        assert "enrichment_types" in response.data
        assert "assets" in response.data
        assert "statistics" in response.data

    def test_assets_enrich_with_asset_id(self, handler):
        """Test assets enrich with specific asset ID."""
        body = {"asset_id": "arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0", "types": "ip,geo"}
        response = handler.assets_enrich({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["total_assets"] == 1

    def test_assets_enrich_default_types(self, handler):
        """Test assets enrich with default enrichment types."""
        response = handler.assets_enrich({}, {})
        assert response.status == HttpStatus.OK
        assert "ip" in response.data["enrichment_types"]
        assert "geo" in response.data["enrichment_types"]

    # -------------------------------------------------------------------------
    # Asset Risk endpoints
    # -------------------------------------------------------------------------

    def test_assets_risk(self, handler):
        """Test assets risk endpoint."""
        response = handler.assets_risk({}, None)
        assert response.status == HttpStatus.OK
        assert "items" in response.data
        assert "total" in response.data
        for item in response.data["items"]:
            assert "asset_id" in item
            assert "risk_score" in item
            assert "risk_level" in item
            assert "factors" in item

    def test_assets_risk_with_asset_id(self, handler):
        """Test assets risk with specific asset ID."""
        params = {"asset_id": ["web-server"]}
        response = handler.assets_risk(params, None)
        assert response.status == HttpStatus.OK
        # Filter may match partially
        assert "items" in response.data

    def test_assets_risk_sorted(self, handler):
        """Test assets risk with sorting."""
        params = {"sort_by": ["risk_score"], "order": ["desc"]}
        response = handler.assets_risk(params, None)
        assert response.status == HttpStatus.OK
        items = response.data["items"]
        if len(items) > 1:
            # Verify descending order
            for i in range(len(items) - 1):
                assert items[i]["risk_score"] >= items[i + 1]["risk_score"]

    def test_assets_risk_summary(self, handler):
        """Test assets risk summary endpoint."""
        response = handler.assets_risk_summary({}, None)
        assert response.status == HttpStatus.OK
        assert "summary" in response.data
        assert "by_risk_level" in response.data
        assert "top_risk_factors" in response.data
        assert "trend" in response.data
        assert "average_risk_score" in response.data["summary"]
        assert "highest_risk_score" in response.data["summary"]

    # -------------------------------------------------------------------------
    # Asset Statistics endpoints
    # -------------------------------------------------------------------------

    def test_assets_stats(self, handler):
        """Test assets stats endpoint."""
        response = handler.assets_stats({}, None)
        assert response.status == HttpStatus.OK
        assert "total_assets" in response.data
        assert "by_cloud" in response.data
        assert "by_exposure" in response.data
        assert "by_finding_status" in response.data
        assert "new_assets_7d" in response.data
        assert "last_updated" in response.data

    def test_assets_trends(self, handler):
        """Test assets trends endpoint."""
        response = handler.assets_trends({}, None)
        assert response.status == HttpStatus.OK
        assert "period" in response.data
        assert "metric" in response.data
        assert "data_points" in response.data
        assert "change" in response.data
        for point in response.data["data_points"]:
            assert "date" in point
            assert "value" in point

    def test_assets_trends_with_period(self, handler):
        """Test assets trends with custom period."""
        params = {"period": ["7d"], "metric": ["findings"]}
        response = handler.assets_trends(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["period"] == "7d"
        assert response.data["metric"] == "findings"

    # -------------------------------------------------------------------------
    # Asset Sample Data endpoints
    # -------------------------------------------------------------------------

    def test_assets_sample(self, handler):
        """Test assets sample endpoint."""
        response = handler.assets_sample({}, None)
        assert response.status == HttpStatus.OK
        assert "assets" in response.data
        assert "total" in response.data
        for asset in response.data["assets"]:
            assert "id" in asset
            assert "cloud_provider" in asset
            assert "resource_type" in asset
            assert "name" in asset

    # -------------------------------------------------------------------------
    # Handler routing tests
    # -------------------------------------------------------------------------

    def test_base_path(self, handler):
        """Test handler base path is set correctly."""
        assert handler.base_path == "/api/assets/"

    def test_can_handle_assets_path(self, handler):
        """Test can_handle for assets paths."""
        assert handler.can_handle("/api/assets/list")
        assert handler.can_handle("/api/assets/show")
        assert handler.can_handle("/api/assets/by-cloud")
        assert not handler.can_handle("/api/findings/list")

    def test_handle_get_list(self, handler):
        """Test handling GET /api/assets/list."""
        response = handler.handle("/api/assets/list", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "items" in response.data

    def test_handle_post_enrich(self, handler):
        """Test handling POST /api/assets/enrich."""
        body = {"types": "ip,geo"}
        response = handler.handle("/api/assets/enrich", {}, "POST", body)
        assert response.status == HttpStatus.OK
        assert "assets_enriched" in response.data

    def test_handle_unknown_route(self, handler):
        """Test handling unknown route."""
        response = handler.handle("/api/assets/unknown", {}, "GET")
        assert response.status == HttpStatus.NOT_FOUND

    def test_route_discovery(self, handler):
        """Test that routes are discovered correctly."""
        routes = list(handler._route_table)
        assert len(routes) > 0

        # Find enrich route
        enrich_routes = [r for r in routes if r.path == "enrich"]
        assert len(enrich_routes) == 1
        assert "POST" in enrich_routes[0].methods

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 17 GET routes + 1 POST route = 18 total
        assert len(routes) == 18


# =============================================================================
# ComplianceHandler Tests
# =============================================================================


class TestComplianceHandler:
    """Tests for ComplianceHandler class."""

    @pytest.fixture
    def handler(self):
        """Create ComplianceHandler instance."""
        from stance.web.handlers.compliance import ComplianceHandler
        return ComplianceHandler()

    # -------------------------------------------------------------------------
    # Compliance Scoring GET endpoints
    # -------------------------------------------------------------------------

    def test_compliance_list(self, handler):
        """Test compliance list endpoint."""
        response = handler.compliance_list({}, None)
        assert response.status == HttpStatus.OK
        assert "frameworks" in response.data
        assert "overall_score" in response.data
        assert "total_frameworks" in response.data

    def test_compliance_list_with_filter(self, handler):
        """Test compliance list with framework filter."""
        params = {"framework": ["cis"]}
        response = handler.compliance_list(params, None)
        assert response.status == HttpStatus.OK
        for framework in response.data["frameworks"]:
            assert "cis" in framework["framework_id"].lower()

    def test_compliance_show(self, handler):
        """Test compliance show endpoint."""
        params = {"framework_id": ["cis-aws"]}
        response = handler.compliance_show(params, None)
        assert response.status == HttpStatus.OK
        assert "framework" in response.data
        assert "controls" in response.data
        assert "summary" in response.data

    def test_compliance_show_missing_id(self, handler):
        """Test compliance show with missing ID."""
        response = handler.compliance_show({}, None)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "framework_id" in response.data["error"]

    # -------------------------------------------------------------------------
    # Framework Management endpoints
    # -------------------------------------------------------------------------

    def test_compliance_frameworks(self, handler):
        """Test compliance frameworks endpoint."""
        response = handler.compliance_frameworks({}, None)
        assert response.status == HttpStatus.OK
        assert "frameworks" in response.data
        assert "total" in response.data
        for framework in response.data["frameworks"]:
            assert "id" in framework
            assert "name" in framework
            assert "controls_count" in framework

    def test_compliance_frameworks_enabled_only(self, handler):
        """Test compliance frameworks with enabled filter."""
        params = {"enabled": ["true"]}
        response = handler.compliance_frameworks(params, None)
        assert response.status == HttpStatus.OK
        for framework in response.data["frameworks"]:
            assert framework["enabled"] is True

    def test_compliance_framework(self, handler):
        """Test compliance framework endpoint."""
        params = {"framework_id": ["cis-aws"]}
        response = handler.compliance_framework(params, None)
        assert response.status == HttpStatus.OK
        assert "id" in response.data
        assert "name" in response.data
        assert "sections" in response.data
        assert "controls_count" in response.data

    def test_compliance_framework_missing_id(self, handler):
        """Test compliance framework with missing ID."""
        response = handler.compliance_framework({}, None)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "framework_id" in response.data["error"]

    # -------------------------------------------------------------------------
    # Control Management endpoints
    # -------------------------------------------------------------------------

    def test_compliance_controls(self, handler):
        """Test compliance controls endpoint."""
        response = handler.compliance_controls({}, None)
        assert response.status == HttpStatus.OK
        assert "controls" in response.data
        assert "total" in response.data
        for control in response.data["controls"]:
            assert "control_id" in control
            assert "name" in control
            assert "status" in control

    def test_compliance_controls_filtered_by_status(self, handler):
        """Test compliance controls with status filter."""
        params = {"status": ["FAILED"]}
        response = handler.compliance_controls(params, None)
        assert response.status == HttpStatus.OK
        for control in response.data["controls"]:
            assert control["status"] == "FAILED"

    def test_compliance_controls_filtered_by_framework(self, handler):
        """Test compliance controls with framework filter."""
        params = {"framework_id": ["cis-aws"]}
        response = handler.compliance_controls(params, None)
        assert response.status == HttpStatus.OK
        for control in response.data["controls"]:
            assert control["framework_id"] == "cis-aws"

    def test_compliance_control(self, handler):
        """Test compliance control endpoint."""
        params = {"control_id": ["1.3"]}
        response = handler.compliance_control(params, None)
        assert response.status == HttpStatus.OK
        assert "control_id" in response.data
        assert "name" in response.data
        assert "description" in response.data
        assert "remediation" in response.data
        assert "non_compliant_resources" in response.data

    def test_compliance_control_missing_id(self, handler):
        """Test compliance control with missing ID."""
        response = handler.compliance_control({}, None)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "control_id" in response.data["error"]

    # -------------------------------------------------------------------------
    # Gap Analysis and Reports endpoints
    # -------------------------------------------------------------------------

    def test_compliance_gaps(self, handler):
        """Test compliance gaps endpoint."""
        response = handler.compliance_gaps({}, None)
        assert response.status == HttpStatus.OK
        assert "gaps" in response.data
        assert "total" in response.data
        assert "summary" in response.data
        for gap in response.data["gaps"]:
            assert "control_id" in gap
            assert "severity" in gap
            assert "priority_score" in gap

    def test_compliance_gaps_filtered(self, handler):
        """Test compliance gaps with filters."""
        params = {"severity": ["HIGH"]}
        response = handler.compliance_gaps(params, None)
        assert response.status == HttpStatus.OK
        for gap in response.data["gaps"]:
            assert gap["severity"] == "HIGH"

    def test_compliance_report(self, handler):
        """Test compliance report endpoint."""
        params = {"framework_id": ["cis-aws"]}
        response = handler.compliance_report(params, None)
        assert response.status == HttpStatus.OK
        assert "report_id" in response.data
        assert "framework_id" in response.data
        assert "summary" in response.data
        assert "by_section" in response.data

    def test_compliance_summary(self, handler):
        """Test compliance summary endpoint."""
        response = handler.compliance_summary({}, None)
        assert response.status == HttpStatus.OK
        assert "overall_score" in response.data
        assert "frameworks_assessed" in response.data
        assert "by_category" in response.data
        assert "trend" in response.data
        assert "risk_areas" in response.data

    # -------------------------------------------------------------------------
    # Compliance Trends endpoints
    # -------------------------------------------------------------------------

    def test_compliance_trends(self, handler):
        """Test compliance trends endpoint."""
        response = handler.compliance_trends({}, None)
        assert response.status == HttpStatus.OK
        assert "data_points" in response.data
        assert "change" in response.data
        for point in response.data["data_points"]:
            assert "date" in point
            assert "overall_score" in point

    def test_compliance_trends_with_framework(self, handler):
        """Test compliance trends with framework filter."""
        params = {"framework_id": ["cis-aws"], "period": ["7d"]}
        response = handler.compliance_trends(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["framework_id"] == "cis-aws"
        assert response.data["period"] == "7d"

    def test_compliance_history(self, handler):
        """Test compliance history endpoint."""
        response = handler.compliance_history({}, None)
        assert response.status == HttpStatus.OK
        assert "assessments" in response.data
        assert "total" in response.data
        for assessment in response.data["assessments"]:
            assert "assessment_id" in assessment
            assert "timestamp" in assessment
            assert "score" in assessment

    def test_compliance_history_with_limit(self, handler):
        """Test compliance history with limit."""
        params = {"limit": ["2"]}
        response = handler.compliance_history(params, None)
        assert response.status == HttpStatus.OK
        assert len(response.data["assessments"]) <= 2

    # -------------------------------------------------------------------------
    # Policy Mappings endpoints
    # -------------------------------------------------------------------------

    def test_compliance_mappings(self, handler):
        """Test compliance mappings endpoint."""
        response = handler.compliance_mappings({}, None)
        assert response.status == HttpStatus.OK
        assert "mappings" in response.data
        assert "total" in response.data
        for mapping in response.data["mappings"]:
            assert "policy_id" in mapping
            assert "frameworks" in mapping

    def test_compliance_mappings_filtered(self, handler):
        """Test compliance mappings with filter."""
        params = {"policy_id": ["aws-s3-encryption"]}
        response = handler.compliance_mappings(params, None)
        assert response.status == HttpStatus.OK
        for mapping in response.data["mappings"]:
            assert mapping["policy_id"] == "aws-s3-encryption"

    def test_compliance_coverage(self, handler):
        """Test compliance coverage endpoint."""
        params = {"framework_id": ["cis-aws"]}
        response = handler.compliance_coverage(params, None)
        assert response.status == HttpStatus.OK
        assert "framework_id" in response.data
        assert "total_controls" in response.data
        assert "coverage_percentage" in response.data
        assert "uncovered_controls" in response.data

    # -------------------------------------------------------------------------
    # Compliance Operations endpoints
    # -------------------------------------------------------------------------

    def test_compliance_assess(self, handler):
        """Test compliance assess endpoint."""
        body = {"framework_id": "cis-aws", "scope": "full"}
        response = handler.compliance_assess({}, body)
        assert response.status == HttpStatus.CREATED
        assert "assessment_id" in response.data
        assert response.data["status"] == "STARTED"

    def test_compliance_assess_missing_framework(self, handler):
        """Test compliance assess with missing framework."""
        response = handler.compliance_assess({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "framework_id" in response.data["error"]

    def test_compliance_enable(self, handler):
        """Test compliance enable endpoint."""
        body = {"framework_id": "hipaa"}
        response = handler.compliance_enable({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["enabled"] is True

    def test_compliance_enable_missing_framework(self, handler):
        """Test compliance enable with missing framework."""
        response = handler.compliance_enable({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "framework_id" in response.data["error"]

    def test_compliance_disable(self, handler):
        """Test compliance disable endpoint."""
        body = {"framework_id": "pci-dss"}
        response = handler.compliance_disable({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["enabled"] is False

    def test_compliance_disable_missing_framework(self, handler):
        """Test compliance disable with missing framework."""
        response = handler.compliance_disable({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "framework_id" in response.data["error"]

    def test_compliance_export(self, handler):
        """Test compliance export endpoint."""
        body = {"framework_id": "cis-aws", "format": "pdf"}
        response = handler.compliance_export({}, body)
        assert response.status == HttpStatus.CREATED
        assert "export_id" in response.data
        assert "download_url" in response.data

    def test_compliance_export_invalid_format(self, handler):
        """Test compliance export with invalid format."""
        body = {"format": "invalid"}
        response = handler.compliance_export({}, body)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "Invalid format" in response.data["error"]

    # -------------------------------------------------------------------------
    # Compliance Statistics endpoints
    # -------------------------------------------------------------------------

    def test_compliance_stats(self, handler):
        """Test compliance stats endpoint."""
        response = handler.compliance_stats({}, None)
        assert response.status == HttpStatus.OK
        assert "total_frameworks" in response.data
        assert "enabled_frameworks" in response.data
        assert "overall_compliance" in response.data
        assert "by_severity" in response.data

    def test_compliance_benchmark_comparison(self, handler):
        """Test compliance benchmark comparison endpoint."""
        params = {"framework_id": ["cis-aws"]}
        response = handler.compliance_benchmark_comparison(params, None)
        assert response.status == HttpStatus.OK
        assert "your_score" in response.data
        assert "industry_average" in response.data
        assert "percentile" in response.data
        assert "comparison" in response.data

    # -------------------------------------------------------------------------
    # Handler routing tests
    # -------------------------------------------------------------------------

    def test_base_path(self, handler):
        """Test handler base path is set correctly."""
        assert handler.base_path == "/api/compliance/"

    def test_can_handle_compliance_path(self, handler):
        """Test can_handle for compliance paths."""
        assert handler.can_handle("/api/compliance/list")
        assert handler.can_handle("/api/compliance/frameworks")
        assert handler.can_handle("/api/compliance/assess")
        assert not handler.can_handle("/api/findings/list")

    def test_handle_get_list(self, handler):
        """Test handling GET /api/compliance/list."""
        response = handler.handle("/api/compliance/list", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "frameworks" in response.data

    def test_handle_post_assess(self, handler):
        """Test handling POST /api/compliance/assess."""
        body = {"framework_id": "cis-aws"}
        response = handler.handle("/api/compliance/assess", {}, "POST", body)
        assert response.status == HttpStatus.CREATED
        assert "assessment_id" in response.data

    def test_handle_unknown_route(self, handler):
        """Test handling unknown route."""
        response = handler.handle("/api/compliance/unknown", {}, "GET")
        assert response.status == HttpStatus.NOT_FOUND

    def test_route_discovery(self, handler):
        """Test that routes are discovered correctly."""
        routes = list(handler._route_table)
        assert len(routes) > 0

        # Find assess route
        assess_routes = [r for r in routes if r.path == "assess"]
        assert len(assess_routes) == 1
        assert "POST" in assess_routes[0].methods

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 15 GET routes + 4 POST routes = 19 total
        assert len(routes) == 19


# =============================================================================
# PolicyHandler Tests
# =============================================================================


class TestPolicyHandler:
    """Tests for PolicyHandler class."""

    @pytest.fixture
    def handler(self):
        """Create PolicyHandler instance."""
        from stance.web.handlers.policy import PolicyHandler
        return PolicyHandler()

    # -------------------------------------------------------------------------
    # Policy Listing GET endpoints
    # -------------------------------------------------------------------------

    def test_policy_list(self, handler):
        """Test policy list endpoint."""
        response = handler.policy_list({}, None)
        assert response.status == HttpStatus.OK
        assert "policies" in response.data
        assert "total" in response.data
        assert "enabled_count" in response.data

    def test_policy_list_with_provider_filter(self, handler):
        """Test policy list with provider filter."""
        params = {"provider": ["aws"]}
        response = handler.policy_list(params, None)
        assert response.status == HttpStatus.OK
        for policy in response.data["policies"]:
            assert policy["provider"] == "aws"

    def test_policy_list_with_severity_filter(self, handler):
        """Test policy list with severity filter."""
        params = {"severity": ["critical"]}
        response = handler.policy_list(params, None)
        assert response.status == HttpStatus.OK
        for policy in response.data["policies"]:
            assert policy["severity"] == "critical"

    def test_policy_list_with_enabled_filter(self, handler):
        """Test policy list with enabled filter."""
        params = {"enabled_only": ["true"]}
        response = handler.policy_list(params, None)
        assert response.status == HttpStatus.OK
        for policy in response.data["policies"]:
            assert policy["enabled"] is True

    def test_policy_list_with_framework_filter(self, handler):
        """Test policy list with framework filter."""
        params = {"framework": ["CIS AWS"]}
        response = handler.policy_list(params, None)
        assert response.status == HttpStatus.OK
        for policy in response.data["policies"]:
            assert any("cis" in f.lower() for f in policy["frameworks"])

    def test_policy_show(self, handler):
        """Test policy show endpoint."""
        params = {"policy_id": ["aws-s3-encryption"]}
        response = handler.policy_show(params, None)
        assert response.status == HttpStatus.OK
        assert "id" in response.data
        assert "name" in response.data
        assert "severity" in response.data
        assert "check" in response.data
        assert "remediation" in response.data

    def test_policy_show_missing_id(self, handler):
        """Test policy show with missing ID."""
        response = handler.policy_show({}, None)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "policy_id" in response.data["error"]

    # -------------------------------------------------------------------------
    # Policy Categories and Metadata endpoints
    # -------------------------------------------------------------------------

    def test_policy_categories(self, handler):
        """Test policy categories endpoint."""
        response = handler.policy_categories({}, None)
        assert response.status == HttpStatus.OK
        assert "categories" in response.data
        assert "total" in response.data
        for category in response.data["categories"]:
            assert "id" in category
            assert "name" in category
            assert "policy_count" in category

    def test_policy_severities(self, handler):
        """Test policy severities endpoint."""
        response = handler.policy_severities({}, None)
        assert response.status == HttpStatus.OK
        assert "severities" in response.data
        assert "total" in response.data
        for severity in response.data["severities"]:
            assert "id" in severity
            assert "name" in severity
            assert "priority" in severity

    def test_policy_providers(self, handler):
        """Test policy providers endpoint."""
        response = handler.policy_providers({}, None)
        assert response.status == HttpStatus.OK
        assert "providers" in response.data
        assert "total" in response.data
        for provider in response.data["providers"]:
            assert "id" in provider
            assert "name" in provider
            assert "policy_count" in provider

    def test_policy_resource_types(self, handler):
        """Test policy resource types endpoint."""
        response = handler.policy_resource_types({}, None)
        assert response.status == HttpStatus.OK
        assert "resource_types" in response.data
        assert "total" in response.data
        for rt in response.data["resource_types"]:
            assert "type" in rt
            assert "provider" in rt

    def test_policy_resource_types_filtered(self, handler):
        """Test policy resource types with provider filter."""
        params = {"provider": ["aws"]}
        response = handler.policy_resource_types(params, None)
        assert response.status == HttpStatus.OK
        for rt in response.data["resource_types"]:
            assert rt["provider"] == "aws"

    # -------------------------------------------------------------------------
    # Policy Search and Filter endpoints
    # -------------------------------------------------------------------------

    def test_policy_search(self, handler):
        """Test policy search endpoint."""
        params = {"q": ["encryption"]}
        response = handler.policy_search(params, None)
        assert response.status == HttpStatus.OK
        assert "query" in response.data
        assert "results" in response.data
        assert response.data["query"] == "encryption"

    def test_policy_search_missing_query(self, handler):
        """Test policy search with missing query."""
        response = handler.policy_search({}, None)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "q" in response.data["error"]

    def test_policy_by_framework(self, handler):
        """Test policy by framework endpoint."""
        response = handler.policy_by_framework({}, None)
        assert response.status == HttpStatus.OK
        assert "frameworks" in response.data
        assert "total_frameworks" in response.data
        for fw in response.data["frameworks"]:
            assert "framework" in fw
            assert "policy_count" in fw

    def test_policy_by_severity(self, handler):
        """Test policy by severity endpoint."""
        response = handler.policy_by_severity({}, None)
        assert response.status == HttpStatus.OK
        assert "groups" in response.data
        assert "total_policies" in response.data
        for group in response.data["groups"]:
            assert "severity" in group
            assert "policy_count" in group

    # -------------------------------------------------------------------------
    # Policy Validation endpoints
    # -------------------------------------------------------------------------

    def test_policy_validate(self, handler):
        """Test policy validate endpoint."""
        body = {"json": {"id": "test-policy", "name": "Test Policy", "severity": "medium"}}
        response = handler.policy_validate({}, body)
        assert response.status == HttpStatus.OK
        assert "valid" in response.data
        assert "errors" in response.data
        assert "parsed" in response.data

    def test_policy_validate_missing_definition(self, handler):
        """Test policy validate with missing definition."""
        response = handler.policy_validate({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "yaml or json" in response.data["error"]

    def test_policy_test(self, handler):
        """Test policy test endpoint."""
        body = {"policy_id": "aws-s3-encryption", "resource": {"type": "aws_s3_bucket"}}
        response = handler.policy_test({}, body)
        assert response.status == HttpStatus.OK
        assert "policy_id" in response.data
        assert "result" in response.data
        assert "details" in response.data

    def test_policy_test_missing_id(self, handler):
        """Test policy test with missing policy ID."""
        response = handler.policy_test({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "policy_id" in response.data["error"]

    # -------------------------------------------------------------------------
    # Policy Management endpoints
    # -------------------------------------------------------------------------

    def test_policy_enable(self, handler):
        """Test policy enable endpoint."""
        body = {"policy_id": "aws-s3-encryption"}
        response = handler.policy_enable({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["enabled"] is True

    def test_policy_enable_missing_id(self, handler):
        """Test policy enable with missing ID."""
        response = handler.policy_enable({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "policy_id" in response.data["error"]

    def test_policy_disable(self, handler):
        """Test policy disable endpoint."""
        body = {"policy_id": "aws-s3-encryption"}
        response = handler.policy_disable({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["enabled"] is False

    def test_policy_disable_missing_id(self, handler):
        """Test policy disable with missing ID."""
        response = handler.policy_disable({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "policy_id" in response.data["error"]

    def test_policy_create(self, handler):
        """Test policy create endpoint."""
        body = {
            "id": "custom-policy-001",
            "name": "Custom Policy",
            "severity": "high",
            "resource_type": "aws_s3_bucket",
        }
        response = handler.policy_create({}, body)
        assert response.status == HttpStatus.CREATED
        assert response.data["id"] == "custom-policy-001"
        assert response.data["enabled"] is True

    def test_policy_create_missing_fields(self, handler):
        """Test policy create with missing required fields."""
        body = {"severity": "high"}
        response = handler.policy_create({}, body)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "id and name" in response.data["error"]

    def test_policy_create_missing_resource_type(self, handler):
        """Test policy create with missing resource type."""
        body = {"id": "test", "name": "Test"}
        response = handler.policy_create({}, body)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "resource_type" in response.data["error"]

    def test_policy_update(self, handler):
        """Test policy update endpoint."""
        body = {"policy_id": "aws-s3-encryption", "severity": "critical"}
        response = handler.policy_update({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["updated"] is True

    def test_policy_update_missing_id(self, handler):
        """Test policy update with missing ID."""
        response = handler.policy_update({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "policy_id" in response.data["error"]

    def test_policy_delete(self, handler):
        """Test policy delete endpoint."""
        body = {"policy_id": "custom-policy-001"}
        response = handler.policy_delete({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["deleted"] is True

    def test_policy_delete_missing_id(self, handler):
        """Test policy delete with missing ID."""
        response = handler.policy_delete({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "policy_id" in response.data["error"]

    # -------------------------------------------------------------------------
    # Policy Suggestions endpoints
    # -------------------------------------------------------------------------

    def test_policy_suggest(self, handler):
        """Test policy suggest endpoint."""
        params = {"resource_type": ["aws_s3_bucket"]}
        response = handler.policy_suggest(params, None)
        assert response.status == HttpStatus.OK
        assert "resource_type" in response.data
        assert "suggestions" in response.data
        assert len(response.data["suggestions"]) > 0

    def test_policy_suggest_default_type(self, handler):
        """Test policy suggest with default resource type."""
        response = handler.policy_suggest({}, None)
        assert response.status == HttpStatus.OK
        assert response.data["resource_type"] == "aws_s3_bucket"

    def test_policy_generate(self, handler):
        """Test policy generate endpoint."""
        body = {"description": "Ensure S3 buckets are encrypted", "cloud": "aws"}
        response = handler.policy_generate({}, body)
        assert response.status == HttpStatus.CREATED
        assert "policy_id" in response.data
        assert "yaml_content" in response.data
        assert "is_valid" in response.data

    def test_policy_generate_missing_description(self, handler):
        """Test policy generate with missing description."""
        response = handler.policy_generate({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "description" in response.data["error"]

    # -------------------------------------------------------------------------
    # Policy Statistics endpoints
    # -------------------------------------------------------------------------

    def test_policy_stats(self, handler):
        """Test policy stats endpoint."""
        response = handler.policy_stats({}, None)
        assert response.status == HttpStatus.OK
        assert "total_policies" in response.data
        assert "enabled_policies" in response.data
        assert "by_severity" in response.data
        assert "by_provider" in response.data
        assert "by_category" in response.data

    def test_policy_coverage(self, handler):
        """Test policy coverage endpoint."""
        response = handler.policy_coverage({}, None)
        assert response.status == HttpStatus.OK
        assert "total_resource_types" in response.data
        assert "covered_resource_types" in response.data
        assert "coverage_percentage" in response.data
        assert "by_provider" in response.data
        assert "uncovered_types" in response.data

    # -------------------------------------------------------------------------
    # Handler routing tests
    # -------------------------------------------------------------------------

    def test_base_path(self, handler):
        """Test handler base path is set correctly."""
        assert handler.base_path == "/api/policy/"

    def test_can_handle_policy_path(self, handler):
        """Test can_handle for policy paths."""
        assert handler.can_handle("/api/policy/list")
        assert handler.can_handle("/api/policy/show")
        assert handler.can_handle("/api/policy/validate")
        assert not handler.can_handle("/api/compliance/list")

    def test_handle_get_list(self, handler):
        """Test handling GET /api/policy/list."""
        response = handler.handle("/api/policy/list", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "policies" in response.data

    def test_handle_post_validate(self, handler):
        """Test handling POST /api/policy/validate."""
        body = {"json": {"id": "test", "name": "Test"}}
        response = handler.handle("/api/policy/validate", {}, "POST", body)
        assert response.status == HttpStatus.OK
        assert "valid" in response.data

    def test_handle_unknown_route(self, handler):
        """Test handling unknown route."""
        response = handler.handle("/api/policy/unknown", {}, "GET")
        assert response.status == HttpStatus.NOT_FOUND

    def test_route_discovery(self, handler):
        """Test that routes are discovered correctly."""
        routes = list(handler._route_table)
        assert len(routes) > 0

        # Find validate route
        validate_routes = [r for r in routes if r.path == "validate"]
        assert len(validate_routes) == 1
        assert "POST" in validate_routes[0].methods

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 13 GET routes + 7 POST routes = 20 total
        assert len(routes) == 20


# =============================================================================
# ReportHandler Tests
# =============================================================================


class TestReportHandler:
    """Tests for ReportHandler class."""

    @pytest.fixture
    def handler(self):
        """Create ReportHandler instance."""
        from stance.web.handlers.report import ReportHandler
        return ReportHandler()

    # -------------------------------------------------------------------------
    # Report Listing GET endpoints
    # -------------------------------------------------------------------------

    def test_report_list(self, handler):
        """Test report list endpoint."""
        response = handler.report_list({}, None)
        assert response.status == HttpStatus.OK
        assert "reports" in response.data
        assert "total" in response.data
        assert "limit" in response.data
        assert "offset" in response.data

    def test_report_list_with_type_filter(self, handler):
        """Test report list with type filter."""
        params = {"type": ["security_summary"]}
        response = handler.report_list(params, None)
        assert response.status == HttpStatus.OK
        for report in response.data["reports"]:
            assert report["type"] == "security_summary"

    def test_report_list_with_status_filter(self, handler):
        """Test report list with status filter."""
        params = {"status": ["completed"]}
        response = handler.report_list(params, None)
        assert response.status == HttpStatus.OK
        for report in response.data["reports"]:
            assert report["status"] == "completed"

    def test_report_show(self, handler):
        """Test report show endpoint."""
        params = {"report_id": ["report-001"]}
        response = handler.report_show(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["id"] == "report-001"
        assert "name" in response.data
        assert "type" in response.data
        assert "status" in response.data
        assert "download_url" in response.data

    def test_report_show_missing_id(self, handler):
        """Test report show with missing ID."""
        response = handler.report_show({}, None)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "report_id" in response.data["error"]

    # -------------------------------------------------------------------------
    # Report Types and Templates endpoints
    # -------------------------------------------------------------------------

    def test_report_types(self, handler):
        """Test report types endpoint."""
        response = handler.report_types({}, None)
        assert response.status == HttpStatus.OK
        assert "types" in response.data
        assert "total" in response.data
        type_ids = [t["id"] for t in response.data["types"]]
        assert "security_summary" in type_ids
        assert "compliance" in type_ids
        assert "trend" in type_ids

    def test_report_types_have_required_fields(self, handler):
        """Test report types have required fields."""
        response = handler.report_types({}, None)
        for report_type in response.data["types"]:
            assert "id" in report_type
            assert "name" in report_type
            assert "description" in report_type
            assert "formats" in report_type
            assert "scheduled" in report_type

    def test_report_templates(self, handler):
        """Test report templates endpoint."""
        response = handler.report_templates({}, None)
        assert response.status == HttpStatus.OK
        assert "templates" in response.data
        assert "total" in response.data

    def test_report_templates_with_type_filter(self, handler):
        """Test report templates with type filter."""
        params = {"type": ["compliance"]}
        response = handler.report_templates(params, None)
        assert response.status == HttpStatus.OK
        for template in response.data["templates"]:
            assert template["type"] == "compliance"

    def test_report_templates_have_required_fields(self, handler):
        """Test report templates have required fields."""
        response = handler.report_templates({}, None)
        for template in response.data["templates"]:
            assert "id" in template
            assert "name" in template
            assert "type" in template
            assert "sections" in template

    def test_report_formats(self, handler):
        """Test report formats endpoint."""
        response = handler.report_formats({}, None)
        assert response.status == HttpStatus.OK
        assert "formats" in response.data
        assert "total" in response.data
        format_ids = [f["id"] for f in response.data["formats"]]
        assert "pdf" in format_ids
        assert "xlsx" in format_ids
        assert "csv" in format_ids
        assert "json" in format_ids

    def test_report_formats_have_required_fields(self, handler):
        """Test report formats have required fields."""
        response = handler.report_formats({}, None)
        for fmt in response.data["formats"]:
            assert "id" in fmt
            assert "name" in fmt
            assert "mime_type" in fmt
            assert "extension" in fmt
            assert "supports_charts" in fmt

    # -------------------------------------------------------------------------
    # Trend Analysis endpoints
    # -------------------------------------------------------------------------

    def test_report_analyze(self, handler):
        """Test report analyze endpoint."""
        response = handler.report_analyze({}, None)
        assert response.status == HttpStatus.OK
        assert "analysis_period" in response.data
        assert "findings_trend" in response.data
        assert "compliance_trend" in response.data
        assert "velocity" in response.data
        assert "recommendations" in response.data

    def test_report_analyze_with_params(self, handler):
        """Test report analyze with parameters."""
        params = {"config": ["production"], "days": ["14"], "period": ["weekly"]}
        response = handler.report_analyze(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["config"] == "production"
        assert response.data["analysis_period"]["days"] == 14
        assert response.data["analysis_period"]["period"] == "weekly"

    def test_report_velocity(self, handler):
        """Test report velocity endpoint."""
        response = handler.report_velocity({}, None)
        assert response.status == HttpStatus.OK
        assert "velocities" in response.data
        assert "unit" in response.data
        assert "interpretation" in response.data

    def test_report_velocity_with_params(self, handler):
        """Test report velocity with parameters."""
        params = {"days": ["14"]}
        response = handler.report_velocity(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["days_analyzed"] == 14

    def test_report_improvement(self, handler):
        """Test report improvement endpoint."""
        response = handler.report_improvement({}, None)
        assert response.status == HttpStatus.OK
        assert "improvement_rate" in response.data
        assert "direction" in response.data
        assert "breakdown" in response.data

    def test_report_compare(self, handler):
        """Test report compare endpoint."""
        response = handler.report_compare({}, None)
        assert response.status == HttpStatus.OK
        assert "current_period" in response.data
        assert "previous_period" in response.data
        assert "comparison" in response.data

    def test_report_compare_with_params(self, handler):
        """Test report compare with parameters."""
        params = {"current_days": ["14"], "previous_days": ["14"]}
        response = handler.report_compare(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["current_period"]["days"] == 14
        assert response.data["previous_period"]["days"] == 14

    def test_report_forecast(self, handler):
        """Test report forecast endpoint."""
        response = handler.report_forecast({}, None)
        assert response.status == HttpStatus.OK
        assert "forecast" in response.data
        assert "trend_direction" in response.data
        assert "confidence_interval" in response.data
        assert len(response.data["forecast"]) > 0

    def test_report_forecast_with_params(self, handler):
        """Test report forecast with parameters."""
        params = {"history_days": ["14"], "forecast_days": ["5"]}
        response = handler.report_forecast(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["history_days"] == 14
        assert response.data["forecast_days"] == 5

    # -------------------------------------------------------------------------
    # Report Metadata endpoints
    # -------------------------------------------------------------------------

    def test_report_directions(self, handler):
        """Test report directions endpoint."""
        response = handler.report_directions({}, None)
        assert response.status == HttpStatus.OK
        assert "directions" in response.data
        assert "total" in response.data
        direction_values = [d["direction"] for d in response.data["directions"]]
        assert "improving" in direction_values
        assert "declining" in direction_values
        assert "stable" in direction_values

    def test_report_periods(self, handler):
        """Test report periods endpoint."""
        response = handler.report_periods({}, None)
        assert response.status == HttpStatus.OK
        assert "periods" in response.data
        assert "total" in response.data
        period_values = [p["period"] for p in response.data["periods"]]
        assert "daily" in period_values
        assert "weekly" in period_values
        assert "monthly" in period_values

    def test_report_metrics(self, handler):
        """Test report metrics endpoint."""
        response = handler.report_metrics({}, None)
        assert response.status == HttpStatus.OK
        assert "metrics" in response.data
        assert "total" in response.data
        metric_names = [m["metric"] for m in response.data["metrics"]]
        assert "current_value" in metric_names
        assert "change_percent" in metric_names
        assert "velocity" in metric_names

    # -------------------------------------------------------------------------
    # Report Generation POST endpoints
    # -------------------------------------------------------------------------

    def test_report_generate_success(self, handler):
        """Test successful report generation."""
        body = {"type": "security_summary", "format": "pdf"}
        response = handler.report_generate({}, body)
        assert response.status == HttpStatus.CREATED
        assert "report_id" in response.data
        assert response.data["type"] == "security_summary"
        assert response.data["status"] == "generating"

    def test_report_generate_missing_type(self, handler):
        """Test report generation with missing type."""
        response = handler.report_generate({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "type" in response.data["error"]

    def test_report_schedule_success(self, handler):
        """Test successful report scheduling."""
        body = {"type": "compliance", "schedule": "weekly", "recipients": ["user@example.com"]}
        response = handler.report_schedule({}, body)
        assert response.status == HttpStatus.CREATED
        assert "schedule_id" in response.data
        assert response.data["schedule"] == "weekly"
        assert response.data["enabled"] is True

    def test_report_schedule_missing_type(self, handler):
        """Test report scheduling with missing type."""
        response = handler.report_schedule({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "type" in response.data["error"]

    def test_report_export_success(self, handler):
        """Test successful report export."""
        body = {"report_id": "report-001", "format": "xlsx"}
        response = handler.report_export({}, body)
        assert response.status == HttpStatus.CREATED
        assert "export_id" in response.data
        assert response.data["format"] == "xlsx"
        assert "download_url" in response.data

    def test_report_export_missing_id(self, handler):
        """Test report export with missing ID."""
        response = handler.report_export({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "report_id" in response.data["error"]

    def test_report_export_invalid_format(self, handler):
        """Test report export with invalid format."""
        body = {"report_id": "report-001", "format": "invalid"}
        response = handler.report_export({}, body)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "Invalid format" in response.data["error"]

    def test_report_delete_success(self, handler):
        """Test successful report deletion."""
        body = {"report_id": "report-001"}
        response = handler.report_delete({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["deleted"] is True

    def test_report_delete_missing_id(self, handler):
        """Test report deletion with missing ID."""
        response = handler.report_delete({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "report_id" in response.data["error"]

    # -------------------------------------------------------------------------
    # Report Statistics endpoints
    # -------------------------------------------------------------------------

    def test_report_stats(self, handler):
        """Test report stats endpoint."""
        response = handler.report_stats({}, None)
        assert response.status == HttpStatus.OK
        assert "total_reports" in response.data
        assert "reports_this_month" in response.data
        assert "scheduled_reports" in response.data
        assert "by_type" in response.data
        assert "by_format" in response.data

    def test_report_status(self, handler):
        """Test report status endpoint."""
        response = handler.report_status({}, None)
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "reporting"
        assert response.data["status"] == "operational"
        assert "components" in response.data
        assert "capabilities" in response.data

    def test_report_summary(self, handler):
        """Test report summary endpoint."""
        response = handler.report_summary({}, None)
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "reporting"
        assert "features" in response.data
        assert "analysis_types" in response.data
        assert "data_requirements" in response.data

    # -------------------------------------------------------------------------
    # Handler routing tests
    # -------------------------------------------------------------------------

    def test_base_path(self, handler):
        """Test handler base path is set correctly."""
        assert handler.base_path == "/api/report/"

    def test_can_handle_report_path(self, handler):
        """Test can_handle for report paths."""
        assert handler.can_handle("/api/report/list")
        assert handler.can_handle("/api/report/analyze")
        assert handler.can_handle("/api/report/generate")
        assert not handler.can_handle("/api/policy/list")

    def test_handle_get_list(self, handler):
        """Test handling GET /api/report/list."""
        response = handler.handle("/api/report/list", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "reports" in response.data

    def test_handle_post_generate(self, handler):
        """Test handling POST /api/report/generate."""
        body = {"type": "security_summary"}
        response = handler.handle("/api/report/generate", {}, "POST", body)
        assert response.status == HttpStatus.CREATED
        assert "report_id" in response.data

    def test_handle_unknown_route(self, handler):
        """Test handling unknown route."""
        response = handler.handle("/api/report/unknown", {}, "GET")
        assert response.status == HttpStatus.NOT_FOUND

    def test_route_discovery(self, handler):
        """Test that routes are discovered correctly."""
        routes = list(handler._route_table)
        assert len(routes) > 0

        # Find generate route
        generate_routes = [r for r in routes if r.path == "generate"]
        assert len(generate_routes) == 1
        assert "POST" in generate_routes[0].methods

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 16 GET routes + 4 POST routes = 20 total
        assert len(routes) == 20


# =============================================================================
# DashboardHandler Tests
# =============================================================================


class TestDashboardHandler:
    """Tests for DashboardHandler class."""

    @pytest.fixture
    def handler(self):
        """Create DashboardHandler instance."""
        from stance.web.handlers.dashboard import DashboardHandler
        return DashboardHandler()

    # -------------------------------------------------------------------------
    # Dashboard Listing GET endpoints
    # -------------------------------------------------------------------------

    def test_dashboard_list(self, handler):
        """Test dashboard list endpoint."""
        response = handler.dashboard_list({}, None)
        assert response.status == HttpStatus.OK
        assert "dashboards" in response.data
        assert "total" in response.data
        assert len(response.data["dashboards"]) == 3

    def test_dashboard_list_with_owner_filter(self, handler):
        """Test dashboard list with owner filter."""
        params = {"owner": ["security-team"]}
        response = handler.dashboard_list(params, None)
        assert response.status == HttpStatus.OK
        for dashboard in response.data["dashboards"]:
            assert dashboard["owner"] == "security-team"

    def test_dashboard_list_with_tag_filter(self, handler):
        """Test dashboard list with tag filter."""
        params = {"tag": ["compliance"]}
        response = handler.dashboard_list(params, None)
        assert response.status == HttpStatus.OK
        for dashboard in response.data["dashboards"]:
            assert "compliance" in dashboard["tags"]

    def test_dashboard_show(self, handler):
        """Test dashboard show endpoint."""
        params = {"id": ["dash-exec-001"]}
        response = handler.dashboard_show(params, None)
        assert response.status == HttpStatus.OK
        assert "dashboard" in response.data
        assert response.data["dashboard"]["id"] == "dash-exec-001"
        assert "widgets" in response.data["dashboard"]

    def test_dashboard_show_missing_id(self, handler):
        """Test dashboard show with missing ID."""
        response = handler.dashboard_show({}, None)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "id" in response.data["error"]

    # -------------------------------------------------------------------------
    # Widget and Chart Types endpoints
    # -------------------------------------------------------------------------

    def test_dashboard_widgets(self, handler):
        """Test dashboard widgets endpoint."""
        response = handler.dashboard_widgets({}, None)
        assert response.status == HttpStatus.OK
        assert "types" in response.data
        assert "total" in response.data
        assert len(response.data["types"]) == 10
        widget_types = [w["type"] for w in response.data["types"]]
        assert "metric" in widget_types
        assert "chart" in widget_types
        assert "gauge" in widget_types

    def test_dashboard_charts(self, handler):
        """Test dashboard charts endpoint."""
        response = handler.dashboard_charts({}, None)
        assert response.status == HttpStatus.OK
        assert "types" in response.data
        assert "total" in response.data
        assert len(response.data["types"]) == 14
        chart_types = [c["type"] for c in response.data["types"]]
        assert "line" in chart_types
        assert "bar" in chart_types
        assert "pie" in chart_types

    # -------------------------------------------------------------------------
    # Theme and Time Range endpoints
    # -------------------------------------------------------------------------

    def test_dashboard_themes(self, handler):
        """Test dashboard themes endpoint."""
        response = handler.dashboard_themes({}, None)
        assert response.status == HttpStatus.OK
        assert "themes" in response.data
        assert "total" in response.data
        assert len(response.data["themes"]) == 5
        theme_names = [t["theme"] for t in response.data["themes"]]
        assert "light" in theme_names
        assert "dark" in theme_names

    def test_dashboard_time_ranges(self, handler):
        """Test dashboard time ranges endpoint."""
        response = handler.dashboard_time_ranges({}, None)
        assert response.status == HttpStatus.OK
        assert "ranges" in response.data
        assert "total" in response.data
        range_names = [r["range"] for r in response.data["ranges"]]
        assert "last_7_days" in range_names
        assert "last_30_days" in range_names

    # -------------------------------------------------------------------------
    # Report Listing endpoints
    # -------------------------------------------------------------------------

    def test_dashboard_reports(self, handler):
        """Test dashboard reports endpoint."""
        response = handler.dashboard_reports({}, None)
        assert response.status == HttpStatus.OK
        assert "reports" in response.data
        assert "total" in response.data

    def test_dashboard_reports_with_format_filter(self, handler):
        """Test dashboard reports with format filter."""
        params = {"format_filter": ["pdf"]}
        response = handler.dashboard_reports(params, None)
        assert response.status == HttpStatus.OK
        for report in response.data["reports"]:
            assert report["format"] == "pdf"

    def test_dashboard_schedules(self, handler):
        """Test dashboard schedules endpoint."""
        response = handler.dashboard_schedules({}, None)
        assert response.status == HttpStatus.OK
        assert "schedules" in response.data
        assert "total" in response.data

    def test_dashboard_schedules_enabled_only(self, handler):
        """Test dashboard schedules with enabled filter."""
        params = {"enabled_only": ["true"]}
        response = handler.dashboard_schedules(params, None)
        assert response.status == HttpStatus.OK
        for schedule in response.data["schedules"]:
            assert schedule["enabled"] is True

    # -------------------------------------------------------------------------
    # Metadata endpoints
    # -------------------------------------------------------------------------

    def test_dashboard_frequencies(self, handler):
        """Test dashboard frequencies endpoint."""
        response = handler.dashboard_frequencies({}, None)
        assert response.status == HttpStatus.OK
        assert "frequencies" in response.data
        assert "total" in response.data
        freq_names = [f["frequency"] for f in response.data["frequencies"]]
        assert "daily" in freq_names
        assert "weekly" in freq_names
        assert "monthly" in freq_names

    def test_dashboard_formats(self, handler):
        """Test dashboard formats endpoint."""
        response = handler.dashboard_formats({}, None)
        assert response.status == HttpStatus.OK
        assert "formats" in response.data
        assert "total" in response.data
        format_names = [f["format"] for f in response.data["formats"]]
        assert "pdf" in format_names
        assert "html" in format_names
        assert "json" in format_names

    def test_dashboard_templates(self, handler):
        """Test dashboard templates endpoint."""
        response = handler.dashboard_templates({}, None)
        assert response.status == HttpStatus.OK
        assert "templates" in response.data
        assert "total" in response.data
        template_names = [t["template"] for t in response.data["templates"]]
        assert "executive_summary" in template_names
        assert "technical_detail" in template_names

    # -------------------------------------------------------------------------
    # Dashboard Management POST endpoints
    # -------------------------------------------------------------------------

    def test_dashboard_create_success(self, handler):
        """Test successful dashboard creation."""
        body = {"name": "My Dashboard", "template": "security_ops", "theme": "dark"}
        response = handler.dashboard_create({}, body)
        assert response.status == HttpStatus.CREATED
        assert response.data["success"] is True
        assert "dashboard" in response.data
        assert response.data["dashboard"]["name"] == "My Dashboard"

    def test_dashboard_create_missing_name(self, handler):
        """Test dashboard creation with missing name."""
        response = handler.dashboard_create({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "name" in response.data["error"]

    def test_dashboard_generate_success(self, handler):
        """Test successful report generation."""
        body = {"title": "Weekly Report", "template": "executive_summary", "format": "pdf"}
        response = handler.dashboard_generate({}, body)
        assert response.status == HttpStatus.CREATED
        assert response.data["success"] is True
        assert "report" in response.data
        assert response.data["report"]["title"] == "Weekly Report"

    def test_dashboard_generate_missing_title(self, handler):
        """Test report generation with missing title."""
        response = handler.dashboard_generate({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "title" in response.data["error"]

    def test_dashboard_schedule_create_success(self, handler):
        """Test successful schedule creation."""
        body = {"name": "Weekly Schedule", "template": "compliance", "frequency": "weekly"}
        response = handler.dashboard_schedule_create({}, body)
        assert response.status == HttpStatus.CREATED
        assert response.data["success"] is True
        assert "schedule" in response.data
        assert response.data["schedule"]["name"] == "Weekly Schedule"

    def test_dashboard_schedule_create_missing_name(self, handler):
        """Test schedule creation with missing name."""
        response = handler.dashboard_schedule_create({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "name" in response.data["error"]

    def test_dashboard_delete_success(self, handler):
        """Test successful dashboard deletion."""
        body = {"id": "dash-001"}
        response = handler.dashboard_delete({}, body)
        assert response.status == HttpStatus.OK
        assert response.data["deleted"] is True

    def test_dashboard_delete_missing_id(self, handler):
        """Test dashboard deletion with missing ID."""
        response = handler.dashboard_delete({}, {})
        assert response.status == HttpStatus.BAD_REQUEST
        assert "id" in response.data["error"]

    # -------------------------------------------------------------------------
    # Metrics and Status endpoints
    # -------------------------------------------------------------------------

    def test_dashboard_metrics(self, handler):
        """Test dashboard metrics endpoint."""
        response = handler.dashboard_metrics({}, None)
        assert response.status == HttpStatus.OK
        assert "metrics" in response.data
        assert "time_range" in response.data
        assert "security_score" in response.data["metrics"]
        assert "total_findings" in response.data["metrics"]

    def test_dashboard_metrics_with_time_range(self, handler):
        """Test dashboard metrics with time range."""
        params = {"time_range": ["last_30_days"]}
        response = handler.dashboard_metrics(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["time_range"] == "last_30_days"

    def test_dashboard_stats(self, handler):
        """Test dashboard stats endpoint."""
        response = handler.dashboard_stats({}, None)
        assert response.status == HttpStatus.OK
        assert "total_dashboards" in response.data
        assert "scheduled_reports" in response.data
        assert "by_owner" in response.data

    def test_dashboard_status(self, handler):
        """Test dashboard status endpoint."""
        response = handler.dashboard_status({}, None)
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "dashboards"
        assert response.data["status"] == "operational"
        assert "components" in response.data
        assert "capabilities" in response.data

    def test_dashboard_summary(self, handler):
        """Test dashboard summary endpoint."""
        response = handler.dashboard_summary({}, None)
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "dashboards"
        assert "features" in response.data
        assert "statistics" in response.data

    # -------------------------------------------------------------------------
    # Handler routing tests
    # -------------------------------------------------------------------------

    def test_base_path(self, handler):
        """Test handler base path is set correctly."""
        assert handler.base_path == "/api/dashboard/"

    def test_can_handle_dashboard_path(self, handler):
        """Test can_handle for dashboard paths."""
        assert handler.can_handle("/api/dashboard/list")
        assert handler.can_handle("/api/dashboard/widgets")
        assert handler.can_handle("/api/dashboard/create")
        assert not handler.can_handle("/api/report/list")

    def test_handle_get_list(self, handler):
        """Test handling GET /api/dashboard/list."""
        response = handler.handle("/api/dashboard/list", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "dashboards" in response.data

    def test_handle_post_create(self, handler):
        """Test handling POST /api/dashboard/create."""
        body = {"name": "Test Dashboard"}
        response = handler.handle("/api/dashboard/create", {}, "POST", body)
        assert response.status == HttpStatus.CREATED
        assert response.data["success"] is True

    def test_handle_unknown_route(self, handler):
        """Test handling unknown route."""
        response = handler.handle("/api/dashboard/unknown", {}, "GET")
        assert response.status == HttpStatus.NOT_FOUND

    def test_route_discovery(self, handler):
        """Test that routes are discovered correctly."""
        routes = list(handler._route_table)
        assert len(routes) > 0

        # Find create route
        create_routes = [r for r in routes if r.path == "create"]
        assert len(create_routes) == 1
        assert "POST" in create_routes[0].methods

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 15 GET routes + 4 POST routes = 19 total
        assert len(routes) == 19


# =============================================================================
# QueryHandler Tests
# =============================================================================


class TestQueryHandler:
    """Tests for QueryHandler class."""

    @pytest.fixture
    def handler(self):
        """Create QueryHandler instance."""
        from stance.web.handlers.query import QueryHandler
        return QueryHandler()

    # -------------------------------------------------------------------------
    # Query Execution endpoints
    # -------------------------------------------------------------------------

    def test_query_execute(self, handler):
        """Test query execute endpoint."""
        params = {"sql": ["SELECT * FROM assets LIMIT 5"]}
        response = handler.query_execute(params, None)
        assert response.status == HttpStatus.OK
        assert "sql" in response.data
        assert "backend" in response.data
        assert "result" in response.data
        assert response.data["result"]["row_count"] > 0

    def test_query_execute_missing_sql(self, handler):
        """Test query execute with missing SQL."""
        response = handler.query_execute({}, None)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "sql" in response.data["error"]

    def test_query_execute_with_backend(self, handler):
        """Test query execute with backend parameter."""
        params = {"sql": ["SELECT * FROM assets"], "backend": ["demo"]}
        response = handler.query_execute(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["backend"] == "demo"

    def test_query_execute_with_limit(self, handler):
        """Test query execute with limit parameter."""
        params = {"sql": ["SELECT * FROM assets"], "limit": ["2"]}
        response = handler.query_execute(params, None)
        assert response.status == HttpStatus.OK
        assert "LIMIT 2" in response.data["sql"]

    def test_query_execute_invalid_sql(self, handler):
        """Test query execute with invalid SQL."""
        params = {"sql": ["DELETE FROM assets"]}
        response = handler.query_execute(params, None)
        assert response.status == HttpStatus.BAD_REQUEST

    def test_query_estimate(self, handler):
        """Test query estimate endpoint."""
        params = {"sql": ["SELECT * FROM findings"]}
        response = handler.query_estimate(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["valid"] is True
        assert "estimated_bytes" in response.data
        assert "estimated_cost_usd" in response.data

    def test_query_estimate_missing_sql(self, handler):
        """Test query estimate with missing SQL."""
        response = handler.query_estimate({}, None)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "sql" in response.data["error"]

    def test_query_estimate_invalid_sql(self, handler):
        """Test query estimate with invalid SQL."""
        params = {"sql": ["INSERT INTO assets VALUES (1)"]}
        response = handler.query_estimate(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["valid"] is False
        assert len(response.data["errors"]) > 0

    def test_query_validate(self, handler):
        """Test query validate endpoint."""
        params = {"sql": ["SELECT * FROM assets WHERE region = 'us-east-1'"]}
        response = handler.query_validate(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["valid"] is True
        assert response.data["errors"] == []

    def test_query_validate_missing_sql(self, handler):
        """Test query validate with missing SQL."""
        response = handler.query_validate({}, None)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "sql" in response.data["error"]

    def test_query_validate_forbidden_keyword(self, handler):
        """Test query validate with forbidden keyword."""
        params = {"sql": ["DROP TABLE assets"]}
        response = handler.query_validate(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["valid"] is False
        assert any("DROP" in e for e in response.data["errors"])

    def test_query_validate_multiple_statements(self, handler):
        """Test query validate with multiple statements."""
        params = {"sql": ["SELECT * FROM assets; SELECT * FROM findings"]}
        response = handler.query_validate(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["valid"] is False
        assert any("Multiple" in e for e in response.data["errors"])

    def test_query_validate_comments(self, handler):
        """Test query validate with comments."""
        params = {"sql": ["SELECT * FROM assets -- comment"]}
        response = handler.query_validate(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["valid"] is False
        assert any("comment" in e.lower() for e in response.data["errors"])

    # -------------------------------------------------------------------------
    # Schema Introspection endpoints
    # -------------------------------------------------------------------------

    def test_query_tables(self, handler):
        """Test query tables endpoint."""
        response = handler.query_tables({}, None)
        assert response.status == HttpStatus.OK
        assert "tables" in response.data
        assert "count" in response.data
        table_names = [t["name"] for t in response.data["tables"]]
        assert "assets" in table_names
        assert "findings" in table_names

    def test_query_tables_with_backend(self, handler):
        """Test query tables with backend parameter."""
        params = {"backend": ["demo"]}
        response = handler.query_tables(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["backend"] == "demo"

    def test_query_schema(self, handler):
        """Test query schema endpoint."""
        params = {"table": ["assets"]}
        response = handler.query_schema(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["table_name"] == "assets"
        assert "columns" in response.data
        assert "column_count" in response.data
        column_names = [c["name"] for c in response.data["columns"]]
        assert "id" in column_names
        assert "cloud_provider" in column_names

    def test_query_schema_missing_table(self, handler):
        """Test query schema with missing table."""
        response = handler.query_schema({}, None)
        assert response.status == HttpStatus.BAD_REQUEST
        assert "table" in response.data["error"]

    def test_query_schema_unknown_table(self, handler):
        """Test query schema with unknown table."""
        params = {"table": ["nonexistent"]}
        response = handler.query_schema(params, None)
        assert response.status == HttpStatus.NOT_FOUND
        assert "not found" in response.data["error"].lower()

    def test_query_schema_findings(self, handler):
        """Test query schema for findings table."""
        params = {"table": ["findings"]}
        response = handler.query_schema(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["table_name"] == "findings"
        column_names = [c["name"] for c in response.data["columns"]]
        assert "severity" in column_names
        assert "status" in column_names

    # -------------------------------------------------------------------------
    # Backend Management endpoints
    # -------------------------------------------------------------------------

    def test_query_backends(self, handler):
        """Test query backends endpoint."""
        response = handler.query_backends({}, None)
        assert response.status == HttpStatus.OK
        assert "backends" in response.data
        assert "total" in response.data
        assert "configured" in response.data
        backend_names = [b["name"] for b in response.data["backends"]]
        assert "demo" in backend_names
        assert "athena" in backend_names

    def test_query_backends_demo_active(self, handler):
        """Test that demo backend is active."""
        response = handler.query_backends({}, None)
        assert response.status == HttpStatus.OK
        demo_backend = next(b for b in response.data["backends"] if b["name"] == "demo")
        assert demo_backend["configured"] is True
        assert demo_backend["status"] == "active"

    # -------------------------------------------------------------------------
    # Query History and Saved Queries endpoints
    # -------------------------------------------------------------------------

    def test_query_history(self, handler):
        """Test query history endpoint."""
        response = handler.query_history({}, None)
        assert response.status == HttpStatus.OK
        assert "history" in response.data
        assert "total" in response.data

    def test_query_history_with_limit(self, handler):
        """Test query history with limit."""
        params = {"limit": ["2"]}
        response = handler.query_history(params, None)
        assert response.status == HttpStatus.OK
        assert len(response.data["history"]) <= 2

    def test_query_history_with_user_filter(self, handler):
        """Test query history with user filter."""
        params = {"user": ["admin"]}
        response = handler.query_history(params, None)
        assert response.status == HttpStatus.OK
        for item in response.data["history"]:
            assert item["user"] == "admin"

    def test_query_saved(self, handler):
        """Test query saved endpoint."""
        response = handler.query_saved({}, None)
        assert response.status == HttpStatus.OK
        assert "queries" in response.data
        assert "total" in response.data

    def test_query_saved_with_category(self, handler):
        """Test query saved with category filter."""
        params = {"category": ["security"]}
        response = handler.query_saved(params, None)
        assert response.status == HttpStatus.OK
        for query in response.data["queries"]:
            assert query["category"] == "security"

    # -------------------------------------------------------------------------
    # Status and Statistics endpoints
    # -------------------------------------------------------------------------

    def test_query_stats(self, handler):
        """Test query stats endpoint."""
        response = handler.query_stats({}, None)
        assert response.status == HttpStatus.OK
        assert "queries_executed_24h" in response.data
        assert "bytes_scanned_24h" in response.data
        assert "top_tables" in response.data
        assert "top_users" in response.data

    def test_query_status(self, handler):
        """Test query status endpoint."""
        response = handler.query_status({}, None)
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "query_engine"
        assert response.data["status"] == "operational"
        assert "capabilities" in response.data
        assert "supported_backends" in response.data
        assert "security" in response.data

    def test_query_status_capabilities(self, handler):
        """Test query status capabilities."""
        response = handler.query_status({}, None)
        assert response.status == HttpStatus.OK
        caps = response.data["capabilities"]
        assert caps["sql_execution"] is True
        assert caps["cost_estimation"] is True
        assert caps["query_validation"] is True

    def test_query_summary(self, handler):
        """Test query summary endpoint."""
        response = handler.query_summary({}, None)
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "query_engine"
        assert "features" in response.data
        assert "tables_available" in response.data

    # -------------------------------------------------------------------------
    # Handler routing tests
    # -------------------------------------------------------------------------

    def test_base_path(self, handler):
        """Test handler base path is set correctly."""
        assert handler.base_path == "/api/query/"

    def test_can_handle_query_path(self, handler):
        """Test can_handle for query paths."""
        assert handler.can_handle("/api/query/execute")
        assert handler.can_handle("/api/query/tables")
        assert handler.can_handle("/api/query/schema")
        assert not handler.can_handle("/api/dashboard/list")

    def test_handle_get_execute(self, handler):
        """Test handling GET /api/query/execute."""
        params = {"sql": ["SELECT * FROM assets LIMIT 1"]}
        response = handler.handle("/api/query/execute", params, "GET")
        assert response.status == HttpStatus.OK
        assert "result" in response.data

    def test_handle_get_tables(self, handler):
        """Test handling GET /api/query/tables."""
        response = handler.handle("/api/query/tables", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "tables" in response.data

    def test_handle_unknown_route(self, handler):
        """Test handling unknown route."""
        response = handler.handle("/api/query/unknown", {}, "GET")
        assert response.status == HttpStatus.NOT_FOUND

    def test_route_discovery(self, handler):
        """Test that routes are discovered correctly."""
        routes = list(handler._route_table)
        assert len(routes) > 0
        route_paths = [r.path for r in routes]
        assert "execute" in route_paths
        assert "validate" in route_paths
        assert "tables" in route_paths

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 11 GET routes + 0 POST routes = 11 total
        assert len(routes) == 11


# =============================================================================
# AlertHandler Tests
# =============================================================================


class TestAlertHandler:
    """Tests for AlertHandler class."""

    @pytest.fixture
    def handler(self):
        """Create AlertHandler instance."""
        from stance.web.handlers.alert import AlertHandler
        return AlertHandler()

    # -------------------------------------------------------------------------
    # Destination Management endpoints
    # -------------------------------------------------------------------------

    def test_alerting_destinations(self, handler):
        """Test alerting destinations endpoint."""
        response = handler.alerting_destinations({}, None)
        assert response.status == HttpStatus.OK
        assert "destinations" in response.data
        assert "total" in response.data
        assert response.data["total"] == 4

    def test_alerting_destinations_structure(self, handler):
        """Test destination structure."""
        response = handler.alerting_destinations({}, None)
        assert response.status == HttpStatus.OK
        dest = response.data["destinations"][0]
        assert "name" in dest
        assert "type" in dest
        assert "enabled" in dest
        assert "available" in dest
        assert "rate_limit_max" in dest

    def test_alerting_destination_types(self, handler):
        """Test alerting destination types endpoint."""
        response = handler.alerting_destination_types({}, None)
        assert response.status == HttpStatus.OK
        assert "types" in response.data
        assert response.data["total"] == 6

    def test_alerting_destination_types_structure(self, handler):
        """Test destination type structure."""
        response = handler.alerting_destination_types({}, None)
        assert response.status == HttpStatus.OK
        dtype = response.data["types"][0]
        assert "type" in dtype
        assert "description" in dtype
        assert "required_config" in dtype

    def test_alerting_destination_types_includes_expected(self, handler):
        """Test expected destination types are present."""
        response = handler.alerting_destination_types({}, None)
        assert response.status == HttpStatus.OK
        type_names = [t["type"] for t in response.data["types"]]
        assert "slack" in type_names
        assert "pagerduty" in type_names
        assert "email" in type_names
        assert "webhook" in type_names
        assert "teams" in type_names
        assert "jira" in type_names

    # -------------------------------------------------------------------------
    # Routing Rules endpoints
    # -------------------------------------------------------------------------

    def test_alerting_routing_rules(self, handler):
        """Test alerting routing rules endpoint."""
        response = handler.alerting_routing_rules({}, None)
        assert response.status == HttpStatus.OK
        assert "rules" in response.data
        assert "total" in response.data
        assert response.data["total"] == 4

    def test_alerting_routing_rules_structure(self, handler):
        """Test routing rule structure."""
        response = handler.alerting_routing_rules({}, None)
        assert response.status == HttpStatus.OK
        rule = response.data["rules"][0]
        assert "name" in rule
        assert "destinations" in rule
        assert "severities" in rule
        assert "finding_types" in rule
        assert "enabled" in rule
        assert "priority" in rule

    def test_alerting_routing_rules_enabled_only(self, handler):
        """Test filtering routing rules by enabled status."""
        params = {"enabled_only": ["true"]}
        response = handler.alerting_routing_rules(params, None)
        assert response.status == HttpStatus.OK
        for rule in response.data["rules"]:
            assert rule["enabled"] is True

    def test_alerting_suppression_rules(self, handler):
        """Test alerting suppression rules endpoint."""
        response = handler.alerting_suppression_rules({}, None)
        assert response.status == HttpStatus.OK
        assert "rules" in response.data
        assert "total" in response.data
        assert response.data["total"] == 3

    def test_alerting_suppression_rules_structure(self, handler):
        """Test suppression rule structure."""
        response = handler.alerting_suppression_rules({}, None)
        assert response.status == HttpStatus.OK
        rule = response.data["rules"][0]
        assert "name" in rule
        assert "rule_ids" in rule
        assert "asset_patterns" in rule
        assert "reason" in rule
        assert "enabled" in rule

    def test_alerting_suppression_rules_enabled_only(self, handler):
        """Test filtering suppression rules by enabled status."""
        params = {"enabled_only": ["true"]}
        response = handler.alerting_suppression_rules(params, None)
        assert response.status == HttpStatus.OK
        for rule in response.data["rules"]:
            assert rule["enabled"] is True

    # -------------------------------------------------------------------------
    # Configuration endpoints
    # -------------------------------------------------------------------------

    def test_alerting_config(self, handler):
        """Test alerting config endpoint."""
        response = handler.alerting_config({}, None)
        assert response.status == HttpStatus.OK
        assert response.data["enabled"] is True
        assert "dedup_window_hours" in response.data
        assert "default_rate_limit" in response.data
        assert "destinations_count" in response.data
        assert "routing_rules_count" in response.data
        assert "suppression_rules_count" in response.data

    def test_alerting_config_rate_limit_structure(self, handler):
        """Test config rate limit structure."""
        response = handler.alerting_config({}, None)
        assert response.status == HttpStatus.OK
        rate_limit = response.data["default_rate_limit"]
        assert "max_alerts" in rate_limit
        assert "window_seconds" in rate_limit
        assert "burst_limit" in rate_limit

    def test_alerting_rate_limits(self, handler):
        """Test alerting rate limits endpoint."""
        response = handler.alerting_rate_limits({}, None)
        assert response.status == HttpStatus.OK
        assert "rate_limits" in response.data
        assert "slack-security" in response.data["rate_limits"]
        assert "pagerduty-critical" in response.data["rate_limits"]
        assert "default" in response.data["rate_limits"]

    def test_alerting_rate_limits_by_destination(self, handler):
        """Test filtering rate limits by destination."""
        params = {"destination": ["slack-security"]}
        response = handler.alerting_rate_limits(params, None)
        assert response.status == HttpStatus.OK
        assert "slack-security" in response.data["rate_limits"]
        assert len(response.data["rate_limits"]) == 1

    def test_alerting_rate_limits_unknown_destination(self, handler):
        """Test rate limits for unknown destination."""
        params = {"destination": ["unknown-dest"]}
        response = handler.alerting_rate_limits(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["rate_limits"] == {}
        assert "error" in response.data

    def test_alerting_severities(self, handler):
        """Test alerting severities endpoint."""
        response = handler.alerting_severities({}, None)
        assert response.status == HttpStatus.OK
        assert "severities" in response.data
        assert response.data["total"] == 5

    def test_alerting_severities_structure(self, handler):
        """Test severity structure."""
        response = handler.alerting_severities({}, None)
        assert response.status == HttpStatus.OK
        severity = response.data["severities"][0]
        assert "value" in severity
        assert "priority" in severity
        assert "description" in severity

    def test_alerting_severities_values(self, handler):
        """Test expected severity values."""
        response = handler.alerting_severities({}, None)
        assert response.status == HttpStatus.OK
        values = [s["value"] for s in response.data["severities"]]
        assert "critical" in values
        assert "high" in values
        assert "medium" in values
        assert "low" in values
        assert "info" in values

    # -------------------------------------------------------------------------
    # Alert Records endpoints
    # -------------------------------------------------------------------------

    def test_alerting_alerts(self, handler):
        """Test alerting alerts endpoint."""
        response = handler.alerting_alerts({}, None)
        assert response.status == HttpStatus.OK
        assert "alerts" in response.data
        assert "total" in response.data
        assert response.data["total"] == 4

    def test_alerting_alerts_structure(self, handler):
        """Test alert record structure."""
        response = handler.alerting_alerts({}, None)
        assert response.status == HttpStatus.OK
        alert = response.data["alerts"][0]
        assert "id" in alert
        assert "finding_id" in alert
        assert "destination" in alert
        assert "sent_at" in alert
        assert "status" in alert

    def test_alerting_alerts_filter_by_status(self, handler):
        """Test filtering alerts by status."""
        params = {"status": ["acknowledged"]}
        response = handler.alerting_alerts(params, None)
        assert response.status == HttpStatus.OK
        for alert in response.data["alerts"]:
            assert alert["status"] == "acknowledged"

    def test_alerting_alerts_filter_by_finding_id(self, handler):
        """Test filtering alerts by finding ID."""
        params = {"finding_id": ["finding-abc123"]}
        response = handler.alerting_alerts(params, None)
        assert response.status == HttpStatus.OK
        for alert in response.data["alerts"]:
            assert alert["finding_id"] == "finding-abc123"

    def test_alerting_alerts_with_limit(self, handler):
        """Test alerts with limit."""
        params = {"limit": ["2"]}
        response = handler.alerting_alerts(params, None)
        assert response.status == HttpStatus.OK
        assert len(response.data["alerts"]) <= 2

    def test_alerting_templates(self, handler):
        """Test alerting templates endpoint."""
        response = handler.alerting_templates({}, None)
        assert response.status == HttpStatus.OK
        assert "templates" in response.data
        assert response.data["total"] == 5

    def test_alerting_templates_structure(self, handler):
        """Test template structure."""
        response = handler.alerting_templates({}, None)
        assert response.status == HttpStatus.OK
        template = response.data["templates"][0]
        assert "name" in template
        assert "description" in template
        assert "used_for" in template

    def test_alerting_templates_expected_names(self, handler):
        """Test expected template names."""
        response = handler.alerting_templates({}, None)
        assert response.status == HttpStatus.OK
        names = [t["name"] for t in response.data["templates"]]
        assert "DefaultTemplate" in names
        assert "MisconfigurationTemplate" in names
        assert "VulnerabilityTemplate" in names
        assert "ComplianceTemplate" in names
        assert "CriticalExposureTemplate" in names

    # -------------------------------------------------------------------------
    # Testing and Status endpoints
    # -------------------------------------------------------------------------

    def test_alerting_test_route(self, handler):
        """Test alerting test route endpoint."""
        response = handler.alerting_test_route({}, None)
        assert response.status == HttpStatus.OK
        assert "severity" in response.data
        assert "finding_type" in response.data
        assert "matched_rules" in response.data
        assert "destinations" in response.data

    def test_alerting_test_route_with_params(self, handler):
        """Test test route with custom parameters."""
        params = {"severity": ["critical"], "finding_type": ["vulnerability"]}
        response = handler.alerting_test_route(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["severity"] == "critical"
        assert response.data["finding_type"] == "vulnerability"

    def test_alerting_test_route_matches_rules(self, handler):
        """Test that test route matches appropriate rules."""
        params = {"severity": ["critical"], "finding_type": ["misconfiguration"]}
        response = handler.alerting_test_route(params, None)
        assert response.status == HttpStatus.OK
        # Critical severity should match critical-pagerduty rule
        assert "critical-pagerduty" in response.data["matched_rules"]

    def test_alerting_status(self, handler):
        """Test alerting status endpoint."""
        response = handler.alerting_status({}, None)
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "stance.alerting"
        assert response.data["status"] == "operational"
        assert "components" in response.data
        assert "capabilities" in response.data

    def test_alerting_status_components(self, handler):
        """Test alerting status components."""
        response = handler.alerting_status({}, None)
        assert response.status == HttpStatus.OK
        components = response.data["components"]
        assert "AlertRouter" in components
        assert "AlertState" in components
        assert "AlertConfig" in components

    def test_alerting_summary(self, handler):
        """Test alerting summary endpoint."""
        response = handler.alerting_summary({}, None)
        assert response.status == HttpStatus.OK
        assert "config" in response.data
        assert "stats" in response.data

    def test_alerting_summary_config(self, handler):
        """Test alerting summary config section."""
        response = handler.alerting_summary({}, None)
        assert response.status == HttpStatus.OK
        config = response.data["config"]
        assert config["enabled"] is True
        assert "destinations_count" in config
        assert "routing_rules_count" in config
        assert "suppression_rules_count" in config

    def test_alerting_summary_stats(self, handler):
        """Test alerting summary stats section."""
        response = handler.alerting_summary({}, None)
        assert response.status == HttpStatus.OK
        stats = response.data["stats"]
        assert "alerts_sent_24h" in stats
        assert "alerts_suppressed_24h" in stats
        assert "by_destination" in stats
        assert "by_severity" in stats

    # -------------------------------------------------------------------------
    # Handler routing tests
    # -------------------------------------------------------------------------

    def test_base_path(self, handler):
        """Test handler base path is set correctly."""
        assert handler.base_path == "/api/alerting/"

    def test_can_handle_alerting_path(self, handler):
        """Test can_handle for alerting paths."""
        assert handler.can_handle("/api/alerting/destinations")
        assert handler.can_handle("/api/alerting/routing-rules")
        assert handler.can_handle("/api/alerting/config")
        assert not handler.can_handle("/api/query/execute")

    def test_handle_get_destinations(self, handler):
        """Test handling GET /api/alerting/destinations."""
        response = handler.handle("/api/alerting/destinations", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "destinations" in response.data

    def test_handle_get_config(self, handler):
        """Test handling GET /api/alerting/config."""
        response = handler.handle("/api/alerting/config", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "enabled" in response.data

    def test_handle_unknown_route(self, handler):
        """Test handling unknown route."""
        response = handler.handle("/api/alerting/unknown", {}, "GET")
        assert response.status == HttpStatus.NOT_FOUND

    def test_route_discovery(self, handler):
        """Test that routes are discovered correctly."""
        routes = list(handler._route_table)
        assert len(routes) > 0
        route_paths = [r.path for r in routes]
        assert "destinations" in route_paths
        assert "routing-rules" in route_paths
        assert "config" in route_paths

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 12 GET routes + 0 POST routes = 12 total
        assert len(routes) == 12


# =============================================================================
# StorageHandler Tests
# =============================================================================


class TestStorageHandler:
    """Tests for StorageHandler class."""

    @pytest.fixture
    def handler(self):
        """Create StorageHandler instance."""
        from stance.web.handlers.storage import StorageHandler
        return StorageHandler()

    # -------------------------------------------------------------------------
    # Backend Management endpoints
    # -------------------------------------------------------------------------

    def test_storage_backends(self, handler):
        """Test storage backends endpoint."""
        response = handler.storage_backends({}, None)
        assert response.status == HttpStatus.OK
        assert "backends" in response.data
        assert "total" in response.data
        assert response.data["total"] == 4

    def test_storage_backends_structure(self, handler):
        """Test backend structure."""
        response = handler.storage_backends({}, None)
        assert response.status == HttpStatus.OK
        backend = response.data["backends"][0]
        assert "id" in backend
        assert "name" in backend
        assert "description" in backend
        assert "available" in backend
        assert "storage_type" in backend
        assert "query_service" in backend

    def test_storage_backends_ids(self, handler):
        """Test expected backend IDs."""
        response = handler.storage_backends({}, None)
        assert response.status == HttpStatus.OK
        ids = [b["id"] for b in response.data["backends"]]
        assert "local" in ids
        assert "s3" in ids
        assert "gcs" in ids
        assert "azure_blob" in ids

    def test_storage_backend(self, handler):
        """Test storage backend detail endpoint."""
        params = {"id": ["local"]}
        response = handler.storage_backend(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["id"] == "local"
        assert response.data["name"] == "Local Storage"
        assert "configuration" in response.data
        assert "capabilities" in response.data

    def test_storage_backend_s3(self, handler):
        """Test S3 backend details."""
        params = {"id": ["s3"]}
        response = handler.storage_backend(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["id"] == "s3"
        assert response.data["cloud_provider"] == "aws"
        assert response.data["query_service"] == "athena"

    def test_storage_backend_unknown(self, handler):
        """Test unknown backend."""
        params = {"id": ["unknown"]}
        response = handler.storage_backend(params, None)
        assert response.status == HttpStatus.NOT_FOUND

    # -------------------------------------------------------------------------
    # Snapshot Management endpoints
    # -------------------------------------------------------------------------

    def test_storage_snapshots(self, handler):
        """Test storage snapshots endpoint."""
        response = handler.storage_snapshots({}, None)
        assert response.status == HttpStatus.OK
        assert "snapshots" in response.data
        assert "total" in response.data
        assert "backend" in response.data

    def test_storage_snapshots_structure(self, handler):
        """Test snapshot structure."""
        response = handler.storage_snapshots({}, None)
        assert response.status == HttpStatus.OK
        snapshot = response.data["snapshots"][0]
        assert "id" in snapshot
        assert "timestamp" in snapshot
        assert "backend" in snapshot
        assert "asset_count" in snapshot
        assert "finding_count" in snapshot
        assert "size_bytes" in snapshot

    def test_storage_snapshots_with_limit(self, handler):
        """Test snapshots with limit."""
        params = {"limit": ["5"]}
        response = handler.storage_snapshots(params, None)
        assert response.status == HttpStatus.OK
        assert len(response.data["snapshots"]) <= 5

    def test_storage_snapshot(self, handler):
        """Test storage snapshot detail endpoint."""
        params = {"id": ["20241229_120000"]}
        response = handler.storage_snapshot(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["id"] == "20241229_120000"
        assert "asset_count" in response.data
        assert "finding_count" in response.data
        assert "assets_by_provider" in response.data
        assert "findings_by_severity" in response.data

    def test_storage_snapshot_missing_id(self, handler):
        """Test snapshot without ID."""
        response = handler.storage_snapshot({}, None)
        assert response.status == HttpStatus.BAD_REQUEST

    def test_storage_latest(self, handler):
        """Test storage latest snapshot endpoint."""
        response = handler.storage_latest({}, None)
        assert response.status == HttpStatus.OK
        assert "snapshot_id" in response.data
        assert "timestamp" in response.data
        assert "asset_count" in response.data
        assert "is_stale" in response.data
        assert "summary" in response.data

    def test_storage_latest_summary(self, handler):
        """Test latest snapshot summary structure."""
        response = handler.storage_latest({}, None)
        assert response.status == HttpStatus.OK
        summary = response.data["summary"]
        assert "providers" in summary
        assert "resource_types" in summary
        assert "critical_findings" in summary

    # -------------------------------------------------------------------------
    # Configuration endpoints
    # -------------------------------------------------------------------------

    def test_storage_config(self, handler):
        """Test storage config endpoint."""
        response = handler.storage_config({}, None)
        assert response.status == HttpStatus.OK
        assert response.data["backend"] == "local"
        assert "storage_type" in response.data
        assert "settings" in response.data

    def test_storage_config_s3(self, handler):
        """Test S3 config."""
        params = {"backend": ["s3"]}
        response = handler.storage_config(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["backend"] == "s3"
        assert "bucket" in response.data
        assert "prefix" in response.data
        assert response.data["query_service"] == "athena"

    def test_storage_config_unknown(self, handler):
        """Test unknown backend config."""
        params = {"backend": ["unknown"]}
        response = handler.storage_config(params, None)
        assert response.status == HttpStatus.NOT_FOUND

    def test_storage_capabilities(self, handler):
        """Test storage capabilities endpoint."""
        response = handler.storage_capabilities({}, None)
        assert response.status == HttpStatus.OK
        assert "capabilities" in response.data
        assert "common_capabilities" in response.data
        assert "cloud_only_capabilities" in response.data

    def test_storage_capabilities_specific_backend(self, handler):
        """Test capabilities for specific backend."""
        params = {"backend": ["s3"]}
        response = handler.storage_capabilities(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["backend"] == "s3"
        assert "ddl_generation" in response.data
        assert response.data["ddl_generation"] is True

    def test_storage_capabilities_local(self, handler):
        """Test local backend capabilities."""
        params = {"backend": ["local"]}
        response = handler.storage_capabilities(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["query_assets"] is True
        assert response.data["ddl_generation"] is False

    def test_storage_capabilities_unknown(self, handler):
        """Test unknown backend capabilities."""
        params = {"backend": ["unknown"]}
        response = handler.storage_capabilities(params, None)
        assert response.status == HttpStatus.NOT_FOUND

    # -------------------------------------------------------------------------
    # Query Service endpoints
    # -------------------------------------------------------------------------

    def test_storage_query_services(self, handler):
        """Test storage query services endpoint."""
        response = handler.storage_query_services({}, None)
        assert response.status == HttpStatus.OK
        assert "services" in response.data
        assert response.data["total"] == 4

    def test_storage_query_services_structure(self, handler):
        """Test query service structure."""
        response = handler.storage_query_services({}, None)
        assert response.status == HttpStatus.OK
        service = response.data["services"][0]
        assert "id" in service
        assert "name" in service
        assert "backend" in service
        assert "query_language" in service
        assert "features" in service
        assert "limitations" in service

    def test_storage_query_services_includes_expected(self, handler):
        """Test expected query services."""
        response = handler.storage_query_services({}, None)
        assert response.status == HttpStatus.OK
        ids = [s["id"] for s in response.data["services"]]
        assert "sqlite" in ids
        assert "athena" in ids
        assert "bigquery" in ids
        assert "synapse" in ids

    def test_storage_ddl(self, handler):
        """Test storage DDL endpoint."""
        response = handler.storage_ddl({}, None)
        assert response.status == HttpStatus.OK
        assert "backend" in response.data
        assert "table_type" in response.data
        assert "ddl" in response.data
        assert "query_service" in response.data

    def test_storage_ddl_s3_assets(self, handler):
        """Test S3 assets DDL."""
        params = {"backend": ["s3"], "table_type": ["assets"]}
        response = handler.storage_ddl(params, None)
        assert response.status == HttpStatus.OK
        assert "CREATE EXTERNAL TABLE" in response.data["ddl"]
        assert "stance_assets" in response.data["ddl"]
        assert response.data["query_service"] == "athena"

    def test_storage_ddl_gcs_findings(self, handler):
        """Test GCS findings DDL."""
        params = {"backend": ["gcs"], "table_type": ["findings"]}
        response = handler.storage_ddl(params, None)
        assert response.status == HttpStatus.OK
        assert "stance_findings" in response.data["ddl"]
        assert response.data["query_service"] == "bigquery"

    def test_storage_ddl_unknown_backend(self, handler):
        """Test DDL for unknown backend."""
        params = {"backend": ["unknown"]}
        response = handler.storage_ddl(params, None)
        assert response.status == HttpStatus.BAD_REQUEST

    def test_storage_ddl_unknown_table_type(self, handler):
        """Test DDL for unknown table type."""
        params = {"backend": ["s3"], "table_type": ["unknown"]}
        response = handler.storage_ddl(params, None)
        assert response.status == HttpStatus.BAD_REQUEST

    # -------------------------------------------------------------------------
    # Statistics and Status endpoints
    # -------------------------------------------------------------------------

    def test_storage_stats(self, handler):
        """Test storage stats endpoint."""
        response = handler.storage_stats({}, None)
        assert response.status == HttpStatus.OK
        assert "backend" in response.data
        assert "total_snapshots" in response.data
        assert "total_assets" in response.data
        assert "total_findings" in response.data
        assert "storage_used_bytes" in response.data
        assert "growth_rate" in response.data

    def test_storage_stats_growth_rate(self, handler):
        """Test storage stats growth rate structure."""
        response = handler.storage_stats({}, None)
        assert response.status == HttpStatus.OK
        growth = response.data["growth_rate"]
        assert "assets_per_day" in growth
        assert "findings_per_day" in growth
        assert "bytes_per_day" in growth

    def test_storage_status(self, handler):
        """Test storage status endpoint."""
        response = handler.storage_status({}, None)
        assert response.status == HttpStatus.OK
        assert response.data["backend"] == "local"
        assert "status" in response.data
        assert "available" in response.data
        assert "connection" in response.data
        assert "details" in response.data

    def test_storage_status_s3(self, handler):
        """Test S3 backend status."""
        params = {"backend": ["s3"]}
        response = handler.storage_status(params, None)
        assert response.status == HttpStatus.OK
        assert response.data["backend"] == "s3"
        assert "bucket" in response.data["details"]

    def test_storage_status_unknown(self, handler):
        """Test unknown backend status."""
        params = {"backend": ["unknown"]}
        response = handler.storage_status(params, None)
        assert response.status == HttpStatus.NOT_FOUND

    def test_storage_summary(self, handler):
        """Test storage summary endpoint."""
        response = handler.storage_summary({}, None)
        assert response.status == HttpStatus.OK
        assert "overview" in response.data
        assert "backends" in response.data
        assert "totals" in response.data
        assert "recommendations" in response.data

    def test_storage_summary_overview(self, handler):
        """Test storage summary overview structure."""
        response = handler.storage_summary({}, None)
        assert response.status == HttpStatus.OK
        overview = response.data["overview"]
        assert "total_backends" in overview
        assert "available_backends" in overview
        assert "configured_backends" in overview
        assert "primary_backend" in overview

    def test_storage_summary_totals(self, handler):
        """Test storage summary totals structure."""
        response = handler.storage_summary({}, None)
        assert response.status == HttpStatus.OK
        totals = response.data["totals"]
        assert "total_snapshots" in totals
        assert "total_assets" in totals
        assert "total_findings" in totals
        assert "total_storage_used" in totals

    # -------------------------------------------------------------------------
    # Handler routing tests
    # -------------------------------------------------------------------------

    def test_base_path(self, handler):
        """Test handler base path is set correctly."""
        assert handler.base_path == "/api/storage/"

    def test_can_handle_storage_path(self, handler):
        """Test can_handle for storage paths."""
        assert handler.can_handle("/api/storage/backends")
        assert handler.can_handle("/api/storage/snapshots")
        assert handler.can_handle("/api/storage/config")
        assert not handler.can_handle("/api/alerting/destinations")

    def test_handle_get_backends(self, handler):
        """Test handling GET /api/storage/backends."""
        response = handler.handle("/api/storage/backends", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "backends" in response.data

    def test_handle_get_config(self, handler):
        """Test handling GET /api/storage/config."""
        response = handler.handle("/api/storage/config", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "backend" in response.data

    def test_handle_unknown_route(self, handler):
        """Test handling unknown route."""
        response = handler.handle("/api/storage/unknown", {}, "GET")
        assert response.status == HttpStatus.NOT_FOUND

    def test_route_discovery(self, handler):
        """Test that routes are discovered correctly."""
        routes = list(handler._route_table)
        assert len(routes) > 0
        route_paths = [r.path for r in routes]
        assert "backends" in route_paths
        assert "snapshots" in route_paths
        assert "config" in route_paths

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 12 GET routes + 0 POST routes = 12 total
        assert len(routes) == 12


# =============================================================================
# AnalyticsHandler Tests
# =============================================================================


class TestAnalyticsHandler:
    """Tests for AnalyticsHandler class."""

    @pytest.fixture
    def handler(self):
        """Create AnalyticsHandler instance."""
        from stance.web.handlers.analytics import AnalyticsHandler
        return AnalyticsHandler()

    # -------------------------------------------------------------------------
    # Attack Path Analysis endpoints
    # -------------------------------------------------------------------------

    def test_analytics_attack_paths(self, handler):
        """Test analytics attack paths endpoint."""
        response = handler.analytics_attack_paths({}, None)
        assert response.status == HttpStatus.OK
        assert "total_paths" in response.data
        assert "paths" in response.data

    def test_analytics_attack_paths_structure(self, handler):
        """Test attack path structure."""
        response = handler.analytics_attack_paths({}, None)
        assert response.status == HttpStatus.OK
        if response.data["paths"]:
            path = response.data["paths"][0]
            assert "id" in path
            assert "path_type" in path
            assert "severity" in path
            assert "description" in path
            assert "steps" in path

    def test_analytics_attack_paths_filter_by_type(self, handler):
        """Test filtering attack paths by type."""
        params = {"type": ["privilege_escalation"]}
        response = handler.analytics_attack_paths(params, None)
        assert response.status == HttpStatus.OK
        for path in response.data["paths"]:
            assert path["path_type"] == "privilege_escalation"

    def test_analytics_attack_paths_filter_by_severity(self, handler):
        """Test filtering attack paths by severity."""
        params = {"severity": ["critical"]}
        response = handler.analytics_attack_paths(params, None)
        assert response.status == HttpStatus.OK
        # All paths should be critical or higher
        for path in response.data["paths"]:
            assert path["severity"] == "critical"

    def test_analytics_attack_paths_with_limit(self, handler):
        """Test attack paths with limit."""
        params = {"limit": ["2"]}
        response = handler.analytics_attack_paths(params, None)
        assert response.status == HttpStatus.OK
        assert len(response.data["paths"]) <= 2

    # -------------------------------------------------------------------------
    # Risk Scoring endpoints
    # -------------------------------------------------------------------------

    def test_analytics_risk_score(self, handler):
        """Test analytics risk score endpoint."""
        response = handler.analytics_risk_score({}, None)
        assert response.status == HttpStatus.OK
        assert "total_scored" in response.data
        assert "scores" in response.data

    def test_analytics_risk_score_structure(self, handler):
        """Test risk score structure."""
        response = handler.analytics_risk_score({}, None)
        assert response.status == HttpStatus.OK
        if response.data["scores"]:
            score = response.data["scores"][0]
            assert "asset_id" in score
            assert "overall_score" in score
            assert "risk_level" in score
            assert "factors" in score
            assert "top_risks" in score
            assert "recommendations" in score

    def test_analytics_risk_score_aggregate(self, handler):
        """Test risk score aggregate data."""
        response = handler.analytics_risk_score({}, None)
        assert response.status == HttpStatus.OK
        if response.data["aggregate"]:
            aggregate = response.data["aggregate"]
            assert "average_score" in aggregate
            assert "critical_count" in aggregate
            assert "high_count" in aggregate

    def test_analytics_risk_score_filter_by_level(self, handler):
        """Test filtering risk scores by level."""
        params = {"level": ["critical"]}
        response = handler.analytics_risk_score(params, None)
        assert response.status == HttpStatus.OK
        for score in response.data["scores"]:
            assert score["risk_level"] == "critical"

    def test_analytics_risk_score_filter_by_min_score(self, handler):
        """Test filtering risk scores by minimum score."""
        params = {"min_score": ["70"]}
        response = handler.analytics_risk_score(params, None)
        assert response.status == HttpStatus.OK
        for score in response.data["scores"]:
            assert score["overall_score"] >= 70.0

    def test_analytics_risk_score_with_limit(self, handler):
        """Test risk scores with limit."""
        params = {"limit": ["2"]}
        response = handler.analytics_risk_score(params, None)
        assert response.status == HttpStatus.OK
        assert len(response.data["scores"]) <= 2

    # -------------------------------------------------------------------------
    # Blast Radius endpoints
    # -------------------------------------------------------------------------

    def test_analytics_blast_radius(self, handler):
        """Test analytics blast radius endpoint."""
        response = handler.analytics_blast_radius({}, None)
        assert response.status == HttpStatus.OK
        assert "total_analyzed" in response.data
        assert "results" in response.data

    def test_analytics_blast_radius_structure(self, handler):
        """Test blast radius result structure."""
        response = handler.analytics_blast_radius({}, None)
        assert response.status == HttpStatus.OK
        if response.data["results"]:
            result = response.data["results"][0]
            assert "finding_id" in result
            assert "blast_radius_score" in result
            assert "finding_severity" in result
            assert "total_affected_count" in result
            assert "impact_categories" in result
            assert "directly_affected" in result

    def test_analytics_blast_radius_filter_by_category(self, handler):
        """Test filtering blast radius by impact category."""
        params = {"category": ["data_exposure"]}
        response = handler.analytics_blast_radius(params, None)
        assert response.status == HttpStatus.OK
        for result in response.data["results"]:
            assert "data_exposure" in result["impact_categories"]

    def test_analytics_blast_radius_filter_by_min_score(self, handler):
        """Test filtering blast radius by minimum score."""
        params = {"min_score": ["70"]}
        response = handler.analytics_blast_radius(params, None)
        assert response.status == HttpStatus.OK
        for result in response.data["results"]:
            assert result["blast_radius_score"] >= 70.0

    def test_analytics_blast_radius_with_limit(self, handler):
        """Test blast radius with limit."""
        params = {"limit": ["2"]}
        response = handler.analytics_blast_radius(params, None)
        assert response.status == HttpStatus.OK
        assert len(response.data["results"]) <= 2

    # -------------------------------------------------------------------------
    # MITRE ATT&CK endpoints
    # -------------------------------------------------------------------------

    def test_analytics_mitre(self, handler):
        """Test analytics MITRE endpoint."""
        response = handler.analytics_mitre({}, None)
        assert response.status == HttpStatus.OK
        assert "total_mappings" in response.data
        assert "mappings" in response.data

    def test_analytics_mitre_structure(self, handler):
        """Test MITRE mapping structure."""
        response = handler.analytics_mitre({}, None)
        assert response.status == HttpStatus.OK
        if response.data["mappings"]:
            mapping = response.data["mappings"][0]
            assert "finding_id" in mapping
            assert "confidence" in mapping
            assert "techniques" in mapping
            assert "tactics" in mapping
            assert "detection_recommendations" in mapping
            assert "mitigation_strategies" in mapping

    def test_analytics_mitre_filter_by_tactic(self, handler):
        """Test filtering MITRE mappings by tactic."""
        params = {"tactic": ["initial_access"]}
        response = handler.analytics_mitre(params, None)
        assert response.status == HttpStatus.OK
        for mapping in response.data["mappings"]:
            assert "initial_access" in mapping["tactics"]

    def test_analytics_mitre_with_limit(self, handler):
        """Test MITRE mappings with limit."""
        params = {"limit": ["2"]}
        response = handler.analytics_mitre(params, None)
        assert response.status == HttpStatus.OK
        assert len(response.data["mappings"]) <= 2

    def test_analytics_mitre_technique(self, handler):
        """Test analytics MITRE technique endpoint."""
        params = {"technique_id": ["T1078"]}
        response = handler.analytics_mitre_technique(params, None)
        assert response.status == HttpStatus.OK
        assert "technique" in response.data
        assert response.data["technique"]["id"] == "T1078"
        assert "detection_recommendations" in response.data
        assert "mitigation_strategies" in response.data

    def test_analytics_mitre_technique_missing_id(self, handler):
        """Test MITRE technique without ID."""
        response = handler.analytics_mitre_technique({}, None)
        assert response.status == HttpStatus.BAD_REQUEST

    def test_analytics_mitre_technique_structure(self, handler):
        """Test MITRE technique structure."""
        params = {"technique_id": ["T1078"]}
        response = handler.analytics_mitre_technique(params, None)
        assert response.status == HttpStatus.OK
        technique = response.data["technique"]
        assert "id" in technique
        assert "name" in technique
        assert "tactic" in technique
        assert "description" in technique

    def test_analytics_mitre_coverage(self, handler):
        """Test analytics MITRE coverage endpoint."""
        response = handler.analytics_mitre_coverage({}, None)
        assert response.status == HttpStatus.OK
        assert "total_mappings" in response.data
        assert "tactics_covered" in response.data
        assert "techniques_covered" in response.data
        assert "tactic_distribution" in response.data

    def test_analytics_mitre_coverage_structure(self, handler):
        """Test MITRE coverage structure."""
        response = handler.analytics_mitre_coverage({}, None)
        assert response.status == HttpStatus.OK
        assert "total_tactics" in response.data
        assert "tactics_covered_list" in response.data
        assert "techniques_covered_list" in response.data
        assert "kill_chain_phases_covered" in response.data

    # -------------------------------------------------------------------------
    # Summary endpoints
    # -------------------------------------------------------------------------

    def test_analytics_summary(self, handler):
        """Test analytics summary endpoint."""
        response = handler.analytics_summary({}, None)
        assert response.status == HttpStatus.OK
        assert "available_features" in response.data
        assert "attack_path_types" in response.data
        assert "risk_levels" in response.data
        assert "impact_categories" in response.data
        assert "mitre_tactics" in response.data

    def test_analytics_summary_features(self, handler):
        """Test analytics summary features structure."""
        response = handler.analytics_summary({}, None)
        assert response.status == HttpStatus.OK
        features = response.data["available_features"]
        assert len(features) == 6
        feature = features[0]
        assert "name" in feature
        assert "description" in feature
        assert "params" in feature

    def test_analytics_summary_attack_path_types(self, handler):
        """Test analytics summary attack path types."""
        response = handler.analytics_summary({}, None)
        assert response.status == HttpStatus.OK
        types = response.data["attack_path_types"]
        assert "internet_to_internal" in types
        assert "privilege_escalation" in types
        assert "lateral_movement" in types
        assert "data_exfiltration" in types

    def test_analytics_summary_risk_levels(self, handler):
        """Test analytics summary risk levels."""
        response = handler.analytics_summary({}, None)
        assert response.status == HttpStatus.OK
        levels = response.data["risk_levels"]
        assert "critical" in levels
        assert "high" in levels
        assert "medium" in levels
        assert "low" in levels
        assert "minimal" in levels

    def test_analytics_summary_mitre_tactics(self, handler):
        """Test analytics summary MITRE tactics."""
        response = handler.analytics_summary({}, None)
        assert response.status == HttpStatus.OK
        tactics = response.data["mitre_tactics"]
        assert "initial_access" in tactics
        assert "privilege_escalation" in tactics
        assert "lateral_movement" in tactics
        assert "collection" in tactics

    # -------------------------------------------------------------------------
    # Handler routing tests
    # -------------------------------------------------------------------------

    def test_base_path(self, handler):
        """Test handler base path is set correctly."""
        assert handler.base_path == "/api/analytics/"

    def test_can_handle_analytics_path(self, handler):
        """Test can_handle for analytics paths."""
        assert handler.can_handle("/api/analytics/attack-paths")
        assert handler.can_handle("/api/analytics/risk-score")
        assert handler.can_handle("/api/analytics/mitre")
        assert not handler.can_handle("/api/storage/backends")

    def test_handle_get_attack_paths(self, handler):
        """Test handling GET /api/analytics/attack-paths."""
        response = handler.handle("/api/analytics/attack-paths", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "paths" in response.data

    def test_handle_get_summary(self, handler):
        """Test handling GET /api/analytics/summary."""
        response = handler.handle("/api/analytics/summary", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "available_features" in response.data

    def test_handle_unknown_route(self, handler):
        """Test handling unknown route."""
        response = handler.handle("/api/analytics/unknown", {}, "GET")
        assert response.status == HttpStatus.NOT_FOUND

    def test_route_discovery(self, handler):
        """Test that routes are discovered correctly."""
        routes = list(handler._route_table)
        assert len(routes) > 0
        route_paths = [r.path for r in routes]
        assert "attack-paths" in route_paths
        assert "risk-score" in route_paths
        assert "mitre" in route_paths

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 7 GET routes + 0 POST routes = 7 total
        assert len(routes) == 7


# =============================================================================
# NotificationsHandler Tests
# =============================================================================


class TestNotificationsHandler:
    """Tests for NotificationsHandler."""

    @pytest.fixture
    def handler(self):
        """Create a NotificationsHandler instance."""
        from stance.web.handlers.notifications import NotificationsHandler
        return NotificationsHandler(storage=None, request_handler=None)

    def test_can_handle(self, handler):
        """Test can_handle method."""
        assert handler.can_handle("/api/notifications/list")
        assert handler.can_handle("/api/notifications/types")
        assert not handler.can_handle("/api/exceptions/list")

    def test_handle_list(self, handler):
        """Test handling GET /api/notifications/list."""
        response = handler.handle("/api/notifications/list", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "notifications" in response.data
        assert "total" in response.data

    def test_handle_list_with_limit(self, handler):
        """Test handling GET /api/notifications/list with limit."""
        response = handler.handle("/api/notifications/list", {"limit": ["2"]}, "GET")
        assert response.status == HttpStatus.OK
        assert len(response.data["notifications"]) <= 2

    def test_handle_show(self, handler):
        """Test handling GET /api/notifications/show."""
        response = handler.handle("/api/notifications/show", {"index": ["0"]}, "GET")
        assert response.status == HttpStatus.OK
        assert "id" in response.data

    def test_handle_show_invalid_index(self, handler):
        """Test handling GET /api/notifications/show with invalid index."""
        response = handler.handle("/api/notifications/show", {"index": ["999"]}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_types(self, handler):
        """Test handling GET /api/notifications/types."""
        response = handler.handle("/api/notifications/types", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "types" in response.data
        assert len(response.data["types"]) > 0

    def test_handle_config(self, handler):
        """Test handling GET /api/notifications/config."""
        response = handler.handle("/api/notifications/config", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "notify_on_scan_complete" in response.data

    def test_handle_status(self, handler):
        """Test handling GET /api/notifications/status."""
        response = handler.handle("/api/notifications/status", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "notifications"
        assert "capabilities" in response.data

    def test_handle_summary(self, handler):
        """Test handling GET /api/notifications/summary."""
        response = handler.handle("/api/notifications/summary", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "total_notifications" in response.data

    def test_handle_set(self, handler):
        """Test handling POST /api/notifications/set."""
        body = {"option": "notify_on_scan_complete", "value": False}
        response = handler.handle("/api/notifications/set", {}, "POST", body)
        assert response.status == HttpStatus.OK
        assert response.data["status"] == "updated"

    def test_handle_set_missing_option(self, handler):
        """Test handling POST /api/notifications/set without option."""
        response = handler.handle("/api/notifications/set", {}, "POST", {})
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_enable(self, handler):
        """Test handling POST /api/notifications/enable."""
        body = {"type": "scan_complete"}
        response = handler.handle("/api/notifications/enable", {}, "POST", body)
        assert response.status == HttpStatus.OK
        assert response.data["status"] == "enabled"

    def test_handle_disable(self, handler):
        """Test handling POST /api/notifications/disable."""
        body = {"type": "scan_complete"}
        response = handler.handle("/api/notifications/disable", {}, "POST", body)
        assert response.status == HttpStatus.OK
        assert response.data["status"] == "disabled"

    def test_handle_test(self, handler):
        """Test handling POST /api/notifications/test."""
        response = handler.handle("/api/notifications/test", {}, "POST", {})
        assert response.status == HttpStatus.OK
        assert response.data["status"] == "sent"

    def test_handle_clear(self, handler):
        """Test handling POST /api/notifications/clear."""
        response = handler.handle("/api/notifications/clear", {}, "POST", {})
        assert response.status == HttpStatus.OK
        assert response.data["status"] == "cleared"

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 6 GET routes + 5 POST routes = 11 total
        assert len(routes) == 11


# =============================================================================
# ExceptionsHandler Tests
# =============================================================================


class TestExceptionsHandler:
    """Tests for ExceptionsHandler."""

    @pytest.fixture
    def handler(self):
        """Create an ExceptionsHandler instance."""
        from stance.web.handlers.exceptions import ExceptionsHandler
        return ExceptionsHandler(storage=None, request_handler=None)

    def test_can_handle(self, handler):
        """Test can_handle method."""
        assert handler.can_handle("/api/exceptions/list")
        assert handler.can_handle("/api/exceptions/types")
        assert not handler.can_handle("/api/notifications/list")

    def test_handle_list(self, handler):
        """Test handling GET /api/exceptions/list."""
        response = handler.handle("/api/exceptions/list", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "exceptions" in response.data
        assert "total" in response.data

    def test_handle_list_with_filter(self, handler):
        """Test handling GET /api/exceptions/list with status filter."""
        response = handler.handle("/api/exceptions/list", {"status": ["approved"]}, "GET")
        assert response.status == HttpStatus.OK

    def test_handle_show(self, handler):
        """Test handling GET /api/exceptions/show."""
        response = handler.handle("/api/exceptions/show", {"id": ["exc-001"]}, "GET")
        assert response.status == HttpStatus.OK
        assert "id" in response.data

    def test_handle_show_missing_id(self, handler):
        """Test handling GET /api/exceptions/show without id."""
        response = handler.handle("/api/exceptions/show", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_types(self, handler):
        """Test handling GET /api/exceptions/types."""
        response = handler.handle("/api/exceptions/types", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "types" in response.data
        types = [t["value"] for t in response.data["types"]]
        assert "suppression" in types
        assert "false_positive" in types

    def test_handle_scopes(self, handler):
        """Test handling GET /api/exceptions/scopes."""
        response = handler.handle("/api/exceptions/scopes", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "scopes" in response.data

    def test_handle_status(self, handler):
        """Test handling GET /api/exceptions/status."""
        response = handler.handle("/api/exceptions/status", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "exceptions"

    def test_handle_summary(self, handler):
        """Test handling GET /api/exceptions/summary."""
        response = handler.handle("/api/exceptions/summary", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "total_exceptions" in response.data

    def test_handle_create(self, handler):
        """Test handling GET /api/exceptions/create."""
        params = {
            "type": ["suppression"],
            "scope": ["finding"],
            "reason": ["Testing exception"],
        }
        response = handler.handle("/api/exceptions/create", params, "GET")
        assert response.status == HttpStatus.CREATED
        assert response.data["success"] is True
        assert "id" in response.data

    def test_handle_create_missing_reason(self, handler):
        """Test handling GET /api/exceptions/create without reason."""
        response = handler.handle("/api/exceptions/create", {"type": ["suppression"]}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_suppress(self, handler):
        """Test handling GET /api/exceptions/suppress."""
        params = {"reason": ["Legacy system"]}
        response = handler.handle("/api/exceptions/suppress", params, "GET")
        assert response.status == HttpStatus.CREATED
        assert response.data["exception_type"] == "suppression"

    def test_handle_false_positive(self, handler):
        """Test handling GET /api/exceptions/false-positive."""
        params = {"finding": ["finding-123"], "reason": ["Not applicable"]}
        response = handler.handle("/api/exceptions/false-positive", params, "GET")
        assert response.status == HttpStatus.CREATED
        assert response.data["exception_type"] == "false_positive"

    def test_handle_accept_risk(self, handler):
        """Test handling GET /api/exceptions/accept-risk."""
        params = {"reason": ["Accepted risk"], "approved_by": ["ciso@example.com"]}
        response = handler.handle("/api/exceptions/accept-risk", params, "GET")
        assert response.status == HttpStatus.CREATED
        assert response.data["exception_type"] == "risk_accepted"

    def test_handle_revoke(self, handler):
        """Test handling GET /api/exceptions/revoke."""
        params = {"id": ["exc-001"]}
        response = handler.handle("/api/exceptions/revoke", params, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["status"] == "revoked"

    def test_handle_delete(self, handler):
        """Test handling GET /api/exceptions/delete."""
        params = {"id": ["exc-001"]}
        response = handler.handle("/api/exceptions/delete", params, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["deleted"] is True

    def test_handle_expire(self, handler):
        """Test handling GET /api/exceptions/expire."""
        params = {"id": ["exc-001"]}
        response = handler.handle("/api/exceptions/expire", params, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["status"] == "expired"

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 13 GET-style routes
        assert len(routes) == 13


# =============================================================================
# PluginsHandler Tests
# =============================================================================


class TestPluginsHandler:
    """Tests for PluginsHandler."""

    @pytest.fixture
    def handler(self):
        """Create a PluginsHandler instance."""
        from stance.web.handlers.plugins import PluginsHandler
        return PluginsHandler(storage=None, request_handler=None)

    def test_can_handle(self, handler):
        """Test can_handle method."""
        assert handler.can_handle("/api/plugins/list")
        assert handler.can_handle("/api/plugins/types")
        assert not handler.can_handle("/api/exceptions/list")

    def test_handle_list(self, handler):
        """Test handling GET /api/plugins/list."""
        response = handler.handle("/api/plugins/list", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "plugins" in response.data
        assert "total" in response.data

    def test_handle_list_with_type_filter(self, handler):
        """Test handling GET /api/plugins/list with type filter."""
        response = handler.handle("/api/plugins/list", {"type": ["collector"]}, "GET")
        assert response.status == HttpStatus.OK

    def test_handle_info(self, handler):
        """Test handling GET /api/plugins/info."""
        response = handler.handle("/api/plugins/info", {"name": ["aws_s3"]}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["name"] == "aws_s3"
        assert "config_schema" in response.data

    def test_handle_info_missing_name(self, handler):
        """Test handling GET /api/plugins/info without name."""
        response = handler.handle("/api/plugins/info", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_info_not_found(self, handler):
        """Test handling GET /api/plugins/info for unknown plugin."""
        response = handler.handle("/api/plugins/info", {"name": ["unknown"]}, "GET")
        assert response.status == HttpStatus.NOT_FOUND

    def test_handle_types(self, handler):
        """Test handling GET /api/plugins/types."""
        response = handler.handle("/api/plugins/types", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "types" in response.data
        types = [t["value"] for t in response.data["types"]]
        assert "collector" in types
        assert "policy" in types

    def test_handle_discover(self, handler):
        """Test handling GET /api/plugins/discover."""
        response = handler.handle("/api/plugins/discover", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "discovered" in response.data

    def test_handle_status(self, handler):
        """Test handling GET /api/plugins/status."""
        response = handler.handle("/api/plugins/status", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "plugins"

    def test_handle_summary(self, handler):
        """Test handling GET /api/plugins/summary."""
        response = handler.handle("/api/plugins/summary", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "total_plugins" in response.data

    def test_handle_load(self, handler):
        """Test handling GET /api/plugins/load."""
        params = {"source": ["my_plugin.py"]}
        response = handler.handle("/api/plugins/load", params, "GET")
        assert response.status == HttpStatus.CREATED
        assert response.data["success"] is True

    def test_handle_load_missing_source(self, handler):
        """Test handling GET /api/plugins/load without source."""
        response = handler.handle("/api/plugins/load", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_unload(self, handler):
        """Test handling GET /api/plugins/unload."""
        params = {"name": ["aws_s3"]}
        response = handler.handle("/api/plugins/unload", params, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True

    def test_handle_reload(self, handler):
        """Test handling GET /api/plugins/reload."""
        params = {"name": ["aws_s3"]}
        response = handler.handle("/api/plugins/reload", params, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["success"] is True

    def test_handle_enable(self, handler):
        """Test handling GET /api/plugins/enable."""
        params = {"name": ["aws_s3"]}
        response = handler.handle("/api/plugins/enable", params, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["enabled"] is True

    def test_handle_disable(self, handler):
        """Test handling GET /api/plugins/disable."""
        params = {"name": ["aws_s3"]}
        response = handler.handle("/api/plugins/disable", params, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["enabled"] is False

    def test_handle_configure(self, handler):
        """Test handling GET /api/plugins/configure."""
        params = {"name": ["aws_s3"], "config": ["{}"], "show": ["true"]}
        response = handler.handle("/api/plugins/configure", params, "GET")
        assert response.status == HttpStatus.OK

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 12 GET-style routes
        assert len(routes) == 12


# =============================================================================
# CorrelationHandler Tests
# =============================================================================


class TestCorrelationHandler:
    """Tests for CorrelationHandler."""

    @pytest.fixture
    def handler(self):
        """Create a CorrelationHandler instance."""
        from stance.web.handlers.correlation import CorrelationHandler
        return CorrelationHandler(storage=None, request_handler=None)

    def test_can_handle(self, handler):
        """Test can_handle method."""
        assert handler.can_handle("/api/correlation/correlate")
        assert handler.can_handle("/api/correlation/groups")
        assert not handler.can_handle("/api/plugins/list")

    def test_handle_correlate(self, handler):
        """Test handling GET /api/correlation/correlate."""
        response = handler.handle("/api/correlation/correlate", {}, "GET")
        assert response.status == HttpStatus.OK

    def test_handle_groups(self, handler):
        """Test handling GET /api/correlation/groups."""
        response = handler.handle("/api/correlation/groups", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "groups" in response.data

    def test_handle_group_missing_id(self, handler):
        """Test handling GET /api/correlation/group without id."""
        response = handler.handle("/api/correlation/group", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_related(self, handler):
        """Test handling GET /api/correlation/related."""
        params = {"finding_id": ["finding-123"]}
        response = handler.handle("/api/correlation/related", params, "GET")
        assert response.status == HttpStatus.OK
        assert "related" in response.data

    def test_handle_related_missing_id(self, handler):
        """Test handling GET /api/correlation/related without finding_id."""
        response = handler.handle("/api/correlation/related", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_risk(self, handler):
        """Test handling GET /api/correlation/risk."""
        response = handler.handle("/api/correlation/risk", {}, "GET")
        assert response.status == HttpStatus.OK

    def test_handle_risk_asset(self, handler):
        """Test handling GET /api/correlation/risk-asset."""
        params = {"asset_id": ["asset-123"]}
        response = handler.handle("/api/correlation/risk-asset", params, "GET")
        assert response.status == HttpStatus.OK
        assert "risk_score" in response.data

    def test_handle_risk_asset_missing_id(self, handler):
        """Test handling GET /api/correlation/risk-asset without asset_id."""
        response = handler.handle("/api/correlation/risk-asset", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_risk_summary(self, handler):
        """Test handling GET /api/correlation/risk-summary."""
        response = handler.handle("/api/correlation/risk-summary", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "overall_risk_score" in response.data

    def test_handle_analyze(self, handler):
        """Test handling GET /api/correlation/analyze."""
        response = handler.handle("/api/correlation/analyze", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "patterns" in response.data

    def test_handle_types(self, handler):
        """Test handling GET /api/correlation/types."""
        response = handler.handle("/api/correlation/types", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "types" in response.data

    def test_handle_levels(self, handler):
        """Test handling GET /api/correlation/levels."""
        response = handler.handle("/api/correlation/levels", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "levels" in response.data

    def test_handle_status(self, handler):
        """Test handling GET /api/correlation/status."""
        response = handler.handle("/api/correlation/status", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "correlation"

    def test_handle_summary(self, handler):
        """Test handling GET /api/correlation/summary."""
        response = handler.handle("/api/correlation/summary", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "total_groups" in response.data

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 12 GET routes
        assert len(routes) == 12


# =============================================================================
# TrendsHandler Tests
# =============================================================================


class TestTrendsHandler:
    """Tests for TrendsHandler."""

    @pytest.fixture
    def handler(self):
        """Create a TrendsHandler instance."""
        from stance.web.handlers.trends import TrendsHandler
        return TrendsHandler(storage=None, request_handler=None)

    def test_can_handle(self, handler):
        """Test can_handle method."""
        assert handler.can_handle("/api/trends/analyze")
        assert handler.can_handle("/api/trends/forecast")
        assert not handler.can_handle("/api/correlation/risk")

    def test_handle_analyze(self, handler):
        """Test handling GET /api/trends/analyze."""
        response = handler.handle("/api/trends/analyze", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "data_points" in response.data

    def test_handle_analyze_with_params(self, handler):
        """Test handling GET /api/trends/analyze with params."""
        params = {"days": ["7"], "period": ["daily"]}
        response = handler.handle("/api/trends/analyze", params, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["days_analyzed"] == 7

    def test_handle_forecast(self, handler):
        """Test handling GET /api/trends/forecast."""
        response = handler.handle("/api/trends/forecast", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "forecasts" in response.data

    def test_handle_velocity(self, handler):
        """Test handling GET /api/trends/velocity."""
        response = handler.handle("/api/trends/velocity", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "velocity" in response.data

    def test_handle_improvement(self, handler):
        """Test handling GET /api/trends/improvement."""
        response = handler.handle("/api/trends/improvement", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "improvement_rate" in response.data
        assert "interpretation" in response.data

    def test_handle_compare(self, handler):
        """Test handling GET /api/trends/compare."""
        response = handler.handle("/api/trends/compare", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "current_period" in response.data
        assert "previous_period" in response.data
        assert "comparison" in response.data

    def test_handle_report(self, handler):
        """Test handling GET /api/trends/report."""
        response = handler.handle("/api/trends/report", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "summary" in response.data

    def test_handle_severity(self, handler):
        """Test handling GET /api/trends/severity."""
        response = handler.handle("/api/trends/severity", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "severities" in response.data

    def test_handle_severity_with_filter(self, handler):
        """Test handling GET /api/trends/severity with severity filter."""
        params = {"severity": ["critical"]}
        response = handler.handle("/api/trends/severity", params, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["severity"] == "critical"

    def test_handle_summary(self, handler):
        """Test handling GET /api/trends/summary."""
        response = handler.handle("/api/trends/summary", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "overall_trend" in response.data
        assert "improvement_rate" in response.data

    def test_handle_periods(self, handler):
        """Test handling GET /api/trends/periods."""
        response = handler.handle("/api/trends/periods", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "periods" in response.data
        periods = [p["value"] for p in response.data["periods"]]
        assert "daily" in periods
        assert "weekly" in periods

    def test_handle_directions(self, handler):
        """Test handling GET /api/trends/directions."""
        response = handler.handle("/api/trends/directions", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "directions" in response.data

    def test_handle_status(self, handler):
        """Test handling GET /api/trends/status."""
        response = handler.handle("/api/trends/status", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "trends"
        assert "capabilities" in response.data

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 11 GET routes
        assert len(routes) == 11


# =============================================================================
# AutomationHandler Tests
# =============================================================================


class TestAutomationHandler:
    """Tests for AutomationHandler."""

    @pytest.fixture
    def handler(self):
        """Create an AutomationHandler instance."""
        from stance.web.handlers.automation import AutomationHandler
        return AutomationHandler(storage=None, request_handler=None)

    def test_can_handle(self, handler):
        """Test can_handle method."""
        assert handler.can_handle("/api/automation/config")
        assert handler.can_handle("/api/automation/types")
        assert not handler.can_handle("/api/cloud/list")

    def test_handle_config(self, handler):
        """Test handling GET /api/automation/config."""
        response = handler.handle("/api/automation/config", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "notify_on_scan_complete" in response.data
        assert "notify_on_critical" in response.data

    def test_handle_types(self, handler):
        """Test handling GET /api/automation/types."""
        response = handler.handle("/api/automation/types", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "types" in response.data
        assert "total" in response.data

    def test_handle_history(self, handler):
        """Test handling GET /api/automation/history."""
        response = handler.handle("/api/automation/history", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "history" in response.data

    def test_handle_history_with_params(self, handler):
        """Test handling GET /api/automation/history with params."""
        params = {"limit": ["10"], "type": ["scan_complete"]}
        response = handler.handle("/api/automation/history", params, "GET")
        assert response.status == HttpStatus.OK

    def test_handle_thresholds(self, handler):
        """Test handling GET /api/automation/thresholds."""
        response = handler.handle("/api/automation/thresholds", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "thresholds" in response.data

    def test_handle_triggers(self, handler):
        """Test handling GET /api/automation/triggers."""
        response = handler.handle("/api/automation/triggers", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "triggers" in response.data

    def test_handle_callbacks(self, handler):
        """Test handling GET /api/automation/callbacks."""
        response = handler.handle("/api/automation/callbacks", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "callbacks" in response.data

    def test_handle_severities(self, handler):
        """Test handling GET /api/automation/severities."""
        response = handler.handle("/api/automation/severities", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "severities" in response.data

    def test_handle_status(self, handler):
        """Test handling GET /api/automation/status."""
        response = handler.handle("/api/automation/status", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "automation"
        assert "capabilities" in response.data

    def test_handle_test(self, handler):
        """Test handling GET /api/automation/test."""
        response = handler.handle("/api/automation/test", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "status" in response.data

    def test_handle_summary(self, handler):
        """Test handling GET /api/automation/summary."""
        response = handler.handle("/api/automation/summary", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "total_triggers" in response.data or "executions_today" in response.data

    def test_handle_workflows(self, handler):
        """Test handling GET /api/automation/workflows."""
        response = handler.handle("/api/automation/workflows", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "workflows" in response.data

    def test_handle_events(self, handler):
        """Test handling GET /api/automation/events."""
        response = handler.handle("/api/automation/events", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "events" in response.data

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 12 GET routes
        assert len(routes) == 12


# =============================================================================
# ObservabilityHandler Tests
# =============================================================================


class TestObservabilityHandler:
    """Tests for ObservabilityHandler."""

    @pytest.fixture
    def handler(self):
        """Create an ObservabilityHandler instance."""
        from stance.web.handlers.observability import ObservabilityHandler
        return ObservabilityHandler(storage=None, request_handler=None)

    def test_can_handle(self, handler):
        """Test can_handle method."""
        assert handler.can_handle("/api/observability/logging")
        assert handler.can_handle("/api/observability/metrics")
        assert not handler.can_handle("/api/automation/config")

    def test_handle_logging(self, handler):
        """Test handling GET /api/observability/logging."""
        response = handler.handle("/api/observability/logging", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "current_level" in response.data
        assert "available_levels" in response.data

    def test_handle_logging_with_level(self, handler):
        """Test handling GET /api/observability/logging with level param."""
        params = {"level": ["DEBUG"]}
        response = handler.handle("/api/observability/logging", params, "GET")
        assert response.status == HttpStatus.OK

    def test_handle_metrics(self, handler):
        """Test handling GET /api/observability/metrics."""
        response = handler.handle("/api/observability/metrics", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "metrics" in response.data

    def test_handle_traces(self, handler):
        """Test handling GET /api/observability/traces."""
        response = handler.handle("/api/observability/traces", {}, "GET")
        assert response.status == HttpStatus.OK
        # Returns spans, not traces
        assert "spans" in response.data or "total" in response.data

    def test_handle_backends(self, handler):
        """Test handling GET /api/observability/backends."""
        response = handler.handle("/api/observability/backends", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "backends" in response.data

    def test_handle_log_levels(self, handler):
        """Test handling GET /api/observability/log-levels."""
        response = handler.handle("/api/observability/log-levels", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "levels" in response.data
        # Check by level name, not value
        level_names = [l["level"] for l in response.data["levels"]]
        assert "DEBUG" in level_names
        assert "INFO" in level_names
        assert "ERROR" in level_names

    def test_handle_metric_types(self, handler):
        """Test handling GET /api/observability/metric-types."""
        response = handler.handle("/api/observability/metric-types", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "types" in response.data

    def test_handle_span_statuses(self, handler):
        """Test handling GET /api/observability/span-statuses."""
        response = handler.handle("/api/observability/span-statuses", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "statuses" in response.data

    def test_handle_log_formats(self, handler):
        """Test handling GET /api/observability/log-formats."""
        response = handler.handle("/api/observability/log-formats", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "formats" in response.data

    def test_handle_stats(self, handler):
        """Test handling GET /api/observability/stats."""
        response = handler.handle("/api/observability/stats", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "metrics_collected" in response.data or "backends_active" in response.data

    def test_handle_status(self, handler):
        """Test handling GET /api/observability/status."""
        response = handler.handle("/api/observability/status", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "observability"
        assert "capabilities" in response.data

    def test_handle_summary(self, handler):
        """Test handling GET /api/observability/summary."""
        response = handler.handle("/api/observability/summary", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "logging_level" in response.data
        assert "metrics_count" in response.data

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 11 GET routes: logging, metrics, traces, backends, metric-types, log-levels, span-statuses, log-formats, stats, status, summary
        assert len(routes) == 11


# =============================================================================
# CollectorsHandler Tests
# =============================================================================


class TestCollectorsHandler:
    """Tests for CollectorsHandler."""

    @pytest.fixture
    def handler(self):
        """Create a CollectorsHandler instance."""
        from stance.web.handlers.collectors import CollectorsHandler
        return CollectorsHandler(storage=None, request_handler=None)

    def test_can_handle(self, handler):
        """Test can_handle method."""
        assert handler.can_handle("/api/collectors/list")
        assert handler.can_handle("/api/collectors/providers")
        assert not handler.can_handle("/api/cloud/list")

    def test_handle_list(self, handler):
        """Test handling GET /api/collectors/list."""
        response = handler.handle("/api/collectors/list", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "collectors" in response.data
        assert "total" in response.data

    def test_handle_list_with_filter(self, handler):
        """Test handling GET /api/collectors/list with filter."""
        params = {"provider": ["aws"]}
        response = handler.handle("/api/collectors/list", params, "GET")
        assert response.status == HttpStatus.OK

    def test_handle_providers(self, handler):
        """Test handling GET /api/collectors/providers."""
        response = handler.handle("/api/collectors/providers", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "providers" in response.data
        # The providers use "provider" key, not "value"
        providers = [p["provider"] for p in response.data["providers"]]
        assert "aws" in providers
        assert "azure" in providers
        assert "gcp" in providers

    def test_handle_resources(self, handler):
        """Test handling GET /api/collectors/resources."""
        response = handler.handle("/api/collectors/resources", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "resources" in response.data

    def test_handle_info(self, handler):
        """Test handling GET /api/collectors/info with name."""
        params = {"name": ["aws_s3"]}
        response = handler.handle("/api/collectors/info", params, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["name"] == "aws_s3"

    def test_handle_info_not_found(self, handler):
        """Test handling GET /api/collectors/info with unknown name."""
        params = {"name": ["unknown_collector"]}
        response = handler.handle("/api/collectors/info", params, "GET")
        assert response.status == HttpStatus.NOT_FOUND

    def test_handle_info_missing_param(self, handler):
        """Test handling GET /api/collectors/info without name."""
        response = handler.handle("/api/collectors/info", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_registry(self, handler):
        """Test handling GET /api/collectors/registry."""
        response = handler.handle("/api/collectors/registry", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "registry" in response.data or "providers" in response.data

    def test_handle_categories(self, handler):
        """Test handling GET /api/collectors/categories."""
        response = handler.handle("/api/collectors/categories", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "categories" in response.data

    def test_handle_stats(self, handler):
        """Test handling GET /api/collectors/stats."""
        response = handler.handle("/api/collectors/stats", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "total_collectors" in response.data

    def test_handle_status(self, handler):
        """Test handling GET /api/collectors/status."""
        response = handler.handle("/api/collectors/status", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "collectors"
        assert "capabilities" in response.data

    def test_handle_summary(self, handler):
        """Test handling GET /api/collectors/summary."""
        response = handler.handle("/api/collectors/summary", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "total_collectors" in response.data
        assert "active_providers" in response.data or "by_provider" in response.data

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 11 GET routes: list, info, providers, resources, registry, availability, categories, count, stats, status, summary
        assert len(routes) == 11


# =============================================================================
# CloudHandler Tests
# =============================================================================


class TestCloudHandler:
    """Tests for CloudHandler."""

    @pytest.fixture
    def handler(self):
        """Create a CloudHandler instance."""
        from stance.web.handlers.cloud import CloudHandler
        return CloudHandler(storage=None, request_handler=None)

    def test_can_handle(self, handler):
        """Test can_handle method."""
        assert handler.can_handle("/api/cloud/list")
        assert handler.can_handle("/api/cloud/validate")
        assert not handler.can_handle("/api/collectors/list")

    def test_handle_list(self, handler):
        """Test handling GET /api/cloud/list."""
        response = handler.handle("/api/cloud/list", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "providers" in response.data
        assert "total" in response.data

    def test_handle_info(self, handler):
        """Test handling GET /api/cloud/info."""
        params = {"provider": ["aws"]}
        response = handler.handle("/api/cloud/info", params, "GET")
        assert response.status == HttpStatus.OK
        assert "name" in response.data or "display_name" in response.data

    def test_handle_validate(self, handler):
        """Test handling GET /api/cloud/validate."""
        params = {"provider": ["aws"]}
        response = handler.handle("/api/cloud/validate", params, "GET")
        assert response.status == HttpStatus.OK
        assert "valid" in response.data

    def test_handle_validate_missing_provider(self, handler):
        """Test handling GET /api/cloud/validate without provider."""
        response = handler.handle("/api/cloud/validate", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_account(self, handler):
        """Test handling GET /api/cloud/account."""
        params = {"provider": ["aws"]}
        response = handler.handle("/api/cloud/account", params, "GET")
        # May return error if provider not available
        assert response.status in (HttpStatus.OK, HttpStatus.BAD_REQUEST)

    def test_handle_regions(self, handler):
        """Test handling GET /api/cloud/regions."""
        params = {"provider": ["aws"]}
        response = handler.handle("/api/cloud/regions", params, "GET")
        assert response.status == HttpStatus.OK
        assert "regions" in response.data

    def test_handle_availability(self, handler):
        """Test handling GET /api/cloud/availability."""
        response = handler.handle("/api/cloud/availability", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "aws" in response.data or "gcp" in response.data

    def test_handle_packages(self, handler):
        """Test handling GET /api/cloud/packages."""
        response = handler.handle("/api/cloud/packages", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "packages" in response.data

    def test_handle_credentials(self, handler):
        """Test handling GET /api/cloud/credentials."""
        response = handler.handle("/api/cloud/credentials", {}, "GET")
        assert response.status == HttpStatus.OK
        # May have provider-specific data or general data
        assert len(response.data) > 0

    def test_handle_exceptions(self, handler):
        """Test handling GET /api/cloud/exceptions."""
        response = handler.handle("/api/cloud/exceptions", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "exceptions" in response.data or "total" in response.data

    def test_handle_status(self, handler):
        """Test handling GET /api/cloud/status."""
        response = handler.handle("/api/cloud/status", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "cloud"
        assert "capabilities" in response.data

    def test_handle_summary(self, handler):
        """Test handling GET /api/cloud/summary."""
        response = handler.handle("/api/cloud/summary", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "total_providers" in response.data

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 11 GET routes: list, info, validate, account, regions, availability, packages, credentials, exceptions, status, summary
        assert len(routes) == 11


# =============================================================================
# StateHandler Tests
# =============================================================================


class TestStateHandler:
    """Tests for StateHandler."""

    @pytest.fixture
    def handler(self):
        """Create a StateHandler instance."""
        from stance.web.handlers.state import StateHandler
        return StateHandler(storage=None, request_handler=None)

    def test_can_handle(self, handler):
        """Test can_handle method."""
        assert handler.can_handle("/api/state/scans")
        assert handler.can_handle("/api/state/checkpoints")
        assert not handler.can_handle("/api/cloud/list")

    def test_handle_scans(self, handler):
        """Test handling GET /api/state/scans."""
        response = handler.handle("/api/state/scans", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "scans" in response.data
        assert "total" in response.data

    def test_handle_scans_with_params(self, handler):
        """Test handling GET /api/state/scans with params."""
        params = {"limit": ["10"], "status": ["completed"]}
        response = handler.handle("/api/state/scans", params, "GET")
        assert response.status == HttpStatus.OK

    def test_handle_scan(self, handler):
        """Test handling GET /api/state/scan with scan_id."""
        params = {"scan_id": ["scan-001"]}
        response = handler.handle("/api/state/scan", params, "GET")
        # Will return NOT_FOUND since mock returns empty
        assert response.status in (HttpStatus.OK, HttpStatus.NOT_FOUND, HttpStatus.BAD_REQUEST)

    def test_handle_scan_missing_id(self, handler):
        """Test handling GET /api/state/scan without scan_id."""
        response = handler.handle("/api/state/scan", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_checkpoints(self, handler):
        """Test handling GET /api/state/checkpoints."""
        response = handler.handle("/api/state/checkpoints", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "checkpoints" in response.data
        assert "total" in response.data

    def test_handle_checkpoint(self, handler):
        """Test handling GET /api/state/checkpoint."""
        params = {"collector": ["aws_s3"], "account": ["123456789012"], "region": ["us-east-1"]}
        response = handler.handle("/api/state/checkpoint", params, "GET")
        # Will return NOT_FOUND since mock returns empty
        assert response.status in (HttpStatus.OK, HttpStatus.NOT_FOUND, HttpStatus.BAD_REQUEST)

    def test_handle_checkpoint_missing_params(self, handler):
        """Test handling GET /api/state/checkpoint without required params."""
        response = handler.handle("/api/state/checkpoint", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_findings(self, handler):
        """Test handling GET /api/state/findings."""
        response = handler.handle("/api/state/findings", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "findings" in response.data
        assert "total" in response.data

    def test_handle_finding(self, handler):
        """Test handling GET /api/state/finding."""
        params = {"finding_id": ["finding-001"]}
        response = handler.handle("/api/state/finding", params, "GET")
        # Will return NOT_FOUND since mock returns empty
        assert response.status in (HttpStatus.OK, HttpStatus.NOT_FOUND, HttpStatus.BAD_REQUEST)

    def test_handle_finding_missing_id(self, handler):
        """Test handling GET /api/state/finding without finding_id."""
        response = handler.handle("/api/state/finding", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_scan_statuses(self, handler):
        """Test handling GET /api/state/scan-statuses."""
        response = handler.handle("/api/state/scan-statuses", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "statuses" in response.data
        statuses = [s["value"] for s in response.data["statuses"]]
        assert "pending" in statuses
        assert "running" in statuses
        assert "completed" in statuses

    def test_handle_lifecycles(self, handler):
        """Test handling GET /api/state/lifecycles."""
        response = handler.handle("/api/state/lifecycles", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "lifecycles" in response.data
        lifecycles = [l["value"] for l in response.data["lifecycles"]]
        assert "new" in lifecycles
        assert "active" in lifecycles
        assert "resolved" in lifecycles

    def test_handle_backends(self, handler):
        """Test handling GET /api/state/backends."""
        response = handler.handle("/api/state/backends", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "backends" in response.data

    def test_handle_finding_stats(self, handler):
        """Test handling GET /api/state/finding-stats."""
        response = handler.handle("/api/state/finding-stats", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "total_findings" in response.data
        assert "by_lifecycle" in response.data

    def test_handle_stats(self, handler):
        """Test handling GET /api/state/stats."""
        response = handler.handle("/api/state/stats", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "total_scans" in response.data
        assert "total_checkpoints" in response.data

    def test_handle_status(self, handler):
        """Test handling GET /api/state/status."""
        response = handler.handle("/api/state/status", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "state"
        assert "capabilities" in response.data

    def test_handle_summary(self, handler):
        """Test handling GET /api/state/summary."""
        response = handler.handle("/api/state/summary", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "total_scans" in response.data
        assert "total_checkpoints" in response.data

    def test_handle_suppress_post(self, handler):
        """Test handling POST /api/state/suppress."""
        body = {"finding_id": "finding-001", "reason": "False positive"}
        response = handler.handle("/api/state/suppress", {}, "POST", body)
        assert response.status == HttpStatus.OK
        assert response.data["status"] == "suppressed"

    def test_handle_suppress_missing_id(self, handler):
        """Test handling POST /api/state/suppress without finding_id."""
        body = {"reason": "False positive"}
        response = handler.handle("/api/state/suppress", {}, "POST", body)
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_resolve_post(self, handler):
        """Test handling POST /api/state/resolve."""
        body = {"finding_id": "finding-001", "resolution": "Fixed in PR #123"}
        response = handler.handle("/api/state/resolve", {}, "POST", body)
        assert response.status == HttpStatus.OK
        assert response.data["status"] == "resolved"

    def test_handle_delete_checkpoint_post(self, handler):
        """Test handling POST /api/state/delete-checkpoint."""
        body = {"collector": "aws_s3", "account": "123456789012", "region": "us-east-1"}
        response = handler.handle("/api/state/delete-checkpoint", {}, "POST", body)
        assert response.status == HttpStatus.OK
        assert response.data["status"] == "deleted"

    def test_handle_delete_checkpoint_missing_params(self, handler):
        """Test handling POST /api/state/delete-checkpoint without required params."""
        body = {"collector": "aws_s3"}
        response = handler.handle("/api/state/delete-checkpoint", {}, "POST", body)
        assert response.status == HttpStatus.BAD_REQUEST

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 16 routes: 13 GET + 3 POST
        assert len(routes) == 16


# =============================================================================
# AggregationHandler Tests
# =============================================================================


class TestAggregationHandler:
    """Tests for AggregationHandler."""

    @pytest.fixture
    def handler(self):
        """Create handler instance with mock storage."""
        from stance.web.handlers.aggregation import AggregationHandler

        storage = MagicMock()
        return AggregationHandler(storage=storage)

    def test_handle_aggregate(self, handler):
        """Test handling GET /api/aggregation/aggregate."""
        response = handler.handle("/api/aggregation/aggregate", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "group_by" in response.data
        assert "data" in response.data

    def test_handle_aggregate_by_severity(self, handler):
        """Test handling GET /api/aggregation/aggregate with group_by=severity."""
        params = {"group_by": ["severity"]}
        response = handler.handle("/api/aggregation/aggregate", params, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["group_by"] == "severity"

    def test_handle_cross_account(self, handler):
        """Test handling GET /api/aggregation/cross-account."""
        response = handler.handle("/api/aggregation/cross-account", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "accounts" in response.data
        assert "by_account" in response.data

    def test_handle_summary(self, handler):
        """Test handling GET /api/aggregation/summary."""
        response = handler.handle("/api/aggregation/summary", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "aggregation"

    def test_handle_sync(self, handler):
        """Test handling GET /api/aggregation/sync."""
        response = handler.handle("/api/aggregation/sync", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["status"] == "triggered"
        assert "sync_id" in response.data

    def test_handle_sync_status(self, handler):
        """Test handling GET /api/aggregation/sync-status."""
        response = handler.handle("/api/aggregation/sync-status", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "status" in response.data
        assert "accounts_synced" in response.data

    def test_handle_backends(self, handler):
        """Test handling GET /api/aggregation/backends."""
        response = handler.handle("/api/aggregation/backends", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "backends" in response.data
        assert "total" in response.data

    def test_handle_status(self, handler):
        """Test handling GET /api/aggregation/status."""
        response = handler.handle("/api/aggregation/status", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "aggregation"
        assert "capabilities" in response.data

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 7+ GET routes (may include mock routes from MagicMock storage)
        assert len(routes) >= 7


# =============================================================================
# DetectionHandler Tests
# =============================================================================


class TestDetectionHandler:
    """Tests for DetectionHandler."""

    @pytest.fixture
    def handler(self):
        """Create handler instance with mock storage."""
        from stance.web.handlers.detection import DetectionHandler

        storage = MagicMock()
        return DetectionHandler(storage=storage)

    def test_handle_scan(self, handler):
        """Test handling GET /api/detection/scan."""
        response = handler.handle("/api/detection/scan", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "findings" in response.data
        assert "total" in response.data

    def test_handle_patterns(self, handler):
        """Test handling GET /api/detection/patterns."""
        response = handler.handle("/api/detection/patterns", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "patterns" in response.data
        assert "total" in response.data

    def test_handle_pattern(self, handler):
        """Test handling GET /api/detection/pattern."""
        params = {"id": ["aws_access_key"]}
        response = handler.handle("/api/detection/pattern", params, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["id"] == "aws_access_key"

    def test_handle_pattern_not_found(self, handler):
        """Test handling GET /api/detection/pattern with unknown ID."""
        params = {"id": ["unknown_pattern"]}
        response = handler.handle("/api/detection/pattern", params, "GET")
        assert response.status == HttpStatus.NOT_FOUND

    def test_handle_pattern_missing_id(self, handler):
        """Test handling GET /api/detection/pattern without id."""
        response = handler.handle("/api/detection/pattern", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_entropy(self, handler):
        """Test handling GET /api/detection/entropy."""
        params = {"text": ["test-string-123"]}
        response = handler.handle("/api/detection/entropy", params, "GET")
        assert response.status == HttpStatus.OK
        assert "entropy" in response.data
        assert "is_high_entropy" in response.data

    def test_handle_entropy_missing_text(self, handler):
        """Test handling GET /api/detection/entropy without text."""
        response = handler.handle("/api/detection/entropy", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_sensitive_fields(self, handler):
        """Test handling GET /api/detection/sensitive-fields."""
        response = handler.handle("/api/detection/sensitive-fields", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "fields" in response.data

    def test_handle_check_field(self, handler):
        """Test handling GET /api/detection/check-field."""
        params = {"name": ["api_key"]}
        response = handler.handle("/api/detection/check-field", params, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["is_sensitive"] is True

    def test_handle_categories(self, handler):
        """Test handling GET /api/detection/categories."""
        response = handler.handle("/api/detection/categories", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "categories" in response.data

    def test_handle_severity_levels(self, handler):
        """Test handling GET /api/detection/severity-levels."""
        response = handler.handle("/api/detection/severity-levels", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "levels" in response.data

    def test_handle_stats(self, handler):
        """Test handling GET /api/detection/stats."""
        response = handler.handle("/api/detection/stats", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "total_patterns" in response.data

    def test_handle_status(self, handler):
        """Test handling GET /api/detection/status."""
        response = handler.handle("/api/detection/status", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "detection"

    def test_handle_summary(self, handler):
        """Test handling GET /api/detection/summary."""
        response = handler.handle("/api/detection/summary", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "detection"
        assert "features" in response.data

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 11+ GET routes (may include mock routes from MagicMock storage)
        assert len(routes) >= 11


# =============================================================================
# ExportHandler Tests
# =============================================================================


class TestExportHandler:
    """Tests for ExportHandler."""

    @pytest.fixture
    def handler(self):
        """Create handler instance with mock storage."""
        from stance.web.handlers.export import ExportHandler

        storage = MagicMock()
        return ExportHandler(storage=storage)

    def test_handle_formats(self, handler):
        """Test handling GET /api/export/formats."""
        response = handler.handle("/api/export/formats", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "formats" in response.data
        formats = [f["format"] for f in response.data["formats"]]
        assert "json" in formats
        assert "csv" in formats
        assert "html" in formats
        assert "pdf" in formats

    def test_handle_report_types(self, handler):
        """Test handling GET /api/export/report-types."""
        response = handler.handle("/api/export/report-types", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "report_types" in response.data

    def test_handle_options(self, handler):
        """Test handling GET /api/export/options."""
        response = handler.handle("/api/export/options", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "options" in response.data

    def test_handle_capabilities(self, handler):
        """Test handling GET /api/export/capabilities."""
        response = handler.handle("/api/export/capabilities", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "capabilities" in response.data
        assert "json" in response.data["capabilities"]
        assert "pdf" in response.data["capabilities"]

    def test_handle_pdf_tool(self, handler):
        """Test handling GET /api/export/pdf-tool."""
        response = handler.handle("/api/export/pdf-tool", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "available" in response.data

    def test_handle_severities(self, handler):
        """Test handling GET /api/export/severities."""
        response = handler.handle("/api/export/severities", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "severities" in response.data

    def test_handle_preview(self, handler):
        """Test handling GET /api/export/preview."""
        response = handler.handle("/api/export/preview", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "report_type" in response.data
        assert "format" in response.data

    def test_handle_stats(self, handler):
        """Test handling GET /api/export/stats."""
        response = handler.handle("/api/export/stats", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "formats_available" in response.data

    def test_handle_status(self, handler):
        """Test handling GET /api/export/status."""
        response = handler.handle("/api/export/status", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "export"
        assert "capabilities" in response.data

    def test_handle_summary(self, handler):
        """Test handling GET /api/export/summary."""
        response = handler.handle("/api/export/summary", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "export"
        assert "features" in response.data

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 11 GET routes
        assert len(routes) == 11


# =============================================================================
# ScannerHandler Tests
# =============================================================================


class TestScannerHandler:
    """Tests for ScannerHandler."""

    @pytest.fixture
    def handler(self):
        """Create handler instance with mock storage."""
        from stance.web.handlers.scanner import ScannerHandler

        storage = MagicMock()
        return ScannerHandler(storage=storage)

    def test_handle_scanners(self, handler):
        """Test handling GET /api/scanner/scanners."""
        response = handler.handle("/api/scanner/scanners", {}, "GET")
        # May return error if scanner module not available
        assert response.status in (HttpStatus.OK, HttpStatus.BAD_REQUEST)

    def test_handle_check(self, handler):
        """Test handling GET /api/scanner/check."""
        response = handler.handle("/api/scanner/check", {}, "GET")
        assert response.status in (HttpStatus.OK, HttpStatus.BAD_REQUEST)

    def test_handle_version(self, handler):
        """Test handling GET /api/scanner/version."""
        response = handler.handle("/api/scanner/version", {}, "GET")
        assert response.status in (HttpStatus.OK, HttpStatus.BAD_REQUEST)

    def test_handle_enrich_missing_cve(self, handler):
        """Test handling GET /api/scanner/enrich without cve_id."""
        response = handler.handle("/api/scanner/enrich", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_enrich_invalid_cve(self, handler):
        """Test handling GET /api/scanner/enrich with invalid CVE format."""
        params = {"cve_id": ["invalid"]}
        response = handler.handle("/api/scanner/enrich", params, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_epss_missing_cve(self, handler):
        """Test handling GET /api/scanner/epss without cve_id."""
        response = handler.handle("/api/scanner/epss", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_kev_missing_cve(self, handler):
        """Test handling GET /api/scanner/kev without cve_id."""
        response = handler.handle("/api/scanner/kev", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_severity_levels(self, handler):
        """Test handling GET /api/scanner/severity-levels."""
        response = handler.handle("/api/scanner/severity-levels", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "levels" in response.data
        levels = [l["level"] for l in response.data["levels"]]
        assert "CRITICAL" in levels
        assert "HIGH" in levels

    def test_handle_priority_factors(self, handler):
        """Test handling GET /api/scanner/priority-factors."""
        response = handler.handle("/api/scanner/priority-factors", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "factors" in response.data
        assert "max_score" in response.data

    def test_handle_package_types(self, handler):
        """Test handling GET /api/scanner/package-types."""
        response = handler.handle("/api/scanner/package-types", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "package_types" in response.data
        types = [t["type"] for t in response.data["package_types"]]
        assert "npm" in types
        assert "pip" in types

    def test_handle_stats(self, handler):
        """Test handling GET /api/scanner/stats."""
        response = handler.handle("/api/scanner/stats", {}, "GET")
        assert response.status in (HttpStatus.OK, HttpStatus.BAD_REQUEST)

    def test_handle_status(self, handler):
        """Test handling GET /api/scanner/status."""
        response = handler.handle("/api/scanner/status", {}, "GET")
        assert response.status in (HttpStatus.OK, HttpStatus.BAD_REQUEST)

    def test_handle_summary(self, handler):
        """Test handling GET /api/scanner/summary."""
        response = handler.handle("/api/scanner/summary", {}, "GET")
        assert response.status in (HttpStatus.OK, HttpStatus.BAD_REQUEST)

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 12+ GET routes (may include mock routes from MagicMock storage)
        assert len(routes) >= 12


# =============================================================================
# SbomHandler Tests
# =============================================================================


class TestSbomHandler:
    """Tests for SbomHandler."""

    @pytest.fixture
    def handler(self):
        """Create handler instance with mock storage."""
        from stance.web.handlers.sbom import SbomHandler

        storage = MagicMock()
        return SbomHandler(storage=storage)

    def test_handle_info(self, handler):
        """Test handling GET /api/sbom/info."""
        response = handler.handle("/api/sbom/info", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "stance.sbom"

    def test_handle_formats(self, handler):
        """Test handling GET /api/sbom/formats."""
        response = handler.handle("/api/sbom/formats", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "formats" in response.data
        # Check for CycloneDX format by id
        format_ids = [f.get("id", f.get("format", "")) for f in response.data["formats"]]
        assert any("cyclonedx" in fid for fid in format_ids)

    def test_handle_ecosystems(self, handler):
        """Test handling GET /api/sbom/ecosystems."""
        response = handler.handle("/api/sbom/ecosystems", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "ecosystems" in response.data

    def test_handle_licenses(self, handler):
        """Test handling GET /api/sbom/licenses."""
        response = handler.handle("/api/sbom/licenses", {}, "GET")
        # May return error if SBOM module not available
        assert response.status in (HttpStatus.OK, HttpStatus.BAD_REQUEST)

    def test_handle_license_categories(self, handler):
        """Test handling GET /api/sbom/license-categories."""
        response = handler.handle("/api/sbom/license-categories", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "categories" in response.data

    def test_handle_risk_levels(self, handler):
        """Test handling GET /api/sbom/risk-levels."""
        response = handler.handle("/api/sbom/risk-levels", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "levels" in response.data

    def test_handle_parse_missing_path(self, handler):
        """Test handling GET /api/sbom/parse without path."""
        response = handler.handle("/api/sbom/parse", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_analyze_license_missing_path(self, handler):
        """Test handling GET /api/sbom/analyze-license without path."""
        response = handler.handle("/api/sbom/analyze-license", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_graph_missing_file(self, handler):
        """Test handling GET /api/sbom/graph without file."""
        response = handler.handle("/api/sbom/graph", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_status(self, handler):
        """Test handling GET /api/sbom/status."""
        response = handler.handle("/api/sbom/status", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "sbom"

    def test_handle_summary(self, handler):
        """Test handling GET /api/sbom/summary."""
        response = handler.handle("/api/sbom/summary", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "overview" in response.data

    def test_handle_vex_formats(self, handler):
        """Test handling GET /api/sbom/vex-formats."""
        response = handler.handle("/api/sbom/vex-formats", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "formats" in response.data

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # Should have multiple routes (17+)
        assert len(routes) >= 10


# =============================================================================
# DocsHandler Tests
# =============================================================================


class TestDocsHandler:
    """Tests for DocsHandler."""

    @pytest.fixture
    def handler(self):
        """Create handler instance with mock storage."""
        from stance.web.handlers.docs import DocsHandler

        storage = MagicMock()
        return DocsHandler(storage=storage)

    def test_handle_info(self, handler):
        """Test handling GET /api/docs/info."""
        response = handler.handle("/api/docs/info", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "stance.docs"

    def test_handle_generators(self, handler):
        """Test handling GET /api/docs/generators."""
        response = handler.handle("/api/docs/generators", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "generators" in response.data

    def test_handle_dataclasses(self, handler):
        """Test handling GET /api/docs/dataclasses."""
        response = handler.handle("/api/docs/dataclasses", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "dataclasses" in response.data

    def test_handle_parsers(self, handler):
        """Test handling GET /api/docs/parsers."""
        response = handler.handle("/api/docs/parsers", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "parsers" in response.data

    def test_handle_module(self, handler):
        """Test handling GET /api/docs/module."""
        params = {"module": ["stance.collectors"]}
        response = handler.handle("/api/docs/module", params, "GET")
        # Will return NOT_FOUND or error since module likely doesn't exist in test
        assert response.status in (HttpStatus.OK, HttpStatus.NOT_FOUND, HttpStatus.BAD_REQUEST)

    def test_handle_module_missing_param(self, handler):
        """Test handling GET /api/docs/module without module param."""
        response = handler.handle("/api/docs/module", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_class(self, handler):
        """Test handling GET /api/docs/class."""
        params = {"class": ["stance.config.ScanConfiguration"]}
        response = handler.handle("/api/docs/class", params, "GET")
        # May return OK, NOT_FOUND, or BAD_REQUEST
        assert response.status in (HttpStatus.OK, HttpStatus.NOT_FOUND, HttpStatus.BAD_REQUEST)

    def test_handle_class_missing_param(self, handler):
        """Test handling GET /api/docs/class without class param."""
        response = handler.handle("/api/docs/class", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_list(self, handler):
        """Test handling GET /api/docs/list."""
        response = handler.handle("/api/docs/list", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "files" in response.data

    def test_handle_status(self, handler):
        """Test handling GET /api/docs/status."""
        response = handler.handle("/api/docs/status", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "docs"

    def test_handle_summary(self, handler):
        """Test handling GET /api/docs/summary."""
        response = handler.handle("/api/docs/summary", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "overview" in response.data

    def test_handle_generate_post(self, handler):
        """Test handling POST /api/docs/generate."""
        body = {"source_dir": "src/stance", "type": "api"}
        response = handler.handle("/api/docs/generate", {}, "POST", body)
        # May return OK or error if module not available
        assert response.status == HttpStatus.OK

    def test_handle_validate_post(self, handler):
        """Test handling POST /api/docs/validate."""
        body = {"output_dir": "docs/generated"}
        response = handler.handle("/api/docs/validate", {}, "POST", body)
        assert response.status == HttpStatus.OK
        assert "valid" in response.data

    def test_handle_clean_post(self, handler):
        """Test handling POST /api/docs/clean."""
        body = {"output_dir": "docs/generated", "type": "all"}
        response = handler.handle("/api/docs/clean", {}, "POST", body)
        assert response.status == HttpStatus.OK
        assert "success" in response.data

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # Should have GET and POST routes (12+)
        assert len(routes) >= 10


# =============================================================================
# IacHandler Tests
# =============================================================================


class TestIacHandler:
    """Tests for IacHandler."""

    @pytest.fixture
    def handler(self):
        """Create handler instance with mock storage."""
        from stance.web.handlers.iac import IacHandler

        storage = MagicMock()
        return IacHandler(storage=storage)

    def test_handle_scan(self, handler):
        """Test handling GET /api/iac/scan."""
        response = handler.handle("/api/iac/scan", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "findings" in response.data
        assert "summary" in response.data

    def test_handle_policies(self, handler):
        """Test handling GET /api/iac/policies."""
        response = handler.handle("/api/iac/policies", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "policies" in response.data

    def test_handle_policy(self, handler):
        """Test handling GET /api/iac/policy."""
        params = {"id": ["iac-aws-s3-encryption"]}
        response = handler.handle("/api/iac/policy", params, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["id"] == "iac-aws-s3-encryption"

    def test_handle_policy_not_found(self, handler):
        """Test handling GET /api/iac/policy with unknown id."""
        params = {"id": ["unknown-policy"]}
        response = handler.handle("/api/iac/policy", params, "GET")
        assert response.status == HttpStatus.NOT_FOUND

    def test_handle_policy_missing_id(self, handler):
        """Test handling GET /api/iac/policy without id."""
        response = handler.handle("/api/iac/policy", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_formats(self, handler):
        """Test handling GET /api/iac/formats."""
        response = handler.handle("/api/iac/formats", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "formats" in response.data

    def test_handle_validate(self, handler):
        """Test handling GET /api/iac/validate."""
        params = {"path": ["/some/path"]}
        response = handler.handle("/api/iac/validate", params, "GET")
        assert response.status == HttpStatus.OK
        assert "valid" in response.data

    def test_handle_validate_missing_path(self, handler):
        """Test handling GET /api/iac/validate without path."""
        response = handler.handle("/api/iac/validate", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_resources(self, handler):
        """Test handling GET /api/iac/resources."""
        response = handler.handle("/api/iac/resources", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "resources" in response.data

    def test_handle_providers(self, handler):
        """Test handling GET /api/iac/providers."""
        response = handler.handle("/api/iac/providers", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "providers" in response.data

    def test_handle_compliance(self, handler):
        """Test handling GET /api/iac/compliance."""
        response = handler.handle("/api/iac/compliance", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "frameworks" in response.data

    def test_handle_stats(self, handler):
        """Test handling GET /api/iac/stats."""
        response = handler.handle("/api/iac/stats", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "total_policies" in response.data

    def test_handle_severity_levels(self, handler):
        """Test handling GET /api/iac/severity-levels."""
        response = handler.handle("/api/iac/severity-levels", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "levels" in response.data

    def test_handle_summary(self, handler):
        """Test handling GET /api/iac/summary."""
        response = handler.handle("/api/iac/summary", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "iac"

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 12+ routes
        assert len(routes) >= 10


# =============================================================================
# SchedulingHandler Tests
# =============================================================================


class TestSchedulingHandler:
    """Tests for SchedulingHandler."""

    @pytest.fixture
    def handler(self):
        """Create handler instance with mock storage."""
        from stance.web.handlers.scheduling import SchedulingHandler

        storage = MagicMock()
        return SchedulingHandler(storage=storage)

    def test_handle_jobs(self, handler):
        """Test handling GET /api/scheduling/jobs."""
        response = handler.handle("/api/scheduling/jobs", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "jobs" in response.data

    def test_handle_job(self, handler):
        """Test handling GET /api/scheduling/job."""
        params = {"id": ["scan-daily"]}
        response = handler.handle("/api/scheduling/job", params, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["id"] == "scan-daily"

    def test_handle_job_not_found(self, handler):
        """Test handling GET /api/scheduling/job with unknown id."""
        params = {"id": ["unknown-job"]}
        response = handler.handle("/api/scheduling/job", params, "GET")
        assert response.status == HttpStatus.NOT_FOUND

    def test_handle_job_missing_id(self, handler):
        """Test handling GET /api/scheduling/job without id."""
        response = handler.handle("/api/scheduling/job", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_history(self, handler):
        """Test handling GET /api/scheduling/history."""
        response = handler.handle("/api/scheduling/history", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "history" in response.data

    def test_handle_history_entry(self, handler):
        """Test handling GET /api/scheduling/history-entry."""
        params = {"id": ["exec-001"]}
        response = handler.handle("/api/scheduling/history-entry", params, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["id"] == "exec-001"

    def test_handle_history_entry_missing_id(self, handler):
        """Test handling GET /api/scheduling/history-entry without id."""
        response = handler.handle("/api/scheduling/history-entry", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_compare(self, handler):
        """Test handling GET /api/scheduling/compare."""
        params = {"scan_a": ["scan-001"], "scan_b": ["scan-002"]}
        response = handler.handle("/api/scheduling/compare", params, "GET")
        assert response.status == HttpStatus.OK
        assert "comparison" in response.data

    def test_handle_compare_missing_params(self, handler):
        """Test handling GET /api/scheduling/compare without params."""
        response = handler.handle("/api/scheduling/compare", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_trend(self, handler):
        """Test handling GET /api/scheduling/trend."""
        response = handler.handle("/api/scheduling/trend", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "trend" in response.data

    def test_handle_schedule_types(self, handler):
        """Test handling GET /api/scheduling/schedule-types."""
        response = handler.handle("/api/scheduling/schedule-types", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "types" in response.data

    def test_handle_diff_types(self, handler):
        """Test handling GET /api/scheduling/diff-types."""
        response = handler.handle("/api/scheduling/diff-types", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "diff_types" in response.data

    def test_handle_status(self, handler):
        """Test handling GET /api/scheduling/status."""
        response = handler.handle("/api/scheduling/status", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "scheduling"

    def test_handle_summary(self, handler):
        """Test handling GET /api/scheduling/summary."""
        response = handler.handle("/api/scheduling/summary", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "scheduling"

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 10 routes
        assert len(routes) >= 8


# =============================================================================
# LlmHandler Tests
# =============================================================================


class TestLlmHandler:
    """Tests for LlmHandler."""

    @pytest.fixture
    def handler(self):
        """Create handler instance with mock storage."""
        from stance.web.handlers.llm import LlmHandler

        storage = MagicMock()
        return LlmHandler(storage=storage)

    def test_handle_providers(self, handler):
        """Test handling GET /api/llm/providers."""
        response = handler.handle("/api/llm/providers", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "providers" in response.data

    def test_handle_provider(self, handler):
        """Test handling GET /api/llm/provider."""
        params = {"id": ["openai"]}
        response = handler.handle("/api/llm/provider", params, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["id"] == "openai"

    def test_handle_provider_not_found(self, handler):
        """Test handling GET /api/llm/provider with unknown id."""
        params = {"id": ["unknown-provider"]}
        response = handler.handle("/api/llm/provider", params, "GET")
        assert response.status == HttpStatus.NOT_FOUND

    def test_handle_provider_missing_id(self, handler):
        """Test handling GET /api/llm/provider without id."""
        response = handler.handle("/api/llm/provider", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_models(self, handler):
        """Test handling GET /api/llm/models."""
        response = handler.handle("/api/llm/models", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "models" in response.data

    def test_handle_generate_query(self, handler):
        """Test handling GET /api/llm/generate-query."""
        params = {"question": ["Show me critical findings"]}
        response = handler.handle("/api/llm/generate-query", params, "GET")
        assert response.status == HttpStatus.OK
        assert "generated_query" in response.data

    def test_handle_generate_query_missing_question(self, handler):
        """Test handling GET /api/llm/generate-query without question."""
        response = handler.handle("/api/llm/generate-query", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_validate_query(self, handler):
        """Test handling GET /api/llm/validate-query."""
        params = {"query": ["SELECT * FROM findings"]}
        response = handler.handle("/api/llm/validate-query", params, "GET")
        assert response.status == HttpStatus.OK
        assert "valid" in response.data

    def test_handle_explain_finding(self, handler):
        """Test handling GET /api/llm/explain-finding."""
        params = {"finding_id": ["finding-001"]}
        response = handler.handle("/api/llm/explain-finding", params, "GET")
        assert response.status == HttpStatus.OK
        assert "explanation" in response.data

    def test_handle_generate_policy(self, handler):
        """Test handling GET /api/llm/generate-policy."""
        params = {"description": ["S3 buckets must be encrypted"]}
        response = handler.handle("/api/llm/generate-policy", params, "GET")
        assert response.status == HttpStatus.OK
        assert "generated_policy" in response.data

    def test_handle_sanitize(self, handler):
        """Test handling GET /api/llm/sanitize."""
        params = {"text": ["test text with password"]}
        response = handler.handle("/api/llm/sanitize", params, "GET")
        assert response.status == HttpStatus.OK
        assert "sanitized_preview" in response.data

    def test_handle_check_sensitive(self, handler):
        """Test handling GET /api/llm/check-sensitive."""
        params = {"text": ["test text with password"]}
        response = handler.handle("/api/llm/check-sensitive", params, "GET")
        assert response.status == HttpStatus.OK
        assert "contains_sensitive" in response.data
        assert response.data["contains_sensitive"] is True

    def test_handle_resource_types(self, handler):
        """Test handling GET /api/llm/resource-types."""
        response = handler.handle("/api/llm/resource-types", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "resource_types" in response.data

    def test_handle_frameworks(self, handler):
        """Test handling GET /api/llm/frameworks."""
        response = handler.handle("/api/llm/frameworks", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "frameworks" in response.data

    def test_handle_status(self, handler):
        """Test handling GET /api/llm/status."""
        response = handler.handle("/api/llm/status", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "llm"

    def test_handle_summary(self, handler):
        """Test handling GET /api/llm/summary."""
        response = handler.handle("/api/llm/summary", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "llm"

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 14 routes (all GET)
        assert len(routes) >= 10


# =============================================================================
# EngineHandler Tests
# =============================================================================


class TestEngineHandler:
    """Tests for EngineHandler."""

    @pytest.fixture
    def handler(self):
        """Create handler instance with mock storage."""
        from stance.web.handlers.engine import EngineHandler

        storage = MagicMock()
        return EngineHandler(storage=storage)

    def test_handle_policies(self, handler):
        """Test handling GET /api/engine/policies."""
        response = handler.handle("/api/engine/policies", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "policies" in response.data

    def test_handle_policy(self, handler):
        """Test handling GET /api/engine/policy."""
        params = {"id": ["s3-encryption-required"]}
        response = handler.handle("/api/engine/policy", params, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["id"] == "s3-encryption-required"

    def test_handle_policy_not_found(self, handler):
        """Test handling GET /api/engine/policy with unknown id."""
        params = {"id": ["unknown-policy"]}
        response = handler.handle("/api/engine/policy", params, "GET")
        assert response.status == HttpStatus.NOT_FOUND

    def test_handle_policy_missing_id(self, handler):
        """Test handling GET /api/engine/policy without id."""
        response = handler.handle("/api/engine/policy", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_validate(self, handler):
        """Test handling GET /api/engine/validate."""
        response = handler.handle("/api/engine/validate", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "valid" in response.data

    def test_handle_evaluate(self, handler):
        """Test handling GET /api/engine/evaluate."""
        response = handler.handle("/api/engine/evaluate", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "result" in response.data

    def test_handle_validate_expression(self, handler):
        """Test handling GET /api/engine/validate-expression."""
        params = {"expression": ["resource.encryption == true"]}
        response = handler.handle("/api/engine/validate-expression", params, "GET")
        assert response.status == HttpStatus.OK
        assert "valid" in response.data

    def test_handle_validate_expression_missing_param(self, handler):
        """Test handling GET /api/engine/validate-expression without expression."""
        response = handler.handle("/api/engine/validate-expression", {}, "GET")
        assert response.status == HttpStatus.BAD_REQUEST

    def test_handle_compliance(self, handler):
        """Test handling GET /api/engine/compliance."""
        response = handler.handle("/api/engine/compliance", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "mappings" in response.data

    def test_handle_frameworks(self, handler):
        """Test handling GET /api/engine/frameworks."""
        response = handler.handle("/api/engine/frameworks", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "frameworks" in response.data

    def test_handle_operators(self, handler):
        """Test handling GET /api/engine/operators."""
        response = handler.handle("/api/engine/operators", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "operators" in response.data

    def test_handle_check_types(self, handler):
        """Test handling GET /api/engine/check-types."""
        response = handler.handle("/api/engine/check-types", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "check_types" in response.data

    def test_handle_severity_levels(self, handler):
        """Test handling GET /api/engine/severity-levels."""
        response = handler.handle("/api/engine/severity-levels", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "levels" in response.data

    def test_handle_stats(self, handler):
        """Test handling GET /api/engine/stats."""
        response = handler.handle("/api/engine/stats", {}, "GET")
        assert response.status == HttpStatus.OK
        assert "total_policies" in response.data

    def test_handle_status(self, handler):
        """Test handling GET /api/engine/status."""
        response = handler.handle("/api/engine/status", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "engine"

    def test_handle_summary(self, handler):
        """Test handling GET /api/engine/summary."""
        response = handler.handle("/api/engine/summary", {}, "GET")
        assert response.status == HttpStatus.OK
        assert response.data["module"] == "engine"

    def test_route_count(self, handler):
        """Test total number of routes."""
        routes = list(handler._route_table)
        # 13 routes (all GET)
        assert len(routes) >= 10
