"""
Base handler class for web request handlers.

This module provides the foundation for modular request handlers,
allowing the 19K+ line server.py to be split into maintainable pieces.
"""

from __future__ import annotations

import json
import logging
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, TypeVar

logger = logging.getLogger(__name__)


class HttpStatus(int, Enum):
    """HTTP status codes."""

    OK = 200
    CREATED = 201
    NO_CONTENT = 204
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    METHOD_NOT_ALLOWED = 405
    CONFLICT = 409
    UNPROCESSABLE_ENTITY = 422
    INTERNAL_SERVER_ERROR = 500
    SERVICE_UNAVAILABLE = 503


@dataclass
class HandlerResponse:
    """
    Response from a handler method.

    Encapsulates status code, data, and headers for HTTP responses.
    """

    data: Any = None
    status: HttpStatus = HttpStatus.OK
    headers: dict[str, str] = field(default_factory=dict)
    content_type: str = "application/json"

    def to_json(self) -> str:
        """Serialize response data to JSON."""
        if self.data is None:
            return ""
        return json.dumps(self.data, indent=2, default=self._json_serializer)

    @staticmethod
    def _json_serializer(obj: Any) -> Any:
        """Custom JSON serializer for complex types."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Enum):
            return obj.value
        if hasattr(obj, "__dict__"):
            return obj.__dict__
        if hasattr(obj, "to_dict"):
            return obj.to_dict()
        return str(obj)

    @classmethod
    def success(cls, data: Any = None, status: HttpStatus = HttpStatus.OK) -> "HandlerResponse":
        """Create a success response."""
        return cls(data=data, status=status)

    @classmethod
    def error(
        cls,
        message: str,
        status: HttpStatus = HttpStatus.BAD_REQUEST,
        details: dict[str, Any] | None = None,
    ) -> "HandlerResponse":
        """Create an error response."""
        error_data = {"error": message}
        if details:
            error_data["details"] = details
        return cls(data=error_data, status=status)

    @classmethod
    def not_found(cls, resource: str = "Resource") -> "HandlerResponse":
        """Create a 404 not found response."""
        return cls.error(f"{resource} not found", HttpStatus.NOT_FOUND)

    @classmethod
    def unauthorized(cls, message: str = "Authentication required") -> "HandlerResponse":
        """Create a 401 unauthorized response."""
        return cls.error(message, HttpStatus.UNAUTHORIZED)

    @classmethod
    def forbidden(cls, message: str = "Access denied") -> "HandlerResponse":
        """Create a 403 forbidden response."""
        return cls.error(message, HttpStatus.FORBIDDEN)

    @classmethod
    def server_error(cls, message: str = "Internal server error") -> "HandlerResponse":
        """Create a 500 server error response."""
        return cls.error(message, HttpStatus.INTERNAL_SERVER_ERROR)


class BaseHandler:
    """
    Base class for domain-specific request handlers.

    Subclasses implement methods for specific API endpoints.
    Each handler focuses on a single domain (auth, visualization, etc.)

    Usage:
        class AuthHandler(BaseHandler):
            def handle_login(self, params: dict) -> HandlerResponse:
                # Handle /api/auth/login
                ...

            def handle_logout(self, params: dict) -> HandlerResponse:
                # Handle /api/auth/logout
                ...
    """

    # Base path for this handler (e.g., "/api/auth/")
    base_path: str = ""

    def __init__(
        self,
        storage: Any = None,
        request_handler: Any = None,
    ) -> None:
        """
        Initialize the handler.

        Args:
            storage: Storage backend instance
            request_handler: Reference to the HTTP request handler (for shared state)
        """
        self.storage = storage
        self.request_handler = request_handler
        self._routes: dict[str, Callable] = {}
        self._setup_routes()

    def _setup_routes(self) -> None:
        """
        Set up route mappings.

        Override in subclasses to register routes.
        """
        pass

    def register_route(
        self,
        path: str,
        handler: Callable[..., HandlerResponse],
        methods: list[str] | None = None,
    ) -> None:
        """
        Register a route handler.

        Args:
            path: Path relative to base_path (e.g., "login" for /api/auth/login)
            handler: Handler method to call
            methods: Allowed HTTP methods (default: ["GET"])
        """
        if methods is None:
            methods = ["GET"]
        for method in methods:
            key = f"{method}:{path}"
            self._routes[key] = handler

    def can_handle(self, path: str) -> bool:
        """
        Check if this handler can process the given path.

        Args:
            path: Request path

        Returns:
            True if this handler should process the path
        """
        return path.startswith(self.base_path)

    def handle(
        self,
        path: str,
        params: dict[str, list[str]],
        method: str = "GET",
        body: dict[str, Any] | None = None,
    ) -> HandlerResponse:
        """
        Handle a request.

        Args:
            path: Full request path
            params: Query parameters
            method: HTTP method
            body: Request body (for POST/PUT)

        Returns:
            HandlerResponse with result data
        """
        # Strip base path to get relative path
        relative_path = path[len(self.base_path) :].rstrip("/")
        if not relative_path:
            relative_path = "index"

        # Look up handler
        key = f"{method}:{relative_path}"
        if key in self._routes:
            try:
                handler = self._routes[key]
                return handler(params, body)
            except Exception as e:
                logger.exception(f"Handler error for {path}: {e}")
                return HandlerResponse.server_error(str(e))

        # Try GET fallback for path without method prefix
        if method != "GET":
            get_key = f"GET:{relative_path}"
            if get_key in self._routes:
                return HandlerResponse.error(
                    f"Method {method} not allowed",
                    HttpStatus.METHOD_NOT_ALLOWED,
                )

        return HandlerResponse.not_found(f"Endpoint {path}")

    def get_param(
        self,
        params: dict[str, list[str]],
        name: str,
        default: str | None = None,
    ) -> str | None:
        """
        Get a single query parameter value.

        Args:
            params: Query parameters dict
            name: Parameter name
            default: Default value if not found

        Returns:
            Parameter value or default
        """
        values = params.get(name, [])
        return values[0] if values else default

    def get_param_int(
        self,
        params: dict[str, list[str]],
        name: str,
        default: int = 0,
    ) -> int:
        """
        Get a query parameter as integer.

        Args:
            params: Query parameters dict
            name: Parameter name
            default: Default value if not found or invalid

        Returns:
            Integer value
        """
        value = self.get_param(params, name)
        if value is None:
            return default
        try:
            return int(value)
        except ValueError:
            return default

    def get_param_bool(
        self,
        params: dict[str, list[str]],
        name: str,
        default: bool = False,
    ) -> bool:
        """
        Get a query parameter as boolean.

        Args:
            params: Query parameters dict
            name: Parameter name
            default: Default value if not found

        Returns:
            Boolean value
        """
        value = self.get_param(params, name)
        if value is None:
            return default
        return value.lower() in ("true", "1", "yes", "on")

    def get_param_list(
        self,
        params: dict[str, list[str]],
        name: str,
    ) -> list[str]:
        """
        Get all values for a query parameter.

        Args:
            params: Query parameters dict
            name: Parameter name

        Returns:
            List of values (empty list if not found)
        """
        return params.get(name, [])

    def require_storage(self) -> Any:
        """
        Get storage backend, raising error if not available.

        Returns:
            Storage backend

        Raises:
            RuntimeError: If storage is not configured
        """
        if self.storage is None:
            raise RuntimeError("Storage backend not configured")
        return self.storage

    def get_snapshot_id(self, params: dict[str, list[str]]) -> str | None:
        """
        Get snapshot ID from params or use latest.

        Args:
            params: Query parameters

        Returns:
            Snapshot ID or None if no snapshots exist
        """
        snapshot_id = self.get_param(params, "snapshot_id")
        if snapshot_id:
            return snapshot_id
        storage = self.require_storage()
        return storage.get_latest_snapshot_id()


class HandlerRegistry:
    """
    Registry for managing multiple handlers.

    Provides routing to appropriate handlers based on request path.

    Usage:
        registry = HandlerRegistry(storage=storage)
        registry.register_handler("/api/auth/", AuthHandler)
        registry.register_handler("/api/viz/", VisualizationHandler)

        response = registry.handle("/api/auth/login", params)
    """

    def __init__(self, storage: Any = None, request_handler: Any = None) -> None:
        """
        Initialize the registry.

        Args:
            storage: Storage backend instance
            request_handler: Reference to HTTP request handler
        """
        self.storage = storage
        self.request_handler = request_handler
        self._handlers: list[BaseHandler] = []
        self._path_handlers: dict[str, BaseHandler] = {}

    def register_handler(
        self,
        base_path: str,
        handler_class: type[BaseHandler],
    ) -> None:
        """
        Register a handler for a path prefix.

        Args:
            base_path: Path prefix (e.g., "/api/auth/")
            handler_class: Handler class to instantiate
        """
        handler = handler_class(
            storage=self.storage,
            request_handler=self.request_handler,
        )
        handler.base_path = base_path
        self._handlers.append(handler)
        self._path_handlers[base_path] = handler

    def register_instance(self, handler: BaseHandler) -> None:
        """
        Register an existing handler instance.

        Args:
            handler: Handler instance
        """
        self._handlers.append(handler)
        if handler.base_path:
            self._path_handlers[handler.base_path] = handler

    def handle(
        self,
        path: str,
        params: dict[str, list[str]],
        method: str = "GET",
        body: dict[str, Any] | None = None,
    ) -> HandlerResponse | None:
        """
        Route request to appropriate handler.

        Args:
            path: Request path
            params: Query parameters
            method: HTTP method
            body: Request body

        Returns:
            HandlerResponse if a handler matches, None otherwise
        """
        # Try exact path prefix match first
        for base_path, handler in self._path_handlers.items():
            if path.startswith(base_path):
                return handler.handle(path, params, method, body)

        # Fallback to can_handle check
        for handler in self._handlers:
            if handler.can_handle(path):
                return handler.handle(path, params, method, body)

        return None

    def list_handlers(self) -> list[str]:
        """
        List all registered handler paths.

        Returns:
            List of base paths
        """
        return list(self._path_handlers.keys())
