"""
Base handler class for web request handlers.

This module provides the foundation for modular request handlers,
allowing the 19K+ line server.py to be split into maintainable pieces.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, TypeVar

logger = logging.getLogger(__name__)


# =============================================================================
# Error Sanitization Utilities
# =============================================================================

def _is_production_environment() -> bool:
    """Check if running in a production environment."""
    return any([
        os.environ.get("STANCE_ENV", "").lower() == "production",
        os.environ.get("STANCE_PRODUCTION", "").lower() in ("1", "true", "yes"),
        os.environ.get("ENV", "").lower() == "production",
        os.environ.get("ENVIRONMENT", "").lower() == "production",
        os.environ.get("NODE_ENV", "").lower() == "production",
    ])


def sanitize_error_message(
    error: Exception | str,
    include_type: bool = False,
) -> tuple[str, str]:
    """
    Sanitize an error message to prevent information leakage.

    In production, returns a generic error message with a unique error ID.
    In development, returns the full error message for debugging.

    Args:
        error: The exception or error message
        include_type: Whether to include exception type in dev mode

    Returns:
        Tuple of (user_message, error_id) where:
        - user_message: Safe message to return to the user
        - error_id: Unique ID for correlating with logs
    """
    error_id = secrets.token_hex(8)
    error_str = str(error)

    # Always log the full error for debugging
    if isinstance(error, Exception):
        logger.error(
            "Error [%s] (%s): %s",
            error_id,
            type(error).__name__,
            error_str,
        )
    else:
        logger.error("Error [%s]: %s", error_id, error_str)

    if _is_production_environment():
        # In production, return generic message with error ID
        return f"An internal error occurred (ref: {error_id})", error_id
    else:
        # In development, return more details
        if include_type and isinstance(error, Exception):
            return f"{type(error).__name__}: {error_str}", error_id
        return error_str, error_id


def get_safe_error_response(
    error: Exception | str,
    default_message: str = "An internal error occurred",
) -> str:
    """
    Get a safe error message for HTTP responses.

    Args:
        error: The exception or error message
        default_message: Default message to use in production

    Returns:
        Safe error message string
    """
    user_message, _ = sanitize_error_message(error)
    return user_message


# =============================================================================
# Path Validation Utilities
# =============================================================================

class PathValidationError(ValueError):
    """Raised when path validation fails."""
    pass


def validate_safe_path(
    path: str,
    base_dir: str | None = None,
    allow_absolute: bool = False,
    allow_parent_refs: bool = False,
    allowed_extensions: list[str] | None = None,
    max_length: int = 4096,
) -> str:
    """
    Validate and sanitize a file path to prevent path traversal attacks.

    Args:
        path: The path to validate
        base_dir: Optional base directory that the path must stay within
        allow_absolute: Whether to allow absolute paths (default: False)
        allow_parent_refs: Whether to allow .. references (default: False)
        allowed_extensions: Optional list of allowed file extensions
        max_length: Maximum path length

    Returns:
        The validated/normalized path

    Raises:
        PathValidationError: If the path is invalid or unsafe
    """
    if not path:
        raise PathValidationError("Path cannot be empty")

    # Check length
    if len(path) > max_length:
        raise PathValidationError(f"Path exceeds maximum length of {max_length}")

    # Check for null bytes (path truncation attack)
    if "\x00" in path:
        raise PathValidationError("Path contains null bytes")

    # Check for dangerous characters that could be used in attacks
    dangerous_patterns = [
        r"[\x00-\x1f]",  # Control characters
        r"[<>:\"|?*]",   # Invalid on Windows and potentially dangerous
    ]
    for pattern in dangerous_patterns:
        if re.search(pattern, path):
            raise PathValidationError("Path contains invalid characters")

    # Check for parent directory references (path traversal)
    if not allow_parent_refs:
        # Normalize and check for traversal attempts
        normalized = os.path.normpath(path)
        if normalized.startswith("..") or "/.." in normalized or "\\.." in normalized:
            raise PathValidationError("Path traversal detected (..)")

        # Also check the raw path for encoded traversals
        traversal_patterns = [
            r"\.\./",           # ../
            r"\.\.\\",          # ..\
            r"%2e%2e%2f",       # ../  URL encoded
            r"%2e%2e/",         # ../  partially encoded
            r"\.%2e/",          # ../  mixed encoding
            r"%2e\./",          # ../  mixed encoding
            r"%2e%2e%5c",       # ..\  URL encoded
            r"\.\.%5c",         # ..\  partially encoded
            r"\.\.%c0%af",      # ../ overlong UTF-8
            r"\.\.%c1%9c",      # ..\ overlong UTF-8
        ]
        path_lower = path.lower()
        for pattern in traversal_patterns:
            if re.search(pattern, path_lower, re.IGNORECASE):
                raise PathValidationError("Path traversal attempt detected")

    # Check absolute path
    if not allow_absolute and os.path.isabs(path):
        raise PathValidationError("Absolute paths are not allowed")

    # Validate against base directory if provided
    if base_dir:
        base_resolved = os.path.realpath(base_dir)
        if os.path.isabs(path):
            full_path = os.path.realpath(path)
        else:
            full_path = os.path.realpath(os.path.join(base_dir, path))

        # Ensure the resolved path is within the base directory
        if not full_path.startswith(base_resolved + os.sep) and full_path != base_resolved:
            raise PathValidationError(
                f"Path resolves outside allowed directory"
            )

    # Check file extension if restrictions provided
    if allowed_extensions:
        ext = os.path.splitext(path)[1].lower()
        if ext not in [e.lower() for e in allowed_extensions]:
            raise PathValidationError(
                f"File extension '{ext}' not allowed. "
                f"Allowed: {allowed_extensions}"
            )

    return path


def sanitize_filename(filename: str, max_length: int = 255) -> str:
    """
    Sanitize a filename to remove dangerous characters.

    Args:
        filename: The filename to sanitize
        max_length: Maximum filename length

    Returns:
        Sanitized filename
    """
    if not filename:
        return "unnamed"

    # Remove path separators and null bytes
    sanitized = filename.replace("/", "_").replace("\\", "_").replace("\x00", "")

    # Remove other dangerous characters
    sanitized = re.sub(r'[<>:"|?*\x00-\x1f]', "_", sanitized)

    # Prevent hidden files on Unix
    while sanitized.startswith("."):
        sanitized = sanitized[1:] or "unnamed"

    # Limit length
    if len(sanitized) > max_length:
        name, ext = os.path.splitext(sanitized)
        sanitized = name[: max_length - len(ext)] + ext

    return sanitized or "unnamed"


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
    TOO_MANY_REQUESTS = 429
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
    def server_error(
        cls,
        message: str | Exception = "Internal server error",
        sanitize: bool = True,
    ) -> "HandlerResponse":
        """
        Create a 500 server error response.

        Args:
            message: Error message or exception
            sanitize: Whether to sanitize the error message (default: True)

        Returns:
            HandlerResponse with error status
        """
        if sanitize:
            safe_message = get_safe_error_response(message)
        else:
            safe_message = str(message)
        return cls.error(safe_message, HttpStatus.INTERNAL_SERVER_ERROR)


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

    def validate_path_param(
        self,
        params: dict[str, list[str]],
        name: str,
        base_dir: str | None = None,
        allowed_extensions: list[str] | None = None,
        required: bool = True,
    ) -> str | None:
        """
        Get and validate a path parameter safely.

        Args:
            params: Query parameters dict
            name: Parameter name
            base_dir: Optional base directory for path containment
            allowed_extensions: Optional list of allowed file extensions
            required: Whether the parameter is required

        Returns:
            Validated path or None if not required and not provided

        Raises:
            PathValidationError: If path validation fails
        """
        path = self.get_param(params, name)
        if not path:
            if required:
                raise PathValidationError(f"Required parameter '{name}' is missing")
            return None

        return validate_safe_path(
            path,
            base_dir=base_dir,
            allowed_extensions=allowed_extensions,
        )

    def get_safe_path(
        self,
        path: str,
        base_dir: str | None = None,
        allowed_extensions: list[str] | None = None,
    ) -> str:
        """
        Validate a path value safely.

        Args:
            path: Path to validate
            base_dir: Optional base directory for path containment
            allowed_extensions: Optional list of allowed file extensions

        Returns:
            Validated path

        Raises:
            PathValidationError: If path validation fails
        """
        return validate_safe_path(
            path,
            base_dir=base_dir,
            allowed_extensions=allowed_extensions,
        )


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
