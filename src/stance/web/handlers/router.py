"""
Route table and decorators for handler methods.

This module provides a decorator-based routing system for handler methods,
allowing cleaner route definitions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from stance.web.handlers.base import BaseHandler, HandlerResponse


@dataclass
class Route:
    """Definition of a single route."""

    path: str
    handler: Callable[..., HandlerResponse]
    methods: list[str] = field(default_factory=lambda: ["GET"])
    path_pattern: re.Pattern | None = None

    def __post_init__(self):
        """Compile path pattern if it contains parameters."""
        if "{" in self.path:
            # Convert {param} to named capture group
            pattern = re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", self.path)
            self.path_pattern = re.compile(f"^{pattern}$")

    def matches(self, path: str, method: str) -> tuple[bool, dict[str, str]]:
        """
        Check if this route matches the given path and method.

        Args:
            path: Request path (relative to handler base)
            method: HTTP method

        Returns:
            Tuple of (matches, path_params)
        """
        if method not in self.methods:
            return False, {}

        if self.path_pattern:
            match = self.path_pattern.match(path)
            if match:
                return True, match.groupdict()
            return False, {}

        return path == self.path, {}


class RouteTable:
    """
    Collection of routes for a handler.

    Usage:
        routes = RouteTable()

        @routes.get("/users")
        def list_users(params, body):
            return HandlerResponse.success({"users": []})

        @routes.get("/users/{user_id}")
        def get_user(params, body, user_id: str):
            return HandlerResponse.success({"user_id": user_id})

        @routes.post("/users")
        def create_user(params, body):
            return HandlerResponse.success(body, status=HttpStatus.CREATED)
    """

    def __init__(self) -> None:
        """Initialize empty route table."""
        self._routes: list[Route] = []

    def add(
        self,
        path: str,
        handler: Callable[..., HandlerResponse],
        methods: list[str] | None = None,
    ) -> None:
        """
        Add a route to the table.

        Args:
            path: Route path (can include {param} placeholders)
            handler: Handler function
            methods: Allowed HTTP methods
        """
        if methods is None:
            methods = ["GET"]
        self._routes.append(Route(path=path, handler=handler, methods=methods))

    def get(self, path: str) -> Callable:
        """Decorator to add a GET route."""

        def decorator(func: Callable) -> Callable:
            self.add(path, func, ["GET"])
            return func

        return decorator

    def post(self, path: str) -> Callable:
        """Decorator to add a POST route."""

        def decorator(func: Callable) -> Callable:
            self.add(path, func, ["POST"])
            return func

        return decorator

    def put(self, path: str) -> Callable:
        """Decorator to add a PUT route."""

        def decorator(func: Callable) -> Callable:
            self.add(path, func, ["PUT"])
            return func

        return decorator

    def delete(self, path: str) -> Callable:
        """Decorator to add a DELETE route."""

        def decorator(func: Callable) -> Callable:
            self.add(path, func, ["DELETE"])
            return func

        return decorator

    def route(self, path: str, methods: list[str] | None = None) -> Callable:
        """Decorator to add a route with custom methods."""
        if methods is None:
            methods = ["GET"]

        def decorator(func: Callable) -> Callable:
            self.add(path, func, methods)
            return func

        return decorator

    def match(
        self,
        path: str,
        method: str,
    ) -> tuple[Callable | None, dict[str, str]]:
        """
        Find a matching route.

        Args:
            path: Request path
            method: HTTP method

        Returns:
            Tuple of (handler, path_params) or (None, {})
        """
        for route in self._routes:
            matches, params = route.matches(path, method)
            if matches:
                return route.handler, params
        return None, {}

    def __iter__(self):
        """Iterate over routes."""
        return iter(self._routes)


def route(path: str, methods: list[str] | None = None) -> Callable:
    """
    Method decorator to mark a handler method as a route.

    Usage:
        class MyHandler(BaseHandler):
            @route("/list")
            def handle_list(self, params, body):
                ...

            @route("/item/{item_id}")
            def handle_item(self, params, body, item_id: str):
                ...

            @route("/create", methods=["POST"])
            def handle_create(self, params, body):
                ...
    """
    if methods is None:
        methods = ["GET"]

    def decorator(func: Callable) -> Callable:
        func._route_path = path
        func._route_methods = methods
        return func

    return decorator


class RoutedHandler(BaseHandler):
    """
    Base handler that uses decorator-based routing.

    Subclasses can use @route decorators on methods:

        class UserHandler(RoutedHandler):
            base_path = "/api/users/"

            @route("list")
            def list_users(self, params, body):
                ...

            @route("{user_id}")
            def get_user(self, params, body, user_id: str):
                ...

            @route("create", methods=["POST"])
            def create_user(self, params, body):
                ...
    """

    def __init__(self, *args, **kwargs) -> None:
        """Initialize handler and discover routes."""
        super().__init__(*args, **kwargs)
        self._route_table = RouteTable()
        self._discover_routes()

    def _discover_routes(self) -> None:
        """Find all methods decorated with @route and register them."""
        for name in dir(self):
            if name.startswith("_"):
                continue
            method = getattr(self, name)
            if callable(method) and hasattr(method, "_route_path"):
                self._route_table.add(
                    method._route_path,
                    method,
                    method._route_methods,
                )

    def handle(
        self,
        path: str,
        params: dict[str, list[str]],
        method: str = "GET",
        body: dict[str, Any] | None = None,
    ) -> HandlerResponse:
        """
        Handle a request using the route table.

        Args:
            path: Full request path
            params: Query parameters
            method: HTTP method
            body: Request body

        Returns:
            HandlerResponse
        """
        # Strip base path
        relative_path = path[len(self.base_path) :].rstrip("/")
        if not relative_path:
            relative_path = ""

        # Find matching route
        handler, path_params = self._route_table.match(relative_path, method)

        if handler:
            try:
                if path_params:
                    return handler(params, body, **path_params)
                return handler(params, body)
            except Exception as e:
                import logging

                logging.exception(f"Handler error for {path}: {e}")
                return HandlerResponse.server_error(str(e))

        return HandlerResponse.not_found(f"Endpoint {path}")
