"""
Web dashboard for Mantissa Stance.

This package provides a local web dashboard for viewing
posture data, findings, and compliance scores.

The dashboard is intentionally local-only (binds to 127.0.0.1)
and does not include authentication. It is designed as a
developer tool for investigating findings, not as a multi-user
application.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from stance.web.server import StanceServer

if TYPE_CHECKING:
    from stance.storage import StorageBackend

__all__ = [
    "StanceServer",
    "serve_dashboard",
]


def serve_dashboard(
    host: str = "127.0.0.1",
    port: int = 8080,
    storage: StorageBackend | None = None,
    open_browser: bool = True,
) -> None:
    """
    Start the Stance dashboard server.

    This is a convenience function that creates a StanceServer
    and starts it. The function blocks until the server is
    stopped (via Ctrl+C).

    Args:
        host: Host to bind to (default: 127.0.0.1)
        port: Port to listen on (default: 8080)
        storage: Storage backend to use (default: LocalStorage)
        open_browser: Whether to open browser automatically

    Example:
        >>> from stance.web import serve_dashboard
        >>>
        >>> # Start dashboard on default port
        >>> serve_dashboard()
        >>>
        >>> # Start on custom port without opening browser
        >>> serve_dashboard(port=3000, open_browser=False)
    """
    import webbrowser

    server = StanceServer(host=host, port=port, storage=storage)

    if open_browser:
        webbrowser.open(server.url)

    server.start()
