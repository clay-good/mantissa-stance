"""
Real-time dashboard streaming for Mantissa Stance.

Provides real-time data updates for dashboards:
- Server-Sent Events (SSE) for live updates
- WebSocket support for bidirectional communication
- Subscription management for dashboard widgets
- Event broadcasting for data changes
- Connection pooling and management

Part of Phase 94: Enhanced Visualization
"""

from __future__ import annotations

import asyncio
import json
import logging
import queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable

logger = logging.getLogger(__name__)


class EventType(Enum):
    """Types of real-time events."""

    # Data updates
    FINDING_CREATED = "finding_created"
    FINDING_UPDATED = "finding_updated"
    FINDING_RESOLVED = "finding_resolved"
    ASSET_DISCOVERED = "asset_discovered"
    ASSET_UPDATED = "asset_updated"
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"

    # Metrics updates
    METRIC_UPDATE = "metric_update"
    SCORE_CHANGE = "score_change"
    TREND_UPDATE = "trend_update"

    # Alert events
    ALERT_TRIGGERED = "alert_triggered"
    ALERT_RESOLVED = "alert_resolved"
    SLA_WARNING = "sla_warning"
    SLA_BREACH = "sla_breach"

    # System events
    HEARTBEAT = "heartbeat"
    CONNECTION_ACK = "connection_ack"
    SUBSCRIPTION_ACK = "subscription_ack"
    ERROR = "error"

    # Dashboard events
    WIDGET_REFRESH = "widget_refresh"
    DASHBOARD_UPDATE = "dashboard_update"


class ConnectionState(Enum):
    """State of a client connection."""

    CONNECTING = "connecting"
    CONNECTED = "connected"
    SUBSCRIBED = "subscribed"
    DISCONNECTING = "disconnecting"
    DISCONNECTED = "disconnected"
    ERROR = "error"


@dataclass
class RealtimeEvent:
    """
    Real-time event data structure.

    Represents an event that can be sent to clients.
    """

    id: str
    event_type: EventType
    data: dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.utcnow)
    source: str = "system"
    targets: list[str] = field(default_factory=list)  # Empty = broadcast to all

    def to_sse(self) -> str:
        """Convert to Server-Sent Events format."""
        event_data = {
            "id": self.id,
            "type": self.event_type.value,
            "data": self.data,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
        }
        return f"id: {self.id}\nevent: {self.event_type.value}\ndata: {json.dumps(event_data)}\n\n"

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps({
            "id": self.id,
            "type": self.event_type.value,
            "data": self.data,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
        })

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "type": self.event_type.value,
            "data": self.data,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
        }


@dataclass
class Subscription:
    """
    Client subscription to events.

    Defines what events a client wants to receive.
    """

    id: str
    client_id: str
    event_types: list[EventType] = field(default_factory=list)  # Empty = all events
    filters: dict[str, Any] = field(default_factory=dict)
    dashboard_id: str = ""
    widget_ids: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)

    def matches(self, event: RealtimeEvent) -> bool:
        """
        Check if subscription matches an event.

        Args:
            event: Event to check

        Returns:
            True if subscription should receive event
        """
        # Check event type filter
        if self.event_types and event.event_type not in self.event_types:
            return False

        # Check target filter
        if event.targets and self.client_id not in event.targets:
            return False

        # Check dashboard filter
        if self.dashboard_id:
            event_dashboard = event.data.get("dashboard_id", "")
            if event_dashboard and event_dashboard != self.dashboard_id:
                return False

        # Check widget filter
        if self.widget_ids:
            event_widget = event.data.get("widget_id", "")
            if event_widget and event_widget not in self.widget_ids:
                return False

        # Check custom filters
        for key, value in self.filters.items():
            event_value = event.data.get(key)
            if event_value != value:
                return False

        return True


@dataclass
class ClientConnection:
    """
    Client connection state.

    Tracks a connected client and its subscriptions.
    """

    id: str
    state: ConnectionState = ConnectionState.CONNECTING
    subscriptions: list[Subscription] = field(default_factory=list)
    message_queue: queue.Queue = field(default_factory=queue.Queue)
    connected_at: datetime = field(default_factory=datetime.utcnow)
    last_heartbeat: datetime = field(default_factory=datetime.utcnow)
    user_id: str = ""
    tenant_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Initialize message queue if None."""
        if self.message_queue is None:
            self.message_queue = queue.Queue()

    def is_alive(self, timeout_seconds: int = 60) -> bool:
        """Check if connection is still alive."""
        if self.state in (ConnectionState.DISCONNECTED, ConnectionState.ERROR):
            return False
        elapsed = (datetime.utcnow() - self.last_heartbeat).total_seconds()
        return elapsed < timeout_seconds

    def add_subscription(self, subscription: Subscription) -> None:
        """Add a subscription."""
        self.subscriptions.append(subscription)
        if self.state == ConnectionState.CONNECTED:
            self.state = ConnectionState.SUBSCRIBED

    def remove_subscription(self, subscription_id: str) -> bool:
        """Remove a subscription by ID."""
        for i, sub in enumerate(self.subscriptions):
            if sub.id == subscription_id:
                self.subscriptions.pop(i)
                return True
        return False

    def matches_event(self, event: RealtimeEvent) -> bool:
        """Check if any subscription matches the event."""
        if not self.subscriptions:
            return True  # No subscriptions = receive all
        return any(sub.matches(event) for sub in self.subscriptions)


class EventBus:
    """
    Central event bus for real-time events.

    Manages event publishing and subscription.

    Example:
        >>> bus = EventBus()
        >>> bus.subscribe("client-1", EventType.FINDING_CREATED)
        >>> bus.publish(RealtimeEvent(...))
    """

    def __init__(self) -> None:
        """Initialize the event bus."""
        self._connections: dict[str, ClientConnection] = {}
        self._lock = threading.RLock()
        self._event_handlers: list[Callable[[RealtimeEvent], None]] = []
        self._running = False
        self._dispatcher_thread: threading.Thread | None = None

        logger.info("EventBus initialized")

    def start(self) -> None:
        """Start the event bus dispatcher."""
        if self._running:
            return

        self._running = True
        self._dispatcher_thread = threading.Thread(
            target=self._dispatch_loop,
            daemon=True,
            name="EventBusDispatcher",
        )
        self._dispatcher_thread.start()
        logger.info("EventBus dispatcher started")

    def stop(self) -> None:
        """Stop the event bus dispatcher."""
        self._running = False
        if self._dispatcher_thread:
            self._dispatcher_thread.join(timeout=5.0)
        logger.info("EventBus dispatcher stopped")

    def _dispatch_loop(self) -> None:
        """Main dispatch loop for event processing."""
        while self._running:
            try:
                # Send heartbeats periodically
                self._send_heartbeats()

                # Clean up stale connections
                self._cleanup_stale_connections()

                time.sleep(1.0)

            except Exception as e:
                logger.error(f"Dispatch loop error: {e}")

    def _send_heartbeats(self) -> None:
        """Send heartbeat events to all connected clients."""
        heartbeat = RealtimeEvent(
            id=str(uuid.uuid4()),
            event_type=EventType.HEARTBEAT,
            data={"timestamp": datetime.utcnow().isoformat()},
        )

        with self._lock:
            for conn in self._connections.values():
                if conn.state in (ConnectionState.CONNECTED, ConnectionState.SUBSCRIBED):
                    try:
                        conn.message_queue.put_nowait(heartbeat)
                    except queue.Full:
                        pass

    def _cleanup_stale_connections(self) -> None:
        """Remove stale connections."""
        with self._lock:
            stale = [
                cid for cid, conn in self._connections.items()
                if not conn.is_alive()
            ]
            for cid in stale:
                del self._connections[cid]
                logger.debug(f"Removed stale connection: {cid}")

    def connect(
        self,
        client_id: str | None = None,
        user_id: str = "",
        tenant_id: str = "",
    ) -> ClientConnection:
        """
        Register a new client connection.

        Args:
            client_id: Optional client ID (generated if not provided)
            user_id: User ID for the connection
            tenant_id: Tenant ID for the connection

        Returns:
            ClientConnection instance
        """
        client_id = client_id or str(uuid.uuid4())

        conn = ClientConnection(
            id=client_id,
            state=ConnectionState.CONNECTED,
            user_id=user_id,
            tenant_id=tenant_id,
        )

        with self._lock:
            self._connections[client_id] = conn

        # Send connection acknowledgment
        ack = RealtimeEvent(
            id=str(uuid.uuid4()),
            event_type=EventType.CONNECTION_ACK,
            data={"client_id": client_id},
            targets=[client_id],
        )
        conn.message_queue.put_nowait(ack)

        logger.info(f"Client connected: {client_id}")
        return conn

    def disconnect(self, client_id: str) -> bool:
        """
        Disconnect a client.

        Args:
            client_id: Client ID to disconnect

        Returns:
            True if client was disconnected
        """
        with self._lock:
            if client_id in self._connections:
                conn = self._connections[client_id]
                conn.state = ConnectionState.DISCONNECTED
                del self._connections[client_id]
                logger.info(f"Client disconnected: {client_id}")
                return True
        return False

    def get_connection(self, client_id: str) -> ClientConnection | None:
        """Get a connection by client ID."""
        with self._lock:
            return self._connections.get(client_id)

    def subscribe(
        self,
        client_id: str,
        event_types: list[EventType] | None = None,
        filters: dict[str, Any] | None = None,
        dashboard_id: str = "",
        widget_ids: list[str] | None = None,
    ) -> Subscription | None:
        """
        Create a subscription for a client.

        Args:
            client_id: Client ID
            event_types: Event types to subscribe to (None = all)
            filters: Custom filters
            dashboard_id: Dashboard ID to subscribe to
            widget_ids: Widget IDs to subscribe to

        Returns:
            Subscription instance or None if client not found
        """
        with self._lock:
            conn = self._connections.get(client_id)
            if not conn:
                return None

            subscription = Subscription(
                id=str(uuid.uuid4()),
                client_id=client_id,
                event_types=event_types or [],
                filters=filters or {},
                dashboard_id=dashboard_id,
                widget_ids=widget_ids or [],
            )

            conn.add_subscription(subscription)

            # Send subscription acknowledgment
            ack = RealtimeEvent(
                id=str(uuid.uuid4()),
                event_type=EventType.SUBSCRIPTION_ACK,
                data={
                    "subscription_id": subscription.id,
                    "event_types": [et.value for et in subscription.event_types],
                    "dashboard_id": dashboard_id,
                    "widget_ids": widget_ids or [],
                },
                targets=[client_id],
            )
            conn.message_queue.put_nowait(ack)

            logger.debug(f"Client {client_id} subscribed: {subscription.id}")
            return subscription

    def unsubscribe(self, client_id: str, subscription_id: str) -> bool:
        """
        Remove a subscription.

        Args:
            client_id: Client ID
            subscription_id: Subscription ID to remove

        Returns:
            True if subscription was removed
        """
        with self._lock:
            conn = self._connections.get(client_id)
            if conn:
                return conn.remove_subscription(subscription_id)
        return False

    def publish(self, event: RealtimeEvent) -> int:
        """
        Publish an event to all matching subscribers.

        Args:
            event: Event to publish

        Returns:
            Number of clients that received the event
        """
        count = 0

        with self._lock:
            for conn in self._connections.values():
                if conn.state not in (
                    ConnectionState.CONNECTED,
                    ConnectionState.SUBSCRIBED,
                ):
                    continue

                if conn.matches_event(event):
                    try:
                        conn.message_queue.put_nowait(event)
                        count += 1
                    except queue.Full:
                        logger.warning(f"Message queue full for client: {conn.id}")

        # Notify handlers
        for handler in self._event_handlers:
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Event handler error: {e}")

        logger.debug(f"Published event {event.event_type.value} to {count} clients")
        return count

    def register_handler(
        self,
        handler: Callable[[RealtimeEvent], None],
    ) -> None:
        """Register an event handler."""
        self._event_handlers.append(handler)

    def get_messages(
        self,
        client_id: str,
        timeout: float = 0.1,
        max_messages: int = 10,
    ) -> list[RealtimeEvent]:
        """
        Get pending messages for a client.

        Args:
            client_id: Client ID
            timeout: Timeout for blocking
            max_messages: Maximum messages to return

        Returns:
            List of pending events
        """
        with self._lock:
            conn = self._connections.get(client_id)
            if not conn:
                return []

            # Update heartbeat
            conn.last_heartbeat = datetime.utcnow()

        messages = []
        try:
            while len(messages) < max_messages:
                try:
                    msg = conn.message_queue.get(timeout=timeout)
                    messages.append(msg)
                except queue.Empty:
                    break
        except Exception:
            pass

        return messages

    def get_statistics(self) -> dict[str, Any]:
        """Get event bus statistics."""
        with self._lock:
            connections = list(self._connections.values())

        connected = sum(
            1 for c in connections
            if c.state in (ConnectionState.CONNECTED, ConnectionState.SUBSCRIBED)
        )
        subscribed = sum(
            1 for c in connections if c.state == ConnectionState.SUBSCRIBED
        )

        return {
            "total_connections": len(connections),
            "connected_clients": connected,
            "subscribed_clients": subscribed,
            "registered_handlers": len(self._event_handlers),
            "is_running": self._running,
        }


class DashboardStreamManager:
    """
    Manager for dashboard real-time streaming.

    Handles subscriptions and updates for dashboard widgets.

    Example:
        >>> manager = DashboardStreamManager(event_bus)
        >>> manager.subscribe_dashboard("client-1", "dashboard-1")
        >>> manager.push_widget_update("widget-1", {"value": 42})
    """

    def __init__(self, event_bus: EventBus | None = None) -> None:
        """Initialize the stream manager."""
        self._event_bus = event_bus or EventBus()
        self._widget_data: dict[str, dict[str, Any]] = {}
        self._refresh_intervals: dict[str, int] = {}  # widget_id -> seconds
        self._running = False
        self._refresh_thread: threading.Thread | None = None

        logger.info("DashboardStreamManager initialized")

    @property
    def event_bus(self) -> EventBus:
        """Get the event bus."""
        return self._event_bus

    def start(self) -> None:
        """Start the stream manager."""
        self._running = True
        self._event_bus.start()

        self._refresh_thread = threading.Thread(
            target=self._refresh_loop,
            daemon=True,
            name="WidgetRefreshLoop",
        )
        self._refresh_thread.start()
        logger.info("DashboardStreamManager started")

    def stop(self) -> None:
        """Stop the stream manager."""
        self._running = False
        self._event_bus.stop()
        if self._refresh_thread:
            self._refresh_thread.join(timeout=5.0)
        logger.info("DashboardStreamManager stopped")

    def _refresh_loop(self) -> None:
        """Loop to trigger widget refreshes based on intervals."""
        last_refresh: dict[str, float] = {}

        while self._running:
            try:
                now = time.time()

                for widget_id, interval in self._refresh_intervals.items():
                    last = last_refresh.get(widget_id, 0)
                    if now - last >= interval:
                        self._trigger_widget_refresh(widget_id)
                        last_refresh[widget_id] = now

                time.sleep(1.0)

            except Exception as e:
                logger.error(f"Refresh loop error: {e}")

    def _trigger_widget_refresh(self, widget_id: str) -> None:
        """Trigger a widget refresh event."""
        data = self._widget_data.get(widget_id, {})

        event = RealtimeEvent(
            id=str(uuid.uuid4()),
            event_type=EventType.WIDGET_REFRESH,
            data={
                "widget_id": widget_id,
                "data": data,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

        self._event_bus.publish(event)

    def subscribe_dashboard(
        self,
        client_id: str,
        dashboard_id: str,
        widget_ids: list[str] | None = None,
    ) -> Subscription | None:
        """
        Subscribe a client to dashboard updates.

        Args:
            client_id: Client ID
            dashboard_id: Dashboard ID
            widget_ids: Optional specific widget IDs

        Returns:
            Subscription instance
        """
        return self._event_bus.subscribe(
            client_id=client_id,
            event_types=[
                EventType.WIDGET_REFRESH,
                EventType.DASHBOARD_UPDATE,
                EventType.METRIC_UPDATE,
            ],
            dashboard_id=dashboard_id,
            widget_ids=widget_ids,
        )

    def subscribe_findings(
        self,
        client_id: str,
        severity_filter: list[str] | None = None,
    ) -> Subscription | None:
        """
        Subscribe a client to finding updates.

        Args:
            client_id: Client ID
            severity_filter: Optional severity filter

        Returns:
            Subscription instance
        """
        filters = {}
        if severity_filter:
            filters["severity"] = severity_filter

        return self._event_bus.subscribe(
            client_id=client_id,
            event_types=[
                EventType.FINDING_CREATED,
                EventType.FINDING_UPDATED,
                EventType.FINDING_RESOLVED,
            ],
            filters=filters,
        )

    def subscribe_alerts(self, client_id: str) -> Subscription | None:
        """Subscribe a client to alert updates."""
        return self._event_bus.subscribe(
            client_id=client_id,
            event_types=[
                EventType.ALERT_TRIGGERED,
                EventType.ALERT_RESOLVED,
                EventType.SLA_WARNING,
                EventType.SLA_BREACH,
            ],
        )

    def set_widget_refresh_interval(
        self,
        widget_id: str,
        interval_seconds: int,
    ) -> None:
        """
        Set refresh interval for a widget.

        Args:
            widget_id: Widget ID
            interval_seconds: Refresh interval in seconds
        """
        self._refresh_intervals[widget_id] = interval_seconds

    def update_widget_data(
        self,
        widget_id: str,
        data: dict[str, Any],
        push_update: bool = True,
    ) -> None:
        """
        Update cached widget data.

        Args:
            widget_id: Widget ID
            data: New widget data
            push_update: Whether to push update to clients
        """
        self._widget_data[widget_id] = data

        if push_update:
            self._trigger_widget_refresh(widget_id)

    def push_finding_event(
        self,
        event_type: EventType,
        finding_id: str,
        finding_data: dict[str, Any],
    ) -> None:
        """
        Push a finding-related event.

        Args:
            event_type: Event type
            finding_id: Finding ID
            finding_data: Finding data
        """
        event = RealtimeEvent(
            id=str(uuid.uuid4()),
            event_type=event_type,
            data={
                "finding_id": finding_id,
                **finding_data,
            },
            source="finding_manager",
        )
        self._event_bus.publish(event)

    def push_metric_update(
        self,
        metric_name: str,
        value: Any,
        previous_value: Any = None,
        dashboard_id: str = "",
        widget_id: str = "",
    ) -> None:
        """
        Push a metric update event.

        Args:
            metric_name: Metric name
            value: New value
            previous_value: Previous value
            dashboard_id: Dashboard ID
            widget_id: Widget ID
        """
        event = RealtimeEvent(
            id=str(uuid.uuid4()),
            event_type=EventType.METRIC_UPDATE,
            data={
                "metric_name": metric_name,
                "value": value,
                "previous_value": previous_value,
                "dashboard_id": dashboard_id,
                "widget_id": widget_id,
                "change": (
                    value - previous_value
                    if previous_value is not None and isinstance(value, (int, float))
                    else None
                ),
            },
            source="metrics",
        )
        self._event_bus.publish(event)

    def push_alert(
        self,
        alert_type: str,
        severity: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """
        Push an alert event.

        Args:
            alert_type: Alert type
            severity: Alert severity
            message: Alert message
            details: Additional details
        """
        event = RealtimeEvent(
            id=str(uuid.uuid4()),
            event_type=EventType.ALERT_TRIGGERED,
            data={
                "alert_type": alert_type,
                "severity": severity,
                "message": message,
                "details": details or {},
            },
            source="alerting",
        )
        self._event_bus.publish(event)

    def push_scan_event(
        self,
        event_type: EventType,
        scan_id: str,
        scan_data: dict[str, Any],
    ) -> None:
        """
        Push a scan-related event.

        Args:
            event_type: Event type (SCAN_STARTED, SCAN_COMPLETED, SCAN_FAILED)
            scan_id: Scan ID
            scan_data: Scan data
        """
        event = RealtimeEvent(
            id=str(uuid.uuid4()),
            event_type=event_type,
            data={
                "scan_id": scan_id,
                **scan_data,
            },
            source="scanner",
        )
        self._event_bus.publish(event)


class SSEHandler:
    """
    Server-Sent Events handler for HTTP responses.

    Generates SSE-formatted responses for clients.

    Example:
        >>> handler = SSEHandler(stream_manager)
        >>> for event in handler.stream_events("client-1"):
        ...     yield event
    """

    def __init__(self, stream_manager: DashboardStreamManager) -> None:
        """Initialize the SSE handler."""
        self._stream_manager = stream_manager
        self._keep_alive_interval = 15  # seconds

    def connect(
        self,
        user_id: str = "",
        tenant_id: str = "",
    ) -> str:
        """
        Create a new connection and return client ID.

        Args:
            user_id: User ID
            tenant_id: Tenant ID

        Returns:
            Client ID
        """
        conn = self._stream_manager.event_bus.connect(
            user_id=user_id,
            tenant_id=tenant_id,
        )
        return conn.id

    def disconnect(self, client_id: str) -> None:
        """Disconnect a client."""
        self._stream_manager.event_bus.disconnect(client_id)

    def subscribe(
        self,
        client_id: str,
        dashboard_id: str = "",
        widget_ids: list[str] | None = None,
        event_types: list[str] | None = None,
    ) -> str | None:
        """
        Subscribe client to events.

        Args:
            client_id: Client ID
            dashboard_id: Dashboard ID
            widget_ids: Widget IDs
            event_types: Event type strings

        Returns:
            Subscription ID or None
        """
        types = None
        if event_types:
            types = []
            for et in event_types:
                try:
                    types.append(EventType(et))
                except ValueError:
                    pass

        sub = self._stream_manager.event_bus.subscribe(
            client_id=client_id,
            event_types=types,
            dashboard_id=dashboard_id,
            widget_ids=widget_ids,
        )
        return sub.id if sub else None

    def stream_events(
        self,
        client_id: str,
        timeout: float = 30.0,
    ):
        """
        Generator for streaming SSE events.

        Args:
            client_id: Client ID
            timeout: Connection timeout

        Yields:
            SSE-formatted event strings
        """
        start_time = time.time()
        last_event_time = time.time()

        while True:
            # Check timeout
            if time.time() - start_time > timeout:
                break

            # Get messages
            messages = self._stream_manager.event_bus.get_messages(
                client_id,
                timeout=0.5,
                max_messages=5,
            )

            for msg in messages:
                last_event_time = time.time()
                yield msg.to_sse()

            # Send keep-alive comment if no events for a while
            if time.time() - last_event_time > self._keep_alive_interval:
                yield ": keep-alive\n\n"
                last_event_time = time.time()

    def get_headers(self) -> dict[str, str]:
        """Get HTTP headers for SSE response."""
        return {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }


def create_event_bus() -> EventBus:
    """Create a new EventBus instance."""
    return EventBus()


def create_stream_manager(event_bus: EventBus | None = None) -> DashboardStreamManager:
    """Create a new DashboardStreamManager instance."""
    return DashboardStreamManager(event_bus)


def create_sse_handler(
    stream_manager: DashboardStreamManager | None = None,
) -> SSEHandler:
    """Create a new SSEHandler instance."""
    manager = stream_manager or DashboardStreamManager()
    return SSEHandler(manager)
