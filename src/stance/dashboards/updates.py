"""
Real-time dashboard update manager for Mantissa Stance.

Integrates streaming infrastructure with dashboards, providing
automatic data refresh, widget synchronization, and live updates.

Part of Phase 94: Enhanced Visualization
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from stance.dashboards.models import (
    Dashboard,
    Widget,
    WidgetType,
    TimeRange,
)
from stance.dashboards.realtime import (
    EventBus,
    EventType,
    RealtimeEvent,
    DashboardStreamManager,
    Subscription,
    create_event_bus,
    create_stream_manager,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Update Enums
# =============================================================================

class UpdateStrategy(Enum):
    """Strategies for updating widget data."""
    POLL = "poll"  # Periodic polling
    PUSH = "push"  # Server push via events
    HYBRID = "hybrid"  # Combination of both
    MANUAL = "manual"  # Only update on user request


class UpdatePriority(Enum):
    """Priority levels for updates."""
    CRITICAL = 0  # Immediate update
    HIGH = 1  # Within 1 second
    NORMAL = 2  # Within refresh interval
    LOW = 3  # Can be batched/delayed
    BACKGROUND = 4  # Best effort


class WidgetStatus(Enum):
    """Widget data status."""
    FRESH = "fresh"  # Data is current
    STALE = "stale"  # Data needs refresh
    UPDATING = "updating"  # Update in progress
    ERROR = "error"  # Update failed


# =============================================================================
# Data Providers
# =============================================================================

@dataclass
class DataProviderConfig:
    """Configuration for a data provider."""
    provider_id: str
    name: str
    fetch_function: Optional[str] = None  # Function name to call
    query_template: Optional[str] = None  # Query template
    cache_ttl_seconds: int = 60
    supports_incremental: bool = False
    rate_limit_per_minute: int = 60
    timeout_seconds: int = 30
    retry_count: int = 3
    retry_delay_seconds: float = 1.0


class DataProvider:
    """
    Base class for widget data providers.

    Provides data fetching with caching, rate limiting, and error handling.
    """

    def __init__(self, config: DataProviderConfig):
        self.config = config
        self.cache: Dict[str, Any] = {}
        self.cache_timestamps: Dict[str, datetime] = {}
        self.call_timestamps: List[datetime] = []
        self.error_count: int = 0
        self.last_error: Optional[str] = None

    def get_data(
        self,
        widget_id: str,
        params: Optional[Dict[str, Any]] = None,
        force_refresh: bool = False,
    ) -> Tuple[Any, bool]:
        """
        Get data for a widget.

        Returns (data, from_cache) tuple.
        """
        cache_key = self._make_cache_key(widget_id, params)

        # Check cache
        if not force_refresh and self._is_cache_valid(cache_key):
            return self.cache.get(cache_key), True

        # Check rate limit
        if not self._check_rate_limit():
            # Return cached data if available
            if cache_key in self.cache:
                return self.cache[cache_key], True
            raise RateLimitError(f"Rate limit exceeded for {self.config.provider_id}")

        # Fetch new data
        try:
            data = self._fetch_data(widget_id, params)
            self._update_cache(cache_key, data)
            self.error_count = 0
            self.last_error = None
            return data, False
        except Exception as e:
            self.error_count += 1
            self.last_error = str(e)
            # Return stale cache if available
            if cache_key in self.cache:
                return self.cache[cache_key], True
            raise

    def _fetch_data(
        self,
        widget_id: str,
        params: Optional[Dict[str, Any]] = None
    ) -> Any:
        """Override to implement data fetching."""
        raise NotImplementedError

    def _make_cache_key(
        self,
        widget_id: str,
        params: Optional[Dict[str, Any]]
    ) -> str:
        """Create cache key from widget and params."""
        parts = [widget_id]
        if params:
            for k, v in sorted(params.items()):
                parts.append(f"{k}={v}")
        return ":".join(parts)

    def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if cached data is still valid."""
        if cache_key not in self.cache_timestamps:
            return False
        age = (datetime.utcnow() - self.cache_timestamps[cache_key]).total_seconds()
        return age < self.config.cache_ttl_seconds

    def _update_cache(self, cache_key: str, data: Any) -> None:
        """Update cache with new data."""
        self.cache[cache_key] = data
        self.cache_timestamps[cache_key] = datetime.utcnow()

    def _check_rate_limit(self) -> bool:
        """Check if within rate limit."""
        now = datetime.utcnow()
        cutoff = now - timedelta(minutes=1)

        # Remove old timestamps
        self.call_timestamps = [
            ts for ts in self.call_timestamps
            if ts > cutoff
        ]

        if len(self.call_timestamps) >= self.config.rate_limit_per_minute:
            return False

        self.call_timestamps.append(now)
        return True

    def invalidate_cache(self, widget_id: Optional[str] = None) -> None:
        """Invalidate cache entries."""
        if widget_id:
            # Invalidate specific widget
            keys_to_remove = [
                k for k in self.cache.keys()
                if k.startswith(widget_id)
            ]
            for key in keys_to_remove:
                self.cache.pop(key, None)
                self.cache_timestamps.pop(key, None)
        else:
            # Invalidate all
            self.cache.clear()
            self.cache_timestamps.clear()


class RateLimitError(Exception):
    """Raised when rate limit is exceeded."""
    pass


# =============================================================================
# Widget Update Tracker
# =============================================================================

@dataclass
class WidgetUpdateState:
    """Tracks update state for a widget."""
    widget_id: str
    status: WidgetStatus = WidgetStatus.STALE
    last_update: Optional[datetime] = None
    last_error: Optional[str] = None
    update_count: int = 0
    error_count: int = 0
    average_update_time_ms: float = 0.0
    pending_update: bool = False
    data_version: int = 0

    def mark_updating(self) -> None:
        """Mark widget as updating."""
        self.status = WidgetStatus.UPDATING
        self.pending_update = True

    def mark_updated(self, update_time_ms: float) -> None:
        """Mark widget as updated."""
        self.status = WidgetStatus.FRESH
        self.last_update = datetime.utcnow()
        self.pending_update = False
        self.update_count += 1
        self.data_version += 1

        # Update rolling average
        if self.update_count == 1:
            self.average_update_time_ms = update_time_ms
        else:
            self.average_update_time_ms = (
                self.average_update_time_ms * 0.9 + update_time_ms * 0.1
            )

    def mark_error(self, error: str) -> None:
        """Mark widget update as failed."""
        self.status = WidgetStatus.ERROR
        self.last_error = error
        self.pending_update = False
        self.error_count += 1

    def mark_stale(self) -> None:
        """Mark widget data as stale."""
        if self.status != WidgetStatus.UPDATING:
            self.status = WidgetStatus.STALE

    def needs_update(self, refresh_interval: int) -> bool:
        """Check if widget needs an update."""
        if self.status in (WidgetStatus.STALE, WidgetStatus.ERROR):
            return True
        if self.pending_update:
            return False
        if self.last_update is None:
            return True
        age = (datetime.utcnow() - self.last_update).total_seconds()
        return age >= refresh_interval

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "widget_id": self.widget_id,
            "status": self.status.value,
            "last_update": self.last_update.isoformat() if self.last_update else None,
            "last_error": self.last_error,
            "update_count": self.update_count,
            "error_count": self.error_count,
            "average_update_time_ms": round(self.average_update_time_ms, 2),
            "data_version": self.data_version,
        }


# =============================================================================
# Dashboard Update Manager
# =============================================================================

class DashboardUpdateManager:
    """
    Manages real-time updates for dashboards.

    Coordinates data fetching, caching, and event distribution.
    """

    def __init__(
        self,
        event_bus: Optional[EventBus] = None,
        stream_manager: Optional[DashboardStreamManager] = None,
    ):
        self.event_bus = event_bus or create_event_bus()
        self.stream_manager = stream_manager or create_stream_manager(self.event_bus)

        self.dashboards: Dict[str, Dashboard] = {}
        self.widget_states: Dict[str, WidgetUpdateState] = {}
        self.data_providers: Dict[str, DataProvider] = {}
        self.update_handlers: Dict[str, Callable] = {}
        self.active_subscriptions: Dict[str, Set[str]] = {}  # dashboard_id -> client_ids

        self._update_thread: Optional[threading.Thread] = None
        self._running = False
        self._update_queue: List[Tuple[str, str, UpdatePriority]] = []  # (dashboard_id, widget_id, priority)
        self._queue_lock = threading.Lock()

    def register_dashboard(self, dashboard: Dashboard) -> None:
        """Register a dashboard for updates."""
        self.dashboards[dashboard.id] = dashboard

        # Initialize widget states
        for widget in dashboard.widgets:
            if widget.id not in self.widget_states:
                self.widget_states[widget.id] = WidgetUpdateState(
                    widget_id=widget.id
                )

        self.active_subscriptions[dashboard.id] = set()

    def unregister_dashboard(self, dashboard_id: str) -> None:
        """Unregister a dashboard."""
        if dashboard_id in self.dashboards:
            dashboard = self.dashboards.pop(dashboard_id)
            # Clean up widget states
            for widget in dashboard.widgets:
                self.widget_states.pop(widget.id, None)

        self.active_subscriptions.pop(dashboard_id, None)

    def register_data_provider(
        self,
        source_name: str,
        provider: DataProvider
    ) -> None:
        """Register a data provider for a source type."""
        self.data_providers[source_name] = provider

    def register_update_handler(
        self,
        widget_type: WidgetType,
        handler: Callable[[Widget, Any], None]
    ) -> None:
        """Register a handler for widget updates."""
        self.update_handlers[widget_type.value] = handler

    def subscribe_client(
        self,
        client_id: str,
        dashboard_id: str,
        user_id: str,
        tenant_id: str,
    ) -> Subscription:
        """Subscribe a client to dashboard updates."""
        if dashboard_id not in self.dashboards:
            raise ValueError(f"Dashboard not found: {dashboard_id}")

        # Connect to event bus
        self.event_bus.connect(client_id, user_id, tenant_id)

        # Subscribe to dashboard events
        subscription = self.stream_manager.subscribe_dashboard(
            client_id=client_id,
            dashboard_id=dashboard_id,
        )

        # Track subscription
        if dashboard_id in self.active_subscriptions:
            self.active_subscriptions[dashboard_id].add(client_id)

        # Trigger initial data load
        self.refresh_dashboard(dashboard_id)

        return subscription

    def unsubscribe_client(self, client_id: str, dashboard_id: str) -> None:
        """Unsubscribe a client from dashboard updates."""
        self.event_bus.disconnect(client_id)

        if dashboard_id in self.active_subscriptions:
            self.active_subscriptions[dashboard_id].discard(client_id)

    def refresh_dashboard(
        self,
        dashboard_id: str,
        priority: UpdatePriority = UpdatePriority.NORMAL
    ) -> None:
        """Queue all widgets in a dashboard for refresh."""
        if dashboard_id not in self.dashboards:
            return

        dashboard = self.dashboards[dashboard_id]
        for widget in dashboard.widgets:
            if widget.visible:
                self.queue_widget_update(dashboard_id, widget.id, priority)

    def refresh_widget(
        self,
        dashboard_id: str,
        widget_id: str,
        priority: UpdatePriority = UpdatePriority.HIGH
    ) -> None:
        """Queue a specific widget for refresh."""
        self.queue_widget_update(dashboard_id, widget_id, priority)

    def queue_widget_update(
        self,
        dashboard_id: str,
        widget_id: str,
        priority: UpdatePriority = UpdatePriority.NORMAL
    ) -> None:
        """Add widget to update queue."""
        with self._queue_lock:
            # Check if already queued
            for item in self._update_queue:
                if item[0] == dashboard_id and item[1] == widget_id:
                    return

            self._update_queue.append((dashboard_id, widget_id, priority))
            # Sort by priority
            self._update_queue.sort(key=lambda x: x[2].value)

        # Mark widget as pending update
        if widget_id in self.widget_states:
            self.widget_states[widget_id].mark_stale()

    def process_update_queue(self) -> int:
        """Process pending updates. Returns number processed."""
        processed = 0

        while True:
            with self._queue_lock:
                if not self._update_queue:
                    break
                dashboard_id, widget_id, priority = self._update_queue.pop(0)

            try:
                self._update_widget(dashboard_id, widget_id)
                processed += 1
            except Exception as e:
                logger.error(f"Error updating widget {widget_id}: {e}")
                if widget_id in self.widget_states:
                    self.widget_states[widget_id].mark_error(str(e))

        return processed

    def _update_widget(self, dashboard_id: str, widget_id: str) -> None:
        """Perform widget update."""
        if dashboard_id not in self.dashboards:
            return

        dashboard = self.dashboards[dashboard_id]
        widget = dashboard.get_widget(widget_id)
        if not widget:
            return

        state = self.widget_states.get(widget_id)
        if state:
            state.mark_updating()

        start_time = time.time()

        try:
            # Get data from provider
            data = self._fetch_widget_data(widget)

            # Update widget cached data
            widget.cached_data = data
            widget.last_updated = datetime.utcnow()

            # Notify handler
            handler = self.update_handlers.get(widget.widget_type.value)
            if handler:
                handler(widget, data)

            # Update state
            update_time_ms = (time.time() - start_time) * 1000
            if state:
                state.mark_updated(update_time_ms)

            # Push update to subscribed clients
            self._push_widget_update(dashboard_id, widget, data)

        except Exception as e:
            if state:
                state.mark_error(str(e))
            raise

    def _fetch_widget_data(self, widget: Widget) -> Any:
        """Fetch data for a widget."""
        source = widget.data_source
        if not source:
            return None

        provider = self.data_providers.get(source)
        if not provider:
            # Try to get data from a general provider
            provider = self.data_providers.get("default")
            if not provider:
                return None

        params = {
            "time_range": widget.config.time_range.value if hasattr(widget.config, "time_range") else "last_7_days",
            "filters": widget.config.filters if hasattr(widget.config, "filters") else {},
        }

        data, from_cache = provider.get_data(widget.id, params)
        return data

    def _push_widget_update(
        self,
        dashboard_id: str,
        widget: Widget,
        data: Any
    ) -> None:
        """Push widget update to subscribed clients."""
        self.stream_manager.push_widget_update(
            dashboard_id=dashboard_id,
            widget_id=widget.id,
            data=data,
            metadata={
                "title": widget.config.title,
                "type": widget.widget_type.value,
            }
        )

    def start(self) -> None:
        """Start the update manager background thread."""
        if self._running:
            return

        self._running = True
        self._update_thread = threading.Thread(
            target=self._update_loop,
            daemon=True,
            name="DashboardUpdateManager"
        )
        self._update_thread.start()
        logger.info("Dashboard update manager started")

    def stop(self) -> None:
        """Stop the update manager."""
        self._running = False
        if self._update_thread:
            self._update_thread.join(timeout=5.0)
            self._update_thread = None
        logger.info("Dashboard update manager stopped")

    def _update_loop(self) -> None:
        """Background update loop."""
        while self._running:
            try:
                # Process queued updates
                self.process_update_queue()

                # Check for widgets needing refresh
                self._check_stale_widgets()

                # Brief sleep
                time.sleep(0.1)

            except Exception as e:
                logger.error(f"Error in update loop: {e}")
                time.sleep(1.0)

    def _check_stale_widgets(self) -> None:
        """Check for stale widgets and queue updates."""
        for dashboard_id, dashboard in self.dashboards.items():
            # Only check if dashboard has subscribers
            if not self.active_subscriptions.get(dashboard_id):
                continue

            for widget in dashboard.widgets:
                if not widget.visible:
                    continue

                state = self.widget_states.get(widget.id)
                if not state:
                    continue

                refresh_interval = getattr(
                    widget.config, "refresh_interval_seconds",
                    dashboard.auto_refresh
                )

                if state.needs_update(refresh_interval):
                    self.queue_widget_update(
                        dashboard_id,
                        widget.id,
                        UpdatePriority.LOW
                    )

    def get_widget_status(self, widget_id: str) -> Optional[Dict[str, Any]]:
        """Get status for a widget."""
        state = self.widget_states.get(widget_id)
        return state.to_dict() if state else None

    def get_dashboard_status(self, dashboard_id: str) -> Dict[str, Any]:
        """Get update status for a dashboard."""
        if dashboard_id not in self.dashboards:
            return {"error": "Dashboard not found"}

        dashboard = self.dashboards[dashboard_id]
        widgets_status = []

        for widget in dashboard.widgets:
            state = self.widget_states.get(widget.id)
            if state:
                widgets_status.append(state.to_dict())

        subscriber_count = len(self.active_subscriptions.get(dashboard_id, set()))

        return {
            "dashboard_id": dashboard_id,
            "widget_count": len(dashboard.widgets),
            "subscriber_count": subscriber_count,
            "widgets": widgets_status,
            "queue_size": len(self._update_queue),
        }

    def invalidate_widget(self, widget_id: str) -> None:
        """Invalidate a widget's data."""
        if widget_id in self.widget_states:
            self.widget_states[widget_id].mark_stale()

        # Invalidate in data providers
        for provider in self.data_providers.values():
            provider.invalidate_cache(widget_id)

    def invalidate_dashboard(self, dashboard_id: str) -> None:
        """Invalidate all widgets in a dashboard."""
        if dashboard_id not in self.dashboards:
            return

        dashboard = self.dashboards[dashboard_id]
        for widget in dashboard.widgets:
            self.invalidate_widget(widget.id)


# =============================================================================
# Batch Update Coordinator
# =============================================================================

class BatchUpdateCoordinator:
    """
    Coordinates batch updates across multiple dashboards.

    Optimizes update scheduling to reduce load.
    """

    def __init__(self, update_manager: DashboardUpdateManager):
        self.update_manager = update_manager
        self.batch_size = 10
        self.batch_interval_seconds = 1.0
        self.pending_batches: List[List[Tuple[str, str]]] = []
        self._lock = threading.Lock()

    def schedule_batch_update(
        self,
        updates: List[Tuple[str, str]],  # List of (dashboard_id, widget_id)
        priority: UpdatePriority = UpdatePriority.NORMAL
    ) -> None:
        """Schedule a batch of updates."""
        with self._lock:
            # Split into smaller batches
            for i in range(0, len(updates), self.batch_size):
                batch = updates[i:i + self.batch_size]
                self.pending_batches.append(batch)

        # Queue all updates
        for dashboard_id, widget_id in updates:
            self.update_manager.queue_widget_update(
                dashboard_id, widget_id, priority
            )

    def process_batches(self) -> int:
        """Process pending batches. Returns count processed."""
        return self.update_manager.process_update_queue()


# =============================================================================
# Live Metric Tracker
# =============================================================================

class LiveMetricTracker:
    """
    Tracks live metrics and pushes updates.

    Monitors metric values and triggers updates on change.
    """

    def __init__(
        self,
        stream_manager: DashboardStreamManager,
        threshold_percent: float = 5.0
    ):
        self.stream_manager = stream_manager
        self.threshold_percent = threshold_percent
        self.metric_values: Dict[str, float] = {}
        self.metric_timestamps: Dict[str, datetime] = {}

    def update_metric(
        self,
        metric_name: str,
        value: float,
        dashboard_id: Optional[str] = None,
        widget_id: Optional[str] = None,
        force_push: bool = False,
    ) -> bool:
        """
        Update a metric value.

        Returns True if value was pushed to clients.
        """
        previous_value = self.metric_values.get(metric_name)
        self.metric_values[metric_name] = value
        self.metric_timestamps[metric_name] = datetime.utcnow()

        # Check if update should be pushed
        should_push = force_push
        if not should_push and previous_value is not None:
            if previous_value == 0:
                should_push = value != 0
            else:
                change_percent = abs((value - previous_value) / previous_value) * 100
                should_push = change_percent >= self.threshold_percent

        if should_push:
            self.stream_manager.push_metric_update(
                metric_name=metric_name,
                value=value,
                previous_value=previous_value,
                dashboard_id=dashboard_id,
                widget_id=widget_id,
            )
            return True

        return False

    def get_metric(self, metric_name: str) -> Optional[Dict[str, Any]]:
        """Get current metric value."""
        if metric_name not in self.metric_values:
            return None

        return {
            "name": metric_name,
            "value": self.metric_values[metric_name],
            "timestamp": self.metric_timestamps[metric_name].isoformat(),
        }

    def get_all_metrics(self) -> List[Dict[str, Any]]:
        """Get all tracked metrics."""
        return [
            self.get_metric(name)
            for name in self.metric_values.keys()
        ]


# =============================================================================
# Factory Functions
# =============================================================================

def create_update_manager(
    event_bus: Optional[EventBus] = None,
) -> DashboardUpdateManager:
    """Create a dashboard update manager."""
    return DashboardUpdateManager(event_bus=event_bus)


def create_batch_coordinator(
    update_manager: DashboardUpdateManager
) -> BatchUpdateCoordinator:
    """Create a batch update coordinator."""
    return BatchUpdateCoordinator(update_manager)


def create_metric_tracker(
    stream_manager: DashboardStreamManager,
    threshold_percent: float = 5.0
) -> LiveMetricTracker:
    """Create a live metric tracker."""
    return LiveMetricTracker(stream_manager, threshold_percent)


def create_data_provider_config(
    provider_id: str,
    name: str,
    cache_ttl: int = 60,
    rate_limit: int = 60,
) -> DataProviderConfig:
    """Create a data provider configuration."""
    return DataProviderConfig(
        provider_id=provider_id,
        name=name,
        cache_ttl_seconds=cache_ttl,
        rate_limit_per_minute=rate_limit,
    )
