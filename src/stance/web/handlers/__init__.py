"""
Web request handlers for Mantissa Stance.

This module provides modular request handlers that can be plugged into
the main StanceRequestHandler. Each handler module focuses on a specific
domain (auth, visualization, workflow, etc.) to improve maintainability.

Usage:
    from stance.web.handlers import HandlerRegistry

    # In StanceRequestHandler:
    registry = HandlerRegistry(storage=self.storage)

    # Register route patterns
    registry.register_handler("/api/auth/", AuthHandler)
    registry.register_handler("/api/viz/", VisualizationHandler)
    registry.register_handler("/api/workflow/", WorkflowHandler)

    # Handle request
    result = registry.handle(path, params, method="GET")
"""

from stance.web.handlers.base import BaseHandler, HandlerRegistry, HandlerResponse, HttpStatus
from stance.web.handlers.router import RouteTable, RoutedHandler, route
from stance.web.handlers.aggregation import AggregationHandler
from stance.web.handlers.alert import AlertHandler
from stance.web.handlers.analytics import AnalyticsHandler
from stance.web.handlers.assets import AssetHandler
from stance.web.handlers.auth import AuthHandler
from stance.web.handlers.automation import AutomationHandler
from stance.web.handlers.cloud import CloudHandler
from stance.web.handlers.collectors import CollectorsHandler
from stance.web.handlers.compliance import ComplianceHandler
from stance.web.handlers.config import ConfigHandler
from stance.web.handlers.correlation import CorrelationHandler
from stance.web.handlers.dashboard import DashboardHandler
from stance.web.handlers.detection import DetectionHandler
from stance.web.handlers.docs import DocsHandler
from stance.web.handlers.engine import EngineHandler
from stance.web.handlers.exceptions import ExceptionsHandler
from stance.web.handlers.export import ExportHandler
from stance.web.handlers.findings import FindingsHandler
from stance.web.handlers.iac import IacHandler
from stance.web.handlers.llm import LlmHandler
from stance.web.handlers.notifications import NotificationsHandler
from stance.web.handlers.observability import ObservabilityHandler
from stance.web.handlers.plugins import PluginsHandler
from stance.web.handlers.policy import PolicyHandler
from stance.web.handlers.query import QueryHandler
from stance.web.handlers.report import ReportHandler
from stance.web.handlers.sbom import SbomHandler
from stance.web.handlers.scan import ScanHandler
from stance.web.handlers.scanner import ScannerHandler
from stance.web.handlers.scheduling import SchedulingHandler
from stance.web.handlers.state import StateHandler
from stance.web.handlers.storage import StorageHandler
from stance.web.handlers.trends import TrendsHandler
from stance.web.handlers.visualization import VisualizationHandler
from stance.web.handlers.workflow import WorkflowHandler

__all__ = [
    "AggregationHandler",
    "AlertHandler",
    "AnalyticsHandler",
    "AssetHandler",
    "AuthHandler",
    "AutomationHandler",
    "BaseHandler",
    "CloudHandler",
    "CollectorsHandler",
    "ComplianceHandler",
    "ConfigHandler",
    "CorrelationHandler",
    "DashboardHandler",
    "DetectionHandler",
    "DocsHandler",
    "EngineHandler",
    "ExceptionsHandler",
    "ExportHandler",
    "FindingsHandler",
    "HandlerRegistry",
    "HandlerResponse",
    "HttpStatus",
    "IacHandler",
    "LlmHandler",
    "NotificationsHandler",
    "ObservabilityHandler",
    "PluginsHandler",
    "PolicyHandler",
    "QueryHandler",
    "ReportHandler",
    "RouteTable",
    "RoutedHandler",
    "route",
    "SbomHandler",
    "ScanHandler",
    "ScannerHandler",
    "SchedulingHandler",
    "StateHandler",
    "StorageHandler",
    "TrendsHandler",
    "VisualizationHandler",
    "WorkflowHandler",
]

__version__ = "1.0.0"
