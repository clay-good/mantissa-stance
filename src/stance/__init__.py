"""
Mantissa Stance - Cloud Security Posture Management and Vulnerability Detection

A minimal, focused CSPM tool that answers one question:
"What is wrong with my cloud configuration RIGHT NOW?"

Key Features:
- Read-only by design: Can never modify cloud resources
- Minimal dependencies: Only boto3 required
- YAML-based policies: Write and version control your own security rules
- Natural language queries: Ask questions like "Are we PCI compliant?"
- Multiple LLM providers: Anthropic, OpenAI, and Gemini supported

Quick Start:
    >>> from stance.collectors import run_collection
    >>> from stance.engine import run_evaluation
    >>>
    >>> # Collect assets from AWS
    >>> assets, findings, results = run_collection()
    >>>
    >>> # Evaluate policies
    >>> eval_findings, result = run_evaluation(assets)
    >>> print(f"Found {len(eval_findings)} issues")
"""

from __future__ import annotations

__version__ = "0.1.0"
__author__ = "Mantissa"

# Core models
from stance.models import (
    Asset,
    AssetCollection,
    Finding,
    FindingCollection,
    FindingType,
    Severity,
    FindingStatus,
    Policy,
    PolicyCollection,
    Check,
    CheckType,
    ComplianceMapping,
    Remediation,
    NETWORK_EXPOSURE_INTERNET,
    NETWORK_EXPOSURE_INTERNAL,
    NETWORK_EXPOSURE_ISOLATED,
)

# Storage
from stance.storage import (
    StorageBackend,
    LocalStorage,
    S3Storage,
    get_storage,
    generate_snapshot_id,
)

# Collectors
from stance.collectors import (
    BaseCollector,
    CollectorResult,
    CollectorRunner,
    IAMCollector,
    S3Collector,
    EC2Collector,
    SecurityCollector,
    get_default_collectors,
    run_collection,
    list_collector_names,
)

# Engine
from stance.engine import (
    ExpressionEvaluator,
    ExpressionError,
    PolicyLoader,
    PolicyLoadError,
    PolicyEvaluator,
    EvaluationResult,
    PolicyEvalResult,
    BenchmarkCalculator,
    BenchmarkReport,
    BenchmarkScore,
    ControlStatus,
    run_evaluation,
)

# LLM
from stance.llm import (
    LLMProvider,
    LLMResponse,
    LLMError,
    RateLimitError,
    AuthenticationError,
    AnthropicProvider,
    OpenAIProvider,
    GeminiProvider,
    QueryGenerator,
    GeneratedQuery,
    get_llm_provider,
)

# CLI
from stance.cli import main

# Correlation and Analytics
from stance.correlation import (
    CorrelatedFinding,
    CorrelationGroup,
    CorrelationResult,
    FindingCorrelator,
    AttackPath,
    AttackPathAnalysisResult,
    AttackPathAnalyzer,
    AttackPathType,
    AttackStep,
    AssetRiskScore,
    RiskFactor,
    RiskLevel,
    RiskScorer,
    RiskScoringResult,
    RiskTrend,
    analyze_findings,
)

# Analytics (Asset Graph based)
from stance.analytics import (
    AssetGraph,
    AssetGraphBuilder,
    AssetNode,
    Relationship,
    RelationshipType,
)

# Alerting
from stance.alerting import (
    AlertRouter,
    AlertConfig,
    AlertState,
    BaseDestination,
    SlackDestination,
    PagerDutyDestination,
    EmailDestination,
    WebhookDestination,
    TeamsDestination,
    JiraDestination,
    create_destination,
)

# Enrichment
from stance.enrichment import (
    BaseEnricher,
    EnrichmentResult,
    IPEnricher,
    AssetEnricher,
    ThreatIntelEnricher,
)

# Drift Detection
from stance.drift import (
    BaselineManager,
    Baseline,
    DriftDetector,
    DriftDetectionResult,
    ChangeTracker,
    ChangeEvent,
)

# Export
from stance.export import (
    BaseExporter,
    ExportResult,
    ExportManager,
    CSVExporter,
    JSONExporter,
    HTMLExporter,
    PDFExporter,
    create_export_manager,
    export_report,
)

# State Management
from stance.state import (
    StateManager,
    get_state_manager,
)

# Observability
from stance.observability import (
    StanceLogger,
    configure_logging,
    get_logger,
    StanceMetrics,
    configure_metrics,
    get_metrics,
    StanceTracer,
    configure_tracing,
    get_tracer,
    Span,
    SpanContext,
    SpanStatus,
    TracingBackend,
    InMemoryTracingBackend,
)

__all__ = [
    # Version
    "__version__",
    "__author__",
    # Models
    "Asset",
    "AssetCollection",
    "Finding",
    "FindingCollection",
    "FindingType",
    "Severity",
    "FindingStatus",
    "Policy",
    "PolicyCollection",
    "Check",
    "CheckType",
    "ComplianceMapping",
    "Remediation",
    "NETWORK_EXPOSURE_INTERNET",
    "NETWORK_EXPOSURE_INTERNAL",
    "NETWORK_EXPOSURE_ISOLATED",
    # Storage
    "StorageBackend",
    "LocalStorage",
    "S3Storage",
    "get_storage",
    "generate_snapshot_id",
    # Collectors
    "BaseCollector",
    "CollectorResult",
    "CollectorRunner",
    "IAMCollector",
    "S3Collector",
    "EC2Collector",
    "SecurityCollector",
    "get_default_collectors",
    "run_collection",
    "list_collector_names",
    # Engine
    "ExpressionEvaluator",
    "ExpressionError",
    "PolicyLoader",
    "PolicyLoadError",
    "PolicyEvaluator",
    "EvaluationResult",
    "PolicyEvalResult",
    "BenchmarkCalculator",
    "BenchmarkReport",
    "BenchmarkScore",
    "ControlStatus",
    "run_evaluation",
    # LLM
    "LLMProvider",
    "LLMResponse",
    "LLMError",
    "RateLimitError",
    "AuthenticationError",
    "AnthropicProvider",
    "OpenAIProvider",
    "GeminiProvider",
    "QueryGenerator",
    "GeneratedQuery",
    "get_llm_provider",
    # CLI
    "main",
    # Correlation and Analytics
    "CorrelatedFinding",
    "CorrelationGroup",
    "CorrelationResult",
    "FindingCorrelator",
    "AttackPath",
    "AttackPathAnalysisResult",
    "AttackPathAnalyzer",
    "AttackPathType",
    "AttackStep",
    "AssetRiskScore",
    "RiskFactor",
    "RiskLevel",
    "RiskScorer",
    "RiskScoringResult",
    "RiskTrend",
    "analyze_findings",
    # Analytics (Asset Graph)
    "AssetGraph",
    "AssetGraphBuilder",
    "AssetNode",
    "Relationship",
    "RelationshipType",
    # Alerting
    "AlertRouter",
    "AlertConfig",
    "AlertState",
    "BaseDestination",
    "SlackDestination",
    "PagerDutyDestination",
    "EmailDestination",
    "WebhookDestination",
    "TeamsDestination",
    "JiraDestination",
    "create_destination",
    # Enrichment
    "BaseEnricher",
    "EnrichmentResult",
    "IPEnricher",
    "AssetEnricher",
    "ThreatIntelEnricher",
    # Drift Detection
    "BaselineManager",
    "Baseline",
    "DriftDetector",
    "DriftDetectionResult",
    "ChangeTracker",
    "ChangeEvent",
    # Export
    "BaseExporter",
    "ExportResult",
    "ExportManager",
    "CSVExporter",
    "JSONExporter",
    "HTMLExporter",
    "PDFExporter",
    "create_export_manager",
    "export_report",
    # State Management
    "StateManager",
    "get_state_manager",
    # Observability
    "StanceLogger",
    "configure_logging",
    "get_logger",
    "StanceMetrics",
    "configure_metrics",
    "get_metrics",
    "StanceTracer",
    "configure_tracing",
    "get_tracer",
    "Span",
    "SpanContext",
    "SpanStatus",
    "TracingBackend",
    "InMemoryTracingBackend",
]
