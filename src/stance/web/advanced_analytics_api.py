"""
Web API for Advanced Analytics in Mantissa Stance.

Provides REST API endpoints for:
- Predictive security scoring
- Trend forecasting
- Risk correlation analysis
- Anomaly detection and analysis

Part of Phase 96: Advanced Analytics
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

from stance.analytics import (
    # Predictive Scoring
    PredictiveSecurityScorer,
    PredictiveScoringConfig,
    RiskDataPoint,
    PredictionModel,
    # Trend Forecasting
    TrendForecaster,
    TrendForecastConfig,
    ForecastMetric,
    TimeSeriesPoint,
    # Risk Correlation
    RiskCorrelationAnalyzer,
    RiskCorrelationConfig,
    RiskDataSample,
    RiskFactor,
    # Anomaly Integration
    AnomalyIntegrationEngine,
    AnomalyIntegrationConfig,
)

logger = logging.getLogger(__name__)


@dataclass
class AdvancedAnalyticsAPIConfig:
    """Configuration for advanced analytics API."""
    max_history_points: int = 1000
    max_forecast_days: int = 90
    default_prediction_days: int = 30
    enable_caching: bool = True
    cache_ttl_seconds: int = 300


class AdvancedAnalyticsAPI:
    """
    REST API handler for advanced analytics.
    """

    def __init__(self, config: Optional[AdvancedAnalyticsAPIConfig] = None):
        """Initialize API handler."""
        self.config = config or AdvancedAnalyticsAPIConfig()
        self.predictive_scorer = PredictiveSecurityScorer()
        self.forecaster = TrendForecaster()
        self.correlation_analyzer = RiskCorrelationAnalyzer()
        self.anomaly_engine = AnomalyIntegrationEngine()
        self._cache: Dict[str, Any] = {}

    def get_routes(self) -> List[Dict[str, Any]]:
        """
        Get API route definitions.

        Returns:
            List of route definitions
        """
        return [
            # Predictive Scoring
            {
                "method": "GET",
                "path": "/api/v1/analytics/predictions/{asset_id}",
                "handler": self.get_prediction,
                "description": "Get risk prediction for an asset",
            },
            {
                "method": "POST",
                "path": "/api/v1/analytics/predictions/{asset_id}/history",
                "handler": self.add_risk_history,
                "description": "Add risk history data point",
            },
            {
                "method": "GET",
                "path": "/api/v1/analytics/predictions/{asset_id}/velocity",
                "handler": self.get_velocity,
                "description": "Get risk velocity",
            },
            {
                "method": "GET",
                "path": "/api/v1/analytics/predictions/{asset_id}/probability",
                "handler": self.get_probability,
                "description": "Get risk probability",
            },
            {
                "method": "GET",
                "path": "/api/v1/analytics/predictions/high-risk",
                "handler": self.get_high_risk_predictions,
                "description": "Get high risk predictions",
            },
            {
                "method": "GET",
                "path": "/api/v1/analytics/predictions/worsening",
                "handler": self.get_worsening_assets,
                "description": "Get worsening assets",
            },
            # Trend Forecasting
            {
                "method": "GET",
                "path": "/api/v1/analytics/forecasts/{entity_id}",
                "handler": self.get_forecast,
                "description": "Get forecast for entity",
            },
            {
                "method": "POST",
                "path": "/api/v1/analytics/forecasts/{entity_id}/data",
                "handler": self.add_timeseries_data,
                "description": "Add time series data",
            },
            {
                "method": "GET",
                "path": "/api/v1/analytics/forecasts/{entity_id}/decomposition",
                "handler": self.get_decomposition,
                "description": "Get series decomposition",
            },
            {
                "method": "GET",
                "path": "/api/v1/analytics/forecasts/{entity_id}/trend-change",
                "handler": self.get_trend_change,
                "description": "Detect trend changes",
            },
            {
                "method": "GET",
                "path": "/api/v1/analytics/forecasts/{entity_id}/seasonal",
                "handler": self.get_seasonal_insights,
                "description": "Get seasonal insights",
            },
            {
                "method": "GET",
                "path": "/api/v1/analytics/forecasts/{entity_id}/multi",
                "handler": self.get_multi_forecast,
                "description": "Get multi-metric forecast",
            },
            # Risk Correlation
            {
                "method": "GET",
                "path": "/api/v1/analytics/correlations/entities",
                "handler": self.get_entity_correlation,
                "description": "Get entity correlation",
            },
            {
                "method": "GET",
                "path": "/api/v1/analytics/correlations/factors",
                "handler": self.get_factor_correlation,
                "description": "Get factor correlation",
            },
            {
                "method": "GET",
                "path": "/api/v1/analytics/correlations/matrix/entities",
                "handler": self.get_entity_matrix,
                "description": "Get entity correlation matrix",
            },
            {
                "method": "GET",
                "path": "/api/v1/analytics/correlations/matrix/factors",
                "handler": self.get_factor_matrix,
                "description": "Get factor correlation matrix",
            },
            {
                "method": "GET",
                "path": "/api/v1/analytics/correlations/causal",
                "handler": self.get_causal_relationships,
                "description": "Get causal relationships",
            },
            {
                "method": "GET",
                "path": "/api/v1/analytics/correlations/clusters",
                "handler": self.get_risk_clusters,
                "description": "Get risk clusters",
            },
            {
                "method": "GET",
                "path": "/api/v1/analytics/correlations/report",
                "handler": self.get_correlation_report,
                "description": "Get full correlation report",
            },
            {
                "method": "POST",
                "path": "/api/v1/analytics/correlations/data",
                "handler": self.add_correlation_data,
                "description": "Add correlation data sample",
            },
            # Anomaly Detection
            {
                "method": "POST",
                "path": "/api/v1/analytics/anomalies/{entity_id}/detect",
                "handler": self.detect_anomaly,
                "description": "Detect anomaly in observation",
            },
            {
                "method": "GET",
                "path": "/api/v1/analytics/anomalies/{entity_id}/trend",
                "handler": self.get_anomaly_trend,
                "description": "Get anomaly trend",
            },
            {
                "method": "GET",
                "path": "/api/v1/analytics/anomalies/{entity_id}/prediction",
                "handler": self.get_anomaly_prediction,
                "description": "Predict future anomalies",
            },
            {
                "method": "GET",
                "path": "/api/v1/analytics/anomalies/{entity_id}/analysis",
                "handler": self.get_anomaly_analysis,
                "description": "Get comprehensive analysis",
            },
            {
                "method": "GET",
                "path": "/api/v1/analytics/anomalies/high-risk",
                "handler": self.get_high_risk_entities,
                "description": "Get high risk entities",
            },
            {
                "method": "GET",
                "path": "/api/v1/analytics/anomalies/{entity_id}/baseline",
                "handler": self.get_baseline,
                "description": "Get entity baseline",
            },
        ]

    # ==========================================================================
    # Predictive Scoring Endpoints
    # ==========================================================================

    def get_prediction(
        self,
        asset_id: str,
        days: int = 30,
        model: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Get risk prediction for an asset.

        Args:
            asset_id: Asset ID
            days: Prediction horizon in days
            model: Optional prediction model

        Returns:
            API response
        """
        days = min(days, self.config.max_forecast_days)
        pred_model = PredictionModel(model) if model else None

        prediction = self.predictive_scorer.predict_risk(asset_id, days, pred_model)

        if not prediction:
            return {
                "success": False,
                "error": "Insufficient historical data",
                "code": "INSUFFICIENT_DATA",
            }

        return {
            "success": True,
            "data": prediction.to_dict(),
        }

    def add_risk_history(
        self,
        asset_id: str,
        body: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Add risk history data point.

        Args:
            asset_id: Asset ID
            body: Request body with risk data

        Returns:
            API response
        """
        try:
            timestamp = (
                datetime.fromisoformat(body["timestamp"])
                if "timestamp" in body
                else datetime.utcnow()
            )

            data_point = RiskDataPoint(
                timestamp=timestamp,
                risk_score=float(body["risk_score"]),
                finding_count=body.get("finding_count", 0),
                critical_count=body.get("critical_count", 0),
                high_count=body.get("high_count", 0),
                compliance_violations=body.get("compliance_violations", 0),
                exposure_score=body.get("exposure_score", 0.0),
            )

            self.predictive_scorer.add_data_point(asset_id, data_point)

            return {
                "success": True,
                "message": "Data point added",
                "data": data_point.to_dict(),
            }
        except (KeyError, ValueError) as e:
            return {
                "success": False,
                "error": str(e),
                "code": "INVALID_REQUEST",
            }

    def get_velocity(self, asset_id: str) -> Dict[str, Any]:
        """Get risk velocity for an asset."""
        velocity = self.predictive_scorer.get_velocity(asset_id)

        if not velocity:
            return {
                "success": False,
                "error": "Insufficient data",
                "code": "INSUFFICIENT_DATA",
            }

        return {
            "success": True,
            "data": velocity.to_dict(),
        }

    def get_probability(
        self,
        asset_id: str,
        days: int = 30,
    ) -> Dict[str, Any]:
        """Get risk probability for an asset."""
        probability = self.predictive_scorer.calculate_risk_probability(asset_id, days)

        if not probability:
            return {
                "success": False,
                "error": "Insufficient data",
                "code": "INSUFFICIENT_DATA",
            }

        return {
            "success": True,
            "data": probability.to_dict(),
        }

    def get_high_risk_predictions(
        self,
        threshold: float = 70.0,
        days: int = 30,
    ) -> Dict[str, Any]:
        """Get high risk predictions."""
        predictions = self.predictive_scorer.get_high_risk_predictions(threshold, days)

        return {
            "success": True,
            "data": {
                "threshold": threshold,
                "days": days,
                "count": len(predictions),
                "predictions": [p.to_dict() for p in predictions],
            },
        }

    def get_worsening_assets(
        self,
        min_change: float = 10.0,
        days: int = 30,
    ) -> Dict[str, Any]:
        """Get assets with worsening trajectory."""
        predictions = self.predictive_scorer.get_worsening_assets(min_change, days)

        return {
            "success": True,
            "data": {
                "min_change": min_change,
                "days": days,
                "count": len(predictions),
                "assets": [p.to_dict() for p in predictions],
            },
        }

    # ==========================================================================
    # Trend Forecasting Endpoints
    # ==========================================================================

    def get_forecast(
        self,
        entity_id: str,
        metric: str = "risk_score",
        days: int = 30,
    ) -> Dict[str, Any]:
        """Get forecast for entity."""
        try:
            forecast_metric = ForecastMetric(metric)
        except ValueError:
            return {
                "success": False,
                "error": f"Invalid metric: {metric}",
                "code": "INVALID_METRIC",
            }

        days = min(days, self.config.max_forecast_days)
        forecast = self.forecaster.forecast(entity_id, forecast_metric, days)

        if not forecast:
            return {
                "success": False,
                "error": "Insufficient data for forecasting",
                "code": "INSUFFICIENT_DATA",
            }

        return {
            "success": True,
            "data": forecast.to_dict(),
        }

    def add_timeseries_data(
        self,
        entity_id: str,
        body: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Add time series data point."""
        try:
            metric = ForecastMetric(body.get("metric", "risk_score"))
            timestamp = (
                datetime.fromisoformat(body["timestamp"])
                if "timestamp" in body
                else datetime.utcnow()
            )

            point = TimeSeriesPoint(
                timestamp=timestamp,
                value=float(body["value"]),
                metric=metric,
            )

            self.forecaster.add_data_point(entity_id, point)

            return {
                "success": True,
                "message": "Data point added",
                "data": point.to_dict(),
            }
        except (KeyError, ValueError) as e:
            return {
                "success": False,
                "error": str(e),
                "code": "INVALID_REQUEST",
            }

    def get_decomposition(
        self,
        entity_id: str,
        metric: str = "risk_score",
    ) -> Dict[str, Any]:
        """Get series decomposition."""
        try:
            forecast_metric = ForecastMetric(metric)
        except ValueError:
            return {
                "success": False,
                "error": f"Invalid metric: {metric}",
                "code": "INVALID_METRIC",
            }

        decomposition = self.forecaster.decompose(entity_id, forecast_metric)

        if not decomposition:
            return {
                "success": False,
                "error": "Insufficient data for decomposition",
                "code": "INSUFFICIENT_DATA",
            }

        return {
            "success": True,
            "data": decomposition.to_dict(),
        }

    def get_trend_change(
        self,
        entity_id: str,
        metric: str = "risk_score",
        days: int = 30,
    ) -> Dict[str, Any]:
        """Detect trend changes."""
        try:
            forecast_metric = ForecastMetric(metric)
        except ValueError:
            return {
                "success": False,
                "error": f"Invalid metric: {metric}",
                "code": "INVALID_METRIC",
            }

        result = self.forecaster.detect_trend_change(entity_id, forecast_metric, days)

        if not result:
            return {
                "success": False,
                "error": "Insufficient data for trend change detection",
                "code": "INSUFFICIENT_DATA",
            }

        return {
            "success": True,
            "data": result,
        }

    def get_seasonal_insights(
        self,
        entity_id: str,
        metric: str = "risk_score",
    ) -> Dict[str, Any]:
        """Get seasonal insights."""
        try:
            forecast_metric = ForecastMetric(metric)
        except ValueError:
            return {
                "success": False,
                "error": f"Invalid metric: {metric}",
                "code": "INVALID_METRIC",
            }

        insights = self.forecaster.get_seasonal_insights(entity_id, forecast_metric)

        if not insights:
            return {
                "success": False,
                "error": "No seasonal pattern detected",
                "code": "NO_PATTERN",
            }

        return {
            "success": True,
            "data": insights,
        }

    def get_multi_forecast(
        self,
        entity_id: str,
        metrics: Optional[List[str]] = None,
        days: int = 30,
    ) -> Dict[str, Any]:
        """Get multi-metric forecast."""
        forecast_metrics = None
        if metrics:
            try:
                forecast_metrics = [ForecastMetric(m) for m in metrics]
            except ValueError as e:
                return {
                    "success": False,
                    "error": f"Invalid metric: {e}",
                    "code": "INVALID_METRIC",
                }

        days = min(days, self.config.max_forecast_days)
        forecast = self.forecaster.forecast_multiple_metrics(
            entity_id, forecast_metrics, days
        )

        if not forecast:
            return {
                "success": False,
                "error": "Insufficient data for multi-metric forecast",
                "code": "INSUFFICIENT_DATA",
            }

        return {
            "success": True,
            "data": forecast.to_dict(),
        }

    # ==========================================================================
    # Risk Correlation Endpoints
    # ==========================================================================

    def get_entity_correlation(
        self,
        entity1: str,
        entity2: str,
        factor: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get correlation between two entities."""
        risk_factor = RiskFactor(factor) if factor else None

        correlation = self.correlation_analyzer.calculate_entity_correlation(
            entity1, entity2, risk_factor
        )

        if not correlation:
            return {
                "success": False,
                "error": "Insufficient data for correlation",
                "code": "INSUFFICIENT_DATA",
            }

        return {
            "success": True,
            "data": correlation.to_dict(),
        }

    def get_factor_correlation(
        self,
        entity_id: str,
        factor1: str,
        factor2: str,
    ) -> Dict[str, Any]:
        """Get correlation between two factors."""
        try:
            rf1 = RiskFactor(factor1)
            rf2 = RiskFactor(factor2)
        except ValueError as e:
            return {
                "success": False,
                "error": f"Invalid factor: {e}",
                "code": "INVALID_FACTOR",
            }

        correlation = self.correlation_analyzer.calculate_factor_correlation(
            entity_id, rf1, rf2
        )

        if not correlation:
            return {
                "success": False,
                "error": "Insufficient data for correlation",
                "code": "INSUFFICIENT_DATA",
            }

        return {
            "success": True,
            "data": correlation.to_dict(),
        }

    def get_entity_matrix(self) -> Dict[str, Any]:
        """Get entity correlation matrix."""
        matrix = self.correlation_analyzer.build_entity_correlation_matrix()

        return {
            "success": True,
            "data": matrix.to_dict(),
        }

    def get_factor_matrix(
        self,
        entity_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get factor correlation matrix."""
        matrix = self.correlation_analyzer.build_factor_correlation_matrix(entity_id)

        return {
            "success": True,
            "data": matrix.to_dict(),
        }

    def get_causal_relationships(
        self,
        entity_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get causal relationships."""
        relationships = self.correlation_analyzer.detect_causal_relationships(entity_id)

        return {
            "success": True,
            "data": {
                "count": len(relationships),
                "relationships": [r.to_dict() for r in relationships],
            },
        }

    def get_risk_clusters(self) -> Dict[str, Any]:
        """Get risk clusters."""
        clusters = self.correlation_analyzer.cluster_by_risk()

        return {
            "success": True,
            "data": {
                "count": len(clusters),
                "clusters": [c.to_dict() for c in clusters],
            },
        }

    def get_correlation_report(self) -> Dict[str, Any]:
        """Get full correlation report."""
        report = self.correlation_analyzer.generate_report()

        return {
            "success": True,
            "data": report.to_dict(),
        }

    def add_correlation_data(
        self,
        body: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Add correlation data sample."""
        try:
            entity_id = body["entity_id"]
            timestamp = (
                datetime.fromisoformat(body["timestamp"])
                if "timestamp" in body
                else datetime.utcnow()
            )

            factors = {}
            for factor_str, value in body.get("factors", {}).items():
                try:
                    factor = RiskFactor(factor_str)
                    factors[factor] = float(value)
                except ValueError:
                    continue

            sample = RiskDataSample(
                entity_id=entity_id,
                timestamp=timestamp,
                factors=factors,
            )

            self.correlation_analyzer.add_sample(sample)

            return {
                "success": True,
                "message": "Sample added",
                "data": sample.to_dict(),
            }
        except (KeyError, ValueError) as e:
            return {
                "success": False,
                "error": str(e),
                "code": "INVALID_REQUEST",
            }

    # ==========================================================================
    # Anomaly Detection Endpoints
    # ==========================================================================

    def detect_anomaly(
        self,
        entity_id: str,
        body: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Detect anomaly in observation."""
        features = body.get("features")
        if not features:
            return {
                "success": False,
                "error": "features dictionary is required",
                "code": "INVALID_REQUEST",
            }

        timestamp = (
            datetime.fromisoformat(body["timestamp"])
            if "timestamp" in body
            else None
        )

        anomaly = self.anomaly_engine.process_observation(
            entity_id, features, timestamp
        )

        if anomaly:
            return {
                "success": True,
                "anomaly_detected": True,
                "data": anomaly.to_dict(),
            }
        else:
            return {
                "success": True,
                "anomaly_detected": False,
                "message": "No anomaly detected",
            }

    def get_anomaly_trend(
        self,
        entity_id: str,
        days: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Get anomaly trend for entity."""
        trend = self.anomaly_engine.trend_analyzer.analyze_trend(entity_id, days)

        if not trend:
            return {
                "success": False,
                "error": "Insufficient anomaly history",
                "code": "INSUFFICIENT_DATA",
            }

        return {
            "success": True,
            "data": trend.to_dict(),
        }

    def get_anomaly_prediction(
        self,
        entity_id: str,
        days: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Predict future anomalies."""
        prediction = self.anomaly_engine.trend_analyzer.predict_anomalies(
            entity_id, days
        )

        if not prediction:
            return {
                "success": False,
                "error": "Insufficient data for prediction",
                "code": "INSUFFICIENT_DATA",
            }

        return {
            "success": True,
            "data": prediction.to_dict(),
        }

    def get_anomaly_analysis(self, entity_id: str) -> Dict[str, Any]:
        """Get comprehensive anomaly analysis."""
        analysis = self.anomaly_engine.get_comprehensive_analysis(entity_id)

        return {
            "success": True,
            "data": analysis,
        }

    def get_high_risk_entities(
        self,
        threshold: float = 0.7,
    ) -> Dict[str, Any]:
        """Get entities with high anomaly risk."""
        entities = self.anomaly_engine.get_high_risk_entities(threshold)

        return {
            "success": True,
            "data": {
                "threshold": threshold,
                "count": len(entities),
                "entities": entities,
            },
        }

    def get_baseline(self, entity_id: str) -> Dict[str, Any]:
        """Get baseline for entity."""
        baseline = self.anomaly_engine.behavioral_detector.get_baseline(entity_id)

        if not baseline:
            return {
                "success": False,
                "error": "No baseline established",
                "code": "NO_BASELINE",
            }

        return {
            "success": True,
            "data": baseline.to_dict(),
        }
