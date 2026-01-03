"""
Finding correlation for Mantissa Stance.

Provides correlation, attack path analysis, and risk scoring
for security findings across multi-cloud environments.
"""

from stance.correlation.correlator import (
    CorrelatedFinding,
    CorrelationGroup,
    CorrelationResult,
    FindingCorrelator,
)
from stance.correlation.attack_paths import (
    AttackPath,
    AttackPathAnalysisResult,
    AttackPathAnalyzer,
    AttackPathType,
    AttackStep,
)
from stance.correlation.risk_scoring import (
    AssetRiskScore,
    RiskFactor,
    RiskLevel,
    RiskScorer,
    RiskScoringResult,
    RiskTrend,
)

__all__ = [
    # Correlator
    "CorrelatedFinding",
    "CorrelationGroup",
    "CorrelationResult",
    "FindingCorrelator",
    # Attack paths
    "AttackPath",
    "AttackPathAnalysisResult",
    "AttackPathAnalyzer",
    "AttackPathType",
    "AttackStep",
    # Risk scoring
    "AssetRiskScore",
    "RiskFactor",
    "RiskLevel",
    "RiskScorer",
    "RiskScoringResult",
    "RiskTrend",
]


def analyze_findings(
    findings,
    assets,
    include_attack_paths: bool = True,
    include_risk_scores: bool = True,
) -> dict:
    """
    Perform comprehensive finding analysis.

    Convenience function that runs correlation, attack path analysis,
    and risk scoring in a single call.

    Args:
        findings: Collection of findings
        assets: Collection of assets
        include_attack_paths: Whether to analyze attack paths
        include_risk_scores: Whether to calculate risk scores

    Returns:
        Dictionary containing:
        - correlation: CorrelationResult
        - attack_paths: AttackPathAnalysisResult (if enabled)
        - risk_scores: RiskScoringResult (if enabled)
    """
    result = {}

    # Run correlation
    correlator = FindingCorrelator()
    result["correlation"] = correlator.correlate(findings, assets)

    # Run attack path analysis
    if include_attack_paths:
        analyzer = AttackPathAnalyzer()
        result["attack_paths"] = analyzer.analyze(findings, assets)

    # Run risk scoring
    if include_risk_scores:
        scorer = RiskScorer()
        result["risk_scores"] = scorer.calculate_scores(findings, assets)

    return result
