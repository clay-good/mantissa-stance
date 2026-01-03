"""
Analytics module for Mantissa Stance.

Provides finding correlation, attack path analysis, risk scoring,
toxic combinations detection, blast radius calculation, and MITRE ATT&CK mapping
for comprehensive security posture assessment.

Components:
- AssetGraph: Graph-based asset relationship modeling
- AttackPathAnalyzer: Attack path detection and analysis
- BlastRadiusCalculator: Impact assessment and blast radius
- MitreAttackMapper: MITRE ATT&CK technique mapping
- RiskScorer: Asset risk scoring with multiple factors
- ToxicCombinationDetector: Dangerous configuration detection
"""

from stance.analytics.asset_graph import (
    AssetGraph,
    AssetGraphBuilder,
    AssetNode,
    Relationship,
    RelationshipType,
)
from stance.analytics.attack_paths import (
    AttackPath,
    AttackPathAnalyzer,
    AttackPathStep,
    AttackPathType,
)
from stance.analytics.blast_radius import (
    AffectedResource,
    BlastRadius,
    BlastRadiusCalculator,
    ImpactCategory,
)
from stance.analytics.mitre_attack import (
    AttackMapping,
    KillChainPhase,
    MitreAttackMapper,
    MitreTactic,
    MitreTechnique,
)
from stance.analytics.risk_scoring import (
    RiskFactors,
    RiskScore,
    RiskScorer,
    RiskTrend,
)
from stance.analytics.toxic_combinations import (
    ToxicCombination,
    ToxicCombinationDetector,
    ToxicCombinationType,
    ToxicCondition,
)

__all__ = [
    # Asset Graph
    "AssetGraph",
    "AssetGraphBuilder",
    "AssetNode",
    "Relationship",
    "RelationshipType",
    # Attack Paths
    "AttackPath",
    "AttackPathAnalyzer",
    "AttackPathStep",
    "AttackPathType",
    # Blast Radius
    "AffectedResource",
    "BlastRadius",
    "BlastRadiusCalculator",
    "ImpactCategory",
    # MITRE ATT&CK
    "AttackMapping",
    "KillChainPhase",
    "MitreAttackMapper",
    "MitreTactic",
    "MitreTechnique",
    # Risk Scoring
    "RiskFactors",
    "RiskScore",
    "RiskScorer",
    "RiskTrend",
    # Toxic Combinations
    "ToxicCombination",
    "ToxicCombinationDetector",
    "ToxicCombinationType",
    "ToxicCondition",
]
