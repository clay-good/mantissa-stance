# stance.correlation

Finding correlation for Mantissa Stance.

Provides correlation, attack path analysis, and risk scoring
for security findings across multi-cloud environments.

## Contents

### Functions

- [analyze_findings](#analyze_findings)

### `analyze_findings(findings, assets, include_attack_paths: bool = True, include_risk_scores: bool = True) -> dict`

Perform comprehensive finding analysis.  Convenience function that runs correlation, attack path analysis, and risk scoring in a single call.

**Parameters:**

- `findings` - Collection of findings
- `assets` - Collection of assets
- `include_attack_paths` (`bool`) - default: `True` - Whether to analyze attack paths
- `include_risk_scores` (`bool`) - default: `True` - Whether to calculate risk scores

**Returns:**

`dict` - Dictionary containing: - correlation: CorrelationResult - attack_paths: AttackPathAnalysisResult (if enabled) - risk_scores: RiskScoringResult (if enabled)
