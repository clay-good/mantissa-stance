# stance.engine

Policy engine for Mantissa Stance.

This package provides the policy evaluation framework including:

- ExpressionEvaluator: Safe evaluation of boolean expressions
- PolicyLoader: Load and validate YAML policies
- PolicyEvaluator: Evaluate policies against assets
- ComplianceCalculator: Calculate compliance scores

## Contents

### Functions

- [run_evaluation](#run_evaluation)

### `run_evaluation(assets: AssetCollection, policy_dirs: list[str] | None) -> tuple[(FindingCollection, EvaluationResult)]`

Run full policy evaluation.  Loads policies from configured directories and evaluates them against the provided assets.

**Parameters:**

- `assets` (`AssetCollection`) - Collected assets to evaluate
- `policy_dirs` (`list[str] | None`) - Optional list of policy directories. Defaults to ["policies/"]

**Returns:**

`tuple[(FindingCollection, EvaluationResult)]` - Tuple of (FindingCollection, EvaluationResult)

**Examples:**

```python
>>> from stance.collectors import run_collection
    >>> from stance.engine import run_evaluation
    >>>
    >>> # Collect assets
    >>> assets, _, _ = run_collection()
    >>>
    >>> # Evaluate policies
    >>> findings, result = run_evaluation(assets)
    >>> print(f"Found {len(findings)} issues")
```
