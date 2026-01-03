# stance.engine.evaluator

Policy evaluator for Mantissa Stance.

Evaluates security policies against collected assets
and generates findings for non-compliant resources.

## Contents

### Classes

- [PolicyEvalResult](#policyevalresult)
- [EvaluationResult](#evaluationresult)
- [PolicyEvaluator](#policyevaluator)

## PolicyEvalResult

**Tags:** dataclass

Result of evaluating a single policy.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `policy_id` | `str` | - |
| `assets_checked` | `int` | - |
| `compliant` | `int` | - |
| `non_compliant` | `int` | - |
| `errors` | `list[str]` | `field(...)` |

## EvaluationResult

**Tags:** dataclass

Result of evaluating all policies.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `policies_evaluated` | `int` | - |
| `assets_evaluated` | `int` | - |
| `findings_generated` | `int` | - |
| `duration_seconds` | `float` | - |
| `policy_results` | `dict[(str, PolicyEvalResult)]` | `field(...)` |

## PolicyEvaluator

Evaluates security policies against asset configurations.

Generates findings for resources that do not comply with
policy requirements.

### Methods

#### `__init__(self)`

Initialize the policy evaluator.

#### `evaluate_all(self, policies: PolicyCollection, assets: AssetCollection) -> tuple[(FindingCollection, EvaluationResult)]`

Evaluate all enabled policies against all assets.

**Parameters:**

- `policies` (`PolicyCollection`) - Collection of policies to evaluate
- `assets` (`AssetCollection`) - Collection of assets to check

**Returns:**

`tuple[(FindingCollection, EvaluationResult)]` - Tuple of (FindingCollection, EvaluationResult)

#### `evaluate_policy(self, policy: Policy, assets: AssetCollection) -> list[Finding]`

Evaluate single policy against matching assets.

**Parameters:**

- `policy` (`Policy`) - Policy to evaluate
- `assets` (`AssetCollection`) - Assets to check

**Returns:**

`list[Finding]` - List of findings for non-compliant resources

#### `evaluate_asset(self, policy: Policy, asset: Asset) -> Finding | None`

Evaluate single policy against single asset.

**Parameters:**

- `policy` (`Policy`) - Policy to evaluate
- `asset` (`Asset`) - Asset to check

**Returns:**

`Finding | None` - Finding if non-compliant, None if compliant
