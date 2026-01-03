"""
Policy engine for Mantissa Stance.

This package provides the policy evaluation framework including:

- ExpressionEvaluator: Safe evaluation of boolean expressions
- PolicyLoader: Load and validate YAML policies
- PolicyEvaluator: Evaluate policies against assets
- BenchmarkCalculator: Calculate CIS benchmark scores
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from stance.engine.expressions import ExpressionEvaluator, ExpressionError
from stance.engine.loader import PolicyLoader, PolicyLoadError
from stance.engine.evaluator import (
    PolicyEvaluator,
    EvaluationResult,
    PolicyEvalResult,
)
from stance.engine.benchmark import (
    BenchmarkCalculator,
    BenchmarkReport,
    BenchmarkScore,
    ControlStatus,
)

if TYPE_CHECKING:
    from stance.models import AssetCollection, FindingCollection

__all__ = [
    # Expressions
    "ExpressionEvaluator",
    "ExpressionError",
    # Loader
    "PolicyLoader",
    "PolicyLoadError",
    # Evaluator
    "PolicyEvaluator",
    "EvaluationResult",
    "PolicyEvalResult",
    # Benchmark
    "BenchmarkCalculator",
    "BenchmarkReport",
    "BenchmarkScore",
    "ControlStatus",
    # Convenience functions
    "run_evaluation",
]


def run_evaluation(
    assets: AssetCollection,
    policy_dirs: list[str] | None = None,
) -> tuple[FindingCollection, EvaluationResult]:
    """
    Run full policy evaluation.

    Loads policies from configured directories and evaluates
    them against the provided assets.

    Args:
        assets: Collected assets to evaluate
        policy_dirs: Optional list of policy directories.
                    Defaults to ["policies/"]

    Returns:
        Tuple of (FindingCollection, EvaluationResult)

    Example:
        >>> from stance.collectors import run_collection
        >>> from stance.engine import run_evaluation
        >>>
        >>> # Collect assets
        >>> assets, _, _ = run_collection()
        >>>
        >>> # Evaluate policies
        >>> findings, result = run_evaluation(assets)
        >>> print(f"Found {len(findings)} issues")
    """
    # Load policies
    loader = PolicyLoader(policy_dirs=policy_dirs)
    policies = loader.load_all()

    # Evaluate
    evaluator = PolicyEvaluator()
    findings, result = evaluator.evaluate_all(policies, assets)

    return findings, result
