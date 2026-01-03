"""
Policy Exceptions and Suppressions for Mantissa Stance.

Provides mechanisms to suppress or exempt findings from policies
based on various criteria like asset ID, policy ID, time windows, etc.
"""

from __future__ import annotations

from stance.exceptions.models import (
    ExceptionType,
    ExceptionScope,
    ExceptionStatus,
    PolicyException,
    ExceptionMatch,
    ExceptionResult,
)
from stance.exceptions.matcher import (
    ExceptionMatcher,
    match_exception,
)
from stance.exceptions.store import (
    ExceptionStore,
    LocalExceptionStore,
    get_exception_store,
)
from stance.exceptions.manager import (
    ExceptionManager,
    get_exception_manager,
)

__all__ = [
    # Models
    "ExceptionType",
    "ExceptionScope",
    "ExceptionStatus",
    "PolicyException",
    "ExceptionMatch",
    "ExceptionResult",
    # Matcher
    "ExceptionMatcher",
    "match_exception",
    # Store
    "ExceptionStore",
    "LocalExceptionStore",
    "get_exception_store",
    # Manager
    "ExceptionManager",
    "get_exception_manager",
]
