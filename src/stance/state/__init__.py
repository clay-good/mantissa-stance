"""
State management for Mantissa Stance.

Provides state tracking for scans, checkpoints, and finding lifecycle.
"""

from stance.state.state_manager import (
    Checkpoint,
    FindingLifecycle,
    FindingState,
    LocalStateBackend,
    ScanRecord,
    ScanStatus,
    StateBackend,
    StateManager,
    get_state_manager,
)

__all__ = [
    "Checkpoint",
    "FindingLifecycle",
    "FindingState",
    "LocalStateBackend",
    "ScanRecord",
    "ScanStatus",
    "StateBackend",
    "StateManager",
    "get_state_manager",
]
