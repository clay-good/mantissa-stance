"""
Exception storage for Mantissa Stance.

Provides persistent storage for policy exceptions.
"""

from __future__ import annotations

import json
import os
import threading
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from stance.exceptions.models import (
    PolicyException,
    ExceptionType,
    ExceptionScope,
    ExceptionStatus,
)


class ExceptionStore(ABC):
    """
    Abstract base class for exception storage.

    Implementations provide persistent storage for policy exceptions.
    """

    @abstractmethod
    def save(self, exception: PolicyException) -> bool:
        """
        Save an exception.

        Args:
            exception: Exception to save

        Returns:
            True if saved successfully
        """
        pass

    @abstractmethod
    def get(self, exception_id: str) -> PolicyException | None:
        """
        Get an exception by ID.

        Args:
            exception_id: Exception ID

        Returns:
            PolicyException or None
        """
        pass

    @abstractmethod
    def delete(self, exception_id: str) -> bool:
        """
        Delete an exception.

        Args:
            exception_id: Exception ID to delete

        Returns:
            True if deleted
        """
        pass

    @abstractmethod
    def list_all(
        self,
        status: ExceptionStatus | None = None,
        exception_type: ExceptionType | None = None,
        scope: ExceptionScope | None = None,
        include_expired: bool = False,
    ) -> list[PolicyException]:
        """
        List exceptions with optional filters.

        Args:
            status: Filter by status
            exception_type: Filter by type
            scope: Filter by scope
            include_expired: Include expired exceptions

        Returns:
            List of matching exceptions
        """
        pass

    @abstractmethod
    def get_active(self) -> list[PolicyException]:
        """
        Get all active exceptions.

        Returns:
            List of active exceptions
        """
        pass

    @abstractmethod
    def find_by_asset(self, asset_id: str) -> list[PolicyException]:
        """
        Find exceptions for a specific asset.

        Args:
            asset_id: Asset ID

        Returns:
            List of matching exceptions
        """
        pass

    @abstractmethod
    def find_by_policy(self, policy_id: str) -> list[PolicyException]:
        """
        Find exceptions for a specific policy.

        Args:
            policy_id: Policy ID

        Returns:
            List of matching exceptions
        """
        pass

    @abstractmethod
    def expire_outdated(self) -> int:
        """
        Mark expired exceptions as expired.

        Returns:
            Number of exceptions marked as expired
        """
        pass


class LocalExceptionStore(ExceptionStore):
    """
    Local file-based exception storage.

    Stores exceptions in a JSON file.
    """

    def __init__(self, file_path: str | Path | None = None):
        """
        Initialize the store.

        Args:
            file_path: Path to storage file
        """
        if file_path is None:
            config_dir = os.environ.get("STANCE_CONFIG_DIR")
            if config_dir:
                file_path = Path(config_dir) / "exceptions.json"
            else:
                file_path = Path.home() / ".stance" / "exceptions.json"

        self._file_path = Path(file_path)
        self._lock = threading.RLock()
        self._cache: dict[str, PolicyException] = {}
        self._loaded = False

    def _ensure_loaded(self) -> None:
        """Ensure exceptions are loaded from file."""
        if self._loaded:
            return

        with self._lock:
            if self._loaded:
                return

            if self._file_path.exists():
                try:
                    with open(self._file_path, "r") as f:
                        data = json.load(f)
                        for item in data.get("exceptions", []):
                            exc = PolicyException.from_dict(item)
                            self._cache[exc.id] = exc
                except Exception:
                    pass

            self._loaded = True

    def _save_to_file(self) -> None:
        """Save all exceptions to file."""
        try:
            self._file_path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "exceptions": [e.to_dict() for e in self._cache.values()],
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            with open(self._file_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def save(self, exception: PolicyException) -> bool:
        """Save an exception."""
        with self._lock:
            self._ensure_loaded()
            self._cache[exception.id] = exception
            self._save_to_file()
            return True

    def get(self, exception_id: str) -> PolicyException | None:
        """Get an exception by ID."""
        with self._lock:
            self._ensure_loaded()
            return self._cache.get(exception_id)

    def delete(self, exception_id: str) -> bool:
        """Delete an exception."""
        with self._lock:
            self._ensure_loaded()
            if exception_id in self._cache:
                del self._cache[exception_id]
                self._save_to_file()
                return True
            return False

    def list_all(
        self,
        status: ExceptionStatus | None = None,
        exception_type: ExceptionType | None = None,
        scope: ExceptionScope | None = None,
        include_expired: bool = False,
    ) -> list[PolicyException]:
        """List exceptions with filters."""
        with self._lock:
            self._ensure_loaded()
            results = list(self._cache.values())

            if status is not None:
                results = [e for e in results if e.status == status]

            if exception_type is not None:
                results = [e for e in results if e.exception_type == exception_type]

            if scope is not None:
                results = [e for e in results if e.scope == scope]

            if not include_expired:
                results = [e for e in results if not e.is_expired]

            return results

    def get_active(self) -> list[PolicyException]:
        """Get all active exceptions."""
        with self._lock:
            self._ensure_loaded()
            return [e for e in self._cache.values() if e.is_active]

    def find_by_asset(self, asset_id: str) -> list[PolicyException]:
        """Find exceptions for an asset."""
        with self._lock:
            self._ensure_loaded()
            return [
                e for e in self._cache.values()
                if e.asset_id == asset_id and e.is_active
            ]

    def find_by_policy(self, policy_id: str) -> list[PolicyException]:
        """Find exceptions for a policy."""
        with self._lock:
            self._ensure_loaded()
            return [
                e for e in self._cache.values()
                if e.policy_id == policy_id and e.is_active
            ]

    def expire_outdated(self) -> int:
        """Mark expired exceptions as expired."""
        with self._lock:
            self._ensure_loaded()
            count = 0
            now = datetime.now(timezone.utc)

            for exception in self._cache.values():
                if (
                    exception.status == ExceptionStatus.APPROVED
                    and exception.expires_at
                    and now >= exception.expires_at
                ):
                    exception.status = ExceptionStatus.EXPIRED
                    count += 1

            if count > 0:
                self._save_to_file()

            return count

    def clear(self) -> None:
        """Clear all exceptions (for testing)."""
        with self._lock:
            self._cache.clear()
            self._loaded = True
            self._save_to_file()


# Global store instance
_global_store: ExceptionStore | None = None
_store_lock = threading.Lock()


def get_exception_store(
    file_path: str | Path | None = None,
) -> ExceptionStore:
    """
    Get the exception store.

    Args:
        file_path: Optional custom file path

    Returns:
        ExceptionStore instance
    """
    global _global_store
    with _store_lock:
        if _global_store is None or file_path is not None:
            _global_store = LocalExceptionStore(file_path)
        return _global_store
