"""
ASM Storage Layer for Mantissa Stance.

This module provides the ASMStorageAdapter class for persisting ASM data
using existing storage backends. It handles storing and retrieving
external assets, scan results, and supporting drift detection.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from stance.asm.models import (
    ASMScanMode,
    ASMScanResult,
    ASMScanStatus,
    CertificateInfo,
    ExternalAsset,
    ExternalAssetCollection,
)

logger = logging.getLogger(__name__)


# Default database path for ASM data
DEFAULT_ASM_DB_PATH = "~/.stance/asm.db"


def _validate_db_path(db_path: str) -> str:
    """
    Validate and normalize a database path.

    Ensures the path doesn't attempt directory traversal outside the
    intended storage location.

    Args:
        db_path: Path to validate

    Returns:
        Validated and normalized path

    Raises:
        ValueError: If path contains directory traversal attempts
    """
    # Expand user directory
    expanded = os.path.expanduser(db_path)

    # Get absolute path
    abs_path = os.path.abspath(expanded)

    # Check for directory traversal attempts in the original path
    if ".." in db_path:
        raise ValueError(f"Invalid database path: directory traversal not allowed: {db_path}")

    # Ensure the path ends with expected extension
    if not abs_path.endswith(".db"):
        logger.warning(f"Database path does not end with .db extension: {abs_path}")

    return abs_path


def generate_scan_id() -> str:
    """
    Generate a unique scan ID for ASM scans.

    Returns:
        Scan ID in format asm-YYYYMMDD-HHMMSS-XXXX
    """
    import secrets

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    suffix = secrets.token_hex(4)
    return f"asm-{timestamp}-{suffix}"


@dataclass
class ASMScanInfo:
    """
    Summary information about an ASM scan.

    Used for listing scans without loading full asset data.
    """

    scan_id: str
    started_at: datetime
    completed_at: datetime | None
    status: ASMScanStatus
    target_domains: list[str]
    scan_mode: ASMScanMode
    assets_discovered: int
    findings_count: int
    duration_seconds: float


class ASMStorageAdapter:
    """
    Storage adapter for ASM data.

    Provides methods to store and retrieve external assets and scan results.
    Uses a SQLite database for local storage, following the patterns
    established in the main Stance storage module.

    Attributes:
        db_path: Path to the ASM SQLite database file
    """

    def __init__(self, db_path: str | None = None) -> None:
        """
        Initialize the ASM storage adapter.

        Creates the database directory and file if they don't exist,
        and initializes the database schema.

        Args:
            db_path: Path to the SQLite database file.
                     Supports ~ for home directory.
                     Defaults to ~/.stance/asm.db

        Raises:
            ValueError: If path contains directory traversal attempts
        """
        self.db_path = _validate_db_path(db_path or DEFAULT_ASM_DB_PATH)

        # Create directory if it doesn't exist
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            Path(db_dir).mkdir(parents=True, exist_ok=True)

        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        """
        Context manager for database connections.

        Ensures connections are properly closed even if exceptions occur.

        Yields:
            SQLite connection object
        """
        conn = self._get_connection()
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initialize database schema for ASM data."""
        with self._connection() as conn:
            cursor = conn.cursor()

            # Create asm_scans table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS asm_scans (
                    scan_id TEXT PRIMARY KEY,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    status TEXT NOT NULL,
                    target_domains TEXT NOT NULL,
                    scan_mode TEXT NOT NULL,
                    assets_discovered INTEGER DEFAULT 0,
                    findings_count INTEGER DEFAULT 0,
                    errors TEXT,
                    collectors_run TEXT,
                    duration_seconds REAL DEFAULT 0.0
                )
            """)

            # Create asm_external_assets table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS asm_external_assets (
                    id TEXT NOT NULL,
                    scan_id TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    ip_address TEXT,
                    port INTEGER,
                    protocol TEXT,
                    service TEXT,
                    technology_stack TEXT,
                    cloud_provider TEXT,
                    cloud_region TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    certificate_info TEXT,
                    risk_score REAL DEFAULT 0.0,
                    raw_data TEXT,
                    source TEXT,
                    is_verified INTEGER DEFAULT 0,
                    PRIMARY KEY (id, scan_id),
                    FOREIGN KEY (scan_id) REFERENCES asm_scans(scan_id)
                )
            """)

            # Create global asset tracking table for first_seen across scans
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS asm_asset_history (
                    asset_id TEXT PRIMARY KEY,
                    domain TEXT NOT NULL,
                    ip_address TEXT,
                    port INTEGER,
                    first_seen_global TEXT NOT NULL,
                    last_seen_global TEXT NOT NULL,
                    scan_count INTEGER DEFAULT 1
                )
            """)

            # Create indexes for common queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_asm_assets_scan
                ON asm_external_assets(scan_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_asm_assets_domain
                ON asm_external_assets(domain)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_asm_assets_port
                ON asm_external_assets(port)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_asm_assets_cloud
                ON asm_external_assets(cloud_provider)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_asm_assets_risk
                ON asm_external_assets(risk_score)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_asm_scans_status
                ON asm_scans(status)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_asm_scans_started
                ON asm_scans(started_at)
            """)

            conn.commit()

        logger.debug(f"ASM database initialized at {self.db_path}")

    def store_scan_result(self, result: ASMScanResult) -> None:
        """
        Store an ASM scan result.

        Args:
            result: The scan result to store
        """
        with self._connection() as conn:
            cursor = conn.cursor()

            # Insert or update scan record
            cursor.execute(
                """
                INSERT OR REPLACE INTO asm_scans (
                    scan_id, started_at, completed_at, status, target_domains,
                    scan_mode, assets_discovered, findings_count, errors,
                    collectors_run, duration_seconds
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.scan_id,
                    result.started_at.isoformat(),
                    result.completed_at.isoformat() if result.completed_at else None,
                    result.status.value,
                    json.dumps(result.target_domains),
                    result.scan_mode.value,
                    result.assets_discovered,
                    result.findings_count,
                    json.dumps(result.errors),
                    json.dumps(result.collectors_run),
                    result.duration_seconds,
                ),
            )

            conn.commit()

        logger.info(f"Stored ASM scan result: {result.scan_id}")

    def store_external_assets(
        self,
        assets: ExternalAssetCollection,
        scan_id: str,
    ) -> None:
        """
        Store external assets from an ASM scan.

        Also updates the global asset history for first_seen tracking.

        Args:
            assets: Collection of external assets to store
            scan_id: Scan ID to associate assets with
        """
        with self._connection() as conn:
            cursor = conn.cursor()

            # Delete existing assets for this scan
            cursor.execute(
                "DELETE FROM asm_external_assets WHERE scan_id = ?",
                (scan_id,),
            )

            now_iso = datetime.now(timezone.utc).isoformat()

            # Insert assets
            for asset in assets:
                # Serialize certificate info if present
                cert_json = None
                if asset.certificate_info:
                    cert_json = json.dumps(asset.certificate_info.to_dict())

                cursor.execute(
                    """
                    INSERT INTO asm_external_assets (
                        id, scan_id, domain, ip_address, port, protocol, service,
                        technology_stack, cloud_provider, cloud_region, first_seen,
                        last_seen, certificate_info, risk_score, raw_data, source,
                        is_verified
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        asset.id,
                        scan_id,
                        asset.domain,
                        asset.ip_address,
                        asset.port,
                        asset.protocol,
                        asset.service,
                        json.dumps(list(asset.technology_stack)),
                        asset.cloud_provider,
                        asset.cloud_region,
                        asset.first_seen.isoformat(),
                        asset.last_seen.isoformat(),
                        cert_json,
                        asset.risk_score,
                        json.dumps(asset.raw_data),
                        asset.source,
                        1 if asset.is_verified else 0,
                    ),
                )

                # Update global asset history
                cursor.execute(
                    """
                    INSERT INTO asm_asset_history (
                        asset_id, domain, ip_address, port,
                        first_seen_global, last_seen_global, scan_count
                    ) VALUES (?, ?, ?, ?, ?, ?, 1)
                    ON CONFLICT(asset_id) DO UPDATE SET
                        last_seen_global = ?,
                        scan_count = scan_count + 1
                    """,
                    (
                        asset.id,
                        asset.domain,
                        asset.ip_address,
                        asset.port,
                        asset.first_seen.isoformat(),
                        asset.last_seen.isoformat(),
                        now_iso,
                    ),
                )

            # Update scan record with asset count
            cursor.execute(
                """
                UPDATE asm_scans SET assets_discovered = ?
                WHERE scan_id = ?
                """,
                (len(assets), scan_id),
            )

            conn.commit()

        logger.info(f"Stored {len(assets)} external assets for scan {scan_id}")

    def get_external_assets(
        self,
        scan_id: str | None = None,
    ) -> ExternalAssetCollection:
        """
        Retrieve external assets from storage.

        Args:
            scan_id: Scan to retrieve assets from. If None, returns latest.

        Returns:
            Collection of external assets from the specified scan
        """
        if scan_id is None:
            latest = self.get_latest_scan()
            if latest is None:
                return ExternalAssetCollection()
            scan_id = latest.scan_id

        with self._connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                "SELECT * FROM asm_external_assets WHERE scan_id = ?",
                (scan_id,),
            )

            assets = [self._deserialize_external_asset(row) for row in cursor.fetchall()]

        return ExternalAssetCollection(assets)

    def get_scan_result(self, scan_id: str) -> ASMScanResult | None:
        """
        Retrieve a specific scan result.

        Args:
            scan_id: ID of the scan to retrieve

        Returns:
            ASMScanResult if found, None otherwise
        """
        with self._connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                "SELECT * FROM asm_scans WHERE scan_id = ?",
                (scan_id,),
            )

            row = cursor.fetchone()

        if row is None:
            return None

        return self._deserialize_scan_result(row)

    def get_latest_scan(self) -> ASMScanResult | None:
        """
        Get the most recent scan result.

        Returns:
            Most recent ASMScanResult, or None if no scans exist
        """
        with self._connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT * FROM asm_scans
                ORDER BY started_at DESC
                LIMIT 1
                """
            )

            row = cursor.fetchone()

        if row is None:
            return None

        return self._deserialize_scan_result(row)

    def get_latest_scan_id(self) -> str | None:
        """
        Get the most recent scan ID.

        Returns:
            Latest scan ID, or None if no scans exist
        """
        with self._connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT scan_id FROM asm_scans
                ORDER BY started_at DESC
                LIMIT 1
                """
            )

            row = cursor.fetchone()

        return row["scan_id"] if row else None

    def list_scans(self, limit: int = 100) -> list[ASMScanInfo]:
        """
        List recent scans with summary information.

        Args:
            limit: Maximum number of scans to return (default 100)

        Returns:
            List of ASMScanInfo objects, most recent first
        """
        with self._connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT scan_id, started_at, completed_at, status, target_domains,
                       scan_mode, assets_discovered, findings_count, duration_seconds
                FROM asm_scans
                ORDER BY started_at DESC
                LIMIT ?
                """,
                (limit,),
            )

            scans = []
            for row in cursor.fetchall():
                started_at = datetime.fromisoformat(row["started_at"])
                completed_at = None
                if row["completed_at"]:
                    completed_at = datetime.fromisoformat(row["completed_at"])

                scans.append(
                    ASMScanInfo(
                        scan_id=row["scan_id"],
                        started_at=started_at,
                        completed_at=completed_at,
                        status=ASMScanStatus(row["status"]),
                        target_domains=json.loads(row["target_domains"]),
                        scan_mode=ASMScanMode(row["scan_mode"]),
                        assets_discovered=row["assets_discovered"],
                        findings_count=row["findings_count"],
                        duration_seconds=row["duration_seconds"],
                    )
                )

        return scans

    def delete_scan(self, scan_id: str) -> bool:
        """
        Delete a scan and all associated data.

        Args:
            scan_id: Scan to delete

        Returns:
            True if scan was deleted, False if not found
        """
        with self._connection() as conn:
            cursor = conn.cursor()

            # Check if scan exists
            cursor.execute(
                "SELECT scan_id FROM asm_scans WHERE scan_id = ?",
                (scan_id,),
            )
            if cursor.fetchone() is None:
                return False

            # Delete assets and scan record
            cursor.execute(
                "DELETE FROM asm_external_assets WHERE scan_id = ?",
                (scan_id,),
            )
            cursor.execute(
                "DELETE FROM asm_scans WHERE scan_id = ?",
                (scan_id,),
            )

            conn.commit()

        logger.info(f"Deleted ASM scan: {scan_id}")
        return True

    def get_asset_history(self, asset_id: str) -> dict[str, Any] | None:
        """
        Get global history for an asset across all scans.

        Args:
            asset_id: Asset ID to look up

        Returns:
            Dictionary with first_seen_global, last_seen_global, scan_count
        """
        with self._connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                "SELECT * FROM asm_asset_history WHERE asset_id = ?",
                (asset_id,),
            )

            row = cursor.fetchone()

        if row is None:
            return None

        return {
            "asset_id": row["asset_id"],
            "domain": row["domain"],
            "ip_address": row["ip_address"],
            "port": row["port"],
            "first_seen_global": datetime.fromisoformat(row["first_seen_global"]),
            "last_seen_global": datetime.fromisoformat(row["last_seen_global"]),
            "scan_count": row["scan_count"],
        }

    def query_external_assets(self, sql: str) -> list[dict[str, Any]]:
        """
        Execute a raw SQL query against the asm_external_assets table.

        Only SELECT queries are allowed for security.

        Args:
            sql: SQL query string (must be SELECT only)

        Returns:
            List of result dictionaries

        Raises:
            ValueError: If query is not a SELECT statement
        """
        if not self._is_safe_query(sql):
            raise ValueError("Only SELECT queries are allowed")

        with self._connection() as conn:
            cursor = conn.cursor()

            cursor.execute(sql)
            columns = [description[0] for description in cursor.description]
            results = [dict(zip(columns, row)) for row in cursor.fetchall()]

        return results

    def get_assets_by_domain(self, domain: str) -> ExternalAssetCollection:
        """
        Get all assets for a specific domain across all scans.

        Args:
            domain: Domain to search for

        Returns:
            ExternalAssetCollection with matching assets
        """
        with self._connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT * FROM asm_external_assets
                WHERE domain = ?
                ORDER BY last_seen DESC
                """,
                (domain.lower(),),
            )

            assets = [self._deserialize_external_asset(row) for row in cursor.fetchall()]

        return ExternalAssetCollection(assets)

    def get_assets_by_port(
        self,
        port: int,
        scan_id: str | None = None,
    ) -> ExternalAssetCollection:
        """
        Get all assets with a specific port.

        Args:
            port: Port number to filter by
            scan_id: Optional scan ID to restrict search

        Returns:
            ExternalAssetCollection with matching assets
        """
        # Get scan_id to use (either provided or latest)
        target_scan_id = scan_id
        if target_scan_id is None:
            target_scan_id = self.get_latest_scan_id()
            if target_scan_id is None:
                return ExternalAssetCollection()

        with self._connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT * FROM asm_external_assets
                WHERE port = ? AND scan_id = ?
                """,
                (port, target_scan_id),
            )

            assets = [self._deserialize_external_asset(row) for row in cursor.fetchall()]

        return ExternalAssetCollection(assets)

    def get_high_risk_assets(
        self,
        min_risk_score: float = 7.0,
        scan_id: str | None = None,
    ) -> ExternalAssetCollection:
        """
        Get assets with high risk scores.

        Args:
            min_risk_score: Minimum risk score (default 7.0)
            scan_id: Optional scan ID to restrict search

        Returns:
            ExternalAssetCollection with high-risk assets
        """
        # Get scan_id to use (either provided or latest)
        target_scan_id = scan_id
        if target_scan_id is None:
            target_scan_id = self.get_latest_scan_id()
            if target_scan_id is None:
                return ExternalAssetCollection()

        with self._connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT * FROM asm_external_assets
                WHERE risk_score >= ? AND scan_id = ?
                ORDER BY risk_score DESC
                """,
                (min_risk_score, target_scan_id),
            )

            assets = [self._deserialize_external_asset(row) for row in cursor.fetchall()]

        return ExternalAssetCollection(assets)

    def _deserialize_external_asset(self, row: sqlite3.Row) -> ExternalAsset:
        """Deserialize an external asset from a database row."""
        first_seen = datetime.fromisoformat(row["first_seen"])
        last_seen = datetime.fromisoformat(row["last_seen"])

        # Parse certificate info if present
        certificate_info = None
        if row["certificate_info"]:
            cert_data = json.loads(row["certificate_info"])
            certificate_info = CertificateInfo.from_dict(cert_data)

        # Parse technology stack
        technology_stack = ()
        if row["technology_stack"]:
            tech_list = json.loads(row["technology_stack"])
            technology_stack = tuple(tech_list)

        # Parse raw_data
        raw_data = {}
        if row["raw_data"]:
            raw_data = json.loads(row["raw_data"])

        return ExternalAsset(
            id=row["id"],
            domain=row["domain"],
            ip_address=row["ip_address"],
            port=row["port"],
            protocol=row["protocol"],
            service=row["service"],
            technology_stack=technology_stack,
            cloud_provider=row["cloud_provider"],
            cloud_region=row["cloud_region"],
            first_seen=first_seen,
            last_seen=last_seen,
            certificate_info=certificate_info,
            risk_score=row["risk_score"],
            raw_data=raw_data,
            source=row["source"] or "unknown",
            is_verified=bool(row["is_verified"]),
        )

    def _deserialize_scan_result(self, row: sqlite3.Row) -> ASMScanResult:
        """Deserialize a scan result from a database row."""
        started_at = datetime.fromisoformat(row["started_at"])

        completed_at = None
        if row["completed_at"]:
            completed_at = datetime.fromisoformat(row["completed_at"])

        return ASMScanResult(
            scan_id=row["scan_id"],
            started_at=started_at,
            completed_at=completed_at,
            status=ASMScanStatus(row["status"]),
            target_domains=json.loads(row["target_domains"]),
            scan_mode=ASMScanMode(row["scan_mode"]),
            assets_discovered=row["assets_discovered"],
            findings_count=row["findings_count"],
            errors=json.loads(row["errors"]) if row["errors"] else [],
            collectors_run=json.loads(row["collectors_run"]) if row["collectors_run"] else [],
            duration_seconds=row["duration_seconds"],
        )

    def _is_safe_query(self, sql: str) -> bool:
        """
        Validate that a SQL query is safe to execute.

        This performs basic validation to prevent destructive operations.
        Note: This still allows arbitrary SELECT queries which could
        potentially access any data in the ASM database. Use with caution.

        Args:
            sql: SQL query to validate

        Returns:
            True if query is safe, False otherwise
        """
        import re

        if not sql or not sql.strip():
            return False

        # Normalize whitespace and convert to uppercase for checking
        normalized = " ".join(sql.split()).upper()

        # Must start with SELECT
        if not normalized.startswith("SELECT"):
            return False

        # Check for dangerous keywords that could modify data
        dangerous_keywords = [
            "INSERT",
            "UPDATE",
            "DELETE",
            "DROP",
            "ALTER",
            "CREATE",
            "TRUNCATE",
            "REPLACE",
            "GRANT",
            "REVOKE",
            "ATTACH",  # Could attach external databases
            "DETACH",
            "PRAGMA",  # Could modify SQLite settings
            "VACUUM",
            "REINDEX",
        ]

        for keyword in dangerous_keywords:
            pattern = r"\b" + keyword + r"\b"
            if re.search(pattern, normalized):
                return False

        # Check for comment sequences that could hide malicious SQL
        if "--" in sql or "/*" in sql or "*/" in sql:
            return False

        # Check for multiple statements (prevent stacked queries)
        if ";" in sql.strip().rstrip(";"):
            return False

        # Check for hex/char encoding that could bypass filters
        if re.search(r"0x[0-9a-fA-F]+", sql) or re.search(r"CHAR\s*\(", normalized):
            return False

        # Limit query length to prevent DoS
        if len(sql) > 10000:
            return False

        return True

    def get_scan_statistics(self, scan_id: str | None = None) -> dict[str, Any]:
        """
        Get statistics for a scan.

        Args:
            scan_id: Scan to get statistics for. If None, uses latest.

        Returns:
            Dictionary with statistics
        """
        # Get scan_id to use (either provided or latest)
        target_scan_id = scan_id
        if target_scan_id is None:
            target_scan_id = self.get_latest_scan_id()
            if target_scan_id is None:
                return {
                    "scan_id": None,
                    "total_assets": 0,
                    "domains_discovered": 0,
                    "unique_ips": 0,
                    "ports_detected": {},
                    "cloud_providers": {},
                    "risk_distribution": {},
                }

        with self._connection() as conn:
            cursor = conn.cursor()

            # Total assets
            cursor.execute(
                "SELECT COUNT(*) as count FROM asm_external_assets WHERE scan_id = ?",
                (target_scan_id,),
            )
            total_assets = cursor.fetchone()["count"]

            # Unique domains
            cursor.execute(
                """
                SELECT COUNT(DISTINCT domain) as count
                FROM asm_external_assets WHERE scan_id = ?
                """,
                (target_scan_id,),
            )
            domains_discovered = cursor.fetchone()["count"]

            # Unique IPs
            cursor.execute(
                """
                SELECT COUNT(DISTINCT ip_address) as count
                FROM asm_external_assets
                WHERE scan_id = ? AND ip_address IS NOT NULL
                """,
                (target_scan_id,),
            )
            unique_ips = cursor.fetchone()["count"]

            # Ports distribution
            cursor.execute(
                """
                SELECT port, COUNT(*) as count
                FROM asm_external_assets
                WHERE scan_id = ? AND port IS NOT NULL
                GROUP BY port
                ORDER BY count DESC
                """,
                (target_scan_id,),
            )
            ports = {row["port"]: row["count"] for row in cursor.fetchall()}

            # Cloud provider distribution
            cursor.execute(
                """
                SELECT COALESCE(cloud_provider, 'unknown') as provider, COUNT(*) as count
                FROM asm_external_assets
                WHERE scan_id = ?
                GROUP BY cloud_provider
                ORDER BY count DESC
                """,
                (target_scan_id,),
            )
            cloud_providers = {row["provider"]: row["count"] for row in cursor.fetchall()}

            # Risk distribution
            cursor.execute(
                """
                SELECT
                    CASE
                        WHEN risk_score >= 8 THEN 'critical'
                        WHEN risk_score >= 6 THEN 'high'
                        WHEN risk_score >= 4 THEN 'medium'
                        WHEN risk_score >= 2 THEN 'low'
                        ELSE 'info'
                    END as risk_level,
                    COUNT(*) as count
                FROM asm_external_assets
                WHERE scan_id = ?
                GROUP BY risk_level
                ORDER BY risk_score DESC
                """,
                (target_scan_id,),
            )
            risk_distribution = {row["risk_level"]: row["count"] for row in cursor.fetchall()}

        return {
            "scan_id": target_scan_id,
            "total_assets": total_assets,
            "domains_discovered": domains_discovered,
            "unique_ips": unique_ips,
            "ports_detected": ports,
            "cloud_providers": cloud_providers,
            "risk_distribution": risk_distribution,
        }
