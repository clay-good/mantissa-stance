"""
SQLite-based local storage implementation.

This module provides LocalStorage, a SQLite-based storage backend
suitable for development and single-user scenarios.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from stance.models import (
    Asset,
    AssetCollection,
    Finding,
    FindingCollection,
    FindingType,
    FindingStatus,
    Severity,
)
from stance.storage.base import StorageBackend


class LocalStorage(StorageBackend):
    """
    SQLite-based local storage for development and single-user scenarios.

    Stores assets and findings in a local SQLite database with support
    for snapshots and basic querying.

    Attributes:
        db_path: Path to the SQLite database file
    """

    def __init__(self, db_path: str = "~/.stance/stance.db") -> None:
        """
        Initialize the local storage backend.

        Creates the database directory and file if they don't exist,
        and initializes the database schema.

        Args:
            db_path: Path to the SQLite database file.
                     Supports ~ for home directory.
        """
        self.db_path = os.path.expanduser(db_path)

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

    def _init_db(self) -> None:
        """Initialize database schema."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Create snapshots table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS snapshots (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                account_id TEXT,
                asset_count INTEGER DEFAULT 0,
                finding_count INTEGER DEFAULT 0
            )
        """)

        # Create assets table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT NOT NULL,
                snapshot_id TEXT NOT NULL,
                cloud_provider TEXT,
                account_id TEXT,
                region TEXT,
                resource_type TEXT,
                name TEXT,
                tags TEXT,
                network_exposure TEXT,
                created_at TEXT,
                last_seen TEXT,
                raw_config TEXT,
                PRIMARY KEY (id, snapshot_id),
                FOREIGN KEY (snapshot_id) REFERENCES snapshots(id)
            )
        """)

        # Create findings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT NOT NULL,
                snapshot_id TEXT NOT NULL,
                asset_id TEXT,
                finding_type TEXT,
                severity TEXT,
                status TEXT,
                title TEXT,
                description TEXT,
                rule_id TEXT,
                resource_path TEXT,
                expected_value TEXT,
                actual_value TEXT,
                cve_id TEXT,
                cvss_score REAL,
                package_name TEXT,
                installed_version TEXT,
                fixed_version TEXT,
                compliance_frameworks TEXT,
                remediation_guidance TEXT,
                first_seen TEXT,
                last_seen TEXT,
                PRIMARY KEY (id, snapshot_id),
                FOREIGN KEY (snapshot_id) REFERENCES snapshots(id)
            )
        """)

        # Create indexes for common queries
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_assets_snapshot
            ON assets(snapshot_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_assets_type
            ON assets(resource_type)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_snapshot
            ON findings(snapshot_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_severity
            ON findings(severity)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_status
            ON findings(status)
        """)

        conn.commit()
        conn.close()

    def _serialize_asset(self, asset: Asset, snapshot_id: str) -> tuple[Any, ...]:
        """Serialize an asset for database insertion."""
        return (
            asset.id,
            snapshot_id,
            asset.cloud_provider,
            asset.account_id,
            asset.region,
            asset.resource_type,
            asset.name,
            json.dumps(asset.tags),
            asset.network_exposure,
            asset.created_at.isoformat() if asset.created_at else None,
            asset.last_seen.isoformat() if asset.last_seen else None,
            json.dumps(asset.raw_config),
        )

    def _deserialize_asset(self, row: sqlite3.Row) -> Asset:
        """Deserialize an asset from a database row."""
        created_at = None
        if row["created_at"]:
            created_at = datetime.fromisoformat(row["created_at"])

        last_seen = None
        if row["last_seen"]:
            last_seen = datetime.fromisoformat(row["last_seen"])

        return Asset(
            id=row["id"],
            cloud_provider=row["cloud_provider"] or "aws",
            account_id=row["account_id"] or "",
            region=row["region"] or "",
            resource_type=row["resource_type"] or "",
            name=row["name"] or "",
            tags=json.loads(row["tags"]) if row["tags"] else {},
            network_exposure=row["network_exposure"] or "internal",
            created_at=created_at,
            last_seen=last_seen,
            raw_config=json.loads(row["raw_config"]) if row["raw_config"] else {},
        )

    def _serialize_finding(
        self, finding: Finding, snapshot_id: str
    ) -> tuple[Any, ...]:
        """Serialize a finding for database insertion."""
        return (
            finding.id,
            snapshot_id,
            finding.asset_id,
            finding.finding_type.value,
            finding.severity.value,
            finding.status.value,
            finding.title,
            finding.description,
            finding.rule_id,
            finding.resource_path,
            finding.expected_value,
            finding.actual_value,
            finding.cve_id,
            finding.cvss_score,
            finding.package_name,
            finding.installed_version,
            finding.fixed_version,
            json.dumps(finding.compliance_frameworks),
            finding.remediation_guidance,
            finding.first_seen.isoformat() if finding.first_seen else None,
            finding.last_seen.isoformat() if finding.last_seen else None,
        )

    def _deserialize_finding(self, row: sqlite3.Row) -> Finding:
        """Deserialize a finding from a database row."""
        first_seen = None
        if row["first_seen"]:
            first_seen = datetime.fromisoformat(row["first_seen"])

        last_seen = None
        if row["last_seen"]:
            last_seen = datetime.fromisoformat(row["last_seen"])

        return Finding(
            id=row["id"],
            asset_id=row["asset_id"] or "",
            finding_type=FindingType(row["finding_type"]),
            severity=Severity.from_string(row["severity"]),
            status=FindingStatus.from_string(row["status"]),
            title=row["title"] or "",
            description=row["description"] or "",
            first_seen=first_seen,
            last_seen=last_seen,
            rule_id=row["rule_id"],
            resource_path=row["resource_path"],
            expected_value=row["expected_value"],
            actual_value=row["actual_value"],
            cve_id=row["cve_id"],
            cvss_score=row["cvss_score"],
            package_name=row["package_name"],
            installed_version=row["installed_version"],
            fixed_version=row["fixed_version"],
            compliance_frameworks=(
                json.loads(row["compliance_frameworks"])
                if row["compliance_frameworks"]
                else []
            ),
            remediation_guidance=row["remediation_guidance"] or "",
        )

    def store_assets(self, assets: AssetCollection, snapshot_id: str) -> None:
        """Store an asset inventory snapshot."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Get account_id from first asset if available
        account_id = None
        if len(assets) > 0:
            account_id = assets[0].account_id

        # Insert or update snapshot record
        cursor.execute(
            """
            INSERT OR REPLACE INTO snapshots (id, created_at, account_id, asset_count, finding_count)
            VALUES (?, ?, ?, ?, COALESCE((SELECT finding_count FROM snapshots WHERE id = ?), 0))
            """,
            (
                snapshot_id,
                datetime.utcnow().isoformat(),
                account_id,
                len(assets),
                snapshot_id,
            ),
        )

        # Delete existing assets for this snapshot
        cursor.execute("DELETE FROM assets WHERE snapshot_id = ?", (snapshot_id,))

        # Insert assets
        for asset in assets:
            cursor.execute(
                """
                INSERT INTO assets (
                    id, snapshot_id, cloud_provider, account_id, region,
                    resource_type, name, tags, network_exposure,
                    created_at, last_seen, raw_config
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                self._serialize_asset(asset, snapshot_id),
            )

        conn.commit()
        conn.close()

    def store_findings(self, findings: FindingCollection, snapshot_id: str) -> None:
        """Store findings from policy evaluation."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Update snapshot record with finding count
        cursor.execute(
            """
            INSERT OR REPLACE INTO snapshots (id, created_at, account_id, asset_count, finding_count)
            VALUES (
                ?,
                COALESCE((SELECT created_at FROM snapshots WHERE id = ?), ?),
                (SELECT account_id FROM snapshots WHERE id = ?),
                COALESCE((SELECT asset_count FROM snapshots WHERE id = ?), 0),
                ?
            )
            """,
            (
                snapshot_id,
                snapshot_id,
                datetime.utcnow().isoformat(),
                snapshot_id,
                snapshot_id,
                len(findings),
            ),
        )

        # Delete existing findings for this snapshot
        cursor.execute("DELETE FROM findings WHERE snapshot_id = ?", (snapshot_id,))

        # Insert findings
        for finding in findings:
            cursor.execute(
                """
                INSERT INTO findings (
                    id, snapshot_id, asset_id, finding_type, severity, status,
                    title, description, rule_id, resource_path, expected_value,
                    actual_value, cve_id, cvss_score, package_name,
                    installed_version, fixed_version, compliance_frameworks,
                    remediation_guidance, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                self._serialize_finding(finding, snapshot_id),
            )

        conn.commit()
        conn.close()

    def get_assets(self, snapshot_id: str | None = None) -> AssetCollection:
        """Retrieve assets from storage."""
        if snapshot_id is None:
            snapshot_id = self.get_latest_snapshot_id()
            if snapshot_id is None:
                return AssetCollection()

        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM assets WHERE snapshot_id = ?",
            (snapshot_id,),
        )

        assets = [self._deserialize_asset(row) for row in cursor.fetchall()]
        conn.close()

        return AssetCollection(assets)

    def get_findings(
        self,
        snapshot_id: str | None = None,
        severity: Severity | None = None,
        status: FindingStatus | None = None,
    ) -> FindingCollection:
        """Retrieve findings from storage with optional filters."""
        if snapshot_id is None:
            snapshot_id = self.get_latest_snapshot_id()
            if snapshot_id is None:
                return FindingCollection()

        conn = self._get_connection()
        cursor = conn.cursor()

        # Build query with optional filters
        query = "SELECT * FROM findings WHERE snapshot_id = ?"
        params: list[Any] = [snapshot_id]

        if severity is not None:
            query += " AND severity = ?"
            params.append(severity.value)

        if status is not None:
            query += " AND status = ?"
            params.append(status.value)

        cursor.execute(query, params)

        findings = [self._deserialize_finding(row) for row in cursor.fetchall()]
        conn.close()

        return FindingCollection(findings)

    def get_latest_snapshot_id(self) -> str | None:
        """Get the most recent snapshot ID."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id FROM snapshots ORDER BY created_at DESC LIMIT 1"
        )

        row = cursor.fetchone()
        conn.close()

        return row["id"] if row else None

    def list_snapshots(self, limit: int = 10) -> list[str]:
        """List recent snapshot IDs."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id FROM snapshots ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )

        snapshot_ids = [row["id"] for row in cursor.fetchall()]
        conn.close()

        return snapshot_ids

    def get_snapshot_info(self, snapshot_id: str) -> dict[str, Any] | None:
        """
        Get information about a specific snapshot.

        Args:
            snapshot_id: The snapshot to get info for

        Returns:
            Dictionary with snapshot metadata, or None if not found
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM snapshots WHERE id = ?",
            (snapshot_id,),
        )

        row = cursor.fetchone()
        conn.close()

        if row is None:
            return None

        return {
            "id": row["id"],
            "created_at": row["created_at"],
            "account_id": row["account_id"],
            "asset_count": row["asset_count"],
            "finding_count": row["finding_count"],
        }

    def query_assets(self, sql: str) -> list[dict[str, Any]]:
        """
        Execute a raw SQL query against the assets table.

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

        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(sql)
        columns = [description[0] for description in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]

        conn.close()
        return results

    def query_findings(self, sql: str) -> list[dict[str, Any]]:
        """
        Execute a raw SQL query against the findings table.

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

        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(sql)
        columns = [description[0] for description in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]

        conn.close()
        return results

    def _is_safe_query(self, sql: str) -> bool:
        """
        Validate that a SQL query is safe to execute.

        Checks that the query is a SELECT statement and doesn't contain
        any dangerous operations.

        Args:
            sql: SQL query to validate

        Returns:
            True if query is safe, False otherwise
        """
        # Normalize whitespace and convert to uppercase for checking
        normalized = " ".join(sql.split()).upper()

        # Must start with SELECT
        if not normalized.startswith("SELECT"):
            return False

        # Check for dangerous keywords
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
        ]

        for keyword in dangerous_keywords:
            # Use word boundary check to avoid false positives
            pattern = r"\b" + keyword + r"\b"
            if re.search(pattern, normalized):
                return False

        # Check for comment sequences that could hide malicious SQL
        if "--" in sql or "/*" in sql or "*/" in sql:
            return False

        # Check for multiple statements
        if ";" in sql.strip().rstrip(";"):
            return False

        return True

    def delete_snapshot(self, snapshot_id: str) -> bool:
        """
        Delete a snapshot and all associated data.

        Args:
            snapshot_id: Snapshot to delete

        Returns:
            True if snapshot was deleted, False if not found
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # Check if snapshot exists
        cursor.execute("SELECT id FROM snapshots WHERE id = ?", (snapshot_id,))
        if cursor.fetchone() is None:
            conn.close()
            return False

        # Delete findings, assets, and snapshot
        cursor.execute("DELETE FROM findings WHERE snapshot_id = ?", (snapshot_id,))
        cursor.execute("DELETE FROM assets WHERE snapshot_id = ?", (snapshot_id,))
        cursor.execute("DELETE FROM snapshots WHERE id = ?", (snapshot_id,))

        conn.commit()
        conn.close()
        return True
