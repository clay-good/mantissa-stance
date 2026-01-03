"""
Alert state management for Mantissa Stance.

Provides persistent tracking of sent alerts for deduplication,
acknowledgment, and audit trail across cloud providers.
"""

from __future__ import annotations

import hashlib
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class AlertRecord:
    """
    Record of a sent alert.

    Attributes:
        id: Unique alert record ID
        finding_id: ID of the finding
        destination: Destination name
        sent_at: When alert was sent
        acknowledged_at: When alert was acknowledged (if applicable)
        acknowledged_by: Who acknowledged the alert
        dedup_key: Deduplication key
        status: Alert status (sent, acknowledged, resolved, expired)
        metadata: Additional metadata
    """

    id: str
    finding_id: str
    destination: str
    sent_at: datetime
    acknowledged_at: datetime | None = None
    acknowledged_by: str | None = None
    dedup_key: str = ""
    status: str = "sent"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "destination": self.destination,
            "sent_at": self.sent_at.isoformat(),
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "acknowledged_by": self.acknowledged_by,
            "dedup_key": self.dedup_key,
            "status": self.status,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AlertRecord:
        """Create from dictionary."""
        return cls(
            id=data["id"],
            finding_id=data["finding_id"],
            destination=data["destination"],
            sent_at=datetime.fromisoformat(data["sent_at"]),
            acknowledged_at=datetime.fromisoformat(data["acknowledged_at"]) if data.get("acknowledged_at") else None,
            acknowledged_by=data.get("acknowledged_by"),
            dedup_key=data.get("dedup_key", ""),
            status=data.get("status", "sent"),
            metadata=data.get("metadata", {}),
        )


class AlertStateBackend(ABC):
    """Abstract base for alert state backends."""

    @abstractmethod
    def record_alert(self, record: AlertRecord) -> None:
        """Record a sent alert."""
        ...

    @abstractmethod
    def get_alert(self, alert_id: str) -> AlertRecord | None:
        """Get an alert record by ID."""
        ...

    @abstractmethod
    def get_alerts_for_finding(self, finding_id: str) -> list[AlertRecord]:
        """Get all alerts for a finding."""
        ...

    @abstractmethod
    def check_dedup(self, dedup_key: str, window: timedelta) -> bool:
        """Check if alert was recently sent (returns True if duplicate)."""
        ...

    @abstractmethod
    def acknowledge(self, alert_id: str, by: str) -> bool:
        """Acknowledge an alert."""
        ...

    @abstractmethod
    def expire_old_alerts(self, before: datetime) -> int:
        """Expire old alert records."""
        ...


class InMemoryAlertState(AlertStateBackend):
    """
    In-memory alert state backend.

    Suitable for development and testing. Data is lost on restart.
    """

    def __init__(self) -> None:
        """Initialize in-memory state."""
        self._alerts: dict[str, AlertRecord] = {}
        self._by_finding: dict[str, list[str]] = {}
        self._by_dedup_key: dict[str, datetime] = {}

    def record_alert(self, record: AlertRecord) -> None:
        """Record a sent alert."""
        self._alerts[record.id] = record

        # Index by finding
        if record.finding_id not in self._by_finding:
            self._by_finding[record.finding_id] = []
        self._by_finding[record.finding_id].append(record.id)

        # Record dedup key
        if record.dedup_key:
            self._by_dedup_key[record.dedup_key] = record.sent_at

        logger.debug(f"Recorded alert: {record.id}")

    def get_alert(self, alert_id: str) -> AlertRecord | None:
        """Get an alert record by ID."""
        return self._alerts.get(alert_id)

    def get_alerts_for_finding(self, finding_id: str) -> list[AlertRecord]:
        """Get all alerts for a finding."""
        alert_ids = self._by_finding.get(finding_id, [])
        return [self._alerts[aid] for aid in alert_ids if aid in self._alerts]

    def check_dedup(self, dedup_key: str, window: timedelta) -> bool:
        """Check if alert was recently sent."""
        if dedup_key not in self._by_dedup_key:
            return False

        sent_at = self._by_dedup_key[dedup_key]
        return datetime.utcnow() - sent_at < window

    def acknowledge(self, alert_id: str, by: str) -> bool:
        """Acknowledge an alert."""
        if alert_id not in self._alerts:
            return False

        self._alerts[alert_id].acknowledged_at = datetime.utcnow()
        self._alerts[alert_id].acknowledged_by = by
        self._alerts[alert_id].status = "acknowledged"
        logger.info(f"Alert {alert_id} acknowledged by {by}")
        return True

    def expire_old_alerts(self, before: datetime) -> int:
        """Expire old alert records."""
        to_expire = [
            aid for aid, record in self._alerts.items()
            if record.sent_at < before and record.status == "sent"
        ]

        for aid in to_expire:
            self._alerts[aid].status = "expired"

        # Clean up dedup keys
        to_remove = [
            key for key, ts in self._by_dedup_key.items()
            if ts < before
        ]
        for key in to_remove:
            del self._by_dedup_key[key]

        logger.info(f"Expired {len(to_expire)} alerts")
        return len(to_expire)


class DynamoDBAlertState(AlertStateBackend):
    """
    DynamoDB-backed alert state for AWS deployments.

    Uses a single table with composite keys for efficient queries.
    """

    def __init__(
        self,
        table_name: str,
        session: Any | None = None,
        region: str = "us-east-1",
    ) -> None:
        """
        Initialize DynamoDB state backend.

        Args:
            table_name: DynamoDB table name
            session: Optional boto3 session
            region: AWS region
        """
        self._table_name = table_name
        self._region = region

        try:
            import boto3

            if session:
                self._dynamodb = session.resource("dynamodb", region_name=region)
            else:
                self._dynamodb = boto3.resource("dynamodb", region_name=region)

            self._table = self._dynamodb.Table(table_name)
        except ImportError:
            raise ImportError("boto3 is required for DynamoDBAlertState")

    def record_alert(self, record: AlertRecord) -> None:
        """Record a sent alert."""
        item = {
            "pk": f"ALERT#{record.id}",
            "sk": "METADATA",
            **record.to_dict(),
            "ttl": int((record.sent_at + timedelta(days=30)).timestamp()),
        }

        # Also create GSI entries for queries
        self._table.put_item(Item=item)

        # Index by finding
        finding_item = {
            "pk": f"FINDING#{record.finding_id}",
            "sk": f"ALERT#{record.id}",
            "alert_id": record.id,
            "sent_at": record.sent_at.isoformat(),
        }
        self._table.put_item(Item=finding_item)

        # Index for deduplication
        if record.dedup_key:
            dedup_item = {
                "pk": f"DEDUP#{record.dedup_key}",
                "sk": record.sent_at.isoformat(),
                "alert_id": record.id,
                "ttl": int((record.sent_at + timedelta(days=7)).timestamp()),
            }
            self._table.put_item(Item=dedup_item)

        logger.debug(f"Recorded alert in DynamoDB: {record.id}")

    def get_alert(self, alert_id: str) -> AlertRecord | None:
        """Get an alert record by ID."""
        response = self._table.get_item(
            Key={"pk": f"ALERT#{alert_id}", "sk": "METADATA"}
        )

        if "Item" not in response:
            return None

        return AlertRecord.from_dict(response["Item"])

    def get_alerts_for_finding(self, finding_id: str) -> list[AlertRecord]:
        """Get all alerts for a finding."""
        response = self._table.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": f"FINDING#{finding_id}"},
        )

        records = []
        for item in response.get("Items", []):
            alert = self.get_alert(item["alert_id"])
            if alert:
                records.append(alert)

        return records

    def check_dedup(self, dedup_key: str, window: timedelta) -> bool:
        """Check if alert was recently sent."""
        cutoff = (datetime.utcnow() - window).isoformat()

        response = self._table.query(
            KeyConditionExpression="pk = :pk AND sk > :cutoff",
            ExpressionAttributeValues={
                ":pk": f"DEDUP#{dedup_key}",
                ":cutoff": cutoff,
            },
            Limit=1,
        )

        return len(response.get("Items", [])) > 0

    def acknowledge(self, alert_id: str, by: str) -> bool:
        """Acknowledge an alert."""
        try:
            self._table.update_item(
                Key={"pk": f"ALERT#{alert_id}", "sk": "METADATA"},
                UpdateExpression="SET acknowledged_at = :at, acknowledged_by = :by, #s = :status",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":at": datetime.utcnow().isoformat(),
                    ":by": by,
                    ":status": "acknowledged",
                },
            )
            logger.info(f"Alert {alert_id} acknowledged by {by}")
            return True
        except Exception as e:
            logger.error(f"Failed to acknowledge alert: {e}")
            return False

    def expire_old_alerts(self, before: datetime) -> int:
        """Expire old alerts (TTL handles cleanup)."""
        # DynamoDB TTL handles automatic cleanup
        # This method can be used for explicit status updates if needed
        return 0


class FirestoreAlertState(AlertStateBackend):
    """
    Firestore-backed alert state for GCP deployments.
    """

    def __init__(
        self,
        project_id: str,
        collection: str = "stance_alerts",
        credentials: Any | None = None,
    ) -> None:
        """
        Initialize Firestore state backend.

        Args:
            project_id: GCP project ID
            collection: Firestore collection name
            credentials: Optional GCP credentials
        """
        self._collection_name = collection

        try:
            from google.cloud import firestore

            self._db = firestore.Client(
                project=project_id,
                credentials=credentials,
            )
            self._collection = self._db.collection(collection)
        except ImportError:
            raise ImportError("google-cloud-firestore is required for FirestoreAlertState")

    def record_alert(self, record: AlertRecord) -> None:
        """Record a sent alert."""
        doc_data = record.to_dict()
        doc_data["_created_at"] = datetime.utcnow()

        self._collection.document(record.id).set(doc_data)

        # Create index document for finding lookup
        self._db.collection("finding_alerts").document(
            f"{record.finding_id}_{record.id}"
        ).set({
            "alert_id": record.id,
            "finding_id": record.finding_id,
            "sent_at": record.sent_at,
        })

        # Create dedup index
        if record.dedup_key:
            self._db.collection("alert_dedup").document(record.dedup_key).set({
                "alert_id": record.id,
                "sent_at": record.sent_at,
            })

        logger.debug(f"Recorded alert in Firestore: {record.id}")

    def get_alert(self, alert_id: str) -> AlertRecord | None:
        """Get an alert record by ID."""
        doc = self._collection.document(alert_id).get()
        if not doc.exists:
            return None

        return AlertRecord.from_dict(doc.to_dict())

    def get_alerts_for_finding(self, finding_id: str) -> list[AlertRecord]:
        """Get all alerts for a finding."""
        refs = self._db.collection("finding_alerts").where(
            "finding_id", "==", finding_id
        ).stream()

        records = []
        for ref in refs:
            data = ref.to_dict()
            alert = self.get_alert(data["alert_id"])
            if alert:
                records.append(alert)

        return records

    def check_dedup(self, dedup_key: str, window: timedelta) -> bool:
        """Check if alert was recently sent."""
        doc = self._db.collection("alert_dedup").document(dedup_key).get()
        if not doc.exists:
            return False

        data = doc.to_dict()
        sent_at = data.get("sent_at")
        if isinstance(sent_at, str):
            sent_at = datetime.fromisoformat(sent_at)

        return datetime.utcnow() - sent_at < window

    def acknowledge(self, alert_id: str, by: str) -> bool:
        """Acknowledge an alert."""
        try:
            self._collection.document(alert_id).update({
                "acknowledged_at": datetime.utcnow().isoformat(),
                "acknowledged_by": by,
                "status": "acknowledged",
            })
            logger.info(f"Alert {alert_id} acknowledged by {by}")
            return True
        except Exception as e:
            logger.error(f"Failed to acknowledge alert: {e}")
            return False

    def expire_old_alerts(self, before: datetime) -> int:
        """Expire old alerts."""
        query = self._collection.where(
            "sent_at", "<", before.isoformat()
        ).where("status", "==", "sent").limit(500)

        count = 0
        for doc in query.stream():
            doc.reference.update({"status": "expired"})
            count += 1

        logger.info(f"Expired {count} alerts in Firestore")
        return count


class CosmosDBAlertState(AlertStateBackend):
    """
    Azure Cosmos DB-backed alert state for Azure deployments.
    """

    def __init__(
        self,
        endpoint: str,
        key: str,
        database_name: str = "stance",
        container_name: str = "alerts",
    ) -> None:
        """
        Initialize Cosmos DB state backend.

        Args:
            endpoint: Cosmos DB endpoint
            key: Cosmos DB key
            database_name: Database name
            container_name: Container name
        """
        try:
            from azure.cosmos import CosmosClient, PartitionKey

            self._client = CosmosClient(endpoint, key)
            self._database = self._client.get_database_client(database_name)
            self._container = self._database.get_container_client(container_name)
        except ImportError:
            raise ImportError("azure-cosmos is required for CosmosDBAlertState")

    def record_alert(self, record: AlertRecord) -> None:
        """Record a sent alert."""
        item = {
            "id": record.id,
            "partitionKey": record.finding_id,
            "type": "alert",
            **record.to_dict(),
        }

        self._container.create_item(body=item)

        # Create dedup index item
        if record.dedup_key:
            dedup_item = {
                "id": f"dedup_{record.dedup_key}",
                "partitionKey": "dedup",
                "type": "dedup",
                "dedup_key": record.dedup_key,
                "alert_id": record.id,
                "sent_at": record.sent_at.isoformat(),
            }
            self._container.upsert_item(body=dedup_item)

        logger.debug(f"Recorded alert in Cosmos DB: {record.id}")

    def get_alert(self, alert_id: str) -> AlertRecord | None:
        """Get an alert record by ID."""
        query = "SELECT * FROM c WHERE c.id = @id AND c.type = 'alert'"
        items = list(self._container.query_items(
            query=query,
            parameters=[{"name": "@id", "value": alert_id}],
            enable_cross_partition_query=True,
        ))

        if not items:
            return None

        return AlertRecord.from_dict(items[0])

    def get_alerts_for_finding(self, finding_id: str) -> list[AlertRecord]:
        """Get all alerts for a finding."""
        query = "SELECT * FROM c WHERE c.partitionKey = @finding_id AND c.type = 'alert'"
        items = list(self._container.query_items(
            query=query,
            parameters=[{"name": "@finding_id", "value": finding_id}],
        ))

        return [AlertRecord.from_dict(item) for item in items]

    def check_dedup(self, dedup_key: str, window: timedelta) -> bool:
        """Check if alert was recently sent."""
        cutoff = (datetime.utcnow() - window).isoformat()

        query = "SELECT * FROM c WHERE c.id = @id AND c.sent_at > @cutoff"
        items = list(self._container.query_items(
            query=query,
            parameters=[
                {"name": "@id", "value": f"dedup_{dedup_key}"},
                {"name": "@cutoff", "value": cutoff},
            ],
            enable_cross_partition_query=True,
        ))

        return len(items) > 0

    def acknowledge(self, alert_id: str, by: str) -> bool:
        """Acknowledge an alert."""
        try:
            alert = self.get_alert(alert_id)
            if not alert:
                return False

            item = {
                "id": alert_id,
                "partitionKey": alert.finding_id,
                "type": "alert",
                **alert.to_dict(),
                "acknowledged_at": datetime.utcnow().isoformat(),
                "acknowledged_by": by,
                "status": "acknowledged",
            }

            self._container.upsert_item(body=item)
            logger.info(f"Alert {alert_id} acknowledged by {by}")
            return True
        except Exception as e:
            logger.error(f"Failed to acknowledge alert: {e}")
            return False

    def expire_old_alerts(self, before: datetime) -> int:
        """Expire old alerts."""
        query = "SELECT * FROM c WHERE c.type = 'alert' AND c.sent_at < @before AND c.status = 'sent'"
        items = list(self._container.query_items(
            query=query,
            parameters=[{"name": "@before", "value": before.isoformat()}],
            enable_cross_partition_query=True,
        ))

        count = 0
        for item in items[:500]:  # Limit batch size
            item["status"] = "expired"
            self._container.upsert_item(body=item)
            count += 1

        logger.info(f"Expired {count} alerts in Cosmos DB")
        return count


class AlertState:
    """
    High-level alert state manager.

    Provides a unified interface for alert state management
    across different backends.
    """

    def __init__(
        self,
        backend: AlertStateBackend | None = None,
        dedup_window: timedelta | None = None,
    ) -> None:
        """
        Initialize alert state manager.

        Args:
            backend: State backend to use (defaults to in-memory)
            dedup_window: Deduplication window (default: 24 hours)
        """
        self._backend = backend or InMemoryAlertState()
        self._dedup_window = dedup_window or timedelta(hours=24)

    def record_sent(
        self,
        finding_id: str,
        destination: str,
        dedup_key: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> AlertRecord:
        """
        Record a sent alert.

        Args:
            finding_id: Finding ID
            destination: Destination name
            dedup_key: Deduplication key
            metadata: Additional metadata

        Returns:
            Created AlertRecord
        """
        record = AlertRecord(
            id=self._generate_id(finding_id, destination),
            finding_id=finding_id,
            destination=destination,
            sent_at=datetime.utcnow(),
            dedup_key=dedup_key,
            metadata=metadata or {},
        )

        self._backend.record_alert(record)
        return record

    def is_duplicate(self, dedup_key: str) -> bool:
        """Check if an alert is a duplicate."""
        return self._backend.check_dedup(dedup_key, self._dedup_window)

    def acknowledge(self, alert_id: str, by: str) -> bool:
        """Acknowledge an alert."""
        return self._backend.acknowledge(alert_id, by)

    def get_alerts_for_finding(self, finding_id: str) -> list[AlertRecord]:
        """Get all alerts for a finding."""
        return self._backend.get_alerts_for_finding(finding_id)

    def cleanup(self, max_age_days: int = 30) -> int:
        """
        Clean up old alert records.

        Args:
            max_age_days: Maximum age in days

        Returns:
            Number of records expired
        """
        before = datetime.utcnow() - timedelta(days=max_age_days)
        return self._backend.expire_old_alerts(before)

    def _generate_id(self, finding_id: str, destination: str) -> str:
        """Generate a unique alert ID."""
        timestamp = datetime.utcnow().isoformat()
        data = f"{finding_id}|{destination}|{timestamp}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
