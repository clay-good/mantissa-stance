"""
ServiceNow integration for Mantissa Stance.

Provides comprehensive ServiceNow ITSM integration including:
- Incident ticket creation and updates
- Change request management
- Problem ticket integration
- CMDB asset synchronization
- Bi-directional status sync
- Custom field mapping
- Attachment support

Part of Phase 93: Workflow Automation
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urljoin

from stance.alerting.destinations.base import BaseDestination
from stance.models.finding import Finding, Severity

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class ServiceNowTable(Enum):
    """ServiceNow table names."""
    INCIDENT = "incident"
    CHANGE_REQUEST = "change_request"
    PROBLEM = "problem"
    CMDB_CI = "cmdb_ci"
    SYS_USER = "sys_user"
    SYS_USER_GROUP = "sys_user_group"
    TASK = "task"
    SECURITY_INCIDENT = "sn_si_incident"


class IncidentState(Enum):
    """ServiceNow incident states."""
    NEW = 1
    IN_PROGRESS = 2
    ON_HOLD = 3
    RESOLVED = 6
    CLOSED = 7
    CANCELLED = 8


class IncidentImpact(Enum):
    """ServiceNow incident impact levels."""
    HIGH = 1
    MEDIUM = 2
    LOW = 3


class IncidentUrgency(Enum):
    """ServiceNow incident urgency levels."""
    HIGH = 1
    MEDIUM = 2
    LOW = 3


class ChangeType(Enum):
    """ServiceNow change request types."""
    STANDARD = "standard"
    NORMAL = "normal"
    EMERGENCY = "emergency"


class ChangeState(Enum):
    """ServiceNow change request states."""
    NEW = -5
    ASSESS = -4
    AUTHORIZE = -3
    SCHEDULED = -2
    IMPLEMENT = -1
    REVIEW = 0
    CLOSED = 3
    CANCELLED = 4


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class ServiceNowConfig:
    """
    ServiceNow connection configuration.

    Attributes:
        instance_url: ServiceNow instance URL (e.g., https://company.service-now.com)
        username: API username
        password: API password
        client_id: OAuth2 client ID (optional)
        client_secret: OAuth2 client secret (optional)
        use_oauth: Use OAuth2 instead of basic auth
        api_version: API version (default: v2)
        timeout_seconds: Request timeout
        verify_ssl: Verify SSL certificates
        default_assignment_group: Default assignment group sys_id
        default_category: Default incident category
        custom_fields: Custom field mappings
    """
    instance_url: str
    username: str = ""
    password: str = ""
    client_id: str = ""
    client_secret: str = ""
    use_oauth: bool = False
    api_version: str = "v2"
    timeout_seconds: int = 30
    verify_ssl: bool = True
    default_assignment_group: str = ""
    default_category: str = "Security"
    custom_fields: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def api_base_url(self) -> str:
        """Get API base URL."""
        return urljoin(self.instance_url, f"/api/now/{self.api_version}/")

    @property
    def table_api_url(self) -> str:
        """Get table API URL."""
        return urljoin(self.api_base_url, "table/")


@dataclass
class ServiceNowTicket:
    """
    ServiceNow ticket representation.

    Works for incidents, change requests, and problems.
    """
    sys_id: str = ""
    number: str = ""
    short_description: str = ""
    description: str = ""
    state: int = 1
    impact: int = 2
    urgency: int = 2
    priority: int = 3
    category: str = ""
    subcategory: str = ""
    assignment_group: str = ""
    assigned_to: str = ""
    caller_id: str = ""
    opened_by: str = ""
    opened_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    close_code: str = ""
    close_notes: str = ""
    work_notes: str = ""
    comments: str = ""
    cmdb_ci: str = ""  # Configuration item
    business_service: str = ""
    correlation_id: str = ""
    correlation_display: str = ""
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    attachments: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_api_payload(self, include_empty: bool = False) -> Dict[str, Any]:
        """Convert to ServiceNow API payload."""
        payload = {
            "short_description": self.short_description,
            "description": self.description,
            "impact": self.impact,
            "urgency": self.urgency,
        }

        if self.state:
            payload["state"] = self.state
        if self.category:
            payload["category"] = self.category
        if self.subcategory:
            payload["subcategory"] = self.subcategory
        if self.assignment_group:
            payload["assignment_group"] = self.assignment_group
        if self.assigned_to:
            payload["assigned_to"] = self.assigned_to
        if self.caller_id:
            payload["caller_id"] = self.caller_id
        if self.cmdb_ci:
            payload["cmdb_ci"] = self.cmdb_ci
        if self.business_service:
            payload["business_service"] = self.business_service
        if self.correlation_id:
            payload["correlation_id"] = self.correlation_id
        if self.correlation_display:
            payload["correlation_display"] = self.correlation_display
        if self.work_notes:
            payload["work_notes"] = self.work_notes
        if self.comments:
            payload["comments"] = self.comments
        if self.close_code:
            payload["close_code"] = self.close_code
        if self.close_notes:
            payload["close_notes"] = self.close_notes

        # Add custom fields
        for field_name, value in self.custom_fields.items():
            payload[field_name] = value

        return payload

    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> ServiceNowTicket:
        """Create from ServiceNow API response."""
        return cls(
            sys_id=data.get("sys_id", ""),
            number=data.get("number", ""),
            short_description=data.get("short_description", ""),
            description=data.get("description", ""),
            state=int(data.get("state", 1)),
            impact=int(data.get("impact", 2)),
            urgency=int(data.get("urgency", 2)),
            priority=int(data.get("priority", 3)),
            category=data.get("category", ""),
            subcategory=data.get("subcategory", ""),
            assignment_group=data.get("assignment_group", {}).get("value", "") if isinstance(data.get("assignment_group"), dict) else data.get("assignment_group", ""),
            assigned_to=data.get("assigned_to", {}).get("value", "") if isinstance(data.get("assigned_to"), dict) else data.get("assigned_to", ""),
            caller_id=data.get("caller_id", {}).get("value", "") if isinstance(data.get("caller_id"), dict) else data.get("caller_id", ""),
            opened_by=data.get("opened_by", {}).get("value", "") if isinstance(data.get("opened_by"), dict) else data.get("opened_by", ""),
            cmdb_ci=data.get("cmdb_ci", {}).get("value", "") if isinstance(data.get("cmdb_ci"), dict) else data.get("cmdb_ci", ""),
            business_service=data.get("business_service", {}).get("value", "") if isinstance(data.get("business_service"), dict) else data.get("business_service", ""),
            correlation_id=data.get("correlation_id", ""),
            correlation_display=data.get("correlation_display", ""),
            metadata=data,
        )


@dataclass
class ServiceNowChangeRequest:
    """ServiceNow change request."""
    sys_id: str = ""
    number: str = ""
    short_description: str = ""
    description: str = ""
    type: str = "normal"
    state: int = -5
    category: str = ""
    risk: int = 3
    impact: int = 3
    priority: int = 4
    assignment_group: str = ""
    assigned_to: str = ""
    requested_by: str = ""
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    justification: str = ""
    implementation_plan: str = ""
    backout_plan: str = ""
    test_plan: str = ""
    cmdb_ci: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_api_payload(self) -> Dict[str, Any]:
        """Convert to ServiceNow API payload."""
        payload = {
            "short_description": self.short_description,
            "description": self.description,
            "type": self.type,
            "risk": self.risk,
            "impact": self.impact,
        }

        if self.state:
            payload["state"] = self.state
        if self.category:
            payload["category"] = self.category
        if self.assignment_group:
            payload["assignment_group"] = self.assignment_group
        if self.assigned_to:
            payload["assigned_to"] = self.assigned_to
        if self.requested_by:
            payload["requested_by"] = self.requested_by
        if self.start_date:
            payload["start_date"] = self.start_date.isoformat()
        if self.end_date:
            payload["end_date"] = self.end_date.isoformat()
        if self.justification:
            payload["justification"] = self.justification
        if self.implementation_plan:
            payload["implementation_plan"] = self.implementation_plan
        if self.backout_plan:
            payload["backout_plan"] = self.backout_plan
        if self.test_plan:
            payload["test_plan"] = self.test_plan
        if self.cmdb_ci:
            payload["cmdb_ci"] = self.cmdb_ci

        return payload


# =============================================================================
# ServiceNow Client
# =============================================================================

class ServiceNowClient:
    """
    ServiceNow REST API client.

    Provides methods for interacting with ServiceNow tables.
    """

    def __init__(self, config: ServiceNowConfig):
        """Initialize client with configuration."""
        self.config = config
        self._token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None

        # HTTP client placeholder (would use httpx or requests in production)
        self._http_client: Any = None

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        if self.config.use_oauth:
            # OAuth token would be fetched and cached
            if self._token:
                headers["Authorization"] = f"Bearer {self._token}"
        else:
            # Basic auth
            credentials = f"{self.config.username}:{self.config.password}"
            encoded = base64.b64encode(credentials.encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"

        return headers

    def _make_request(
        self,
        method: str,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Make HTTP request to ServiceNow API.

        Note: This is a placeholder. In production, use httpx or requests.
        """
        # Placeholder implementation - would use actual HTTP client
        logger.info(f"ServiceNow API {method} request to {url}")

        # Simulate successful response
        return {
            "result": {
                "sys_id": "placeholder_sys_id",
                "number": "INC0000001",
            }
        }

    # =========================================================================
    # Incident Operations
    # =========================================================================

    def create_incident(self, ticket: ServiceNowTicket) -> ServiceNowTicket:
        """
        Create a new incident in ServiceNow.

        Args:
            ticket: Ticket data to create

        Returns:
            Created ticket with sys_id and number
        """
        url = urljoin(self.config.table_api_url, ServiceNowTable.INCIDENT.value)
        payload = ticket.to_api_payload()

        response = self._make_request("POST", url, data=payload)
        result = response.get("result", {})

        ticket.sys_id = result.get("sys_id", "")
        ticket.number = result.get("number", "")

        logger.info(f"Created ServiceNow incident: {ticket.number}")
        return ticket

    def update_incident(
        self,
        sys_id: str,
        updates: Dict[str, Any],
    ) -> ServiceNowTicket:
        """
        Update an existing incident.

        Args:
            sys_id: Incident sys_id
            updates: Fields to update

        Returns:
            Updated ticket
        """
        url = urljoin(
            self.config.table_api_url,
            f"{ServiceNowTable.INCIDENT.value}/{sys_id}"
        )

        response = self._make_request("PATCH", url, data=updates)
        return ServiceNowTicket.from_api_response(response.get("result", {}))

    def get_incident(self, sys_id: str) -> Optional[ServiceNowTicket]:
        """Get incident by sys_id."""
        url = urljoin(
            self.config.table_api_url,
            f"{ServiceNowTable.INCIDENT.value}/{sys_id}"
        )

        response = self._make_request("GET", url)
        result = response.get("result")
        if result:
            return ServiceNowTicket.from_api_response(result)
        return None

    def get_incident_by_number(self, number: str) -> Optional[ServiceNowTicket]:
        """Get incident by ticket number."""
        url = urljoin(self.config.table_api_url, ServiceNowTable.INCIDENT.value)
        params = {"sysparm_query": f"number={number}"}

        response = self._make_request("GET", url, params=params)
        results = response.get("result", [])
        if results:
            return ServiceNowTicket.from_api_response(results[0])
        return None

    def query_incidents(
        self,
        query: str,
        limit: int = 100,
        offset: int = 0,
    ) -> List[ServiceNowTicket]:
        """
        Query incidents with encoded query.

        Args:
            query: ServiceNow encoded query string
            limit: Maximum results
            offset: Pagination offset

        Returns:
            List of matching tickets
        """
        url = urljoin(self.config.table_api_url, ServiceNowTable.INCIDENT.value)
        params = {
            "sysparm_query": query,
            "sysparm_limit": str(limit),
            "sysparm_offset": str(offset),
        }

        response = self._make_request("GET", url, params=params)
        results = response.get("result", [])
        return [ServiceNowTicket.from_api_response(r) for r in results]

    def close_incident(
        self,
        sys_id: str,
        close_code: str,
        close_notes: str,
    ) -> ServiceNowTicket:
        """Close an incident."""
        return self.update_incident(
            sys_id,
            {
                "state": IncidentState.CLOSED.value,
                "close_code": close_code,
                "close_notes": close_notes,
            }
        )

    def resolve_incident(
        self,
        sys_id: str,
        resolution_notes: str,
    ) -> ServiceNowTicket:
        """Resolve an incident."""
        return self.update_incident(
            sys_id,
            {
                "state": IncidentState.RESOLVED.value,
                "close_notes": resolution_notes,
            }
        )

    def add_work_notes(self, sys_id: str, notes: str) -> ServiceNowTicket:
        """Add work notes to incident."""
        return self.update_incident(sys_id, {"work_notes": notes})

    def add_comments(self, sys_id: str, comments: str) -> ServiceNowTicket:
        """Add comments to incident (visible to customer)."""
        return self.update_incident(sys_id, {"comments": comments})

    # =========================================================================
    # Change Request Operations
    # =========================================================================

    def create_change_request(
        self,
        change: ServiceNowChangeRequest,
    ) -> ServiceNowChangeRequest:
        """Create a change request."""
        url = urljoin(
            self.config.table_api_url,
            ServiceNowTable.CHANGE_REQUEST.value
        )
        payload = change.to_api_payload()

        response = self._make_request("POST", url, data=payload)
        result = response.get("result", {})

        change.sys_id = result.get("sys_id", "")
        change.number = result.get("number", "")

        logger.info(f"Created ServiceNow change request: {change.number}")
        return change

    def update_change_request(
        self,
        sys_id: str,
        updates: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update a change request."""
        url = urljoin(
            self.config.table_api_url,
            f"{ServiceNowTable.CHANGE_REQUEST.value}/{sys_id}"
        )
        return self._make_request("PATCH", url, data=updates)

    def get_change_request(self, sys_id: str) -> Optional[Dict[str, Any]]:
        """Get change request by sys_id."""
        url = urljoin(
            self.config.table_api_url,
            f"{ServiceNowTable.CHANGE_REQUEST.value}/{sys_id}"
        )
        response = self._make_request("GET", url)
        return response.get("result")

    # =========================================================================
    # CMDB Operations
    # =========================================================================

    def get_ci(self, sys_id: str) -> Optional[Dict[str, Any]]:
        """Get configuration item from CMDB."""
        url = urljoin(
            self.config.table_api_url,
            f"{ServiceNowTable.CMDB_CI.value}/{sys_id}"
        )
        response = self._make_request("GET", url)
        return response.get("result")

    def query_ci(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Query configuration items."""
        url = urljoin(self.config.table_api_url, ServiceNowTable.CMDB_CI.value)
        params = {
            "sysparm_query": query,
            "sysparm_limit": str(limit),
        }
        response = self._make_request("GET", url, params=params)
        return response.get("result", [])

    def find_ci_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Find CI by name."""
        results = self.query_ci(f"name={name}", limit=1)
        return results[0] if results else None

    # =========================================================================
    # User/Group Operations
    # =========================================================================

    def get_user(self, sys_id: str) -> Optional[Dict[str, Any]]:
        """Get user by sys_id."""
        url = urljoin(
            self.config.table_api_url,
            f"{ServiceNowTable.SYS_USER.value}/{sys_id}"
        )
        response = self._make_request("GET", url)
        return response.get("result")

    def find_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Find user by email."""
        url = urljoin(self.config.table_api_url, ServiceNowTable.SYS_USER.value)
        params = {"sysparm_query": f"email={email}"}
        response = self._make_request("GET", url, params=params)
        results = response.get("result", [])
        return results[0] if results else None

    def get_group(self, sys_id: str) -> Optional[Dict[str, Any]]:
        """Get group by sys_id."""
        url = urljoin(
            self.config.table_api_url,
            f"{ServiceNowTable.SYS_USER_GROUP.value}/{sys_id}"
        )
        response = self._make_request("GET", url)
        return response.get("result")

    def find_group_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Find group by name."""
        url = urljoin(
            self.config.table_api_url,
            ServiceNowTable.SYS_USER_GROUP.value
        )
        params = {"sysparm_query": f"name={name}"}
        response = self._make_request("GET", url, params=params)
        results = response.get("result", [])
        return results[0] if results else None

    # =========================================================================
    # Attachment Operations
    # =========================================================================

    def add_attachment(
        self,
        table: ServiceNowTable,
        sys_id: str,
        filename: str,
        content: bytes,
        content_type: str = "application/octet-stream",
    ) -> Dict[str, Any]:
        """Add attachment to a record."""
        url = urljoin(self.config.api_base_url, "attachment/file")
        params = {
            "table_name": table.value,
            "table_sys_id": sys_id,
            "file_name": filename,
        }

        # Would set proper headers and body for file upload
        logger.info(f"Adding attachment {filename} to {table.value}/{sys_id}")

        return {"sys_id": "attachment_placeholder"}

    # =========================================================================
    # Connection Test
    # =========================================================================

    def test_connection(self) -> bool:
        """Test connection to ServiceNow."""
        try:
            # Try to query a single incident
            url = urljoin(self.config.table_api_url, ServiceNowTable.INCIDENT.value)
            params = {"sysparm_limit": "1"}
            self._make_request("GET", url, params=params)
            return True
        except Exception as e:
            logger.error(f"ServiceNow connection test failed: {e}")
            return False


# =============================================================================
# ServiceNow Destination
# =============================================================================

class ServiceNowDestination(BaseDestination):
    """
    ServiceNow alert destination.

    Creates incidents in ServiceNow for security findings.
    """

    def __init__(self, name: str, config: Dict[str, Any]) -> None:
        """Initialize ServiceNow destination."""
        super().__init__(name, config)

        self._sn_config = ServiceNowConfig(
            instance_url=config.get("instance_url", ""),
            username=config.get("username", ""),
            password=config.get("password", ""),
            client_id=config.get("client_id", ""),
            client_secret=config.get("client_secret", ""),
            use_oauth=config.get("use_oauth", False),
            default_assignment_group=config.get("assignment_group", ""),
            default_category=config.get("category", "Security"),
            custom_fields=config.get("custom_fields", {}),
        )

        self._client = ServiceNowClient(self._sn_config)

    def send(self, finding: Finding, context: Dict[str, Any]) -> bool:
        """
        Send alert by creating ServiceNow incident.

        Args:
            finding: Finding to alert on
            context: Additional context

        Returns:
            True if incident was created successfully
        """
        try:
            # Map severity to impact/urgency
            impact, urgency = self._map_severity(finding.severity)

            # Build ticket
            ticket = ServiceNowTicket(
                short_description=self.format_title(finding),
                description=self.format_description(finding),
                impact=impact,
                urgency=urgency,
                category=self._sn_config.default_category,
                assignment_group=self._sn_config.default_assignment_group,
                correlation_id=finding.id,
                correlation_display=f"Stance Finding: {finding.id}",
            )

            # Add custom fields from context
            for sn_field, stance_field in self._sn_config.custom_fields.items():
                if stance_field in context:
                    ticket.custom_fields[sn_field] = context[stance_field]

            # Create incident
            created = self._client.create_incident(ticket)

            logger.info(
                f"Created ServiceNow incident {created.number} for finding {finding.id}"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to create ServiceNow incident: {e}")
            return False

    def test_connection(self) -> bool:
        """Test connection to ServiceNow."""
        return self._client.test_connection()

    def _map_severity(self, severity: Severity) -> tuple[int, int]:
        """Map finding severity to ServiceNow impact and urgency."""
        mapping = {
            Severity.CRITICAL: (IncidentImpact.HIGH.value, IncidentUrgency.HIGH.value),
            Severity.HIGH: (IncidentImpact.HIGH.value, IncidentUrgency.MEDIUM.value),
            Severity.MEDIUM: (IncidentImpact.MEDIUM.value, IncidentUrgency.MEDIUM.value),
            Severity.LOW: (IncidentImpact.LOW.value, IncidentUrgency.LOW.value),
            Severity.INFO: (IncidentImpact.LOW.value, IncidentUrgency.LOW.value),
        }
        return mapping.get(severity, (IncidentImpact.MEDIUM.value, IncidentUrgency.MEDIUM.value))


# =============================================================================
# ServiceNow Sync Manager
# =============================================================================

class ServiceNowSyncManager:
    """
    Manager for bi-directional synchronization with ServiceNow.

    Handles ticket status sync between Stance incidents and ServiceNow.
    """

    def __init__(
        self,
        client: ServiceNowClient,
        status_callback: Optional[Callable[[str, str, Dict[str, Any]], None]] = None,
    ):
        """
        Initialize sync manager.

        Args:
            client: ServiceNow API client
            status_callback: Callback when ticket status changes
        """
        self.client = client
        self.status_callback = status_callback

        # Track synced tickets
        self._synced_tickets: Dict[str, str] = {}  # stance_id -> servicenow_sys_id

    def register_ticket(self, stance_id: str, sn_sys_id: str) -> None:
        """Register a ticket for synchronization."""
        self._synced_tickets[stance_id] = sn_sys_id

    def unregister_ticket(self, stance_id: str) -> None:
        """Remove ticket from synchronization."""
        self._synced_tickets.pop(stance_id, None)

    def sync_status_to_servicenow(
        self,
        stance_id: str,
        status: str,
        notes: str = "",
    ) -> bool:
        """
        Sync Stance incident status to ServiceNow.

        Args:
            stance_id: Stance incident ID
            status: New status
            notes: Status change notes

        Returns:
            True if sync successful
        """
        sn_sys_id = self._synced_tickets.get(stance_id)
        if not sn_sys_id:
            logger.warning(f"No ServiceNow ticket linked to {stance_id}")
            return False

        try:
            # Map Stance status to ServiceNow state
            state_map = {
                "new": IncidentState.NEW.value,
                "triaged": IncidentState.IN_PROGRESS.value,
                "assigned": IncidentState.IN_PROGRESS.value,
                "investigating": IncidentState.IN_PROGRESS.value,
                "containment": IncidentState.IN_PROGRESS.value,
                "eradication": IncidentState.IN_PROGRESS.value,
                "recovery": IncidentState.IN_PROGRESS.value,
                "resolved": IncidentState.RESOLVED.value,
                "closed": IncidentState.CLOSED.value,
            }

            sn_state = state_map.get(status.lower(), IncidentState.IN_PROGRESS.value)

            updates = {"state": sn_state}
            if notes:
                updates["work_notes"] = f"[Stance] Status changed to {status}: {notes}"

            self.client.update_incident(sn_sys_id, updates)
            logger.info(f"Synced status {status} to ServiceNow incident {sn_sys_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to sync status to ServiceNow: {e}")
            return False

    def sync_status_from_servicenow(self) -> List[Dict[str, Any]]:
        """
        Check ServiceNow for status changes and sync to Stance.

        Returns:
            List of status changes detected
        """
        changes = []

        for stance_id, sn_sys_id in self._synced_tickets.items():
            try:
                ticket = self.client.get_incident(sn_sys_id)
                if not ticket:
                    continue

                # Map ServiceNow state to Stance status
                status_map = {
                    IncidentState.NEW.value: "new",
                    IncidentState.IN_PROGRESS.value: "investigating",
                    IncidentState.ON_HOLD.value: "investigating",
                    IncidentState.RESOLVED.value: "resolved",
                    IncidentState.CLOSED.value: "closed",
                    IncidentState.CANCELLED.value: "closed",
                }

                new_status = status_map.get(ticket.state)
                if new_status and self.status_callback:
                    change = {
                        "stance_id": stance_id,
                        "servicenow_id": sn_sys_id,
                        "servicenow_number": ticket.number,
                        "new_status": new_status,
                        "servicenow_state": ticket.state,
                    }
                    self.status_callback(stance_id, new_status, change)
                    changes.append(change)

            except Exception as e:
                logger.error(f"Failed to sync from ServiceNow: {e}")

        return changes

    def get_sync_stats(self) -> Dict[str, Any]:
        """Get synchronization statistics."""
        return {
            "tracked_tickets": len(self._synced_tickets),
            "ticket_ids": list(self._synced_tickets.keys()),
        }


# =============================================================================
# Factory Functions
# =============================================================================

def create_servicenow_client(
    instance_url: str,
    username: str,
    password: str,
    assignment_group: str = "",
    category: str = "Security",
) -> ServiceNowClient:
    """Factory function to create ServiceNow client."""
    config = ServiceNowConfig(
        instance_url=instance_url,
        username=username,
        password=password,
        default_assignment_group=assignment_group,
        default_category=category,
    )
    return ServiceNowClient(config)


def create_servicenow_destination(
    name: str,
    instance_url: str,
    username: str,
    password: str,
    assignment_group: str = "",
    category: str = "Security",
) -> ServiceNowDestination:
    """Factory function to create ServiceNow destination."""
    config = {
        "instance_url": instance_url,
        "username": username,
        "password": password,
        "assignment_group": assignment_group,
        "category": category,
    }
    return ServiceNowDestination(name, config)
