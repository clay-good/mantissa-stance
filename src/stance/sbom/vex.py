"""
VEX (Vulnerability Exploitability eXchange) Support.

Provides VEX document creation, parsing, and integration with SBOM
vulnerability data for communicating vulnerability status and exploitability.

Based on:
- CISA VEX specification
- OpenVEX format
- CycloneDX VEX extension
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from stance.sbom.vulnerability import (
    Vulnerability,
    VulnerabilityMatch,
    VulnerabilitySeverity,
)

logger = logging.getLogger(__name__)


class VEXStatus(Enum):
    """
    VEX status values indicating vulnerability applicability.

    Based on CISA VEX specification.
    """

    # Vulnerability affects the product
    AFFECTED = "affected"

    # Vulnerability does not affect the product
    NOT_AFFECTED = "not_affected"

    # Remediation has been applied (patched/updated)
    FIXED = "fixed"

    # Investigation is ongoing
    UNDER_INVESTIGATION = "under_investigation"


class VEXJustification(Enum):
    """
    Justification for NOT_AFFECTED status.

    Explains why a vulnerability doesn't affect the product.
    """

    # Component is not present in the product
    COMPONENT_NOT_PRESENT = "component_not_present"

    # Vulnerable code is not present
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"

    # Vulnerable code is not in the execution path
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"

    # Vulnerable code cannot be controlled by adversary
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = (
        "vulnerable_code_cannot_be_controlled_by_adversary"
    )

    # Inline mitigations exist
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"


class ActionType(Enum):
    """Types of remediation actions."""

    NO_ACTION = "no_action"
    CANNOT_FIX = "cannot_fix"
    WILL_NOT_FIX = "will_not_fix"
    UPDATE = "update"
    ROLLBACK = "rollback"
    WORKAROUND_AVAILABLE = "workaround_available"


@dataclass
class VEXProduct:
    """
    Product identification in VEX.

    Identifies the software product that the VEX statement applies to.
    """

    # Product identification
    name: str
    version: str | None = None

    # Package identifiers
    purl: str | None = None  # Package URL
    cpe: str | None = None  # CPE identifier
    sbom_ref: str | None = None  # Reference to SBOM component

    # Additional identifiers
    hashes: dict[str, str] = field(default_factory=dict)
    supplier: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        result: dict[str, Any] = {"name": self.name}

        if self.version:
            result["version"] = self.version
        if self.purl:
            result["purl"] = self.purl
        if self.cpe:
            result["cpe"] = self.cpe
        if self.sbom_ref:
            result["sbom_ref"] = self.sbom_ref
        if self.hashes:
            result["hashes"] = self.hashes
        if self.supplier:
            result["supplier"] = self.supplier

        return result


@dataclass
class VEXVulnerability:
    """
    Vulnerability reference in VEX.
    """

    id: str  # CVE or other vulnerability ID
    source: str = "NVD"  # Source of vulnerability info
    description: str | None = None
    severity: VulnerabilitySeverity | None = None
    cvss_score: float | None = None
    cwe_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    @classmethod
    def from_vulnerability(cls, vuln: Vulnerability) -> "VEXVulnerability":
        """Create from a Vulnerability object."""
        return cls(
            id=vuln.id,
            source=vuln.source.value if vuln.source else "unknown",
            description=vuln.description,
            severity=vuln.severity,
            cvss_score=vuln.cvss_score,
            cwe_ids=vuln.cwe_ids,
            references=[r.url for r in vuln.references if hasattr(r, "url")],
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        result = {
            "id": self.id,
            "source": self.source,
        }

        if self.description:
            result["description"] = self.description
        if self.severity:
            result["severity"] = self.severity.value
        if self.cvss_score is not None:
            result["cvss_score"] = self.cvss_score
        if self.cwe_ids:
            result["cwe_ids"] = self.cwe_ids
        if self.references:
            result["references"] = self.references

        return result


@dataclass
class VEXStatement:
    """
    A VEX statement about a vulnerability.

    Associates a vulnerability with a product and status.
    """

    # Core fields
    vulnerability: VEXVulnerability
    products: list[VEXProduct]
    status: VEXStatus

    # Optional details
    justification: VEXJustification | None = None
    impact_statement: str | None = None
    action_statement: str | None = None
    action_type: ActionType | None = None

    # Timestamps
    timestamp: datetime = field(default_factory=datetime.utcnow)
    last_updated: datetime | None = None

    # Version info for updates
    version: int = 1

    # Additional metadata
    statement_id: str = ""
    supplier: str | None = None

    def __post_init__(self):
        if not self.statement_id:
            # Generate ID from vulnerability and products
            product_ids = "_".join(p.name for p in self.products[:3])
            self.statement_id = f"vex-{self.vulnerability.id}-{product_ids}"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        result = {
            "statement_id": self.statement_id,
            "vulnerability": self.vulnerability.to_dict(),
            "products": [p.to_dict() for p in self.products],
            "status": self.status.value,
            "timestamp": self.timestamp.isoformat(),
            "version": self.version,
        }

        if self.justification:
            result["justification"] = self.justification.value
        if self.impact_statement:
            result["impact_statement"] = self.impact_statement
        if self.action_statement:
            result["action_statement"] = self.action_statement
        if self.action_type:
            result["action_type"] = self.action_type.value
        if self.last_updated:
            result["last_updated"] = self.last_updated.isoformat()
        if self.supplier:
            result["supplier"] = self.supplier

        return result


@dataclass
class VEXDocument:
    """
    A complete VEX document containing multiple statements.

    Follows the OpenVEX specification format.
    """

    # Document metadata
    id: str = ""
    version: int = 1
    author: str = "Mantissa Stance"
    role: str = "security-tool"

    # Timestamps
    timestamp: datetime = field(default_factory=datetime.utcnow)
    last_updated: datetime | None = None

    # Statements
    statements: list[VEXStatement] = field(default_factory=list)

    # Context
    context: str = "https://openvex.dev/ns/v0.2.0"
    tooling: str = "mantissa-stance"

    def __post_init__(self):
        if not self.id:
            ts = self.timestamp.strftime("%Y%m%d%H%M%S")
            self.id = f"https://stance.dev/vex/{ts}"

    def add_statement(self, statement: VEXStatement) -> None:
        """Add a statement to the document."""
        self.statements.append(statement)
        self.last_updated = datetime.utcnow()

    def get_affected_statements(self) -> list[VEXStatement]:
        """Get all statements with AFFECTED status."""
        return [s for s in self.statements if s.status == VEXStatus.AFFECTED]

    def get_not_affected_statements(self) -> list[VEXStatement]:
        """Get all statements with NOT_AFFECTED status."""
        return [s for s in self.statements if s.status == VEXStatus.NOT_AFFECTED]

    def get_fixed_statements(self) -> list[VEXStatement]:
        """Get all statements with FIXED status."""
        return [s for s in self.statements if s.status == VEXStatus.FIXED]

    def get_statements_for_vulnerability(self, vuln_id: str) -> list[VEXStatement]:
        """Get all statements for a specific vulnerability."""
        return [s for s in self.statements if s.vulnerability.id == vuln_id]

    def get_statements_for_product(self, product_name: str) -> list[VEXStatement]:
        """Get all statements for a specific product."""
        return [
            s
            for s in self.statements
            if any(p.name == product_name for p in s.products)
        ]

    @property
    def summary(self) -> dict[str, int]:
        """Get summary of statement statuses."""
        return {
            "total": len(self.statements),
            "affected": len(self.get_affected_statements()),
            "not_affected": len(self.get_not_affected_statements()),
            "fixed": len(self.get_fixed_statements()),
            "under_investigation": len(
                [s for s in self.statements if s.status == VEXStatus.UNDER_INVESTIGATION]
            ),
        }

    def to_openvex(self) -> dict[str, Any]:
        """
        Convert to OpenVEX format.

        Returns:
            OpenVEX JSON-compatible dictionary
        """
        return {
            "@context": self.context,
            "@id": self.id,
            "author": self.author,
            "role": self.role,
            "timestamp": self.timestamp.isoformat() + "Z",
            "version": self.version,
            "tooling": self.tooling,
            "statements": [s.to_dict() for s in self.statements],
        }

    def to_cyclonedx_vex(self) -> dict[str, Any]:
        """
        Convert to CycloneDX VEX format (vulnerabilities array).

        Returns:
            CycloneDX-compatible vulnerabilities dictionary
        """
        vulnerabilities = []

        for statement in self.statements:
            vuln = statement.vulnerability

            # Map VEX status to CycloneDX analysis state
            state_map = {
                VEXStatus.AFFECTED: "exploitable",
                VEXStatus.NOT_AFFECTED: "not_affected",
                VEXStatus.FIXED: "resolved",
                VEXStatus.UNDER_INVESTIGATION: "in_triage",
            }

            analysis = {
                "state": state_map.get(statement.status, "in_triage"),
            }

            if statement.justification:
                justification_map = {
                    VEXJustification.COMPONENT_NOT_PRESENT: "code_not_present",
                    VEXJustification.VULNERABLE_CODE_NOT_PRESENT: "code_not_present",
                    VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH: "code_not_reachable",
                    VEXJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY: "requires_environment",
                    VEXJustification.INLINE_MITIGATIONS_ALREADY_EXIST: "protected_by_mitigating_control",
                }
                analysis["justification"] = justification_map.get(
                    statement.justification, "requires_environment"
                )

            if statement.impact_statement:
                analysis["detail"] = statement.impact_statement

            cdx_vuln = {
                "id": vuln.id,
                "source": {"name": vuln.source},
                "analysis": analysis,
                "affects": [
                    {"ref": p.sbom_ref or p.purl or p.name}
                    for p in statement.products
                ],
            }

            if vuln.description:
                cdx_vuln["description"] = vuln.description
            if vuln.cvss_score:
                cdx_vuln["ratings"] = [
                    {"score": vuln.cvss_score, "method": "CVSSv3"}
                ]
            if vuln.cwe_ids:
                cdx_vuln["cwes"] = [int(c.replace("CWE-", "")) for c in vuln.cwe_ids if c.startswith("CWE-")]

            vulnerabilities.append(cdx_vuln)

        return {"vulnerabilities": vulnerabilities}

    def to_csaf_vex(self) -> dict[str, Any]:
        """
        Convert to CSAF VEX format.

        Returns:
            CSAF-compatible dictionary
        """
        # Group statements by vulnerability
        vuln_statements: dict[str, list[VEXStatement]] = {}
        for statement in self.statements:
            vuln_id = statement.vulnerability.id
            if vuln_id not in vuln_statements:
                vuln_statements[vuln_id] = []
            vuln_statements[vuln_id].append(statement)

        vulnerabilities = []
        for vuln_id, statements in vuln_statements.items():
            vuln = statements[0].vulnerability

            product_status: dict[str, list[str]] = {
                "known_affected": [],
                "known_not_affected": [],
                "fixed": [],
                "under_investigation": [],
            }

            for s in statements:
                status_key = {
                    VEXStatus.AFFECTED: "known_affected",
                    VEXStatus.NOT_AFFECTED: "known_not_affected",
                    VEXStatus.FIXED: "fixed",
                    VEXStatus.UNDER_INVESTIGATION: "under_investigation",
                }.get(s.status, "under_investigation")

                for p in s.products:
                    product_id = p.purl or f"{p.name}:{p.version or 'any'}"
                    product_status[status_key].append(product_id)

            # Remove empty status lists
            product_status = {k: v for k, v in product_status.items() if v}

            csaf_vuln = {
                "cve": vuln_id if vuln_id.startswith("CVE-") else None,
                "ids": [{"system_name": vuln.source, "text": vuln_id}],
                "product_status": product_status,
            }

            if vuln.description:
                csaf_vuln["notes"] = [
                    {"category": "description", "text": vuln.description}
                ]

            vulnerabilities.append(csaf_vuln)

        return {
            "document": {
                "category": "csaf_vex",
                "title": "VEX Document",
                "publisher": {
                    "category": "tool",
                    "name": self.author,
                },
                "tracking": {
                    "id": self.id,
                    "status": "final",
                    "version": str(self.version),
                    "current_release_date": self.timestamp.isoformat(),
                },
            },
            "vulnerabilities": vulnerabilities,
        }

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary (native format)."""
        return {
            "id": self.id,
            "version": self.version,
            "author": self.author,
            "role": self.role,
            "timestamp": self.timestamp.isoformat(),
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
            "summary": self.summary,
            "statements": [s.to_dict() for s in self.statements],
        }

    def to_json(self, format: str = "openvex") -> str:
        """
        Convert to JSON string.

        Args:
            format: Output format (openvex, cyclonedx, csaf, native)

        Returns:
            JSON string
        """
        if format == "openvex":
            data = self.to_openvex()
        elif format == "cyclonedx":
            data = self.to_cyclonedx_vex()
        elif format == "csaf":
            data = self.to_csaf_vex()
        else:
            data = self.to_dict()

        return json.dumps(data, indent=2)


class VEXGenerator:
    """
    Generates VEX documents from vulnerability scan results.
    """

    def __init__(
        self,
        author: str = "Mantissa Stance",
        role: str = "security-tool",
    ):
        """
        Initialize the VEX generator.

        Args:
            author: Author name for VEX documents
            role: Role of the author
        """
        self.author = author
        self.role = role

    def generate_from_matches(
        self,
        matches: list[VulnerabilityMatch],
        default_status: VEXStatus = VEXStatus.UNDER_INVESTIGATION,
    ) -> VEXDocument:
        """
        Generate a VEX document from vulnerability matches.

        Args:
            matches: List of vulnerability matches
            default_status: Default status for vulnerabilities

        Returns:
            VEXDocument
        """
        doc = VEXDocument(author=self.author, role=self.role)

        for match in matches:
            vuln = VEXVulnerability(
                id=match.vulnerability_id,
                severity=match.severity,
            )

            product = VEXProduct(
                name=match.dependency_name,
                version=match.dependency_version,
            )

            statement = VEXStatement(
                vulnerability=vuln,
                products=[product],
                status=default_status,
            )

            doc.add_statement(statement)

        return doc

    def create_affected_statement(
        self,
        vulnerability: Vulnerability | VEXVulnerability,
        products: list[VEXProduct],
        impact_statement: str | None = None,
        action_statement: str | None = None,
        action_type: ActionType | None = None,
    ) -> VEXStatement:
        """
        Create an AFFECTED status statement.

        Args:
            vulnerability: Vulnerability information
            products: Affected products
            impact_statement: Description of impact
            action_statement: Recommended actions
            action_type: Type of action to take

        Returns:
            VEXStatement
        """
        if isinstance(vulnerability, Vulnerability):
            vuln = VEXVulnerability.from_vulnerability(vulnerability)
        else:
            vuln = vulnerability

        return VEXStatement(
            vulnerability=vuln,
            products=products,
            status=VEXStatus.AFFECTED,
            impact_statement=impact_statement,
            action_statement=action_statement,
            action_type=action_type or ActionType.UPDATE,
        )

    def create_not_affected_statement(
        self,
        vulnerability: Vulnerability | VEXVulnerability,
        products: list[VEXProduct],
        justification: VEXJustification,
        impact_statement: str | None = None,
    ) -> VEXStatement:
        """
        Create a NOT_AFFECTED status statement.

        Args:
            vulnerability: Vulnerability information
            products: Products that are not affected
            justification: Why the product is not affected
            impact_statement: Additional explanation

        Returns:
            VEXStatement
        """
        if isinstance(vulnerability, Vulnerability):
            vuln = VEXVulnerability.from_vulnerability(vulnerability)
        else:
            vuln = vulnerability

        return VEXStatement(
            vulnerability=vuln,
            products=products,
            status=VEXStatus.NOT_AFFECTED,
            justification=justification,
            impact_statement=impact_statement,
        )

    def create_fixed_statement(
        self,
        vulnerability: Vulnerability | VEXVulnerability,
        products: list[VEXProduct],
        action_statement: str | None = None,
    ) -> VEXStatement:
        """
        Create a FIXED status statement.

        Args:
            vulnerability: Vulnerability information
            products: Products that have been fixed
            action_statement: Description of the fix

        Returns:
            VEXStatement
        """
        if isinstance(vulnerability, Vulnerability):
            vuln = VEXVulnerability.from_vulnerability(vulnerability)
        else:
            vuln = vulnerability

        return VEXStatement(
            vulnerability=vuln,
            products=products,
            status=VEXStatus.FIXED,
            action_statement=action_statement,
            action_type=ActionType.UPDATE,
        )


class VEXParser:
    """
    Parses VEX documents from various formats.
    """

    def parse_openvex(self, data: dict[str, Any]) -> VEXDocument:
        """
        Parse an OpenVEX document.

        Args:
            data: OpenVEX JSON data

        Returns:
            VEXDocument
        """
        doc = VEXDocument(
            id=data.get("@id", ""),
            author=data.get("author", "unknown"),
            role=data.get("role", "unknown"),
            version=data.get("version", 1),
        )

        if "timestamp" in data:
            try:
                ts = data["timestamp"].replace("Z", "+00:00")
                doc.timestamp = datetime.fromisoformat(ts)
            except (ValueError, TypeError):
                pass

        for stmt_data in data.get("statements", []):
            statement = self._parse_openvex_statement(stmt_data)
            if statement:
                doc.add_statement(statement)

        return doc

    def _parse_openvex_statement(self, data: dict[str, Any]) -> VEXStatement | None:
        """Parse a single OpenVEX statement."""
        vuln_data = data.get("vulnerability", {})
        if isinstance(vuln_data, str):
            vuln = VEXVulnerability(id=vuln_data)
        else:
            vuln = VEXVulnerability(
                id=vuln_data.get("id", vuln_data.get("name", "")),
                description=vuln_data.get("description"),
            )

        products = []
        for p_data in data.get("products", []):
            if isinstance(p_data, str):
                products.append(VEXProduct(name=p_data))
            else:
                products.append(
                    VEXProduct(
                        name=p_data.get("name", p_data.get("@id", "")),
                        version=p_data.get("version"),
                        purl=p_data.get("purl"),
                    )
                )

        status_str = data.get("status", "under_investigation")
        try:
            status = VEXStatus(status_str)
        except ValueError:
            status = VEXStatus.UNDER_INVESTIGATION

        justification = None
        if "justification" in data:
            try:
                justification = VEXJustification(data["justification"])
            except ValueError:
                pass

        return VEXStatement(
            vulnerability=vuln,
            products=products,
            status=status,
            justification=justification,
            impact_statement=data.get("impact_statement"),
            action_statement=data.get("action_statement"),
            statement_id=data.get("statement_id", ""),
        )

    def parse_json(self, json_str: str, format: str = "openvex") -> VEXDocument:
        """
        Parse a VEX document from JSON string.

        Args:
            json_str: JSON string
            format: Format hint (openvex, cyclonedx, csaf)

        Returns:
            VEXDocument
        """
        data = json.loads(json_str)

        if format == "openvex" or "@context" in data:
            return self.parse_openvex(data)

        # Default to native format
        doc = VEXDocument(
            id=data.get("id", ""),
            author=data.get("author", "unknown"),
            version=data.get("version", 1),
        )

        for stmt_data in data.get("statements", []):
            statement = self._parse_openvex_statement(stmt_data)
            if statement:
                doc.add_statement(statement)

        return doc


def create_vex_document(
    vulnerability_matches: list[VulnerabilityMatch],
    author: str = "Mantissa Stance",
) -> VEXDocument:
    """
    Convenience function to create a VEX document from vulnerability matches.

    Args:
        vulnerability_matches: List of vulnerability matches from scanning
        author: Author name

    Returns:
        VEXDocument
    """
    generator = VEXGenerator(author=author)
    return generator.generate_from_matches(vulnerability_matches)
