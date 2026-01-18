"""
ASM finding types for Mantissa Stance.

This module defines ASM-specific finding types and provides factory
functions for creating findings that integrate with the existing
Finding model and alerting system.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from stance.models.finding import Finding, FindingStatus, FindingType, Severity
from stance.asm.models import ExternalAsset


class ASMFindingType(Enum):
    """
    Types of ASM-specific findings.

    These represent security issues discovered through external
    attack surface reconnaissance.
    """

    # Shadow IT - Asset visibility issues
    SHADOW_IT = "shadow_it"  # Asset not in CSPM inventory
    NEW_ASSET = "new_asset"  # Previously unknown asset discovered

    # Certificate issues
    EXPIRED_CERTIFICATE = "expired_certificate"  # Certificate past expiration
    EXPIRING_CERTIFICATE = "expiring_certificate"  # Certificate expiring within 30 days
    WEAK_CERTIFICATE = "weak_certificate"  # Weak algorithm or key size
    SELF_SIGNED_CERTIFICATE = "self_signed_certificate"  # Self-signed cert in production

    # DNS issues
    DANGLING_DNS = "dangling_dns"  # DNS record pointing to non-existent resource
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"  # Vulnerable to subdomain takeover
    MISSING_SPF = "missing_spf"  # Missing SPF record
    MISSING_DMARC = "missing_dmarc"  # Missing DMARC record

    # Exposed services
    EXPOSED_SERVICE = "exposed_service"  # Sensitive service exposed to internet
    UNENCRYPTED_SERVICE = "unencrypted_service"  # Service without TLS on internet
    EXPOSED_DATABASE = "exposed_database"  # Database port exposed
    EXPOSED_ADMIN = "exposed_admin"  # Admin interface exposed
    EXPOSED_DEV_ENVIRONMENT = "exposed_dev_environment"  # Dev/staging exposed

    # Technology vulnerabilities
    TECHNOLOGY_VULNERABILITY = "technology_vulnerability"  # Known vulnerable version
    OUTDATED_SOFTWARE = "outdated_software"  # Software version is outdated

    # Cloud and network issues
    CLOUD_IP_MISMATCH = "cloud_ip_mismatch"  # IP in unexpected cloud provider range
    UNEXPECTED_CLOUD = "unexpected_cloud"  # Asset in unexpected cloud provider

    # Change detection
    PORT_CHANGE = "port_change"  # New port detected since last scan
    SERVICE_CHANGE = "service_change"  # Service changed since last scan
    CERTIFICATE_CHANGE = "certificate_change"  # Certificate changed


# Default severity for each finding type
ASM_FINDING_SEVERITY_MAP: dict[ASMFindingType, Severity] = {
    # Critical - Immediate action required
    ASMFindingType.EXPIRED_CERTIFICATE: Severity.CRITICAL,
    ASMFindingType.SUBDOMAIN_TAKEOVER: Severity.CRITICAL,
    ASMFindingType.EXPOSED_DATABASE: Severity.CRITICAL,

    # High - Important security issue
    ASMFindingType.SHADOW_IT: Severity.HIGH,
    ASMFindingType.EXPIRING_CERTIFICATE: Severity.HIGH,
    ASMFindingType.WEAK_CERTIFICATE: Severity.HIGH,
    ASMFindingType.DANGLING_DNS: Severity.HIGH,
    ASMFindingType.EXPOSED_SERVICE: Severity.HIGH,
    ASMFindingType.EXPOSED_ADMIN: Severity.HIGH,
    ASMFindingType.TECHNOLOGY_VULNERABILITY: Severity.HIGH,

    # Medium - Should be addressed
    ASMFindingType.SELF_SIGNED_CERTIFICATE: Severity.MEDIUM,
    ASMFindingType.UNENCRYPTED_SERVICE: Severity.MEDIUM,
    ASMFindingType.EXPOSED_DEV_ENVIRONMENT: Severity.MEDIUM,
    ASMFindingType.CLOUD_IP_MISMATCH: Severity.MEDIUM,
    ASMFindingType.UNEXPECTED_CLOUD: Severity.MEDIUM,
    ASMFindingType.MISSING_SPF: Severity.MEDIUM,
    ASMFindingType.MISSING_DMARC: Severity.MEDIUM,

    # Low - Informational or minor issues
    ASMFindingType.OUTDATED_SOFTWARE: Severity.LOW,
    ASMFindingType.SERVICE_CHANGE: Severity.LOW,

    # Info - Awareness only
    ASMFindingType.NEW_ASSET: Severity.INFO,
    ASMFindingType.PORT_CHANGE: Severity.INFO,
    ASMFindingType.CERTIFICATE_CHANGE: Severity.INFO,
}


# Remediation guidance for each finding type
ASM_FINDING_REMEDIATION_MAP: dict[ASMFindingType, str] = {
    ASMFindingType.SHADOW_IT: """
1. Identify the owner of this external asset
2. Determine if this asset should exist and be publicly accessible
3. If legitimate, add it to your CSPM inventory for proper monitoring
4. If not legitimate, investigate and potentially decommission
5. Update asset management processes to prevent future shadow IT
""".strip(),

    ASMFindingType.NEW_ASSET: """
1. Verify this is an expected/authorized asset
2. Ensure proper security controls are in place
3. Add to inventory and monitoring systems
4. Document the purpose and owner of this asset
""".strip(),

    ASMFindingType.EXPIRED_CERTIFICATE: """
1. IMMEDIATE: Renew or replace the expired certificate
2. Verify the new certificate is properly installed
3. Test connectivity to ensure services are working
4. Set up certificate expiration monitoring/alerting
5. Consider using automated certificate management (ACME/Let's Encrypt)
""".strip(),

    ASMFindingType.EXPIRING_CERTIFICATE: """
1. Initiate certificate renewal process before expiration
2. Verify the renewal is complete and certificate is installed
3. Test the new certificate in a staging environment if possible
4. Update any pinned certificates in client applications
5. Document the renewal in your certificate inventory
""".strip(),

    ASMFindingType.WEAK_CERTIFICATE: """
1. Generate a new certificate with strong parameters:
   - Use RSA 2048-bit or higher, or ECDSA 256-bit or higher
   - Use SHA-256 or stronger hash algorithm
2. Replace the current certificate with the new one
3. Update server configuration to prefer strong cipher suites
4. Test with SSL Labs or similar tool to verify configuration
""".strip(),

    ASMFindingType.SELF_SIGNED_CERTIFICATE: """
1. Obtain a certificate from a trusted Certificate Authority
2. For internal services, consider using an internal CA
3. Replace the self-signed certificate
4. Update any certificate pinning in client applications
5. For development environments, document the exception
""".strip(),

    ASMFindingType.DANGLING_DNS: """
1. Identify the DNS record pointing to the non-existent resource
2. Determine if the record should be removed or updated
3. If the target resource was decommissioned, delete the DNS record
4. If the target should exist, recreate or reconfigure it
5. Implement DNS record lifecycle management processes
""".strip(),

    ASMFindingType.SUBDOMAIN_TAKEOVER: """
1. IMMEDIATE: This is a critical vulnerability - act now
2. Either delete the DNS record or reclaim the underlying resource
3. For cloud services: recreate the resource with the same name
4. For third-party services: re-register or contact support
5. Audit all DNS records for similar vulnerabilities
6. Implement monitoring for dangling DNS records
""".strip(),

    ASMFindingType.EXPOSED_SERVICE: """
1. Evaluate if this service needs to be publicly accessible
2. If not required publicly, restrict access via:
   - Network security groups/firewall rules
   - VPN or private connectivity
3. If public access is required:
   - Implement strong authentication
   - Enable encryption (TLS)
   - Add rate limiting and monitoring
4. Document the business justification for public exposure
""".strip(),

    ASMFindingType.UNENCRYPTED_SERVICE: """
1. Enable TLS/SSL encryption on the service
2. Obtain and install appropriate certificates
3. Redirect HTTP to HTTPS where applicable
4. Configure HSTS headers for web services
5. Disable older protocol versions (SSLv3, TLS 1.0, 1.1)
6. Test encryption configuration with security scanning tools
""".strip(),

    ASMFindingType.EXPOSED_DATABASE: """
1. IMMEDIATE: Database ports should not be publicly accessible
2. Restrict access to authorized IP addresses only
3. Use VPN or private connectivity for database access
4. If cloud-hosted, use private endpoints or VPC peering
5. Ensure strong authentication is enabled
6. Enable audit logging for database access
7. Consider using a database proxy for added security
""".strip(),

    ASMFindingType.EXPOSED_ADMIN: """
1. Restrict admin interface access to internal networks or VPN
2. Implement multi-factor authentication
3. Use IP allowlisting for admin access
4. Enable comprehensive audit logging
5. Consider using a jump host or bastion for admin access
6. Regularly rotate admin credentials
""".strip(),

    ASMFindingType.EXPOSED_DEV_ENVIRONMENT: """
1. Development/staging environments should not be publicly accessible
2. Move behind VPN or restrict to internal network
3. If temporary public access is needed, use:
   - Strong authentication
   - IP allowlisting
   - Time-limited access
4. Ensure dev environment doesn't contain production data
5. Remove or restrict access after testing is complete
""".strip(),

    ASMFindingType.TECHNOLOGY_VULNERABILITY: """
1. Identify the specific CVE(s) affecting this technology
2. Check vendor advisory for patches or mitigations
3. Plan and execute upgrade to patched version
4. If immediate patching isn't possible, implement mitigations:
   - Web Application Firewall rules
   - Network segmentation
   - Disable vulnerable features
5. Monitor for exploitation attempts
""".strip(),

    ASMFindingType.OUTDATED_SOFTWARE: """
1. Review changelog for security fixes in newer versions
2. Plan upgrade to current supported version
3. Test upgrade in non-production environment
4. Deploy update following change management processes
5. Implement automated update mechanisms where appropriate
""".strip(),

    ASMFindingType.CLOUD_IP_MISMATCH: """
1. Verify the asset is hosted in the expected cloud provider
2. If unexpected, investigate how this occurred
3. Update inventory records with correct cloud provider
4. Review cloud account configurations and permissions
5. Ensure consistent deployment practices
""".strip(),

    ASMFindingType.UNEXPECTED_CLOUD: """
1. Determine if this cloud provider is sanctioned for use
2. If not sanctioned, investigate who provisioned the resource
3. Review cloud governance policies
4. Either migrate to approved cloud or document exception
5. Update asset inventory and monitoring
""".strip(),

    ASMFindingType.MISSING_SPF: """
1. Create an SPF TXT record for your domain
2. Include all authorized mail servers/services
3. Use "-all" or "~all" to indicate policy strictness
4. Test SPF record with online validation tools
5. Monitor for SPF failures in email delivery
""".strip(),

    ASMFindingType.MISSING_DMARC: """
1. Create a DMARC TXT record (_dmarc.yourdomain.com)
2. Start with p=none to monitor without enforcement
3. Configure rua/ruf for aggregate/forensic reports
4. Gradually move to p=quarantine then p=reject
5. Monitor DMARC reports and adjust policy as needed
""".strip(),

    ASMFindingType.PORT_CHANGE: """
1. Review if this port change was expected/authorized
2. If unexpected, investigate the cause
3. Verify the service on this port is properly configured
4. Update firewall rules if necessary
5. Update documentation and monitoring
""".strip(),

    ASMFindingType.SERVICE_CHANGE: """
1. Verify if this service change was planned
2. If unexpected, investigate root cause
3. Ensure new service is properly secured
4. Update monitoring and alerting configurations
5. Document the change in configuration management
""".strip(),

    ASMFindingType.CERTIFICATE_CHANGE: """
1. Verify the certificate change was authorized
2. Check the new certificate's validity and configuration
3. Update certificate pinning if used
4. Document the change in certificate inventory
5. Verify no security downgrade occurred
""".strip(),
}


def create_asm_finding(
    asset: ExternalAsset,
    finding_type: ASMFindingType,
    title: str,
    description: str,
    severity: Severity | None = None,
    additional_data: dict[str, Any] | None = None,
) -> Finding:
    """
    Create a Finding object for an ASM issue.

    This factory function creates a standard Finding that integrates with
    the existing alerting and storage systems while preserving ASM-specific
    context in metadata.

    Args:
        asset: The ExternalAsset this finding relates to
        finding_type: Type of ASM finding
        title: Short title for the finding
        description: Detailed description of the issue
        severity: Severity level (defaults to type-specific default)
        additional_data: Extra data to include in finding

    Returns:
        Finding object ready for storage and alerting
    """
    # Use default severity for this finding type if not specified
    if severity is None:
        severity = ASM_FINDING_SEVERITY_MAP.get(finding_type, Severity.MEDIUM)

    # Get remediation guidance
    remediation = ASM_FINDING_REMEDIATION_MAP.get(finding_type, "")

    # Generate unique finding ID based on asset and finding type
    id_components = [asset.id, finding_type.value]
    finding_id = hashlib.sha256(":".join(id_components).encode()).hexdigest()[:16]
    finding_id = f"asm-{finding_id}"

    # Build rule ID for tracking
    rule_id = f"asm-{finding_type.value}"

    # Create the finding
    now = datetime.now(timezone.utc)

    return Finding(
        id=finding_id,
        asset_id=asset.id,
        finding_type=FindingType.MISCONFIGURATION,
        severity=severity,
        status=FindingStatus.OPEN,
        title=title,
        description=description,
        first_seen=now,
        last_seen=now,
        rule_id=rule_id,
        resource_path=f"external_asset.{finding_type.value}",
        expected_value=_get_expected_value(finding_type),
        actual_value=_get_actual_value(asset, finding_type, additional_data),
        remediation_guidance=remediation,
        compliance_frameworks=_get_compliance_frameworks(finding_type),
    )


def _get_expected_value(finding_type: ASMFindingType) -> str:
    """Get the expected value description for a finding type."""
    expected_values = {
        ASMFindingType.SHADOW_IT: "Asset present in CSPM inventory",
        ASMFindingType.EXPIRED_CERTIFICATE: "Valid, non-expired certificate",
        ASMFindingType.EXPIRING_CERTIFICATE: "Certificate valid for >30 days",
        ASMFindingType.WEAK_CERTIFICATE: "RSA >=2048 bits or ECDSA >=256 bits, SHA-256+",
        ASMFindingType.SELF_SIGNED_CERTIFICATE: "Certificate from trusted CA",
        ASMFindingType.DANGLING_DNS: "DNS record pointing to active resource",
        ASMFindingType.SUBDOMAIN_TAKEOVER: "DNS record pointing to controlled resource",
        ASMFindingType.EXPOSED_SERVICE: "Service restricted to authorized networks",
        ASMFindingType.UNENCRYPTED_SERVICE: "Service using TLS encryption",
        ASMFindingType.EXPOSED_DATABASE: "Database not publicly accessible",
        ASMFindingType.EXPOSED_ADMIN: "Admin interface restricted to internal network",
        ASMFindingType.EXPOSED_DEV_ENVIRONMENT: "Dev environment not publicly accessible",
        ASMFindingType.TECHNOLOGY_VULNERABILITY: "No known vulnerabilities",
        ASMFindingType.MISSING_SPF: "SPF record configured",
        ASMFindingType.MISSING_DMARC: "DMARC record configured",
    }
    return expected_values.get(finding_type, "Secure configuration")


def _get_actual_value(
    asset: ExternalAsset,
    finding_type: ASMFindingType,
    additional_data: dict[str, Any] | None,
) -> str:
    """Get the actual value description for a finding."""
    if additional_data and "actual_value" in additional_data:
        return str(additional_data["actual_value"])

    if finding_type == ASMFindingType.EXPIRED_CERTIFICATE:
        if asset.certificate_info:
            return f"Certificate expired on {asset.certificate_info.not_after.isoformat()}"
        return "Expired certificate"

    if finding_type == ASMFindingType.EXPIRING_CERTIFICATE:
        if asset.certificate_info:
            days = asset.certificate_info.days_until_expiry
            return f"Certificate expires in {days} days"
        return "Certificate expiring soon"

    if finding_type == ASMFindingType.WEAK_CERTIFICATE:
        if asset.certificate_info:
            return f"{asset.certificate_info.key_algorithm} {asset.certificate_info.key_size} bits"
        return "Weak certificate configuration"

    if finding_type == ASMFindingType.SELF_SIGNED_CERTIFICATE:
        return "Self-signed certificate"

    if finding_type == ASMFindingType.EXPOSED_DATABASE:
        return f"Database port {asset.port} publicly accessible"

    if finding_type == ASMFindingType.EXPOSED_SERVICE:
        return f"Service on port {asset.port} publicly accessible"

    if finding_type == ASMFindingType.SHADOW_IT:
        return f"Asset {asset.domain} not found in CSPM inventory"

    return "Non-compliant configuration"


def _get_compliance_frameworks(finding_type: ASMFindingType) -> list[str]:
    """Get relevant compliance frameworks for a finding type."""
    # Map finding types to relevant compliance controls
    compliance_map: dict[ASMFindingType, list[str]] = {
        ASMFindingType.EXPIRED_CERTIFICATE: [
            "CIS Controls 3.10 - Encrypt Sensitive Data in Transit",
            "PCI-DSS 4.1 - Use strong cryptography and security protocols",
        ],
        ASMFindingType.WEAK_CERTIFICATE: [
            "CIS Controls 3.10 - Encrypt Sensitive Data in Transit",
            "PCI-DSS 4.1 - Use strong cryptography and security protocols",
            "NIST 800-53 SC-13 - Cryptographic Protection",
        ],
        ASMFindingType.EXPOSED_DATABASE: [
            "CIS Controls 12.1 - Maintain an Inventory of Network Boundaries",
            "PCI-DSS 1.3 - Prohibit direct public access to DMZ",
            "NIST 800-53 SC-7 - Boundary Protection",
        ],
        ASMFindingType.UNENCRYPTED_SERVICE: [
            "CIS Controls 3.10 - Encrypt Sensitive Data in Transit",
            "PCI-DSS 4.1 - Use strong cryptography",
            "HIPAA 164.312(e)(1) - Transmission Security",
        ],
        ASMFindingType.SHADOW_IT: [
            "CIS Controls 1.1 - Maintain Inventory of Enterprise Assets",
            "NIST 800-53 CM-8 - Information System Component Inventory",
        ],
        ASMFindingType.MISSING_SPF: [
            "DMARC/Email Security Best Practices",
        ],
        ASMFindingType.MISSING_DMARC: [
            "DMARC/Email Security Best Practices",
            "NIST 800-177 - Trustworthy Email",
        ],
    }
    return compliance_map.get(finding_type, [])


def create_certificate_finding(
    asset: ExternalAsset,
    issue_type: str,
) -> Finding | None:
    """
    Create a finding for certificate-related issues.

    Automatically detects the issue type based on certificate info.

    Args:
        asset: ExternalAsset with certificate_info
        issue_type: Type of certificate issue (expired, expiring, weak, self_signed)

    Returns:
        Finding if issue detected, None otherwise
    """
    if not asset.certificate_info:
        return None

    cert = asset.certificate_info

    if issue_type == "expired" and cert.is_expired:
        return create_asm_finding(
            asset=asset,
            finding_type=ASMFindingType.EXPIRED_CERTIFICATE,
            title=f"Expired SSL certificate on {asset.domain}",
            description=(
                f"The SSL/TLS certificate for {asset.domain} expired on "
                f"{cert.not_after.strftime('%Y-%m-%d')}. Expired certificates "
                f"cause browser warnings and may indicate abandoned or poorly "
                f"maintained infrastructure."
            ),
        )

    if issue_type == "expiring" and cert.is_expiring_soon and not cert.is_expired:
        return create_asm_finding(
            asset=asset,
            finding_type=ASMFindingType.EXPIRING_CERTIFICATE,
            title=f"SSL certificate expiring soon on {asset.domain}",
            description=(
                f"The SSL/TLS certificate for {asset.domain} expires in "
                f"{cert.days_until_expiry} days ({cert.not_after.strftime('%Y-%m-%d')}). "
                f"Renew the certificate before expiration to avoid service disruption."
            ),
        )

    if issue_type == "weak" and cert.is_weak_key:
        return create_asm_finding(
            asset=asset,
            finding_type=ASMFindingType.WEAK_CERTIFICATE,
            title=f"Weak SSL certificate on {asset.domain}",
            description=(
                f"The SSL/TLS certificate for {asset.domain} uses a weak key: "
                f"{cert.key_algorithm} {cert.key_size} bits. Modern security "
                f"standards require RSA 2048+ bits or ECDSA 256+ bits."
            ),
        )

    if issue_type == "self_signed" and cert.is_self_signed:
        return create_asm_finding(
            asset=asset,
            finding_type=ASMFindingType.SELF_SIGNED_CERTIFICATE,
            title=f"Self-signed certificate on {asset.domain}",
            description=(
                f"The SSL/TLS certificate for {asset.domain} is self-signed. "
                f"Self-signed certificates are not trusted by browsers and may "
                f"indicate a test/development environment or misconfiguration."
            ),
        )

    return None


def create_exposure_finding(
    asset: ExternalAsset,
    service_type: str,
) -> Finding:
    """
    Create a finding for exposed service.

    Args:
        asset: ExternalAsset representing the exposed service
        service_type: Type of service (database, admin, ssh, rdp, etc.)

    Returns:
        Finding for the exposed service
    """
    service_descriptions = {
        "database": (
            ASMFindingType.EXPOSED_DATABASE,
            f"Database exposed on {asset.domain}:{asset.port}",
            f"A database service ({asset.service or 'unknown'}) is publicly "
            f"accessible on {asset.domain} port {asset.port}. Database services "
            f"should never be directly exposed to the internet.",
        ),
        "admin": (
            ASMFindingType.EXPOSED_ADMIN,
            f"Admin interface exposed on {asset.domain}",
            f"An administrative interface is publicly accessible on {asset.domain}. "
            f"Admin interfaces should be restricted to internal networks or VPN.",
        ),
        "ssh": (
            ASMFindingType.EXPOSED_SERVICE,
            f"SSH exposed on {asset.domain}:{asset.port}",
            f"SSH service is publicly accessible on {asset.domain} port {asset.port}. "
            f"Consider restricting SSH access to specific IP ranges or using a bastion host.",
        ),
        "rdp": (
            ASMFindingType.EXPOSED_SERVICE,
            f"RDP exposed on {asset.domain}:{asset.port}",
            f"Remote Desktop Protocol (RDP) is publicly accessible on {asset.domain}. "
            f"RDP is a common attack vector and should be restricted or disabled.",
        ),
        "dev": (
            ASMFindingType.EXPOSED_DEV_ENVIRONMENT,
            f"Development environment exposed on {asset.domain}",
            f"A development or staging environment appears to be publicly accessible "
            f"on {asset.domain}. Dev environments may contain sensitive data or "
            f"have reduced security controls.",
        ),
    }

    finding_type, title, description = service_descriptions.get(
        service_type,
        (
            ASMFindingType.EXPOSED_SERVICE,
            f"Service exposed on {asset.domain}:{asset.port}",
            f"A service is publicly accessible on {asset.domain} port {asset.port}.",
        ),
    )

    return create_asm_finding(
        asset=asset,
        finding_type=finding_type,
        title=title,
        description=description,
    )
