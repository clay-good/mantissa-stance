"""
ASM collectors for Mantissa Stance.

This module provides collectors for external attack surface discovery:
- CertTransparencyCollector: Certificate Transparency log monitoring
- PassiveDNSCollector: DNS enumeration and resolution
- CloudIPRangeCollector: Cloud provider IP range detection
- TechnologyFingerprinter: Technology stack detection
- PortScanner: TCP port scanning (requires ownership verification)
- SubdomainBruteforcer: DNS brute-forcing (requires ownership verification)

Passive collectors (safe for any domain):
- cert_transparency
- passive_dns
- cloud_ip_ranges
- technology

Active collectors (require ownership verification):
- port_scanner
- subdomain_bruteforce
"""

from stance.asm.collectors.cert_transparency import (
    CertTransparencyCollector,
    CertTransparencyResult,
)
from stance.asm.collectors.passive_dns import (
    PassiveDNSCollector,
    DNSRecord,
    DNSResult,
)
from stance.asm.collectors.cloud_ip_ranges import (
    CloudIPRangeCollector,
    IPRange,
    IPLookupResult,
)
from stance.asm.collectors.technology import (
    TechnologyFingerprinter,
    TechnologyFingerprint,
    FingerprintResult,
)
from stance.asm.collectors.port_scanner import (
    PortScanner,
    OpenPort,
    PortScanResult,
    PortScanAuditEntry,
    OwnershipVerificationRequired,
    OwnershipVerificationFailed,
)
from stance.asm.collectors.subdomain_bruteforce import (
    SubdomainBruteforcer,
    SubdomainResult,
    BruteforceAuditEntry,
)

__all__ = [
    # Passive Collectors
    "CertTransparencyCollector",
    "PassiveDNSCollector",
    "CloudIPRangeCollector",
    "TechnologyFingerprinter",
    # Active Collectors
    "PortScanner",
    "SubdomainBruteforcer",
    # Passive Result types
    "CertTransparencyResult",
    "DNSRecord",
    "DNSResult",
    "IPRange",
    "IPLookupResult",
    "TechnologyFingerprint",
    "FingerprintResult",
    # Active Result types
    "OpenPort",
    "PortScanResult",
    "PortScanAuditEntry",
    "SubdomainResult",
    "BruteforceAuditEntry",
    # Exceptions
    "OwnershipVerificationRequired",
    "OwnershipVerificationFailed",
]

# Registry of available collectors
COLLECTOR_REGISTRY = {
    # Passive collectors
    "cert_transparency": CertTransparencyCollector,
    "passive_dns": PassiveDNSCollector,
    "cloud_ip_ranges": CloudIPRangeCollector,
    "technology": TechnologyFingerprinter,
    # Active collectors
    "port_scanner": PortScanner,
    "subdomain_bruteforce": SubdomainBruteforcer,
}

# Passive collectors (safe for any domain)
PASSIVE_COLLECTORS = [
    "cert_transparency",
    "passive_dns",
    "cloud_ip_ranges",
    "technology",
]

# Active collectors (require ownership verification)
ACTIVE_COLLECTORS = [
    "port_scanner",
    "subdomain_bruteforce",
]
