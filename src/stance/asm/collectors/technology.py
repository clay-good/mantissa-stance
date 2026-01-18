"""
Technology fingerprinting collector for ASM.

This module performs passive technology detection by analyzing:
- HTTP response headers (Server, X-Powered-By, etc.)
- SSL/TLS certificate patterns
- Common technology signatures

This helps identify:
- Web server software and versions
- Application frameworks
- CDN and proxy services
- Potentially vulnerable software versions
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from stance.asm.config import ASMConfiguration
from stance.asm.models import (
    CertificateInfo,
    ExternalAsset,
    ExternalAssetCollection,
)

logger = logging.getLogger(__name__)


# HTTP headers that reveal technology information
FINGERPRINT_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-drupal-cache",
    "x-generator",
    "x-shopify-stage",
    "x-wix-request-id",
    "x-squarespace-vary",
    "via",
    "x-cache",
    "x-served-by",
    "x-amz-cf-id",
    "x-azure-ref",
    "cf-ray",
    "x-vercel-id",
    "x-netlify-request-id",
]

# Server header patterns for technology detection
SERVER_PATTERNS = {
    r"nginx/?(\d+[\.\d]*)?\s*": ("nginx", "web_server"),
    r"Apache/?(\d+[\.\d]*)?\s*": ("Apache", "web_server"),
    r"Microsoft-IIS/?(\d+[\.\d]*)?\s*": ("IIS", "web_server"),
    r"openresty/?(\d+[\.\d]*)?\s*": ("OpenResty", "web_server"),
    r"LiteSpeed": ("LiteSpeed", "web_server"),
    r"cloudflare": ("Cloudflare", "cdn"),
    r"AmazonS3": ("Amazon S3", "storage"),
    r"AkamaiGHost": ("Akamai", "cdn"),
    r"Varnish": ("Varnish", "cache"),
    r"gunicorn/?(\d+[\.\d]*)?\s*": ("Gunicorn", "app_server"),
    r"uvicorn": ("Uvicorn", "app_server"),
    r"Werkzeug/?(\d+[\.\d]*)?\s*": ("Werkzeug", "framework"),
    r"Express": ("Express.js", "framework"),
    r"Kestrel": ("Kestrel", "app_server"),
    r"Tomcat/?(\d+[\.\d]*)?\s*": ("Tomcat", "app_server"),
    r"Jetty": ("Jetty", "app_server"),
    r"WEBrick": ("WEBrick", "app_server"),
    r"Cowboy": ("Cowboy", "app_server"),
    r"Tengine": ("Tengine", "web_server"),
    r"Caddy": ("Caddy", "web_server"),
    r"HAProxy": ("HAProxy", "load_balancer"),
}

# X-Powered-By patterns
POWERED_BY_PATTERNS = {
    r"PHP/?(\d+[\.\d]*)?\s*": ("PHP", "language"),
    r"ASP\.NET": ("ASP.NET", "framework"),
    r"Express": ("Express.js", "framework"),
    r"Next\.js": ("Next.js", "framework"),
    r"Nuxt": ("Nuxt.js", "framework"),
    r"Django": ("Django", "framework"),
    r"Flask": ("Flask", "framework"),
    r"Rails": ("Ruby on Rails", "framework"),
    r"Phusion Passenger": ("Passenger", "app_server"),
    r"Servlet/?(\d+[\.\d]*)?\s*": ("Java Servlet", "framework"),
    r"JSP/?(\d+[\.\d]*)?\s*": ("JSP", "framework"),
    r"JBoss": ("JBoss", "app_server"),
    r"ColdFusion": ("ColdFusion", "framework"),
    r"Perl": ("Perl", "language"),
    r"Python": ("Python", "language"),
}

# Certificate issuer patterns for service detection
CERT_ISSUER_PATTERNS = {
    r"Let's Encrypt": ("Let's Encrypt", "ca"),
    r"DigiCert": ("DigiCert", "ca"),
    r"Comodo": ("Comodo", "ca"),
    r"Sectigo": ("Sectigo", "ca"),
    r"GlobalSign": ("GlobalSign", "ca"),
    r"GoDaddy": ("GoDaddy", "ca"),
    r"Amazon": ("AWS ACM", "ca"),
    r"Google Trust Services": ("Google Trust Services", "ca"),
    r"Microsoft": ("Microsoft", "ca"),
    r"Cloudflare": ("Cloudflare", "cdn"),
    r"Fastly": ("Fastly", "cdn"),
}


@dataclass
class TechnologyFingerprint:
    """Detected technology information."""

    name: str
    category: str  # web_server, framework, language, cdn, etc.
    version: str | None = None
    confidence: float = 1.0  # 0.0 to 1.0
    source: str = "header"  # header, certificate, response


@dataclass
class FingerprintResult:
    """Result of technology fingerprinting."""

    domain: str
    port: int
    technologies: list[TechnologyFingerprint] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    certificate_issuer: str | None = None
    response_code: int | None = None
    errors: list[str] = field(default_factory=list)
    scan_time_seconds: float = 0.0


class TechnologyFingerprinter:
    """
    Collector that detects technologies through passive fingerprinting.

    Analyzes HTTP headers and certificates to identify server software,
    frameworks, and other technologies.

    Attributes:
        config: ASM configuration
    """

    collector_name = "technology"

    def __init__(self, config: ASMConfiguration | None = None) -> None:
        """
        Initialize the Technology Fingerprinter.

        Args:
            config: Optional ASM configuration
        """
        self._config = config or ASMConfiguration()

    @property
    def config(self) -> ASMConfiguration:
        """Get the ASM configuration."""
        return self._config

    def fingerprint(
        self,
        domain: str,
        port: int = 443,
    ) -> FingerprintResult:
        """
        Fingerprint a domain/port for technology detection.

        Args:
            domain: Domain to fingerprint
            port: Port to connect to (default: 443)

        Returns:
            FingerprintResult with detected technologies
        """
        result = FingerprintResult(domain=domain, port=port)
        start_time = time.time()

        # Determine protocol
        protocol = "https" if port == 443 else "http"
        if port in (443, 8443):
            protocol = "https"

        url = f"{protocol}://{domain}"
        if port not in (80, 443):
            url = f"{protocol}://{domain}:{port}"

        try:
            # Fetch headers
            headers = self._fetch_headers(url)
            result.headers = headers

            # Detect technologies from headers
            technologies = self._analyze_headers(headers)
            result.technologies.extend(technologies)

            # For HTTPS, also check certificate
            if protocol == "https":
                cert_tech = self._analyze_certificate(domain, port)
                result.technologies.extend(cert_tech)

                # Store certificate issuer
                if cert_tech:
                    for tech in cert_tech:
                        if tech.category == "ca":
                            result.certificate_issuer = tech.name

        except Exception as e:
            result.errors.append(str(e))
            logger.debug(f"Fingerprinting failed for {domain}:{port}: {e}")

        result.scan_time_seconds = time.time() - start_time

        # Deduplicate technologies
        result.technologies = self._deduplicate_technologies(result.technologies)

        return result

    def fingerprint_certificate(
        self,
        cert: CertificateInfo,
    ) -> list[TechnologyFingerprint]:
        """
        Detect technologies from certificate information.

        Args:
            cert: Certificate information

        Returns:
            List of detected technologies
        """
        technologies: list[TechnologyFingerprint] = []

        # Check issuer
        for pattern, (name, category) in CERT_ISSUER_PATTERNS.items():
            if re.search(pattern, cert.issuer, re.IGNORECASE):
                technologies.append(
                    TechnologyFingerprint(
                        name=name,
                        category=category,
                        source="certificate",
                    )
                )
                break

        return technologies

    def enrich_assets(
        self,
        assets: ExternalAssetCollection,
    ) -> ExternalAssetCollection:
        """
        Enrich assets with technology fingerprinting.

        Args:
            assets: Collection of assets to enrich

        Returns:
            New collection with technology data added
        """
        enriched: list[ExternalAsset] = []

        for asset in assets:
            # Only fingerprint web services
            if not self._should_fingerprint(asset):
                enriched.append(asset)
                continue

            port = asset.port or 443
            result = self.fingerprint(asset.domain, port)

            if result.technologies:
                tech_names = tuple(t.name for t in result.technologies)

                # Merge with existing technology stack
                existing = set(asset.technology_stack)
                combined = existing.union(set(tech_names))

                new_raw_data = dict(asset.raw_data)
                new_raw_data["fingerprint"] = {
                    "technologies": [
                        {
                            "name": t.name,
                            "category": t.category,
                            "version": t.version,
                            "source": t.source,
                        }
                        for t in result.technologies
                    ],
                    "headers": result.headers,
                    "scan_time": result.scan_time_seconds,
                }

                enriched_asset = ExternalAsset(
                    id=asset.id,
                    domain=asset.domain,
                    ip_address=asset.ip_address,
                    port=asset.port,
                    protocol=asset.protocol,
                    service=asset.service,
                    technology_stack=tuple(sorted(combined)),
                    cloud_provider=asset.cloud_provider,
                    cloud_region=asset.cloud_region,
                    first_seen=asset.first_seen,
                    last_seen=datetime.now(timezone.utc),
                    certificate_info=asset.certificate_info,
                    risk_score=asset.risk_score,
                    raw_data=new_raw_data,
                    source=asset.source,
                    is_verified=asset.is_verified,
                )
                enriched.append(enriched_asset)
            else:
                enriched.append(asset)

        return ExternalAssetCollection(enriched)

    def _should_fingerprint(self, asset: ExternalAsset) -> bool:
        """Check if an asset should be fingerprinted."""
        # Fingerprint web services or assets with no port (default to HTTPS)
        if asset.port is None:
            return True
        web_ports = {80, 443, 8080, 8443, 3000, 5000, 8000}
        return asset.port in web_ports

    def _fetch_headers(self, url: str) -> dict[str, str]:
        """
        Fetch HTTP headers from a URL.

        Args:
            url: URL to fetch

        Returns:
            Dictionary of response headers
        """
        try:
            request = Request(
                url,
                method="HEAD",
                headers={
                    "User-Agent": self._config.user_agent,
                    "Accept": "*/*",
                },
            )

            # Create SSL context that doesn't verify (for self-signed certs)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with urlopen(
                request,
                timeout=self._config.http_timeout_seconds,
                context=ctx,
            ) as response:
                # Convert headers to lowercase dict
                headers = {}
                for key, value in response.headers.items():
                    headers[key.lower()] = value
                return headers

        except HTTPError as e:
            # Even on error, we can extract headers
            headers = {}
            if e.headers:
                for key, value in e.headers.items():
                    headers[key.lower()] = value
            return headers

        except Exception:
            # Try GET if HEAD fails
            try:
                request = Request(
                    url,
                    headers={
                        "User-Agent": self._config.user_agent,
                        "Accept": "*/*",
                    },
                )

                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                with urlopen(
                    request,
                    timeout=self._config.http_timeout_seconds,
                    context=ctx,
                ) as response:
                    headers = {}
                    for key, value in response.headers.items():
                        headers[key.lower()] = value
                    return headers

            except Exception as e:
                logger.debug(f"Failed to fetch headers from {url}: {e}")
                return {}

    def _analyze_headers(
        self,
        headers: dict[str, str],
    ) -> list[TechnologyFingerprint]:
        """
        Analyze HTTP headers for technology fingerprints.

        Args:
            headers: HTTP response headers

        Returns:
            List of detected technologies
        """
        technologies: list[TechnologyFingerprint] = []

        # Check Server header
        server = headers.get("server", "")
        if server:
            for pattern, (name, category) in SERVER_PATTERNS.items():
                match = re.search(pattern, server, re.IGNORECASE)
                if match:
                    version = None
                    if match.groups():
                        version = match.group(1)
                    technologies.append(
                        TechnologyFingerprint(
                            name=name,
                            category=category,
                            version=version,
                            source="header",
                        )
                    )
                    break

        # Check X-Powered-By header
        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            for pattern, (name, category) in POWERED_BY_PATTERNS.items():
                match = re.search(pattern, powered_by, re.IGNORECASE)
                if match:
                    version = None
                    if match.groups():
                        version = match.group(1)
                    technologies.append(
                        TechnologyFingerprint(
                            name=name,
                            category=category,
                            version=version,
                            source="header",
                        )
                    )

        # Check for CDN/proxy indicators
        if headers.get("cf-ray"):
            technologies.append(
                TechnologyFingerprint(
                    name="Cloudflare",
                    category="cdn",
                    source="header",
                )
            )

        if headers.get("x-amz-cf-id"):
            technologies.append(
                TechnologyFingerprint(
                    name="CloudFront",
                    category="cdn",
                    source="header",
                )
            )

        if headers.get("x-azure-ref"):
            technologies.append(
                TechnologyFingerprint(
                    name="Azure CDN",
                    category="cdn",
                    source="header",
                )
            )

        if headers.get("x-vercel-id"):
            technologies.append(
                TechnologyFingerprint(
                    name="Vercel",
                    category="hosting",
                    source="header",
                )
            )

        if headers.get("x-netlify-request-id"):
            technologies.append(
                TechnologyFingerprint(
                    name="Netlify",
                    category="hosting",
                    source="header",
                )
            )

        # Check Via header for proxies
        via = headers.get("via", "")
        if via:
            via_lower = via.lower()
            if "varnish" in via_lower:
                technologies.append(
                    TechnologyFingerprint(
                        name="Varnish",
                        category="cache",
                        source="header",
                    )
                )
            if "cloudfront" in via_lower:
                technologies.append(
                    TechnologyFingerprint(
                        name="CloudFront",
                        category="cdn",
                        source="header",
                    )
                )

        # Check X-Cache header
        x_cache = headers.get("x-cache", "")
        if x_cache:
            x_cache_lower = x_cache.lower()
            if "cloudfront" in x_cache_lower:
                technologies.append(
                    TechnologyFingerprint(
                        name="CloudFront",
                        category="cdn",
                        source="header",
                    )
                )

        return technologies

    def _analyze_certificate(
        self,
        domain: str,
        port: int = 443,
    ) -> list[TechnologyFingerprint]:
        """
        Analyze SSL certificate for technology fingerprints.

        Args:
            domain: Domain to connect to
            port: Port number

        Returns:
            List of detected technologies
        """
        technologies: list[TechnologyFingerprint] = []

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection(
                (domain, port),
                timeout=self._config.http_timeout_seconds,
            ) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert(binary_form=False)

                    if cert:
                        # Extract issuer
                        issuer = ""
                        issuer_data = cert.get("issuer", ())
                        for item in issuer_data:
                            for key, value in item:
                                if key in ("organizationName", "commonName"):
                                    issuer = value
                                    break

                        # Check issuer against patterns
                        for pattern, (name, category) in CERT_ISSUER_PATTERNS.items():
                            if re.search(pattern, issuer, re.IGNORECASE):
                                technologies.append(
                                    TechnologyFingerprint(
                                        name=name,
                                        category=category,
                                        source="certificate",
                                    )
                                )
                                break

        except Exception as e:
            logger.debug(f"Certificate analysis failed for {domain}:{port}: {e}")

        return technologies

    def _deduplicate_technologies(
        self,
        technologies: list[TechnologyFingerprint],
    ) -> list[TechnologyFingerprint]:
        """
        Remove duplicate technology entries.

        Args:
            technologies: List of technologies

        Returns:
            Deduplicated list
        """
        seen: set[str] = set()
        unique: list[TechnologyFingerprint] = []

        for tech in technologies:
            key = f"{tech.name}:{tech.category}"
            if key not in seen:
                seen.add(key)
                unique.append(tech)

        return unique
