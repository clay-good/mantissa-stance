"""
CLI command handlers for Enrichment.

Provides commands for:
- Enriching findings with threat intelligence and CVE details
- Enriching assets with context, criticality, and IP information
- Viewing enrichment status and availability
- Looking up specific IPs or CVEs
"""

from __future__ import annotations

import argparse
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def cmd_enrich(args: argparse.Namespace) -> int:
    """
    Route enrichment subcommands to appropriate handlers.

    Returns:
        Exit code (0 success, 1 error)
    """
    action = getattr(args, "enrich_action", None)

    if action is None:
        print("Usage: stance enrich <command>")
        print("")
        print("Commands:")
        print("  findings    Enrich findings with threat intelligence and CVE details")
        print("  assets      Enrich assets with context and IP information")
        print("  ip          Look up information for a specific IP address")
        print("  cve         Look up information for a specific CVE")
        print("  kev         Check if a CVE is in CISA KEV catalog")
        print("  status      Show enrichment capabilities and availability")
        print("")
        print("Run 'stance enrich <command> --help' for more information")
        return 0

    handlers = {
        "findings": _cmd_enrich_findings,
        "assets": _cmd_enrich_assets,
        "ip": _cmd_enrich_ip,
        "cve": _cmd_enrich_cve,
        "kev": _cmd_enrich_kev,
        "status": _cmd_enrich_status,
    }

    handler = handlers.get(action)
    if handler:
        return handler(args)

    print(f"Unknown enrich command: {action}")
    return 1


def _cmd_enrich_findings(args: argparse.Namespace) -> int:
    """
    Enrich findings with threat intelligence and CVE details.

    Applies enrichment pipeline to add:
    - CVE details (CVSS scores, affected products, references)
    - Known exploited vulnerability (KEV) status
    - Vulnerable software identification
    - Threat intelligence indicators
    """
    from stance.enrichment import (
        create_default_pipeline,
        enrich_findings,
        EnrichmentPipeline,
        CVEEnricher,
        KEVEnricher,
        VulnerableSoftwareEnricher,
        ThreatIntelEnricher,
    )
    from stance.storage import get_storage

    output_format = getattr(args, "format", "table")
    enrichment_types = getattr(args, "types", None)
    finding_id = getattr(args, "finding_id", None)
    limit = getattr(args, "limit", 50)

    try:
        # Load findings from storage
        storage = get_storage()
        findings_data = storage.load_findings()

        if not findings_data:
            print("No findings found. Run 'stance scan' first.")
            return 1

        findings = list(findings_data.findings) if hasattr(findings_data, 'findings') else findings_data

        if not findings:
            print("No findings found. Run 'stance scan' first.")
            return 1

        # Filter by finding ID if specified
        if finding_id:
            findings = [f for f in findings if f.id == finding_id]
            if not findings:
                print(f"Finding not found: {finding_id}")
                return 1

        # Limit findings
        findings = findings[:limit]

        # Create pipeline based on requested types
        if enrichment_types:
            types_list = [t.strip().lower() for t in enrichment_types.split(",")]
            enrichers = []
            if "cve" in types_list:
                enrichers.append(CVEEnricher())
            if "kev" in types_list:
                enrichers.append(KEVEnricher())
            if "vuln" in types_list or "vulnerable" in types_list:
                enrichers.append(VulnerableSoftwareEnricher())
            if "threat" in types_list or "intel" in types_list:
                enrichers.append(ThreatIntelEnricher())

            if not enrichers:
                print(f"No valid enrichment types: {enrichment_types}")
                print("Valid types: cve, kev, vuln, threat")
                return 1

            pipeline = EnrichmentPipeline(finding_enrichers=enrichers, asset_enrichers=[])
        else:
            pipeline = create_default_pipeline()

        # Enrich findings
        print(f"Enriching {len(findings)} findings...")
        enriched = pipeline.enrich_findings(findings)

        # Count enrichments
        total_enrichments = sum(len(ef.enrichments) for ef in enriched)
        enriched_count = sum(1 for ef in enriched if ef.enrichments)

        if output_format == "json":
            output = {
                "total_findings": len(findings),
                "findings_enriched": enriched_count,
                "total_enrichments": total_enrichments,
                "enriched_findings": [ef.to_dict() for ef in enriched if ef.enrichments],
            }
            print(json.dumps(output, indent=2, default=str))
        else:
            print("")
            print("Finding Enrichment Results")
            print("=" * 80)
            print(f"Findings processed: {len(findings)}")
            print(f"Findings enriched: {enriched_count}")
            print(f"Total enrichments added: {total_enrichments}")
            print("")

            if not enriched_count:
                print("No enrichments found for the given findings.")
                print("This may be because:")
                print("  - Findings don't have CVE IDs")
                print("  - No threat intelligence matches")
                print("  - External APIs are unavailable")
                return 0

            # Show enriched findings
            print(f"{'Finding ID':<35} {'CVE':<15} {'Enrichments'}")
            print("-" * 80)

            for ef in enriched:
                if ef.enrichments:
                    finding_short = ef.finding.id[:32] + "..." if len(ef.finding.id) > 35 else ef.finding.id
                    cve = ef.finding.cve_id or "N/A"
                    enrich_types = ", ".join(e.enrichment_type.value for e in ef.enrichments)
                    print(f"{finding_short:<35} {cve:<15} {enrich_types}")

            # Show detailed view for single finding
            if finding_id and enriched:
                ef = enriched[0]
                print("")
                print("Enrichment Details:")
                for enrichment in ef.enrichments:
                    print(f"  [{enrichment.enrichment_type.value}]")
                    print(f"    Source: {enrichment.source}")
                    print(f"    Confidence: {enrichment.confidence:.2f}")
                    for key, value in enrichment.data.items():
                        if isinstance(value, list):
                            print(f"    {key}: {len(value)} items")
                        elif isinstance(value, dict):
                            print(f"    {key}: {json.dumps(value)[:50]}...")
                        else:
                            print(f"    {key}: {value}")

        return 0

    except Exception as e:
        logger.error(f"Finding enrichment failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_enrich_assets(args: argparse.Namespace) -> int:
    """
    Enrich assets with context and IP information.

    Applies enrichment pipeline to add:
    - Business unit identification
    - Criticality assessment
    - Owner information
    - IP geolocation and ASN data
    - Cloud provider identification
    """
    from stance.enrichment import (
        create_default_pipeline,
        EnrichmentPipeline,
        IPEnricher,
        CloudProviderRangeEnricher,
        AssetContextEnricher,
        TagEnricher,
    )
    from stance.storage import get_storage

    output_format = getattr(args, "format", "table")
    enrichment_types = getattr(args, "types", None)
    asset_id = getattr(args, "asset_id", None)
    cloud_filter = getattr(args, "cloud", None)
    limit = getattr(args, "limit", 50)

    try:
        # Load assets from storage
        storage = get_storage()
        assets_data = storage.load_assets()

        if not assets_data or not assets_data.assets:
            print("No assets found. Run 'stance scan' first.")
            return 1

        assets = list(assets_data.assets)

        # Filter by asset ID if specified
        if asset_id:
            assets = [a for a in assets if a.id == asset_id]
            if not assets:
                print(f"Asset not found: {asset_id}")
                return 1

        # Filter by cloud provider
        if cloud_filter:
            assets = [a for a in assets if a.cloud_provider.lower() == cloud_filter.lower()]

        # Limit assets
        assets = assets[:limit]

        if not assets:
            print("No assets match the filter criteria.")
            return 1

        # Create pipeline based on requested types
        if enrichment_types:
            types_list = [t.strip().lower() for t in enrichment_types.split(",")]
            enrichers = []
            if "ip" in types_list or "geo" in types_list:
                enrichers.append(IPEnricher())
            if "cloud" in types_list:
                enrichers.append(CloudProviderRangeEnricher())
            if "context" in types_list:
                enrichers.append(AssetContextEnricher())
            if "tags" in types_list:
                enrichers.append(TagEnricher())

            if not enrichers:
                print(f"No valid enrichment types: {enrichment_types}")
                print("Valid types: ip, geo, cloud, context, tags")
                return 1

            pipeline = EnrichmentPipeline(finding_enrichers=[], asset_enrichers=enrichers)
        else:
            pipeline = create_default_pipeline()

        # Enrich assets
        print(f"Enriching {len(assets)} assets...")
        enriched = pipeline.enrich_assets(assets)

        # Count enrichments
        total_enrichments = sum(len(ea.enrichments) for ea in enriched)
        enriched_count = sum(1 for ea in enriched if ea.enrichments)

        if output_format == "json":
            output = {
                "total_assets": len(assets),
                "assets_enriched": enriched_count,
                "total_enrichments": total_enrichments,
                "enriched_assets": [ea.to_dict() for ea in enriched if ea.enrichments],
            }
            print(json.dumps(output, indent=2, default=str))
        else:
            print("")
            print("Asset Enrichment Results")
            print("=" * 100)
            print(f"Assets processed: {len(assets)}")
            print(f"Assets enriched: {enriched_count}")
            print(f"Total enrichments added: {total_enrichments}")
            print("")

            if not enriched_count:
                print("No enrichments found for the given assets.")
                return 0

            # Show enriched assets
            print(f"{'Asset ID':<35} {'Type':<20} {'Cloud':<8} {'Enrichments'}")
            print("-" * 100)

            for ea in enriched:
                if ea.enrichments:
                    asset_short = ea.asset.id[:32] + "..." if len(ea.asset.id) > 35 else ea.asset.id
                    type_short = ea.asset.resource_type[:17] + "..." if len(ea.asset.resource_type) > 20 else ea.asset.resource_type
                    enrich_types = ", ".join(e.enrichment_type.value for e in ea.enrichments)
                    print(
                        f"{asset_short:<35} "
                        f"{type_short:<20} "
                        f"{ea.asset.cloud_provider:<8} "
                        f"{enrich_types[:30]}"
                    )

            # Show detailed view for single asset
            if asset_id and enriched:
                ea = enriched[0]
                print("")
                print("Enrichment Details:")
                for enrichment in ea.enrichments:
                    print(f"  [{enrichment.enrichment_type.value}]")
                    print(f"    Source: {enrichment.source}")
                    print(f"    Confidence: {enrichment.confidence:.2f}")
                    for key, value in enrichment.data.items():
                        if isinstance(value, list):
                            if value and len(value) <= 3:
                                print(f"    {key}: {value}")
                            else:
                                print(f"    {key}: {len(value)} items")
                        elif isinstance(value, dict):
                            print(f"    {key}:")
                            for k, v in list(value.items())[:5]:
                                print(f"      {k}: {v}")
                        else:
                            print(f"    {key}: {value}")

        return 0

    except Exception as e:
        logger.error(f"Asset enrichment failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_enrich_ip(args: argparse.Namespace) -> int:
    """
    Look up information for a specific IP address.

    Returns:
    - Public/private classification
    - Cloud provider identification
    - Geolocation (country, city, coordinates)
    - ASN information (organization, network)
    """
    from stance.enrichment import IPEnricher

    ip_address = getattr(args, "ip", None)
    output_format = getattr(args, "format", "table")
    disable_geoip = getattr(args, "no_geoip", False)

    if not ip_address:
        print("Error: IP address is required.")
        return 1

    try:
        enricher = IPEnricher(enable_geoip=not disable_geoip)
        result = enricher.lookup_ip(ip_address)

        if output_format == "json":
            print(json.dumps(result, indent=2, default=str))
        else:
            print("")
            print(f"IP Information: {ip_address}")
            print("=" * 50)
            print(f"  Version: IPv{result.get('version', 'unknown')}")
            print(f"  Public: {result.get('is_public', False)}")
            print(f"  Private: {result.get('is_private', False)}")

            cloud_provider = result.get("cloud_provider")
            if cloud_provider:
                print(f"  Cloud Provider: {cloud_provider.upper()}")
            else:
                print("  Cloud Provider: Not identified")

            geo = result.get("geolocation")
            if geo:
                print("")
                print("  Geolocation:")
                print(f"    Country: {geo.get('country', 'N/A')} ({geo.get('country_code', '')})")
                print(f"    Region: {geo.get('region', 'N/A')}")
                print(f"    City: {geo.get('city', 'N/A')}")
                print(f"    Coordinates: {geo.get('latitude', 'N/A')}, {geo.get('longitude', 'N/A')}")
                print(f"    Timezone: {geo.get('timezone', 'N/A')}")
                print("")
                print("  Network:")
                print(f"    ISP: {geo.get('isp', 'N/A')}")
                print(f"    Organization: {geo.get('org', 'N/A')}")
                print(f"    ASN: {geo.get('asn', 'N/A')}")
                print(f"    ASN Org: {geo.get('asn_org', 'N/A')}")
            elif not disable_geoip:
                print("")
                print("  Geolocation: Not available (private IP or lookup failed)")

        return 0

    except Exception as e:
        logger.error(f"IP lookup failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_enrich_cve(args: argparse.Namespace) -> int:
    """
    Look up information for a specific CVE.

    Returns:
    - CVE description
    - CVSS v3 and v2 scores
    - Affected products (CPE)
    - References
    - Weaknesses (CWE)
    """
    from stance.enrichment import CVEEnricher

    cve_id = getattr(args, "cve", None)
    output_format = getattr(args, "format", "table")

    if not cve_id:
        print("Error: CVE ID is required (e.g., CVE-2021-44228).")
        return 1

    # Normalize CVE ID
    cve_id = cve_id.upper()
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"

    try:
        enricher = CVEEnricher()
        result = enricher._lookup_cve(cve_id)

        if not result:
            print(f"CVE not found: {cve_id}")
            print("Ensure the CVE ID is valid (format: CVE-YYYY-NNNNN)")
            return 1

        if output_format == "json":
            print(json.dumps(result, indent=2, default=str))
        else:
            print("")
            print(f"CVE Details: {cve_id}")
            print("=" * 80)

            # Description
            description = result.get("description", "N/A")
            if len(description) > 200:
                description = description[:197] + "..."
            print(f"Description: {description}")
            print("")

            # Dates
            print(f"Published: {result.get('published', 'N/A')}")
            print(f"Last Modified: {result.get('last_modified', 'N/A')}")
            print("")

            # CVSS v3
            cvss_v3 = result.get("cvss_v3")
            if cvss_v3:
                print("CVSS v3:")
                print(f"  Score: {cvss_v3.get('score', 'N/A')}")
                print(f"  Severity: {cvss_v3.get('severity', 'N/A')}")
                print(f"  Vector: {cvss_v3.get('vector', 'N/A')}")
                print("")

            # CVSS v2
            cvss_v2 = result.get("cvss_v2")
            if cvss_v2:
                print("CVSS v2:")
                print(f"  Score: {cvss_v2.get('score', 'N/A')}")
                print(f"  Severity: {cvss_v2.get('severity', 'N/A')}")
                print("")

            # Weaknesses
            weaknesses = result.get("weaknesses", [])
            if weaknesses:
                print(f"Weaknesses: {', '.join(weaknesses[:5])}")
                print("")

            # Affected products
            affected = result.get("affected_products", [])
            if affected:
                print(f"Affected Products ({len(affected)} total):")
                for product in affected[:5]:
                    # Extract readable name from CPE
                    parts = product.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3]
                        name = parts[4]
                        version = parts[5] if len(parts) > 5 else "*"
                        print(f"  - {vendor}/{name}:{version}")
                    else:
                        print(f"  - {product}")
                if len(affected) > 5:
                    print(f"  ... and {len(affected) - 5} more")
                print("")

            # References
            references = result.get("references", [])
            if references:
                print(f"References ({len(references)}):")
                for ref in references[:5]:
                    print(f"  - {ref}")
                if len(references) > 5:
                    print(f"  ... and {len(references) - 5} more")

        return 0

    except Exception as e:
        logger.error(f"CVE lookup failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_enrich_kev(args: argparse.Namespace) -> int:
    """
    Check if a CVE is in the CISA Known Exploited Vulnerabilities catalog.

    Returns KEV details if the CVE is in the catalog, including:
    - Vendor and product
    - Required action and due date
    - Description and notes
    """
    from stance.enrichment import KEVEnricher
    from stance.models.finding import Finding, FindingType, Severity

    cve_id = getattr(args, "cve", None)
    output_format = getattr(args, "format", "table")
    list_all = getattr(args, "list", False)

    try:
        enricher = KEVEnricher(auto_fetch=True)

        # Force fetch KEV data
        enricher._fetch_kev_data()

        if list_all:
            # List all KEV entries
            kev_data = enricher._kev_data

            if output_format == "json":
                output = {
                    "total": len(kev_data),
                    "vulnerabilities": list(kev_data.values())[:100],  # Limit to 100
                }
                print(json.dumps(output, indent=2, default=str))
            else:
                print("")
                print(f"CISA KEV Catalog ({len(kev_data)} vulnerabilities)")
                print("=" * 100)
                print(f"{'CVE ID':<20} {'Vendor':<20} {'Product':<20} {'Date Added'}")
                print("-" * 100)

                for cve, entry in list(kev_data.items())[:50]:
                    vendor = entry.get("vendorProject", "N/A")[:17]
                    product = entry.get("product", "N/A")[:17]
                    date_added = entry.get("dateAdded", "N/A")
                    print(f"{cve:<20} {vendor:<20} {product:<20} {date_added}")

                if len(kev_data) > 50:
                    print(f"... and {len(kev_data) - 50} more")

            return 0

        if not cve_id:
            print("Error: CVE ID is required (e.g., CVE-2021-44228).")
            print("Use --list to see all KEV entries.")
            return 1

        # Normalize CVE ID
        cve_id = cve_id.upper()
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"

        # Check if CVE is in KEV
        is_kev = enricher.is_known_exploited(cve_id)

        if not is_kev:
            if output_format == "json":
                print(json.dumps({
                    "cve_id": cve_id,
                    "is_known_exploited": False,
                    "message": "CVE is not in the CISA KEV catalog",
                }))
            else:
                print(f"{cve_id} is NOT in the CISA KEV catalog.")
                print("This CVE may still be exploited in the wild,")
                print("but has not been added to the CISA KEV list.")
            return 0

        # Get KEV details
        kev_entry = enricher._kev_data.get(cve_id, {})

        if output_format == "json":
            output = {
                "cve_id": cve_id,
                "is_known_exploited": True,
                "kev_details": kev_entry,
            }
            print(json.dumps(output, indent=2, default=str))
        else:
            print("")
            print(f"CISA KEV Entry: {cve_id}")
            print("=" * 80)
            print(f"  Status: KNOWN EXPLOITED VULNERABILITY")
            print("")
            print(f"  Vendor: {kev_entry.get('vendorProject', 'N/A')}")
            print(f"  Product: {kev_entry.get('product', 'N/A')}")
            print(f"  Vulnerability: {kev_entry.get('vulnerabilityName', 'N/A')}")
            print("")
            print(f"  Date Added: {kev_entry.get('dateAdded', 'N/A')}")
            print(f"  Due Date: {kev_entry.get('dueDate', 'N/A')}")
            print("")

            description = kev_entry.get("shortDescription", "N/A")
            if len(description) > 200:
                description = description[:197] + "..."
            print(f"  Description: {description}")
            print("")

            required_action = kev_entry.get("requiredAction", "N/A")
            print(f"  Required Action: {required_action}")

            notes = kev_entry.get("notes")
            if notes:
                print(f"  Notes: {notes}")

        return 0

    except Exception as e:
        logger.error(f"KEV lookup failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_enrich_status(args: argparse.Namespace) -> int:
    """
    Show enrichment capabilities and availability.

    Lists all available enrichers and their status.
    """
    from stance.enrichment import (
        IPEnricher,
        CloudProviderRangeEnricher,
        AssetContextEnricher,
        TagEnricher,
        CVEEnricher,
        KEVEnricher,
        VulnerableSoftwareEnricher,
        ThreatIntelEnricher,
    )

    output_format = getattr(args, "format", "table")

    # Check enricher availability
    enrichers = [
        {
            "name": "CVE Enricher",
            "type": "finding",
            "description": "Enriches findings with CVE details from NVD",
            "enricher": CVEEnricher(),
            "data_sources": ["NVD API"],
        },
        {
            "name": "KEV Enricher",
            "type": "finding",
            "description": "Checks CVEs against CISA Known Exploited Vulnerabilities",
            "enricher": KEVEnricher(auto_fetch=False),
            "data_sources": ["CISA KEV Catalog"],
        },
        {
            "name": "Vulnerable Software Enricher",
            "type": "finding",
            "description": "Identifies known vulnerable software patterns",
            "enricher": VulnerableSoftwareEnricher(),
            "data_sources": ["Built-in patterns (Log4j, Spring4Shell, etc.)"],
        },
        {
            "name": "Threat Intel Enricher",
            "type": "finding",
            "description": "Enriches with threat intelligence indicators",
            "enricher": ThreatIntelEnricher(),
            "data_sources": ["Custom indicator feeds"],
        },
        {
            "name": "IP Enricher",
            "type": "asset",
            "description": "Adds IP geolocation and ASN information",
            "enricher": IPEnricher(),
            "data_sources": ["ip-api.com", "Cloud provider IP ranges"],
        },
        {
            "name": "Cloud Provider Range Enricher",
            "type": "asset",
            "description": "Identifies cloud provider from IP ranges",
            "enricher": CloudProviderRangeEnricher(),
            "data_sources": ["AWS, GCP, Azure IP ranges"],
        },
        {
            "name": "Asset Context Enricher",
            "type": "asset",
            "description": "Adds business unit, criticality, and owner info",
            "enricher": AssetContextEnricher(),
            "data_sources": ["Tag analysis", "Name patterns"],
        },
        {
            "name": "Tag Enricher",
            "type": "asset",
            "description": "Analyzes tag compliance and completeness",
            "enricher": TagEnricher(),
            "data_sources": ["Asset tags"],
        },
    ]

    # Check availability
    for e in enrichers:
        try:
            e["available"] = e["enricher"].is_available()
            e["enrichment_types"] = [et.value for et in e["enricher"].enrichment_types]
        except Exception:
            e["available"] = False
            e["enrichment_types"] = []

    if output_format == "json":
        output = {
            "enrichers": [
                {
                    "name": e["name"],
                    "type": e["type"],
                    "description": e["description"],
                    "available": e["available"],
                    "enrichment_types": e["enrichment_types"],
                    "data_sources": e["data_sources"],
                }
                for e in enrichers
            ],
            "finding_enrichers": [e["name"] for e in enrichers if e["type"] == "finding"],
            "asset_enrichers": [e["name"] for e in enrichers if e["type"] == "asset"],
        }
        print(json.dumps(output, indent=2))
    else:
        print("")
        print("Enrichment Capabilities")
        print("=" * 80)

        # Finding enrichers
        print("")
        print("Finding Enrichers:")
        print("-" * 80)
        for e in enrichers:
            if e["type"] == "finding":
                status = "Available" if e["available"] else "Unavailable"
                print(f"  {e['name']} [{status}]")
                print(f"    {e['description']}")
                print(f"    Types: {', '.join(e['enrichment_types'])}")
                print(f"    Sources: {', '.join(e['data_sources'])}")
                print("")

        # Asset enrichers
        print("Asset Enrichers:")
        print("-" * 80)
        for e in enrichers:
            if e["type"] == "asset":
                status = "Available" if e["available"] else "Unavailable"
                print(f"  {e['name']} [{status}]")
                print(f"    {e['description']}")
                print(f"    Types: {', '.join(e['enrichment_types'])}")
                print(f"    Sources: {', '.join(e['data_sources'])}")
                print("")

        # Summary
        available_count = sum(1 for e in enrichers if e["available"])
        print(f"Total Enrichers: {len(enrichers)} ({available_count} available)")

    return 0
