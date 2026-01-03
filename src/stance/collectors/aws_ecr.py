"""
AWS ECR collector for Mantissa Stance.

Collects Elastic Container Registry repositories, images, and their
security configurations for posture assessment.
"""

from __future__ import annotations

import logging
from typing import Any

from stance.collectors.base import BaseCollector
from stance.models import (
    Asset,
    AssetCollection,
    Finding,
    FindingCollection,
    FindingType,
    FindingStatus,
    Severity,
    NETWORK_EXPOSURE_INTERNET,
    NETWORK_EXPOSURE_INTERNAL,
)

logger = logging.getLogger(__name__)


class ECRCollector(BaseCollector):
    """
    Collects AWS ECR repositories, images, and security configurations.

    Gathers ECR repositories with their security settings including
    image scanning results, lifecycle policies, repository policies,
    and encryption configuration. All API calls are read-only.
    """

    collector_name = "aws_ecr"
    resource_types = [
        "aws_ecr_repository",
        "aws_ecr_image",
    ]

    def collect(self) -> AssetCollection:
        """
        Collect all ECR resources.

        Returns:
            Collection of ECR assets
        """
        assets: list[Asset] = []

        # Collect ECR repositories
        try:
            assets.extend(self._collect_repositories())
        except Exception as e:
            logger.warning(f"Failed to collect ECR repositories: {e}")

        return AssetCollection(assets)

    def collect_findings(self) -> FindingCollection:
        """
        Collect security findings from ECR image scans.

        Returns:
            Collection of vulnerability findings from image scans
        """
        findings: list[Finding] = []

        try:
            findings.extend(self._collect_image_scan_findings())
        except Exception as e:
            logger.warning(f"Failed to collect ECR scan findings: {e}")

        return FindingCollection(findings)

    def _collect_repositories(self) -> list[Asset]:
        """Collect ECR repositories with their configurations."""
        ecr = self._get_client("ecr")
        assets: list[Asset] = []
        now = self._now()

        for repo in self._paginate(
            ecr, "describe_repositories", "repositories"
        ):
            repo_name = repo["repositoryName"]
            repo_arn = repo["repositoryArn"]
            repo_uri = repo.get("repositoryUri", "")

            # Get repository tags
            tags = self._get_repository_tags(repo_arn)

            # Get repository policy
            repo_policy = self._get_repository_policy(repo_name)

            # Get lifecycle policy
            lifecycle_policy = self._get_lifecycle_policy(repo_name)

            # Get image scan configuration
            image_scan_config = repo.get("imageScanningConfiguration", {})
            scan_on_push = image_scan_config.get("scanOnPush", False)

            # Get replication configuration
            replication_config = self._get_replication_configuration()

            # Determine network exposure based on policy
            network_exposure = self._determine_network_exposure(repo_policy)

            # Get image details for this repository
            images = self._get_repository_images(repo_name)

            # Calculate repository statistics
            image_count = len(images)
            total_size_bytes = sum(
                img.get("imageSizeInBytes", 0) for img in images
            )
            latest_push_at = self._get_latest_push_time(images)

            # Check for unscanned images
            unscanned_images = self._count_unscanned_images(images)

            # Build raw config
            raw_config: dict[str, Any] = {
                "repository_name": repo_name,
                "repository_arn": repo_arn,
                "repository_uri": repo_uri,
                "registry_id": repo.get("registryId"),
                "created_at": (
                    repo["createdAt"].isoformat()
                    if repo.get("createdAt")
                    else None
                ),
                # Security settings
                "image_tag_mutability": repo.get("imageTagMutability", "MUTABLE"),
                "image_tag_immutable": repo.get("imageTagMutability") == "IMMUTABLE",
                "scan_on_push": scan_on_push,
                "has_scan_on_push": scan_on_push,
                # Encryption
                "encryption_configuration": repo.get("encryptionConfiguration", {}),
                "encryption_type": repo.get(
                    "encryptionConfiguration", {}
                ).get("encryptionType", "AES256"),
                "kms_key": repo.get(
                    "encryptionConfiguration", {}
                ).get("kmsKey"),
                "has_kms_encryption": bool(
                    repo.get("encryptionConfiguration", {}).get("kmsKey")
                ),
                # Repository policy
                "repository_policy": repo_policy,
                "has_repository_policy": bool(repo_policy),
                "is_publicly_accessible": self._is_publicly_accessible(repo_policy),
                # Lifecycle policy
                "lifecycle_policy": lifecycle_policy,
                "has_lifecycle_policy": bool(lifecycle_policy),
                # Replication
                "replication_configuration": replication_config,
                "has_replication": bool(
                    replication_config.get("replicationConfiguration", {}).get("rules")
                ),
                # Image statistics
                "image_count": image_count,
                "total_size_bytes": total_size_bytes,
                "total_size_mb": round(total_size_bytes / (1024 * 1024), 2),
                "latest_push_at": latest_push_at,
                "unscanned_images_count": unscanned_images,
                "has_unscanned_images": unscanned_images > 0,
                # Pull through cache (if configured)
                "pull_through_cache_rules": self._get_pull_through_cache_rules(repo_name),
            }

            asset = Asset(
                id=repo_arn,
                cloud_provider="aws",
                account_id=self.account_id,
                region=self._region,
                resource_type="aws_ecr_repository",
                name=repo_name,
                tags=tags,
                network_exposure=network_exposure,
                created_at=repo.get("createdAt", now),
                last_seen=now,
                raw_config=raw_config,
            )
            assets.append(asset)

            # Also collect individual images as assets
            assets.extend(self._create_image_assets(repo_name, repo_arn, images, now))

        return assets

    def _get_repository_tags(self, repo_arn: str) -> dict[str, str]:
        """Get tags for an ECR repository."""
        ecr = self._get_client("ecr")
        try:
            response = ecr.list_tags_for_resource(resourceArn=repo_arn)
            return {
                tag["Key"]: tag["Value"]
                for tag in response.get("tags", [])
            }
        except Exception as e:
            logger.debug(f"Could not get tags for {repo_arn}: {e}")
            return {}

    def _get_repository_policy(self, repo_name: str) -> dict[str, Any] | None:
        """Get repository policy for an ECR repository."""
        ecr = self._get_client("ecr")
        try:
            response = ecr.get_repository_policy(repositoryName=repo_name)
            import json
            return json.loads(response.get("policyText", "{}"))
        except ecr.exceptions.RepositoryPolicyNotFoundException:
            return None
        except Exception as e:
            logger.debug(f"Could not get policy for {repo_name}: {e}")
            return None

    def _get_lifecycle_policy(self, repo_name: str) -> dict[str, Any] | None:
        """Get lifecycle policy for an ECR repository."""
        ecr = self._get_client("ecr")
        try:
            response = ecr.get_lifecycle_policy(repositoryName=repo_name)
            import json
            return json.loads(response.get("lifecyclePolicyText", "{}"))
        except ecr.exceptions.LifecyclePolicyNotFoundException:
            return None
        except Exception as e:
            logger.debug(f"Could not get lifecycle policy for {repo_name}: {e}")
            return None

    def _get_replication_configuration(self) -> dict[str, Any]:
        """Get registry-level replication configuration."""
        ecr = self._get_client("ecr")
        try:
            response = ecr.describe_registry()
            return {
                "registry_id": response.get("registryId"),
                "replication_configuration": response.get(
                    "replicationConfiguration", {}
                ),
            }
        except Exception as e:
            logger.debug(f"Could not get replication configuration: {e}")
            return {}

    def _get_repository_images(self, repo_name: str) -> list[dict[str, Any]]:
        """Get image details for a repository."""
        ecr = self._get_client("ecr")
        images: list[dict[str, Any]] = []

        try:
            for image in self._paginate(
                ecr, "describe_images", "imageDetails",
                repositoryName=repo_name
            ):
                images.append(image)
        except Exception as e:
            logger.debug(f"Could not get images for {repo_name}: {e}")

        return images

    def _get_latest_push_time(self, images: list[dict[str, Any]]) -> str | None:
        """Get the most recent push time from image list."""
        if not images:
            return None

        push_times = [
            img["imagePushedAt"]
            for img in images
            if img.get("imagePushedAt")
        ]
        if not push_times:
            return None

        latest = max(push_times)
        return latest.isoformat() if hasattr(latest, "isoformat") else str(latest)

    def _count_unscanned_images(self, images: list[dict[str, Any]]) -> int:
        """Count images that have not been scanned."""
        unscanned = 0
        for img in images:
            scan_status = img.get("imageScanStatus", {})
            status = scan_status.get("status", "")
            # Count as unscanned if no scan or scan pending/in progress
            if status not in ["COMPLETE", "ACTIVE", "FINDINGS_UNAVAILABLE"]:
                unscanned += 1
        return unscanned

    def _get_pull_through_cache_rules(
        self, repo_name: str
    ) -> list[dict[str, Any]]:
        """Get pull through cache rules if applicable."""
        ecr = self._get_client("ecr")
        try:
            response = ecr.describe_pull_through_cache_rules()
            # Filter rules relevant to this repository pattern
            rules = response.get("pullThroughCacheRules", [])
            return [
                {
                    "ecr_repository_prefix": rule.get("ecrRepositoryPrefix"),
                    "upstream_registry_url": rule.get("upstreamRegistryUrl"),
                    "created_at": (
                        rule["createdAt"].isoformat()
                        if rule.get("createdAt")
                        else None
                    ),
                    "registry_id": rule.get("registryId"),
                }
                for rule in rules
                if repo_name.startswith(rule.get("ecrRepositoryPrefix", ""))
            ]
        except Exception as e:
            logger.debug(f"Could not get pull through cache rules: {e}")
            return []

    def _determine_network_exposure(
        self, repo_policy: dict[str, Any] | None
    ) -> str:
        """Determine network exposure based on repository policy."""
        if self._is_publicly_accessible(repo_policy):
            return NETWORK_EXPOSURE_INTERNET
        return NETWORK_EXPOSURE_INTERNAL

    def _is_publicly_accessible(
        self, repo_policy: dict[str, Any] | None
    ) -> bool:
        """Check if repository is publicly accessible based on policy."""
        if not repo_policy:
            return False

        statements = repo_policy.get("Statement", [])
        for statement in statements:
            effect = statement.get("Effect", "").upper()
            principal = statement.get("Principal", {})

            if effect == "ALLOW":
                # Check for public access via wildcard principal
                if principal == "*":
                    return True
                if isinstance(principal, dict):
                    aws_principal = principal.get("AWS", "")
                    if aws_principal == "*":
                        return True
                    # Check for list of principals containing wildcard
                    if isinstance(aws_principal, list) and "*" in aws_principal:
                        return True

        return False

    def _create_image_assets(
        self,
        repo_name: str,
        repo_arn: str,
        images: list[dict[str, Any]],
        now: Any,
    ) -> list[Asset]:
        """Create Asset objects for individual images."""
        assets: list[Asset] = []

        for image in images:
            image_digest = image.get("imageDigest", "")
            if not image_digest:
                continue

            # Build image ARN
            image_arn = f"{repo_arn}/image/{image_digest}"

            # Get image tags
            image_tags = image.get("imageTags", [])
            primary_tag = image_tags[0] if image_tags else "untagged"
            image_name = f"{repo_name}:{primary_tag}"

            # Get scan results
            scan_status = image.get("imageScanStatus", {})
            scan_findings = image.get("imageScanFindingsSummary", {})

            # Determine severity counts from scan
            finding_severity_counts = scan_findings.get(
                "findingSeverityCounts", {}
            )

            raw_config: dict[str, Any] = {
                "repository_name": repo_name,
                "repository_arn": repo_arn,
                "image_digest": image_digest,
                "image_tags": image_tags,
                "primary_tag": primary_tag,
                "image_size_bytes": image.get("imageSizeInBytes", 0),
                "image_size_mb": round(
                    image.get("imageSizeInBytes", 0) / (1024 * 1024), 2
                ),
                "image_pushed_at": (
                    image["imagePushedAt"].isoformat()
                    if image.get("imagePushedAt")
                    else None
                ),
                "image_manifest_media_type": image.get("imageManifestMediaType"),
                "artifact_media_type": image.get("artifactMediaType"),
                "last_recorded_pull_time": (
                    image["lastRecordedPullTime"].isoformat()
                    if image.get("lastRecordedPullTime")
                    else None
                ),
                # Scan information
                "scan_status": scan_status.get("status"),
                "scan_status_description": scan_status.get("description"),
                "is_scanned": scan_status.get("status") == "COMPLETE",
                "scan_completed_at": (
                    scan_findings["imageScanCompletedAt"].isoformat()
                    if scan_findings.get("imageScanCompletedAt")
                    else None
                ),
                "vulnerability_source_updated_at": (
                    scan_findings["vulnerabilitySourceUpdatedAt"].isoformat()
                    if scan_findings.get("vulnerabilitySourceUpdatedAt")
                    else None
                ),
                # Vulnerability counts
                "finding_severity_counts": finding_severity_counts,
                "critical_count": finding_severity_counts.get("CRITICAL", 0),
                "high_count": finding_severity_counts.get("HIGH", 0),
                "medium_count": finding_severity_counts.get("MEDIUM", 0),
                "low_count": finding_severity_counts.get("LOW", 0),
                "informational_count": finding_severity_counts.get(
                    "INFORMATIONAL", 0
                ),
                "undefined_count": finding_severity_counts.get("UNDEFINED", 0),
                "total_findings": sum(finding_severity_counts.values()),
                "has_critical_vulnerabilities": finding_severity_counts.get(
                    "CRITICAL", 0
                ) > 0,
                "has_high_vulnerabilities": finding_severity_counts.get(
                    "HIGH", 0
                ) > 0,
            }

            asset = Asset(
                id=image_arn,
                cloud_provider="aws",
                account_id=self.account_id,
                region=self._region,
                resource_type="aws_ecr_image",
                name=image_name,
                tags={},  # Images inherit repo tags, not tracked separately
                network_exposure=NETWORK_EXPOSURE_INTERNAL,
                created_at=image.get("imagePushedAt", now),
                last_seen=now,
                raw_config=raw_config,
            )
            assets.append(asset)

        return assets

    def _collect_image_scan_findings(self) -> list[Finding]:
        """Collect vulnerability findings from ECR image scans."""
        ecr = self._get_client("ecr")
        findings: list[Finding] = []
        now = self._now()

        # Iterate through repositories
        for repo in self._paginate(
            ecr, "describe_repositories", "repositories"
        ):
            repo_name = repo["repositoryName"]
            repo_arn = repo["repositoryArn"]

            # Get images with scan findings
            try:
                for image in self._paginate(
                    ecr, "describe_images", "imageDetails",
                    repositoryName=repo_name,
                    filter={"tagStatus": "ANY"}
                ):
                    image_digest = image.get("imageDigest", "")
                    scan_status = image.get("imageScanStatus", {})

                    if scan_status.get("status") != "COMPLETE":
                        continue

                    # Get detailed scan findings
                    try:
                        scan_response = ecr.describe_image_scan_findings(
                            repositoryName=repo_name,
                            imageId={"imageDigest": image_digest},
                        )
                        scan_findings = scan_response.get(
                            "imageScanFindings", {}
                        ).get("findings", [])

                        for vuln in scan_findings:
                            finding = self._convert_scan_finding_to_finding(
                                vuln, repo_name, repo_arn, image_digest,
                                image.get("imageTags", []), now
                            )
                            if finding:
                                findings.append(finding)

                    except Exception as e:
                        logger.debug(
                            f"Could not get scan findings for "
                            f"{repo_name}:{image_digest}: {e}"
                        )

            except Exception as e:
                logger.debug(f"Could not get images for {repo_name}: {e}")

        return findings

    def _convert_scan_finding_to_finding(
        self,
        vuln: dict[str, Any],
        repo_name: str,
        repo_arn: str,
        image_digest: str,
        image_tags: list[str],
        now: Any,
    ) -> Finding | None:
        """Convert an ECR scan finding to a Finding object."""
        name = vuln.get("name", "")
        if not name:
            return None

        # Map ECR severity to our Severity enum
        severity = self._map_severity(vuln.get("severity", "UNDEFINED"))

        # Extract CVE information
        cve_id = None
        cvss_score = None
        attributes = vuln.get("attributes", [])
        for attr in attributes:
            attr_key = attr.get("key", "")
            if attr_key == "CVSS2_SCORE":
                try:
                    cvss_score = float(attr.get("value", 0))
                except (ValueError, TypeError):
                    pass
            elif attr_key == "CVSS3_SCORE":
                try:
                    cvss_score = float(attr.get("value", 0))
                except (ValueError, TypeError):
                    pass

        # Check if name is a CVE ID
        if name.upper().startswith("CVE-"):
            cve_id = name.upper()

        # Build asset ID for the image
        image_arn = f"{repo_arn}/image/{image_digest}"
        primary_tag = image_tags[0] if image_tags else "untagged"

        # Extract package information
        package_name = None
        installed_version = None
        fixed_version = None
        for attr in attributes:
            attr_key = attr.get("key", "")
            if attr_key == "package_name":
                package_name = attr.get("value")
            elif attr_key == "package_version":
                installed_version = attr.get("value")
            elif attr_key == "patched_version":
                fixed_version = attr.get("value")

        # Generate finding ID (deterministic)
        finding_id = f"ecr-vuln-{repo_name}-{image_digest[:12]}-{name}"

        return Finding(
            id=finding_id,
            asset_id=image_arn,
            finding_type=FindingType.VULNERABILITY,
            severity=severity,
            status=FindingStatus.OPEN,
            title=f"Vulnerability {name} in {repo_name}:{primary_tag}",
            description=(
                vuln.get("description", f"Vulnerability {name} found in container image")
            ),
            first_seen=now,
            last_seen=now,
            # CSPM fields (not used for vulnerabilities)
            rule_id=None,
            resource_path=None,
            expected_value=None,
            actual_value=None,
            # Vulnerability fields
            cve_id=cve_id,
            cvss_score=cvss_score,
            package_name=package_name,
            installed_version=installed_version,
            fixed_version=fixed_version,
            # Compliance
            compliance_frameworks=[],
            # Remediation
            remediation_guidance=(
                f"Update package {package_name} to version {fixed_version}"
                if package_name and fixed_version
                else f"Apply security updates to address {name}"
            ),
        )

    def _map_severity(self, ecr_severity: str) -> Severity:
        """Map ECR severity to our Severity enum."""
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFORMATIONAL": Severity.INFO,
            "UNDEFINED": Severity.INFO,
        }
        return severity_map.get(ecr_severity.upper(), Severity.INFO)
