"""
Google Cloud Storage Data Scanner for DSPM.

Scans GCS buckets to detect sensitive data using sampling and
pattern matching.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Iterator

from stance.dspm.scanners.base import (
    BaseDataScanner,
    ScanConfig,
    ScanResult,
    ScanFinding,
    ScanSummary,
    FindingSeverity,
)

logger = logging.getLogger(__name__)

# Import google-cloud-storage optionally
try:
    from google.cloud import storage
    from google.api_core.exceptions import GoogleAPIError, NotFound, Forbidden

    GCS_AVAILABLE = True
except ImportError:
    GCS_AVAILABLE = False
    storage = None  # type: ignore
    GoogleAPIError = Exception  # type: ignore
    NotFound = Exception  # type: ignore
    Forbidden = Exception  # type: ignore


class GCSDataScanner(BaseDataScanner):
    """
    Google Cloud Storage scanner for sensitive data detection.

    Samples objects from GCS buckets and scans content to identify
    PII, PCI, PHI, and other sensitive data patterns.

    All operations are read-only.
    """

    storage_type = "gcs"

    def __init__(
        self,
        config: ScanConfig | None = None,
        project: str | None = None,
        credentials: Any | None = None,
    ):
        """
        Initialize GCS scanner.

        Args:
            config: Optional scan configuration
            project: GCP project ID
            credentials: Optional credentials object
        """
        super().__init__(config)

        if not GCS_AVAILABLE:
            raise ImportError(
                "google-cloud-storage is required for GCS scanning. "
                "Install with: pip install google-cloud-storage"
            )

        self._project = project
        self._client = storage.Client(project=project, credentials=credentials)

    def scan_bucket(self, bucket_name: str) -> ScanResult:
        """
        Scan a GCS bucket for sensitive data.

        Args:
            bucket_name: Name of the GCS bucket

        Returns:
            Scan result with findings and summary
        """
        scan_id = str(uuid.uuid4())[:8]
        started_at = datetime.now(timezone.utc)

        logger.info(f"Starting GCS scan: bucket={bucket_name}, scan_id={scan_id}")

        result = ScanResult(
            scan_id=scan_id,
            storage_type=self.storage_type,
            target=bucket_name,
            config=self._config,
            started_at=started_at,
        )

        summary = ScanSummary()
        findings: list[ScanFinding] = []

        try:
            # Get bucket metadata
            bucket_metadata = self.get_bucket_metadata(bucket_name)

            # Scan objects
            objects_scanned = 0
            for obj in self.list_objects(bucket_name):
                if self._config.sample_size and objects_scanned >= self._config.sample_size:
                    break

                object_key = obj.get("name", "")
                object_size = obj.get("size", 0)

                # Check if object should be scanned
                should_scan, skip_reason = self._should_scan_object(
                    object_key, object_size
                )

                if not should_scan:
                    summary.total_objects_skipped += 1
                    logger.debug(f"Skipping {object_key}: {skip_reason}")
                    continue

                # Scan the object
                finding = self.scan_object(bucket_name, object_key)
                if finding:
                    findings.append(finding)
                    summary.total_findings += 1

                    # Update severity counts
                    sev = finding.severity.value
                    summary.findings_by_severity[sev] = (
                        summary.findings_by_severity.get(sev, 0) + 1
                    )

                    # Update category counts
                    for cat in finding.categories:
                        cat_val = cat.value
                        summary.findings_by_category[cat_val] = (
                            summary.findings_by_category.get(cat_val, 0) + 1
                        )

                objects_scanned += 1
                summary.total_objects_scanned += 1
                summary.total_bytes_scanned += min(
                    object_size, self._config.content_sample_bytes
                )

        except GoogleAPIError as e:
            error_msg = f"GCS error: {str(e)}"
            summary.errors.append(error_msg)
            logger.error(error_msg)
        except Exception as e:
            error_msg = f"Scan error: {type(e).__name__}: {str(e)}"
            summary.errors.append(error_msg)
            logger.error(error_msg)

        # Finalize result
        completed_at = datetime.now(timezone.utc)
        summary.scan_duration_seconds = (completed_at - started_at).total_seconds()

        result.findings = findings
        result.summary = summary
        result.completed_at = completed_at

        logger.info(
            f"GCS scan complete: {summary.total_objects_scanned} objects, "
            f"{summary.total_findings} findings, "
            f"{summary.scan_duration_seconds:.2f}s"
        )

        return result

    def scan_object(self, bucket_name: str, object_key: str) -> ScanFinding | None:
        """
        Scan a specific GCS object for sensitive data.

        Args:
            bucket_name: GCS bucket name
            object_key: Object name/key

        Returns:
            ScanFinding if sensitive data found, None otherwise
        """
        try:
            # Get object content sample
            content = self.get_object_content(
                bucket_name, object_key, self._config.content_sample_bytes
            )

            if content is None:
                return None

            # Try to decode as text
            text_content = self._decode_content(content)
            if text_content is None:
                logger.debug(f"Skipping binary file: {object_key}")
                return None

            # Scan the content
            detection_result = self._detector.scan_records(
                records=[{"content": text_content}],
                asset_id=f"gs://{bucket_name}/{object_key}",
                asset_type="gcs_object",
                sample_size=1,
            )

            # Get bucket metadata for context
            bucket_metadata = self.get_bucket_metadata(bucket_name)

            # Create finding if sensitive data detected
            return self._create_finding_from_detection(
                bucket_name, object_key, detection_result, bucket_metadata
            )

        except (NotFound, Forbidden) as e:
            logger.debug(f"Cannot access {object_key}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Error scanning {object_key}: {type(e).__name__}: {e}")
            return None

    def list_objects(
        self, bucket_name: str, prefix: str = ""
    ) -> Iterator[dict[str, Any]]:
        """
        List objects in a GCS bucket.

        Args:
            bucket_name: GCS bucket name
            prefix: Optional prefix filter

        Yields:
            Object metadata dictionaries
        """
        bucket = self._client.bucket(bucket_name)
        blobs = bucket.list_blobs(prefix=prefix if prefix else None)

        for blob in blobs:
            yield {
                "name": blob.name,
                "size": blob.size or 0,
                "updated": blob.updated,
                "content_type": blob.content_type,
                "storage_class": blob.storage_class,
                "md5_hash": blob.md5_hash,
            }

    def get_object_content(
        self, bucket_name: str, object_key: str, max_bytes: int | None = None
    ) -> bytes | None:
        """
        Get GCS object content (or sample).

        Args:
            bucket_name: GCS bucket name
            object_key: Object name
            max_bytes: Maximum bytes to read

        Returns:
            Object content as bytes
        """
        try:
            bucket = self._client.bucket(bucket_name)
            blob = bucket.blob(object_key)

            if max_bytes:
                # Use range read for sampling
                return blob.download_as_bytes(start=0, end=max_bytes - 1)
            else:
                return blob.download_as_bytes()

        except NotFound:
            logger.debug(f"Object not found: {object_key}")
            return None
        except Forbidden:
            logger.debug(f"Access denied: {object_key}")
            return None

    def get_bucket_metadata(self, bucket_name: str) -> dict[str, Any]:
        """
        Get GCS bucket metadata.

        Args:
            bucket_name: GCS bucket name

        Returns:
            Bucket metadata including encryption, public access status
        """
        metadata: dict[str, Any] = {
            "bucket_name": bucket_name,
            "encrypted": True,  # GCS always encrypts at rest
            "encryption_type": "Google-managed",
            "public_access": False,
            "uniform_bucket_level_access": False,
            "versioning": False,
            "location": None,
        }

        try:
            bucket = self._client.get_bucket(bucket_name)

            # Location
            metadata["location"] = bucket.location

            # Check for CMEK
            if bucket.default_kms_key_name:
                metadata["encryption_type"] = "Customer-managed (CMEK)"
                metadata["kms_key"] = bucket.default_kms_key_name

            # Check uniform bucket-level access (prevents public ACLs)
            iam_config = bucket.iam_configuration
            metadata["uniform_bucket_level_access"] = (
                iam_config.uniform_bucket_level_access_enabled
                if iam_config
                else False
            )

            # Check public access prevention
            if iam_config and hasattr(iam_config, "public_access_prevention"):
                pap = iam_config.public_access_prevention
                metadata["public_access"] = pap != "enforced"
            else:
                # Check IAM for allUsers/allAuthenticatedUsers
                try:
                    policy = bucket.get_iam_policy()
                    public_members = {"allUsers", "allAuthenticatedUsers"}
                    for binding in policy.bindings:
                        if public_members.intersection(set(binding.get("members", []))):
                            metadata["public_access"] = True
                            break
                except Exception:
                    pass

            # Versioning
            metadata["versioning"] = bucket.versioning_enabled

        except NotFound:
            logger.warning(f"Bucket not found: {bucket_name}")
        except Forbidden:
            logger.warning(f"Access denied to bucket: {bucket_name}")
        except Exception as e:
            logger.warning(f"Error getting bucket metadata: {e}")

        return metadata

    def get_bucket_location(self, bucket_name: str) -> str:
        """
        Get the location where a bucket is stored.

        Args:
            bucket_name: GCS bucket name

        Returns:
            GCS location (e.g., US, EU, us-central1)
        """
        try:
            bucket = self._client.get_bucket(bucket_name)
            return bucket.location or "US"
        except Exception:
            return "UNKNOWN"
