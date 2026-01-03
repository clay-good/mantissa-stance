"""
AWS S3 Data Scanner for DSPM.

Scans S3 buckets to detect sensitive data using sampling and
pattern matching.
"""

from __future__ import annotations

import logging
import time
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
from stance.dspm.detector import DetectionResult

logger = logging.getLogger(__name__)

# Import boto3 optionally
try:
    import boto3
    from botocore.exceptions import ClientError

    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    boto3 = None  # type: ignore
    ClientError = Exception  # type: ignore


class S3DataScanner(BaseDataScanner):
    """
    AWS S3 storage scanner for sensitive data detection.

    Samples objects from S3 buckets and scans content to identify
    PII, PCI, PHI, and other sensitive data patterns.

    All operations are read-only.
    """

    storage_type = "s3"

    def __init__(
        self,
        config: ScanConfig | None = None,
        session: Any | None = None,
        region: str = "us-east-1",
    ):
        """
        Initialize S3 scanner.

        Args:
            config: Optional scan configuration
            session: Optional boto3 Session
            region: AWS region
        """
        super().__init__(config)

        if not BOTO3_AVAILABLE:
            raise ImportError(
                "boto3 is required for S3 scanning. Install with: pip install boto3"
            )

        self._session = session or boto3.Session()
        self._region = region
        self._s3_client = self._session.client("s3", region_name=region)

    def scan_bucket(self, bucket_name: str) -> ScanResult:
        """
        Scan an S3 bucket for sensitive data.

        Args:
            bucket_name: Name of the S3 bucket

        Returns:
            Scan result with findings and summary
        """
        scan_id = str(uuid.uuid4())[:8]
        started_at = datetime.now(timezone.utc)

        logger.info(f"Starting S3 scan: bucket={bucket_name}, scan_id={scan_id}")

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

                object_key = obj.get("Key", "")
                object_size = obj.get("Size", 0)

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

        except ClientError as e:
            error_msg = f"S3 error: {e.response.get('Error', {}).get('Message', str(e))}"
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
            f"S3 scan complete: {summary.total_objects_scanned} objects, "
            f"{summary.total_findings} findings, "
            f"{summary.scan_duration_seconds:.2f}s"
        )

        return result

    def scan_object(self, bucket_name: str, object_key: str) -> ScanFinding | None:
        """
        Scan a specific S3 object for sensitive data.

        Args:
            bucket_name: S3 bucket name
            object_key: Object key

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
                # Binary file, skip
                logger.debug(f"Skipping binary file: {object_key}")
                return None

            # Scan the content
            detection_result = self._detector.scan_records(
                records=[{"content": text_content}],
                asset_id=f"s3://{bucket_name}/{object_key}",
                asset_type="s3_object",
                sample_size=1,
            )

            # Get bucket metadata for context
            bucket_metadata = self.get_bucket_metadata(bucket_name)

            # Create finding if sensitive data detected
            return self._create_finding_from_detection(
                bucket_name, object_key, detection_result, bucket_metadata
            )

        except ClientError as e:
            logger.warning(f"Error scanning {object_key}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Error scanning {object_key}: {type(e).__name__}: {e}")
            return None

    def list_objects(
        self, bucket_name: str, prefix: str = ""
    ) -> Iterator[dict[str, Any]]:
        """
        List objects in an S3 bucket.

        Args:
            bucket_name: S3 bucket name
            prefix: Optional prefix filter

        Yields:
            Object metadata dictionaries
        """
        paginator = self._s3_client.get_paginator("list_objects_v2")
        page_config = {"Bucket": bucket_name}
        if prefix:
            page_config["Prefix"] = prefix

        for page in paginator.paginate(**page_config):
            for obj in page.get("Contents", []):
                yield {
                    "Key": obj.get("Key", ""),
                    "Size": obj.get("Size", 0),
                    "LastModified": obj.get("LastModified"),
                    "ETag": obj.get("ETag", ""),
                    "StorageClass": obj.get("StorageClass", "STANDARD"),
                }

    def get_object_content(
        self, bucket_name: str, object_key: str, max_bytes: int | None = None
    ) -> bytes | None:
        """
        Get S3 object content (or sample).

        Args:
            bucket_name: S3 bucket name
            object_key: Object key
            max_bytes: Maximum bytes to read

        Returns:
            Object content as bytes
        """
        try:
            get_params: dict[str, Any] = {"Bucket": bucket_name, "Key": object_key}

            if max_bytes:
                get_params["Range"] = f"bytes=0-{max_bytes - 1}"

            response = self._s3_client.get_object(**get_params)
            return response["Body"].read()

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("NoSuchKey", "AccessDenied"):
                logger.debug(f"Cannot access {object_key}: {error_code}")
                return None
            raise

    def get_bucket_metadata(self, bucket_name: str) -> dict[str, Any]:
        """
        Get S3 bucket metadata.

        Args:
            bucket_name: S3 bucket name

        Returns:
            Bucket metadata including encryption, public access status
        """
        metadata: dict[str, Any] = {
            "bucket_name": bucket_name,
            "encrypted": False,
            "encryption_type": None,
            "public_access": False,
            "versioning": False,
            "logging": False,
        }

        try:
            # Check encryption
            try:
                encryption = self._s3_client.get_bucket_encryption(Bucket=bucket_name)
                rules = encryption.get("ServerSideEncryptionConfiguration", {}).get(
                    "Rules", []
                )
                if rules:
                    metadata["encrypted"] = True
                    sse_algo = (
                        rules[0]
                        .get("ApplyServerSideEncryptionByDefault", {})
                        .get("SSEAlgorithm", "")
                    )
                    metadata["encryption_type"] = sse_algo
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") != "ServerSideEncryptionConfigurationNotFoundError":
                    pass  # Encryption not configured

            # Check public access block
            try:
                public_access = self._s3_client.get_public_access_block(
                    Bucket=bucket_name
                )
                config = public_access.get("PublicAccessBlockConfiguration", {})
                # If all blocks are True, bucket is not public
                all_blocked = all([
                    config.get("BlockPublicAcls", False),
                    config.get("IgnorePublicAcls", False),
                    config.get("BlockPublicPolicy", False),
                    config.get("RestrictPublicBuckets", False),
                ])
                metadata["public_access"] = not all_blocked
            except ClientError:
                # If we can't get public access block, assume it might be public
                metadata["public_access"] = True

            # Check versioning
            try:
                versioning = self._s3_client.get_bucket_versioning(Bucket=bucket_name)
                metadata["versioning"] = versioning.get("Status") == "Enabled"
            except ClientError:
                pass

            # Check logging
            try:
                logging_config = self._s3_client.get_bucket_logging(Bucket=bucket_name)
                metadata["logging"] = "LoggingEnabled" in logging_config
            except ClientError:
                pass

        except ClientError as e:
            logger.warning(f"Error getting bucket metadata: {e}")

        return metadata

    def get_bucket_location(self, bucket_name: str) -> str:
        """
        Get the region where a bucket is located.

        Args:
            bucket_name: S3 bucket name

        Returns:
            AWS region name
        """
        try:
            response = self._s3_client.get_bucket_location(Bucket=bucket_name)
            location = response.get("LocationConstraint")
            # None means us-east-1
            return location if location else "us-east-1"
        except ClientError:
            return self._region
