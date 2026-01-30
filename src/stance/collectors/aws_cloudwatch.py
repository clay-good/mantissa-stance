"""
AWS CloudWatch collector for Mantissa Stance.

Collects CloudWatch log groups, metric alarms, and their configurations
for security posture assessment.
"""

from __future__ import annotations

import logging
from typing import Any

from stance.collectors.base import BaseCollector
from stance.models import (
    Asset,
    AssetCollection,
    NETWORK_EXPOSURE_ISOLATED,
)

logger = logging.getLogger(__name__)


class CloudWatchCollector(BaseCollector):
    """
    Collects AWS CloudWatch resources.

    Gathers CloudWatch log groups and metric alarms. All API calls are read-only.
    """

    collector_name = "aws_cloudwatch"
    resource_types = [
        "aws_cloudwatch_log_group",
        "aws_cloudwatch_metric_alarm",
    ]

    def collect(self) -> AssetCollection:
        """
        Collect all CloudWatch resources.

        Returns:
            Collection of CloudWatch assets
        """
        assets: list[Asset] = []

        # Collect log groups
        try:
            assets.extend(self._collect_log_groups())
        except Exception as e:
            logger.warning(f"Failed to collect CloudWatch log groups: {e}")

        # Collect metric alarms
        try:
            assets.extend(self._collect_metric_alarms())
        except Exception as e:
            logger.warning(f"Failed to collect CloudWatch metric alarms: {e}")

        return AssetCollection(assets)

    def _collect_log_groups(self) -> list[Asset]:
        """Collect CloudWatch log groups with their configurations."""
        logs = self._get_client("logs")
        assets: list[Asset] = []
        now = self._now()

        try:
            for log_group in self._paginate(
                logs, "describe_log_groups", "logGroups"
            ):
                log_group_name = log_group.get("logGroupName", "")
                log_group_arn = log_group.get("arn", "")

                # Get retention in days
                retention_in_days = log_group.get("retentionInDays")

                # Get KMS key ID if encrypted
                kms_key_id = log_group.get("kmsKeyId")

                # Get metric filters for this log group
                metric_filters = []
                try:
                    filters_response = logs.describe_metric_filters(
                        logGroupName=log_group_name
                    )
                    for mf in filters_response.get("metricFilters", []):
                        metric_filters.append({
                            "filter_name": mf.get("filterName", ""),
                            "filter_pattern": mf.get("filterPattern", ""),
                            "metric_transformations": [
                                {
                                    "metric_name": mt.get("metricName", ""),
                                    "metric_namespace": mt.get("metricNamespace", ""),
                                    "metric_value": mt.get("metricValue", ""),
                                }
                                for mt in mf.get("metricTransformations", [])
                            ],
                        })
                except Exception as e:
                    logger.debug(
                        f"Could not get metric filters for {log_group_name}: {e}"
                    )

                # Get subscription filters
                subscription_filters = []
                try:
                    subs_response = logs.describe_subscription_filters(
                        logGroupName=log_group_name
                    )
                    for sf in subs_response.get("subscriptionFilters", []):
                        subscription_filters.append({
                            "filter_name": sf.get("filterName", ""),
                            "destination_arn": sf.get("destinationArn", ""),
                            "filter_pattern": sf.get("filterPattern", ""),
                        })
                except Exception as e:
                    logger.debug(
                        f"Could not get subscription filters for {log_group_name}: {e}"
                    )

                # Get tags
                tags = {}
                try:
                    tags_response = logs.list_tags_log_group(
                        logGroupName=log_group_name
                    )
                    tags = tags_response.get("tags", {})
                except Exception as e:
                    logger.debug(f"Could not get tags for {log_group_name}: {e}")

                raw_config: dict[str, Any] = {
                    "log_group_name": log_group_name,
                    "log_group_arn": log_group_arn,
                    "creation_time": log_group.get("creationTime"),
                    "retention_in_days": retention_in_days,
                    "has_retention_policy": retention_in_days is not None,
                    "metric_filter_count": log_group.get("metricFilterCount", 0),
                    "stored_bytes": log_group.get("storedBytes", 0),
                    "kms_key_id": kms_key_id,
                    "is_encrypted": kms_key_id is not None,
                    "metric_filters": metric_filters,
                    "subscription_filters": subscription_filters,
                    "has_metric_filters": len(metric_filters) > 0,
                    "has_subscription_filters": len(subscription_filters) > 0,
                }

                # Build ARN if not provided
                if not log_group_arn:
                    log_group_arn = self._build_arn(
                        "logs",
                        "log-group",
                        log_group_name,
                        region=self._region,
                        account_id=self.account_id,
                    )

                assets.append(
                    Asset(
                        id=log_group_arn,
                        cloud_provider="aws",
                        account_id=self.account_id,
                        region=self._region,
                        resource_type="aws_cloudwatch_log_group",
                        name=log_group_name,
                        tags=tags,
                        network_exposure=NETWORK_EXPOSURE_ISOLATED,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing CloudWatch log groups: {e}")
            raise

        return assets

    def _collect_metric_alarms(self) -> list[Asset]:
        """
        Collect CloudWatch metric alarms.

        Also analyzes alarms to determine if required security alarms exist.
        """
        cloudwatch = self._get_client("cloudwatch")
        assets: list[Asset] = []
        now = self._now()

        # Track which security alarms exist
        security_alarm_patterns = {
            "root_login": [
                "root",
                "rootlogin",
                "rootaccount",
                "rootuser",
            ],
            "iam_policy_changes": [
                "iam",
                "policy",
                "iampolicy",
            ],
            "security_group_changes": [
                "securitygroup",
                "sg",
            ],
            "unauthorized_api": [
                "unauthorized",
                "accessdenied",
            ],
        }

        found_security_alarms: dict[str, bool] = {
            "root_login": False,
            "iam_policy_changes": False,
            "security_group_changes": False,
            "unauthorized_api": False,
        }

        all_alarms: list[dict[str, Any]] = []

        try:
            for alarm in self._paginate(
                cloudwatch, "describe_alarms", "MetricAlarms"
            ):
                all_alarms.append(alarm)

        except Exception as e:
            logger.error(f"Error listing CloudWatch metric alarms: {e}")
            raise

        # First pass: identify which security alarms exist
        for alarm in all_alarms:
            alarm_name = alarm.get("AlarmName", "").lower()
            alarm_description = (alarm.get("AlarmDescription") or "").lower()
            metric_name = alarm.get("MetricName", "").lower()
            namespace = alarm.get("Namespace", "").lower()

            combined_text = f"{alarm_name} {alarm_description} {metric_name}"

            for alarm_type, patterns in security_alarm_patterns.items():
                for pattern in patterns:
                    if pattern in combined_text:
                        found_security_alarms[alarm_type] = True
                        break

        # Second pass: create assets
        for alarm in all_alarms:
            alarm_arn = alarm.get("AlarmArn", "")
            alarm_name = alarm.get("AlarmName", "")

            raw_config: dict[str, Any] = {
                "alarm_arn": alarm_arn,
                "alarm_name": alarm_name,
                "alarm_description": alarm.get("AlarmDescription", ""),
                "state_value": alarm.get("StateValue", ""),
                "state_reason": alarm.get("StateReason", ""),
                "metric_name": alarm.get("MetricName", ""),
                "namespace": alarm.get("Namespace", ""),
                "statistic": alarm.get("Statistic", ""),
                "period": alarm.get("Period", 0),
                "evaluation_periods": alarm.get("EvaluationPeriods", 0),
                "threshold": alarm.get("Threshold", 0),
                "comparison_operator": alarm.get("ComparisonOperator", ""),
                "treat_missing_data": alarm.get("TreatMissingData", ""),
                "actions_enabled": alarm.get("ActionsEnabled", False),
                "alarm_actions": alarm.get("AlarmActions", []),
                "ok_actions": alarm.get("OKActions", []),
                "insufficient_data_actions": alarm.get(
                    "InsufficientDataActions", []
                ),
                "dimensions": [
                    {"name": d.get("Name", ""), "value": d.get("Value", "")}
                    for d in alarm.get("Dimensions", [])
                ],
                # Security alarm existence flags - set on all alarms for policy evaluation
                "alarm_for_root_login_exists": found_security_alarms["root_login"],
                "alarm_for_iam_policy_changes_exists": found_security_alarms[
                    "iam_policy_changes"
                ],
                "alarm_for_security_group_changes_exists": found_security_alarms[
                    "security_group_changes"
                ],
                "alarm_for_unauthorized_api_exists": found_security_alarms[
                    "unauthorized_api"
                ],
            }

            # Get tags
            tags = {}
            try:
                tags_response = cloudwatch.list_tags_for_resource(
                    ResourceARN=alarm_arn
                )
                for tag in tags_response.get("Tags", []):
                    tags[tag.get("Key", "")] = tag.get("Value", "")
            except Exception as e:
                logger.debug(f"Could not get tags for alarm {alarm_name}: {e}")

            assets.append(
                Asset(
                    id=alarm_arn,
                    cloud_provider="aws",
                    account_id=self.account_id,
                    region=self._region,
                    resource_type="aws_cloudwatch_metric_alarm",
                    name=alarm_name,
                    tags=tags,
                    network_exposure=NETWORK_EXPOSURE_ISOLATED,
                    last_seen=now,
                    raw_config=raw_config,
                )
            )

        # If no alarms exist, create a synthetic asset to trigger findings
        # for missing security alarms
        if not all_alarms:
            synthetic_arn = self._build_arn(
                "cloudwatch",
                "alarm",
                "no-alarms-configured",
                region=self._region,
                account_id=self.account_id,
            )

            assets.append(
                Asset(
                    id=synthetic_arn,
                    cloud_provider="aws",
                    account_id=self.account_id,
                    region=self._region,
                    resource_type="aws_cloudwatch_metric_alarm",
                    name="no-alarms-configured",
                    tags={},
                    network_exposure=NETWORK_EXPOSURE_ISOLATED,
                    last_seen=now,
                    raw_config={
                        "alarm_for_root_login_exists": False,
                        "alarm_for_iam_policy_changes_exists": False,
                        "alarm_for_security_group_changes_exists": False,
                        "alarm_for_unauthorized_api_exists": False,
                        "is_synthetic": True,
                    },
                )
            )

        return assets
