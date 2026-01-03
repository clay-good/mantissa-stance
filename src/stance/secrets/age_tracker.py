"""
Secret Age Tracker Module

Tracks secret ages, analyzes rotation history, and identifies secrets
that are overdue for rotation based on configurable thresholds.

Part of Phase 82: Secret Rotation Monitoring
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
import statistics
import logging

from stance.secrets.inventory import (
    SecretInventory,
    SecretInventoryItem,
    SecretType,
    SecretSource,
    SecretStatus,
)


logger = logging.getLogger(__name__)


class AgeStatus(Enum):
    """Status of secret age relative to policy."""
    FRESH = "fresh"  # Recently created/rotated
    ACCEPTABLE = "acceptable"  # Within acceptable age range
    AGING = "aging"  # Getting old, should rotate soon
    STALE = "stale"  # Past recommended rotation time
    CRITICAL = "critical"  # Severely overdue for rotation
    EXPIRED = "expired"  # Past expiration date
    UNKNOWN = "unknown"  # Cannot determine age


@dataclass
class AgeThresholds:
    """Configurable thresholds for secret age categorization."""
    fresh_days: int = 7  # Considered fresh within this many days
    acceptable_days: int = 30  # Acceptable up to this age
    aging_days: int = 60  # Aging warning threshold
    stale_days: int = 90  # Stale/overdue threshold
    critical_days: int = 180  # Critical overdue threshold

    def get_status(self, age_days: int) -> AgeStatus:
        """Determine age status based on days since creation/rotation."""
        if age_days < 0:
            return AgeStatus.UNKNOWN
        elif age_days <= self.fresh_days:
            return AgeStatus.FRESH
        elif age_days <= self.acceptable_days:
            return AgeStatus.ACCEPTABLE
        elif age_days <= self.aging_days:
            return AgeStatus.AGING
        elif age_days <= self.stale_days:
            return AgeStatus.STALE
        else:
            return AgeStatus.CRITICAL


@dataclass
class SecretTypeThresholds:
    """Type-specific age thresholds based on security best practices."""
    thresholds: Dict[SecretType, AgeThresholds] = field(default_factory=dict)
    default_thresholds: AgeThresholds = field(default_factory=AgeThresholds)

    def __post_init__(self):
        """Initialize type-specific thresholds if not provided."""
        if not self.thresholds:
            self.thresholds = self._get_default_type_thresholds()

    def _get_default_type_thresholds(self) -> Dict[SecretType, AgeThresholds]:
        """Get security best practice thresholds per secret type."""
        return {
            # High-sensitivity credentials - rotate frequently
            SecretType.AWS_ACCESS_KEY: AgeThresholds(
                fresh_days=7, acceptable_days=30, aging_days=60,
                stale_days=90, critical_days=180
            ),
            SecretType.AWS_SECRET_KEY: AgeThresholds(
                fresh_days=7, acceptable_days=30, aging_days=60,
                stale_days=90, critical_days=180
            ),
            SecretType.AZURE_CLIENT_SECRET: AgeThresholds(
                fresh_days=7, acceptable_days=60, aging_days=90,
                stale_days=180, critical_days=365
            ),
            SecretType.GCP_SERVICE_ACCOUNT_KEY: AgeThresholds(
                fresh_days=7, acceptable_days=30, aging_days=60,
                stale_days=90, critical_days=180
            ),

            # Database credentials - moderate rotation
            SecretType.DATABASE_PASSWORD: AgeThresholds(
                fresh_days=7, acceptable_days=60, aging_days=90,
                stale_days=180, critical_days=365
            ),
            SecretType.MYSQL_PASSWORD: AgeThresholds(
                fresh_days=7, acceptable_days=60, aging_days=90,
                stale_days=180, critical_days=365
            ),
            SecretType.POSTGRESQL_PASSWORD: AgeThresholds(
                fresh_days=7, acceptable_days=60, aging_days=90,
                stale_days=180, critical_days=365
            ),
            SecretType.MONGODB_PASSWORD: AgeThresholds(
                fresh_days=7, acceptable_days=60, aging_days=90,
                stale_days=180, critical_days=365
            ),
            SecretType.REDIS_PASSWORD: AgeThresholds(
                fresh_days=7, acceptable_days=60, aging_days=90,
                stale_days=180, critical_days=365
            ),

            # API keys - depends on sensitivity
            SecretType.API_KEY: AgeThresholds(
                fresh_days=7, acceptable_days=90, aging_days=180,
                stale_days=270, critical_days=365
            ),
            SecretType.JWT_SECRET: AgeThresholds(
                fresh_days=7, acceptable_days=30, aging_days=60,
                stale_days=90, critical_days=180
            ),
            SecretType.OAUTH_TOKEN: AgeThresholds(
                fresh_days=1, acceptable_days=7, aging_days=14,
                stale_days=30, critical_days=60
            ),
            SecretType.OAUTH_REFRESH_TOKEN: AgeThresholds(
                fresh_days=7, acceptable_days=30, aging_days=60,
                stale_days=90, critical_days=180
            ),

            # Certificates - longer lifecycle
            SecretType.TLS_CERTIFICATE: AgeThresholds(
                fresh_days=30, acceptable_days=180, aging_days=270,
                stale_days=330, critical_days=365
            ),
            SecretType.SSL_CERTIFICATE: AgeThresholds(
                fresh_days=30, acceptable_days=180, aging_days=270,
                stale_days=330, critical_days=365
            ),

            # SSH keys - moderate rotation
            SecretType.SSH_PRIVATE_KEY: AgeThresholds(
                fresh_days=30, acceptable_days=90, aging_days=180,
                stale_days=270, critical_days=365
            ),
            SecretType.SSH_PUBLIC_KEY: AgeThresholds(
                fresh_days=30, acceptable_days=180, aging_days=270,
                stale_days=365, critical_days=730
            ),

            # Encryption keys - depends on usage
            SecretType.ENCRYPTION_KEY: AgeThresholds(
                fresh_days=30, acceptable_days=180, aging_days=365,
                stale_days=545, critical_days=730
            ),
            SecretType.PGP_PRIVATE_KEY: AgeThresholds(
                fresh_days=30, acceptable_days=365, aging_days=545,
                stale_days=730, critical_days=1095
            ),

            # Service credentials
            SecretType.SMTP_PASSWORD: AgeThresholds(
                fresh_days=7, acceptable_days=90, aging_days=180,
                stale_days=270, critical_days=365
            ),
            SecretType.LDAP_PASSWORD: AgeThresholds(
                fresh_days=7, acceptable_days=60, aging_days=90,
                stale_days=180, critical_days=365
            ),

            # Third-party integrations
            SecretType.GITHUB_TOKEN: AgeThresholds(
                fresh_days=7, acceptable_days=30, aging_days=60,
                stale_days=90, critical_days=180
            ),
            SecretType.SLACK_TOKEN: AgeThresholds(
                fresh_days=7, acceptable_days=90, aging_days=180,
                stale_days=270, critical_days=365
            ),
            SecretType.STRIPE_KEY: AgeThresholds(
                fresh_days=7, acceptable_days=90, aging_days=180,
                stale_days=270, critical_days=365
            ),
            SecretType.TWILIO_AUTH_TOKEN: AgeThresholds(
                fresh_days=7, acceptable_days=90, aging_days=180,
                stale_days=270, critical_days=365
            ),
            SecretType.SENDGRID_API_KEY: AgeThresholds(
                fresh_days=7, acceptable_days=90, aging_days=180,
                stale_days=270, critical_days=365
            ),
        }

    def get_thresholds(self, secret_type: SecretType) -> AgeThresholds:
        """Get thresholds for a specific secret type."""
        return self.thresholds.get(secret_type, self.default_thresholds)


@dataclass
class SecretAge:
    """Detailed age information for a single secret."""
    secret_id: str
    secret_name: str
    secret_type: SecretType
    source: SecretSource

    # Age metrics
    created_at: Optional[datetime] = None
    last_rotated_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None

    # Calculated fields
    age_days: int = -1
    days_since_rotation: int = -1
    days_until_expiration: int = -1

    # Status
    age_status: AgeStatus = AgeStatus.UNKNOWN
    rotation_status: AgeStatus = AgeStatus.UNKNOWN
    is_expired: bool = False

    # Risk assessment
    risk_score: float = 0.0
    risk_factors: List[str] = field(default_factory=list)

    # Recommendations
    recommended_action: str = ""
    urgency_level: str = "low"


@dataclass
class AgeDistribution:
    """Statistical distribution of secret ages."""
    count: int = 0
    min_days: int = 0
    max_days: int = 0
    mean_days: float = 0.0
    median_days: float = 0.0
    std_dev_days: float = 0.0

    # Distribution by status
    fresh_count: int = 0
    acceptable_count: int = 0
    aging_count: int = 0
    stale_count: int = 0
    critical_count: int = 0
    expired_count: int = 0
    unknown_count: int = 0

    # Percentages
    fresh_pct: float = 0.0
    acceptable_pct: float = 0.0
    aging_pct: float = 0.0
    stale_pct: float = 0.0
    critical_pct: float = 0.0
    expired_pct: float = 0.0


@dataclass
class RotationHistory:
    """Rotation history analysis for a secret."""
    secret_id: str
    secret_name: str
    rotation_dates: List[datetime] = field(default_factory=list)
    rotation_intervals: List[int] = field(default_factory=list)  # Days between rotations

    # Statistics
    rotation_count: int = 0
    avg_rotation_interval: float = 0.0
    min_rotation_interval: int = 0
    max_rotation_interval: int = 0

    # Assessment
    rotation_consistency: str = "unknown"  # regular, irregular, never
    is_auto_rotated: bool = False
    compliance_status: str = "unknown"


@dataclass
class SecretAgeReport:
    """Comprehensive secret age analysis report."""
    generated_at: datetime = field(default_factory=datetime.utcnow)
    report_id: str = ""

    # Summary metrics
    total_secrets: int = 0
    analyzed_secrets: int = 0
    secrets_needing_action: int = 0

    # Overall distribution
    overall_distribution: AgeDistribution = field(default_factory=AgeDistribution)

    # Distribution by type
    distribution_by_type: Dict[SecretType, AgeDistribution] = field(default_factory=dict)

    # Distribution by source
    distribution_by_source: Dict[SecretSource, AgeDistribution] = field(default_factory=dict)

    # Individual secret ages
    secret_ages: List[SecretAge] = field(default_factory=list)

    # Priority lists
    critical_secrets: List[SecretAge] = field(default_factory=list)
    stale_secrets: List[SecretAge] = field(default_factory=list)
    expiring_soon: List[SecretAge] = field(default_factory=list)

    # Rotation history
    rotation_histories: List[RotationHistory] = field(default_factory=list)

    # Risk summary
    overall_risk_score: float = 0.0
    risk_level: str = "low"

    # Recommendations
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "generated_at": self.generated_at.isoformat(),
            "report_id": self.report_id,
            "summary": {
                "total_secrets": self.total_secrets,
                "analyzed_secrets": self.analyzed_secrets,
                "secrets_needing_action": self.secrets_needing_action,
                "overall_risk_score": self.overall_risk_score,
                "risk_level": self.risk_level,
            },
            "distribution": {
                "fresh": self.overall_distribution.fresh_count,
                "acceptable": self.overall_distribution.acceptable_count,
                "aging": self.overall_distribution.aging_count,
                "stale": self.overall_distribution.stale_count,
                "critical": self.overall_distribution.critical_count,
                "expired": self.overall_distribution.expired_count,
            },
            "critical_secrets_count": len(self.critical_secrets),
            "stale_secrets_count": len(self.stale_secrets),
            "expiring_soon_count": len(self.expiring_soon),
            "recommendations": self.recommendations,
        }


class SecretAgeTracker:
    """
    Tracks and analyzes secret ages across the inventory.

    Provides comprehensive age analysis, rotation tracking, and
    risk assessment for secrets management.
    """

    def __init__(
        self,
        type_thresholds: Optional[SecretTypeThresholds] = None,
        expiring_soon_days: int = 30,
    ):
        """
        Initialize the age tracker.

        Args:
            type_thresholds: Custom thresholds per secret type
            expiring_soon_days: Days threshold for "expiring soon" alerts
        """
        self.type_thresholds = type_thresholds or SecretTypeThresholds()
        self.expiring_soon_days = expiring_soon_days
        self.rotation_histories: Dict[str, RotationHistory] = {}

    def analyze_inventory(
        self,
        inventory: SecretInventory,
        include_rotation_history: bool = True,
    ) -> SecretAgeReport:
        """
        Analyze all secrets in the inventory for age-related issues.

        Args:
            inventory: Secret inventory to analyze
            include_rotation_history: Whether to include rotation history analysis

        Returns:
            Comprehensive age analysis report
        """
        report = SecretAgeReport(
            report_id=f"age-report-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
            total_secrets=len(inventory.secrets),
        )

        secret_ages: List[SecretAge] = []
        age_values: List[int] = []

        for item in inventory.secrets:
            secret_age = self._analyze_secret_age(item)
            secret_ages.append(secret_age)

            if secret_age.age_days >= 0:
                age_values.append(secret_age.age_days)

            # Categorize by urgency
            if secret_age.age_status == AgeStatus.CRITICAL or secret_age.is_expired:
                report.critical_secrets.append(secret_age)
            elif secret_age.age_status == AgeStatus.STALE:
                report.stale_secrets.append(secret_age)

            if secret_age.days_until_expiration >= 0 and \
               secret_age.days_until_expiration <= self.expiring_soon_days:
                report.expiring_soon.append(secret_age)

        report.secret_ages = secret_ages
        report.analyzed_secrets = len(age_values)

        # Calculate overall distribution
        report.overall_distribution = self._calculate_distribution(secret_ages)

        # Calculate distribution by type
        report.distribution_by_type = self._calculate_distribution_by_type(secret_ages)

        # Calculate distribution by source
        report.distribution_by_source = self._calculate_distribution_by_source(secret_ages)

        # Analyze rotation history if requested
        if include_rotation_history:
            report.rotation_histories = self._analyze_rotation_histories(inventory)

        # Calculate risk metrics
        report.secrets_needing_action = (
            len(report.critical_secrets) +
            len(report.stale_secrets) +
            len(report.expiring_soon)
        )
        report.overall_risk_score = self._calculate_overall_risk(secret_ages)
        report.risk_level = self._determine_risk_level(report.overall_risk_score)

        # Generate recommendations
        report.recommendations = self._generate_recommendations(report)

        return report

    def _analyze_secret_age(self, item: SecretInventoryItem) -> SecretAge:
        """Analyze age for a single secret."""
        now = datetime.utcnow()
        thresholds = self.type_thresholds.get_thresholds(item.secret_type)

        secret_age = SecretAge(
            secret_id=item.secret_id,
            secret_name=item.name,
            secret_type=item.secret_type,
            source=item.source,
            created_at=item.metadata.created_at if item.metadata else None,
            last_rotated_at=item.metadata.last_rotated_at if item.metadata else None,
            expires_at=item.metadata.expires_at if item.metadata else None,
        )

        # Calculate age metrics
        if secret_age.created_at:
            secret_age.age_days = (now - secret_age.created_at).days
            secret_age.age_status = thresholds.get_status(secret_age.age_days)

        # Calculate rotation age
        if secret_age.last_rotated_at:
            secret_age.days_since_rotation = (now - secret_age.last_rotated_at).days
            secret_age.rotation_status = thresholds.get_status(secret_age.days_since_rotation)
        elif secret_age.created_at:
            # Never rotated, use creation date
            secret_age.days_since_rotation = secret_age.age_days
            secret_age.rotation_status = thresholds.get_status(secret_age.days_since_rotation)

        # Calculate expiration
        if secret_age.expires_at:
            secret_age.days_until_expiration = (secret_age.expires_at - now).days
            secret_age.is_expired = secret_age.days_until_expiration < 0

        # Check item status
        if item.status == SecretStatus.EXPIRED:
            secret_age.is_expired = True
            secret_age.age_status = AgeStatus.EXPIRED

        # Calculate risk score
        secret_age.risk_score, secret_age.risk_factors = self._calculate_secret_risk(
            secret_age, item
        )

        # Determine recommended action
        secret_age.recommended_action, secret_age.urgency_level = \
            self._determine_recommended_action(secret_age)

        return secret_age

    def _calculate_secret_risk(
        self,
        secret_age: SecretAge,
        item: SecretInventoryItem,
    ) -> Tuple[float, List[str]]:
        """Calculate risk score and factors for a secret."""
        risk_score = 0.0
        risk_factors = []

        # Age-based risk
        age_risk_weights = {
            AgeStatus.FRESH: 0.0,
            AgeStatus.ACCEPTABLE: 0.1,
            AgeStatus.AGING: 0.3,
            AgeStatus.STALE: 0.6,
            AgeStatus.CRITICAL: 0.9,
            AgeStatus.EXPIRED: 1.0,
            AgeStatus.UNKNOWN: 0.5,
        }

        age_risk = age_risk_weights.get(secret_age.age_status, 0.5)
        if age_risk > 0.2:
            risk_factors.append(f"Age status: {secret_age.age_status.value}")
        risk_score += age_risk * 0.3  # 30% weight for age

        # Rotation-based risk
        rotation_risk = age_risk_weights.get(secret_age.rotation_status, 0.5)
        if rotation_risk > 0.2:
            risk_factors.append(f"Rotation status: {secret_age.rotation_status.value}")
        risk_score += rotation_risk * 0.3  # 30% weight for rotation

        # Expiration risk
        if secret_age.is_expired:
            risk_score += 0.3
            risk_factors.append("Secret has expired")
        elif secret_age.days_until_expiration >= 0:
            if secret_age.days_until_expiration <= 7:
                risk_score += 0.25
                risk_factors.append(f"Expires in {secret_age.days_until_expiration} days")
            elif secret_age.days_until_expiration <= 30:
                risk_score += 0.15
                risk_factors.append(f"Expires in {secret_age.days_until_expiration} days")

        # Type-based risk multiplier
        high_risk_types = {
            SecretType.AWS_ACCESS_KEY,
            SecretType.AWS_SECRET_KEY,
            SecretType.DATABASE_PASSWORD,
            SecretType.SSH_PRIVATE_KEY,
            SecretType.ENCRYPTION_KEY,
            SecretType.JWT_SECRET,
        }
        if secret_age.secret_type in high_risk_types:
            risk_score *= 1.2
            risk_factors.append(f"High-risk secret type: {secret_age.secret_type.value}")

        # Source-based adjustments
        if item.source in {SecretSource.CODE_REPOSITORY, SecretSource.ENVIRONMENT_VARIABLE}:
            risk_score *= 1.3
            risk_factors.append(f"Less secure storage: {item.source.value}")

        # Cap at 1.0
        risk_score = min(risk_score, 1.0)

        return risk_score, risk_factors

    def _determine_recommended_action(
        self,
        secret_age: SecretAge,
    ) -> Tuple[str, str]:
        """Determine recommended action and urgency level."""
        if secret_age.is_expired:
            return "Rotate immediately - secret has expired", "critical"

        if secret_age.age_status == AgeStatus.CRITICAL:
            return "Rotate urgently - severely overdue for rotation", "critical"

        if secret_age.days_until_expiration >= 0 and secret_age.days_until_expiration <= 7:
            return f"Rotate soon - expires in {secret_age.days_until_expiration} days", "high"

        if secret_age.age_status == AgeStatus.STALE:
            return "Schedule rotation - past recommended rotation period", "high"

        if secret_age.rotation_status == AgeStatus.STALE:
            return "Consider rotation - approaching rotation threshold", "medium"

        if secret_age.age_status == AgeStatus.AGING:
            return "Monitor - approaching rotation threshold", "low"

        if secret_age.days_until_expiration >= 0 and secret_age.days_until_expiration <= 30:
            return f"Plan rotation - expires in {secret_age.days_until_expiration} days", "medium"

        return "No action required", "none"

    def _calculate_distribution(
        self,
        secret_ages: List[SecretAge],
    ) -> AgeDistribution:
        """Calculate age distribution statistics."""
        dist = AgeDistribution(count=len(secret_ages))

        if not secret_ages:
            return dist

        # Collect age values
        age_values = [sa.age_days for sa in secret_ages if sa.age_days >= 0]

        if age_values:
            dist.min_days = min(age_values)
            dist.max_days = max(age_values)
            dist.mean_days = statistics.mean(age_values)
            dist.median_days = statistics.median(age_values)
            if len(age_values) > 1:
                dist.std_dev_days = statistics.stdev(age_values)

        # Count by status
        for sa in secret_ages:
            if sa.age_status == AgeStatus.FRESH:
                dist.fresh_count += 1
            elif sa.age_status == AgeStatus.ACCEPTABLE:
                dist.acceptable_count += 1
            elif sa.age_status == AgeStatus.AGING:
                dist.aging_count += 1
            elif sa.age_status == AgeStatus.STALE:
                dist.stale_count += 1
            elif sa.age_status == AgeStatus.CRITICAL:
                dist.critical_count += 1
            elif sa.age_status == AgeStatus.EXPIRED:
                dist.expired_count += 1
            else:
                dist.unknown_count += 1

        # Calculate percentages
        total = len(secret_ages)
        if total > 0:
            dist.fresh_pct = (dist.fresh_count / total) * 100
            dist.acceptable_pct = (dist.acceptable_count / total) * 100
            dist.aging_pct = (dist.aging_count / total) * 100
            dist.stale_pct = (dist.stale_count / total) * 100
            dist.critical_pct = (dist.critical_count / total) * 100
            dist.expired_pct = (dist.expired_count / total) * 100

        return dist

    def _calculate_distribution_by_type(
        self,
        secret_ages: List[SecretAge],
    ) -> Dict[SecretType, AgeDistribution]:
        """Calculate age distribution by secret type."""
        by_type: Dict[SecretType, List[SecretAge]] = {}

        for sa in secret_ages:
            if sa.secret_type not in by_type:
                by_type[sa.secret_type] = []
            by_type[sa.secret_type].append(sa)

        return {
            secret_type: self._calculate_distribution(ages)
            for secret_type, ages in by_type.items()
        }

    def _calculate_distribution_by_source(
        self,
        secret_ages: List[SecretAge],
    ) -> Dict[SecretSource, AgeDistribution]:
        """Calculate age distribution by secret source."""
        by_source: Dict[SecretSource, List[SecretAge]] = {}

        for sa in secret_ages:
            if sa.source not in by_source:
                by_source[sa.source] = []
            by_source[sa.source].append(sa)

        return {
            source: self._calculate_distribution(ages)
            for source, ages in by_source.items()
        }

    def _analyze_rotation_histories(
        self,
        inventory: SecretInventory,
    ) -> List[RotationHistory]:
        """Analyze rotation history for secrets with history data."""
        histories = []

        for item in inventory.secrets:
            if not item.metadata or not item.metadata.rotation_history:
                continue

            history = RotationHistory(
                secret_id=item.secret_id,
                secret_name=item.name,
                rotation_dates=sorted(item.metadata.rotation_history),
            )

            # Calculate intervals
            if len(history.rotation_dates) >= 2:
                for i in range(1, len(history.rotation_dates)):
                    interval = (history.rotation_dates[i] - history.rotation_dates[i-1]).days
                    history.rotation_intervals.append(interval)

                history.rotation_count = len(history.rotation_dates)
                history.avg_rotation_interval = statistics.mean(history.rotation_intervals)
                history.min_rotation_interval = min(history.rotation_intervals)
                history.max_rotation_interval = max(history.rotation_intervals)

                # Assess consistency
                if len(history.rotation_intervals) > 1:
                    std_dev = statistics.stdev(history.rotation_intervals)
                    cv = std_dev / history.avg_rotation_interval if history.avg_rotation_interval > 0 else 0

                    if cv < 0.2:
                        history.rotation_consistency = "regular"
                        history.is_auto_rotated = True
                    elif cv < 0.5:
                        history.rotation_consistency = "semi-regular"
                    else:
                        history.rotation_consistency = "irregular"
                else:
                    history.rotation_consistency = "insufficient_data"
            elif len(history.rotation_dates) == 1:
                history.rotation_count = 1
                history.rotation_consistency = "single_rotation"
            else:
                history.rotation_consistency = "never"

            histories.append(history)

        return histories

    def _calculate_overall_risk(self, secret_ages: List[SecretAge]) -> float:
        """Calculate overall risk score for the inventory."""
        if not secret_ages:
            return 0.0

        # Weighted average with emphasis on high-risk secrets
        total_weight = 0.0
        weighted_risk = 0.0

        for sa in secret_ages:
            # Higher risk secrets get more weight
            weight = 1.0 + sa.risk_score
            weighted_risk += sa.risk_score * weight
            total_weight += weight

        return weighted_risk / total_weight if total_weight > 0 else 0.0

    def _determine_risk_level(self, risk_score: float) -> str:
        """Convert risk score to risk level."""
        if risk_score >= 0.8:
            return "critical"
        elif risk_score >= 0.6:
            return "high"
        elif risk_score >= 0.4:
            return "medium"
        elif risk_score >= 0.2:
            return "low"
        else:
            return "minimal"

    def _generate_recommendations(self, report: SecretAgeReport) -> List[str]:
        """Generate actionable recommendations based on the report."""
        recommendations = []

        # Critical secrets
        if report.critical_secrets:
            recommendations.append(
                f"CRITICAL: {len(report.critical_secrets)} secrets require immediate rotation. "
                "These are severely overdue and pose significant security risk."
            )

        # Stale secrets
        if report.stale_secrets:
            recommendations.append(
                f"HIGH: {len(report.stale_secrets)} secrets are past their recommended rotation "
                "period. Schedule rotation within the next sprint."
            )

        # Expiring soon
        if report.expiring_soon:
            recommendations.append(
                f"MEDIUM: {len(report.expiring_soon)} secrets will expire within "
                f"{self.expiring_soon_days} days. Plan rotation before expiration."
            )

        # Distribution-based recommendations
        dist = report.overall_distribution

        if dist.critical_pct > 10:
            recommendations.append(
                f"PROCESS: {dist.critical_pct:.1f}% of secrets are in critical state. "
                "Review and improve rotation processes."
            )

        if dist.unknown_count > 0:
            recommendations.append(
                f"DATA QUALITY: {dist.unknown_count} secrets have unknown age. "
                "Ensure all secrets have proper creation timestamps."
            )

        # Auto-rotation recommendation
        auto_rotated = sum(1 for h in report.rotation_histories if h.is_auto_rotated)
        if auto_rotated < len(report.rotation_histories) * 0.5 and report.rotation_histories:
            recommendations.append(
                "AUTOMATION: Less than 50% of secrets appear to be auto-rotated. "
                "Consider implementing automated rotation for high-risk secrets."
            )

        # Type-specific recommendations
        for secret_type, type_dist in report.distribution_by_type.items():
            if type_dist.critical_count > 0:
                recommendations.append(
                    f"TYPE: {type_dist.critical_count} {secret_type.value} secrets are in "
                    "critical state. Prioritize rotation for this credential type."
                )

        return recommendations

    def get_secrets_by_age_status(
        self,
        inventory: SecretInventory,
        status: AgeStatus,
    ) -> List[SecretInventoryItem]:
        """Get all secrets with a specific age status."""
        result = []

        for item in inventory.secrets:
            secret_age = self._analyze_secret_age(item)
            if secret_age.age_status == status:
                result.append(item)

        return result

    def get_rotation_due_secrets(
        self,
        inventory: SecretInventory,
        days_threshold: int = 90,
    ) -> List[Tuple[SecretInventoryItem, int]]:
        """
        Get secrets that are due for rotation.

        Returns list of (secret, days_since_rotation) tuples.
        """
        result = []

        for item in inventory.secrets:
            secret_age = self._analyze_secret_age(item)
            if secret_age.days_since_rotation >= days_threshold:
                result.append((item, secret_age.days_since_rotation))

        # Sort by days since rotation (most overdue first)
        result.sort(key=lambda x: x[1], reverse=True)

        return result

    def get_expiring_secrets(
        self,
        inventory: SecretInventory,
        days_threshold: int = 30,
    ) -> List[Tuple[SecretInventoryItem, int]]:
        """
        Get secrets that will expire within the threshold.

        Returns list of (secret, days_until_expiration) tuples.
        """
        result = []

        for item in inventory.secrets:
            secret_age = self._analyze_secret_age(item)
            if 0 <= secret_age.days_until_expiration <= days_threshold:
                result.append((item, secret_age.days_until_expiration))

        # Sort by days until expiration (soonest first)
        result.sort(key=lambda x: x[1])

        return result

    def calculate_rotation_compliance(
        self,
        inventory: SecretInventory,
        max_rotation_days: Dict[SecretType, int] = None,
    ) -> Dict[str, Any]:
        """
        Calculate rotation compliance metrics.

        Args:
            inventory: Secret inventory to analyze
            max_rotation_days: Maximum allowed days between rotations per type

        Returns:
            Compliance metrics dictionary
        """
        if max_rotation_days is None:
            # Default compliance requirements
            max_rotation_days = {
                SecretType.AWS_ACCESS_KEY: 90,
                SecretType.DATABASE_PASSWORD: 90,
                SecretType.API_KEY: 180,
                SecretType.SSH_PRIVATE_KEY: 180,
                SecretType.TLS_CERTIFICATE: 365,
            }

        compliant = 0
        non_compliant = 0
        not_applicable = 0
        violations = []

        for item in inventory.secrets:
            secret_age = self._analyze_secret_age(item)

            if item.secret_type in max_rotation_days:
                max_days = max_rotation_days[item.secret_type]
                days_since = secret_age.days_since_rotation

                if days_since < 0:
                    not_applicable += 1
                elif days_since <= max_days:
                    compliant += 1
                else:
                    non_compliant += 1
                    violations.append({
                        "secret_id": item.secret_id,
                        "secret_name": item.name,
                        "secret_type": item.secret_type.value,
                        "days_since_rotation": days_since,
                        "max_allowed_days": max_days,
                        "days_overdue": days_since - max_days,
                    })
            else:
                not_applicable += 1

        total_applicable = compliant + non_compliant
        compliance_rate = (compliant / total_applicable * 100) if total_applicable > 0 else 100.0

        return {
            "compliant_count": compliant,
            "non_compliant_count": non_compliant,
            "not_applicable_count": not_applicable,
            "compliance_rate": compliance_rate,
            "violations": violations,
            "policy_applied": {k.value: v for k, v in max_rotation_days.items()},
        }
