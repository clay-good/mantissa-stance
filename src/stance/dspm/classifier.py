"""
Data classification engine for Mantissa Stance DSPM.

Classifies data assets based on sensitivity level and data categories
such as PII, PCI, PHI, and confidential business data.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class ClassificationLevel(Enum):
    """Data sensitivity classification levels."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"

    @property
    def severity_score(self) -> int:
        """Get numeric severity score for classification level."""
        scores = {
            ClassificationLevel.PUBLIC: 0,
            ClassificationLevel.INTERNAL: 25,
            ClassificationLevel.CONFIDENTIAL: 50,
            ClassificationLevel.RESTRICTED: 75,
            ClassificationLevel.TOP_SECRET: 100,
        }
        return scores.get(self, 0)


class DataCategory(Enum):
    """Categories of sensitive data."""

    # Personal Identifiable Information
    PII = "pii"
    PII_NAME = "pii_name"
    PII_EMAIL = "pii_email"
    PII_PHONE = "pii_phone"
    PII_SSN = "pii_ssn"
    PII_ADDRESS = "pii_address"
    PII_DOB = "pii_dob"
    PII_PASSPORT = "pii_passport"
    PII_DRIVERS_LICENSE = "pii_drivers_license"

    # Payment Card Industry
    PCI = "pci"
    PCI_CARD_NUMBER = "pci_card_number"
    PCI_CVV = "pci_cvv"
    PCI_EXPIRY = "pci_expiry"
    PCI_CARDHOLDER = "pci_cardholder"

    # Protected Health Information
    PHI = "phi"
    PHI_MEDICAL_RECORD = "phi_medical_record"
    PHI_DIAGNOSIS = "phi_diagnosis"
    PHI_PRESCRIPTION = "phi_prescription"
    PHI_INSURANCE = "phi_insurance"

    # Financial Data
    FINANCIAL = "financial"
    FINANCIAL_BANK_ACCOUNT = "financial_bank_account"
    FINANCIAL_ROUTING = "financial_routing"
    FINANCIAL_TAX_ID = "financial_tax_id"

    # Credentials and Secrets
    CREDENTIALS = "credentials"
    CREDENTIALS_PASSWORD = "credentials_password"
    CREDENTIALS_API_KEY = "credentials_api_key"
    CREDENTIALS_TOKEN = "credentials_token"
    CREDENTIALS_PRIVATE_KEY = "credentials_private_key"

    # Business Confidential
    BUSINESS = "business"
    BUSINESS_TRADE_SECRET = "business_trade_secret"
    BUSINESS_INTELLECTUAL_PROPERTY = "business_ip"
    BUSINESS_LEGAL = "business_legal"
    BUSINESS_HR = "business_hr"

    # Generic
    UNKNOWN = "unknown"


@dataclass
class ClassificationRule:
    """
    Rule for classifying data based on patterns and context.

    Attributes:
        name: Rule identifier
        description: Human-readable description
        category: Data category this rule detects
        level: Classification level to assign
        patterns: Regex patterns to match
        field_patterns: Field name patterns suggesting this data type
        min_confidence: Minimum confidence threshold
        enabled: Whether rule is active
    """

    name: str
    description: str
    category: DataCategory
    level: ClassificationLevel
    patterns: list[str] = field(default_factory=list)
    field_patterns: list[str] = field(default_factory=list)
    min_confidence: float = 0.7
    enabled: bool = True

    def __post_init__(self):
        """Compile regex patterns."""
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.patterns
        ]
        self._compiled_field_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.field_patterns
        ]


@dataclass
class ClassificationResult:
    """
    Result of data classification.

    Attributes:
        level: Assigned classification level
        categories: Detected data categories
        confidence: Confidence score (0.0-1.0)
        matched_rules: Rules that matched
        evidence: Evidence supporting classification
        recommendations: Security recommendations
    """

    level: ClassificationLevel
    categories: list[DataCategory] = field(default_factory=list)
    confidence: float = 0.0
    matched_rules: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


@dataclass
class DataClassification:
    """
    Classification metadata for a data asset.

    Attributes:
        asset_id: Identifier of the classified asset
        asset_type: Type of asset (s3_bucket, database, etc.)
        classification: Classification result
        location: Geographic location of data
        encryption_status: Whether data is encrypted
        access_level: Current access configuration
        compliance_frameworks: Relevant compliance frameworks
        last_scanned: Timestamp of last scan
    """

    asset_id: str
    asset_type: str
    classification: ClassificationResult
    location: str = ""
    encryption_status: str = "unknown"
    access_level: str = "unknown"
    compliance_frameworks: list[str] = field(default_factory=list)
    last_scanned: str = ""


class DataClassifier:
    """
    Classifies data assets based on content and metadata analysis.

    Analyzes data to determine sensitivity level and applicable
    compliance requirements (PCI-DSS, HIPAA, GDPR, etc.).
    """

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize data classifier.

        Args:
            config: Optional configuration overrides
        """
        self._config = config or {}
        self._rules: list[ClassificationRule] = []
        self._load_default_rules()

    def _load_default_rules(self) -> None:
        """Load default classification rules."""
        # PII Rules
        self._rules.extend([
            ClassificationRule(
                name="pii-ssn",
                description="US Social Security Number",
                category=DataCategory.PII_SSN,
                level=ClassificationLevel.RESTRICTED,
                patterns=[
                    r"\b\d{3}-\d{2}-\d{4}\b",
                    r"\b\d{9}\b",
                ],
                field_patterns=[
                    r"ssn",
                    r"social.*security",
                    r"tax.*id",
                ],
            ),
            ClassificationRule(
                name="pii-email",
                description="Email addresses",
                category=DataCategory.PII_EMAIL,
                level=ClassificationLevel.CONFIDENTIAL,
                patterns=[
                    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                ],
                field_patterns=[
                    r"email",
                    r"e-mail",
                    r"mail.*address",
                ],
            ),
            ClassificationRule(
                name="pii-phone",
                description="Phone numbers",
                category=DataCategory.PII_PHONE,
                level=ClassificationLevel.CONFIDENTIAL,
                patterns=[
                    r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b",
                    r"\b\+1[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b",
                    r"\b\(\d{3}\)\s*\d{3}[-.\s]?\d{4}\b",
                ],
                field_patterns=[
                    r"phone",
                    r"mobile",
                    r"cell",
                    r"telephone",
                    r"fax",
                ],
            ),
            ClassificationRule(
                name="pii-dob",
                description="Date of birth",
                category=DataCategory.PII_DOB,
                level=ClassificationLevel.CONFIDENTIAL,
                patterns=[
                    r"\b\d{1,2}/\d{1,2}/\d{2,4}\b",
                    r"\b\d{4}-\d{2}-\d{2}\b",
                ],
                field_patterns=[
                    r"birth.*date",
                    r"date.*birth",
                    r"dob",
                    r"birthday",
                ],
            ),
            ClassificationRule(
                name="pii-passport",
                description="Passport numbers",
                category=DataCategory.PII_PASSPORT,
                level=ClassificationLevel.RESTRICTED,
                patterns=[
                    r"\b[A-Z]{1,2}\d{6,9}\b",
                ],
                field_patterns=[
                    r"passport",
                    r"travel.*doc",
                ],
            ),
            ClassificationRule(
                name="pii-drivers-license",
                description="Drivers license numbers",
                category=DataCategory.PII_DRIVERS_LICENSE,
                level=ClassificationLevel.RESTRICTED,
                patterns=[
                    r"\b[A-Z]\d{7}\b",
                    r"\b[A-Z]{2}\d{6}\b",
                ],
                field_patterns=[
                    r"driver.*license",
                    r"license.*number",
                    r"dl.*num",
                ],
            ),
        ])

        # PCI Rules
        self._rules.extend([
            ClassificationRule(
                name="pci-card-number",
                description="Credit/debit card numbers",
                category=DataCategory.PCI_CARD_NUMBER,
                level=ClassificationLevel.RESTRICTED,
                patterns=[
                    r"\b4[0-9]{12}(?:[0-9]{3})?\b",  # Visa
                    r"\b5[1-5][0-9]{14}\b",  # Mastercard
                    r"\b3[47][0-9]{13}\b",  # Amex
                    r"\b6(?:011|5[0-9]{2})[0-9]{12}\b",  # Discover
                ],
                field_patterns=[
                    r"card.*num",
                    r"credit.*card",
                    r"debit.*card",
                    r"pan",
                    r"primary.*account",
                ],
            ),
            ClassificationRule(
                name="pci-cvv",
                description="Card verification values",
                category=DataCategory.PCI_CVV,
                level=ClassificationLevel.RESTRICTED,
                patterns=[
                    r"\b\d{3,4}\b",
                ],
                field_patterns=[
                    r"cvv",
                    r"cvc",
                    r"cvv2",
                    r"security.*code",
                    r"card.*code",
                ],
                min_confidence=0.8,  # Require field context
            ),
        ])

        # PHI Rules
        self._rules.extend([
            ClassificationRule(
                name="phi-medical-record",
                description="Medical record numbers",
                category=DataCategory.PHI_MEDICAL_RECORD,
                level=ClassificationLevel.RESTRICTED,
                patterns=[
                    r"\b[A-Z]{2,3}\d{6,10}\b",
                ],
                field_patterns=[
                    r"medical.*record",
                    r"mrn",
                    r"patient.*id",
                    r"health.*record",
                ],
            ),
            ClassificationRule(
                name="phi-diagnosis",
                description="Medical diagnosis codes",
                category=DataCategory.PHI_DIAGNOSIS,
                level=ClassificationLevel.RESTRICTED,
                patterns=[
                    r"\b[A-Z]\d{2}(?:\.\d{1,4})?\b",  # ICD-10
                ],
                field_patterns=[
                    r"diagnosis",
                    r"icd.*code",
                    r"condition",
                    r"disease",
                ],
            ),
        ])

        # Financial Rules
        self._rules.extend([
            ClassificationRule(
                name="financial-bank-account",
                description="Bank account numbers",
                category=DataCategory.FINANCIAL_BANK_ACCOUNT,
                level=ClassificationLevel.RESTRICTED,
                patterns=[
                    r"\b\d{8,17}\b",
                ],
                field_patterns=[
                    r"account.*num",
                    r"bank.*account",
                    r"acct.*num",
                    r"iban",
                ],
                min_confidence=0.8,  # Require field context
            ),
            ClassificationRule(
                name="financial-routing",
                description="Bank routing numbers",
                category=DataCategory.FINANCIAL_ROUTING,
                level=ClassificationLevel.CONFIDENTIAL,
                patterns=[
                    r"\b\d{9}\b",
                ],
                field_patterns=[
                    r"routing",
                    r"aba.*num",
                    r"swift",
                    r"bic",
                ],
                min_confidence=0.8,
            ),
            ClassificationRule(
                name="financial-tax-id",
                description="Tax identification numbers",
                category=DataCategory.FINANCIAL_TAX_ID,
                level=ClassificationLevel.RESTRICTED,
                patterns=[
                    r"\b\d{2}-\d{7}\b",  # EIN
                ],
                field_patterns=[
                    r"tax.*id",
                    r"ein",
                    r"employer.*id",
                    r"tin",
                ],
            ),
        ])

        # Credentials Rules
        self._rules.extend([
            ClassificationRule(
                name="credentials-password",
                description="Passwords",
                category=DataCategory.CREDENTIALS_PASSWORD,
                level=ClassificationLevel.TOP_SECRET,
                patterns=[],
                field_patterns=[
                    r"password",
                    r"passwd",
                    r"pwd",
                    r"secret",
                    r"credential",
                ],
            ),
            ClassificationRule(
                name="credentials-api-key",
                description="API keys",
                category=DataCategory.CREDENTIALS_API_KEY,
                level=ClassificationLevel.TOP_SECRET,
                patterns=[
                    r"(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})",
                ],
                field_patterns=[
                    r"api.*key",
                    r"apikey",
                    r"access.*key",
                ],
            ),
            ClassificationRule(
                name="credentials-private-key",
                description="Private keys",
                category=DataCategory.CREDENTIALS_PRIVATE_KEY,
                level=ClassificationLevel.TOP_SECRET,
                patterns=[
                    r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
                    r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----",
                    r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----",
                ],
                field_patterns=[
                    r"private.*key",
                    r"priv.*key",
                ],
            ),
        ])

    def add_rule(self, rule: ClassificationRule) -> None:
        """
        Add a custom classification rule.

        Args:
            rule: Classification rule to add
        """
        self._rules.append(rule)

    def remove_rule(self, rule_name: str) -> bool:
        """
        Remove a classification rule by name.

        Args:
            rule_name: Name of rule to remove

        Returns:
            True if rule was removed, False if not found
        """
        for i, rule in enumerate(self._rules):
            if rule.name == rule_name:
                self._rules.pop(i)
                return True
        return False

    def classify(
        self,
        content: str | None = None,
        field_name: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ClassificationResult:
        """
        Classify data based on content, field name, and metadata.

        Args:
            content: Data content to analyze
            field_name: Name of field containing data
            metadata: Additional metadata about the data

        Returns:
            Classification result with level, categories, and confidence
        """
        matched_rules: list[ClassificationRule] = []
        evidence: list[str] = []
        categories: set[DataCategory] = set()

        for rule in self._rules:
            if not rule.enabled:
                continue

            match_score = 0.0
            rule_evidence: list[str] = []

            # Check content patterns
            if content and rule._compiled_patterns:
                for pattern in rule._compiled_patterns:
                    matches = pattern.findall(content)
                    if matches:
                        match_score += 0.6
                        rule_evidence.append(
                            f"Content matches pattern: {pattern.pattern[:50]}"
                        )
                        break

            # Check field name patterns
            if field_name and rule._compiled_field_patterns:
                for pattern in rule._compiled_field_patterns:
                    if pattern.search(field_name):
                        match_score += 0.4
                        rule_evidence.append(
                            f"Field name '{field_name}' matches pattern"
                        )
                        break

            # If match exceeds threshold, add rule
            if match_score >= rule.min_confidence:
                matched_rules.append(rule)
                evidence.extend(rule_evidence)
                categories.add(rule.category)

        # Determine highest classification level
        if matched_rules:
            highest_level = max(
                matched_rules, key=lambda r: r.level.severity_score
            ).level
            avg_confidence = sum(
                r.min_confidence for r in matched_rules
            ) / len(matched_rules)
        else:
            highest_level = ClassificationLevel.PUBLIC
            avg_confidence = 1.0  # High confidence it's public

        # Generate recommendations
        recommendations = self._generate_recommendations(
            highest_level, list(categories)
        )

        return ClassificationResult(
            level=highest_level,
            categories=list(categories),
            confidence=min(avg_confidence, 1.0),
            matched_rules=[r.name for r in matched_rules],
            evidence=evidence,
            recommendations=recommendations,
        )

    def classify_asset(
        self,
        asset_id: str,
        asset_type: str,
        samples: list[dict[str, Any]],
        metadata: dict[str, Any] | None = None,
    ) -> DataClassification:
        """
        Classify a data asset based on sampled data.

        Args:
            asset_id: Unique identifier for the asset
            asset_type: Type of asset (s3_bucket, rds_database, etc.)
            samples: Sample records from the asset
            metadata: Asset metadata

        Returns:
            Complete data classification for the asset
        """
        metadata = metadata or {}
        all_categories: set[DataCategory] = set()
        all_rules: set[str] = set()
        all_evidence: list[str] = []
        highest_level = ClassificationLevel.PUBLIC

        # Analyze each sample
        for sample in samples:
            for field_name, value in sample.items():
                if value is None:
                    continue

                content = str(value) if not isinstance(value, str) else value
                result = self.classify(
                    content=content,
                    field_name=field_name,
                    metadata=metadata,
                )

                all_categories.update(result.categories)
                all_rules.update(result.matched_rules)
                all_evidence.extend(result.evidence)

                if result.level.severity_score > highest_level.severity_score:
                    highest_level = result.level

        # Determine compliance frameworks
        compliance = self._determine_compliance_frameworks(list(all_categories))

        # Generate final recommendations
        recommendations = self._generate_recommendations(
            highest_level, list(all_categories)
        )

        classification_result = ClassificationResult(
            level=highest_level,
            categories=list(all_categories),
            confidence=0.8 if all_rules else 1.0,
            matched_rules=list(all_rules),
            evidence=all_evidence[:20],  # Limit evidence
            recommendations=recommendations,
        )

        return DataClassification(
            asset_id=asset_id,
            asset_type=asset_type,
            classification=classification_result,
            location=metadata.get("region", ""),
            encryption_status=metadata.get("encryption", "unknown"),
            access_level=metadata.get("access", "unknown"),
            compliance_frameworks=compliance,
        )

    def _determine_compliance_frameworks(
        self, categories: list[DataCategory]
    ) -> list[str]:
        """Determine applicable compliance frameworks based on data categories."""
        frameworks: set[str] = set()

        category_frameworks = {
            DataCategory.PCI: ["PCI-DSS"],
            DataCategory.PCI_CARD_NUMBER: ["PCI-DSS"],
            DataCategory.PCI_CVV: ["PCI-DSS"],
            DataCategory.PHI: ["HIPAA", "HITECH"],
            DataCategory.PHI_MEDICAL_RECORD: ["HIPAA", "HITECH"],
            DataCategory.PHI_DIAGNOSIS: ["HIPAA", "HITECH"],
            DataCategory.PII: ["GDPR", "CCPA", "SOC2"],
            DataCategory.PII_SSN: ["GDPR", "CCPA", "SOC2"],
            DataCategory.PII_EMAIL: ["GDPR", "CCPA"],
            DataCategory.FINANCIAL: ["SOX", "GLBA"],
            DataCategory.FINANCIAL_BANK_ACCOUNT: ["SOX", "GLBA", "PCI-DSS"],
        }

        for category in categories:
            if category in category_frameworks:
                frameworks.update(category_frameworks[category])

        return sorted(frameworks)

    def _generate_recommendations(
        self,
        level: ClassificationLevel,
        categories: list[DataCategory],
    ) -> list[str]:
        """Generate security recommendations based on classification."""
        recommendations: list[str] = []

        # Level-based recommendations
        if level in (ClassificationLevel.RESTRICTED, ClassificationLevel.TOP_SECRET):
            recommendations.extend([
                "Enable encryption at rest with customer-managed keys",
                "Implement strict access controls with MFA requirement",
                "Enable audit logging for all access",
                "Consider data masking for non-production environments",
                "Implement data loss prevention (DLP) controls",
            ])
        elif level == ClassificationLevel.CONFIDENTIAL:
            recommendations.extend([
                "Enable encryption at rest",
                "Implement role-based access controls",
                "Enable access logging",
            ])

        # Category-based recommendations
        pci_categories = {
            DataCategory.PCI,
            DataCategory.PCI_CARD_NUMBER,
            DataCategory.PCI_CVV,
        }
        phi_categories = {
            DataCategory.PHI,
            DataCategory.PHI_MEDICAL_RECORD,
            DataCategory.PHI_DIAGNOSIS,
        }

        if pci_categories.intersection(categories):
            recommendations.extend([
                "Ensure PCI-DSS compliance controls are in place",
                "Implement tokenization for card data",
                "Restrict access to need-to-know basis",
            ])

        if phi_categories.intersection(categories):
            recommendations.extend([
                "Ensure HIPAA compliance controls are in place",
                "Implement access audit trail",
                "Enable breach notification procedures",
            ])

        return list(dict.fromkeys(recommendations))  # Deduplicate

    def get_rules(self) -> list[ClassificationRule]:
        """Get all classification rules."""
        return self._rules.copy()

    def get_rule(self, name: str) -> ClassificationRule | None:
        """Get a specific rule by name."""
        for rule in self._rules:
            if rule.name == name:
                return rule
        return None
