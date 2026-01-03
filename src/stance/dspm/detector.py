"""
Sensitive data detection for Mantissa Stance DSPM.

Scans cloud storage and databases to detect sensitive data
patterns and report findings.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterator

from stance.dspm.classifier import (
    DataCategory,
    ClassificationLevel,
    DataClassifier,
)

logger = logging.getLogger(__name__)


class PatternType(Enum):
    """Types of detection patterns."""

    REGEX = "regex"
    KEYWORD = "keyword"
    CHECKSUM = "checksum"
    ENTROPY = "entropy"
    ML_MODEL = "ml_model"


@dataclass
class DataPattern:
    """
    Pattern definition for sensitive data detection.

    Attributes:
        name: Pattern identifier
        description: Human-readable description
        pattern_type: Type of pattern matching
        pattern: Pattern string (regex or keyword)
        category: Data category this pattern detects
        confidence: Base confidence score for matches
        validation: Optional validation function name
        enabled: Whether pattern is active
    """

    name: str
    description: str
    pattern_type: PatternType
    pattern: str
    category: DataCategory
    confidence: float = 0.8
    validation: str | None = None
    enabled: bool = True

    def __post_init__(self):
        """Compile regex pattern if applicable."""
        if self.pattern_type == PatternType.REGEX:
            self._compiled = re.compile(self.pattern, re.IGNORECASE)
        else:
            self._compiled = None


@dataclass
class PatternMatch:
    """
    A match found by a detection pattern.

    Attributes:
        pattern_name: Name of pattern that matched
        category: Data category detected
        value: Matched value (may be redacted)
        location: Location in source (line, column, field)
        confidence: Confidence score for this match
        context: Surrounding context
        redacted_value: Redacted version of matched value
    """

    pattern_name: str
    category: DataCategory
    value: str
    location: dict[str, Any]
    confidence: float
    context: str = ""
    redacted_value: str = ""

    def __post_init__(self):
        """Generate redacted value if not provided."""
        if not self.redacted_value and self.value:
            self.redacted_value = self._redact(self.value)

    def _redact(self, value: str) -> str:
        """Redact sensitive value, showing only partial info."""
        if len(value) <= 4:
            return "*" * len(value)
        elif len(value) <= 8:
            return value[:2] + "*" * (len(value) - 2)
        else:
            return value[:4] + "*" * (len(value) - 8) + value[-4:]


@dataclass
class DetectionResult:
    """
    Result of sensitive data detection scan.

    Attributes:
        asset_id: Identifier of scanned asset
        asset_type: Type of asset scanned
        matches: List of pattern matches found
        total_records_scanned: Number of records analyzed
        scan_coverage: Percentage of asset scanned
        highest_classification: Highest classification found
        categories_found: Unique categories detected
        scan_duration_ms: Duration of scan in milliseconds
    """

    asset_id: str
    asset_type: str
    matches: list[PatternMatch] = field(default_factory=list)
    total_records_scanned: int = 0
    scan_coverage: float = 100.0
    highest_classification: ClassificationLevel = ClassificationLevel.PUBLIC
    categories_found: list[DataCategory] = field(default_factory=list)
    scan_duration_ms: int = 0

    @property
    def has_sensitive_data(self) -> bool:
        """Check if sensitive data was detected."""
        return len(self.matches) > 0

    @property
    def match_count(self) -> int:
        """Get total number of matches."""
        return len(self.matches)

    def get_matches_by_category(
        self, category: DataCategory
    ) -> list[PatternMatch]:
        """Get matches for a specific category."""
        return [m for m in self.matches if m.category == category]


class SensitiveDataDetector:
    """
    Detects sensitive data in cloud storage and databases.

    Scans data samples to identify PII, PCI, PHI, and other
    sensitive data types using pattern matching and heuristics.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize sensitive data detector.

        Args:
            config: Optional configuration overrides
        """
        self._config = config or {}
        self._patterns: list[DataPattern] = []
        self._classifier = DataClassifier(config)
        self._load_default_patterns()

    def _load_default_patterns(self) -> None:
        """Load default detection patterns."""
        # PII Patterns
        self._patterns.extend([
            DataPattern(
                name="ssn-formatted",
                description="US Social Security Number (formatted)",
                pattern_type=PatternType.REGEX,
                pattern=r"\b\d{3}-\d{2}-\d{4}\b",
                category=DataCategory.PII_SSN,
                confidence=0.95,
                validation="luhn_check",
            ),
            DataPattern(
                name="ssn-unformatted",
                description="US Social Security Number (unformatted)",
                pattern_type=PatternType.REGEX,
                pattern=r"\b(?!000|666|9\d{2})\d{3}(?!00)\d{2}(?!0000)\d{4}\b",
                category=DataCategory.PII_SSN,
                confidence=0.7,
            ),
            DataPattern(
                name="email-address",
                description="Email address",
                pattern_type=PatternType.REGEX,
                pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b",
                category=DataCategory.PII_EMAIL,
                confidence=0.95,
            ),
            DataPattern(
                name="phone-us",
                description="US phone number",
                pattern_type=PatternType.REGEX,
                pattern=r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
                category=DataCategory.PII_PHONE,
                confidence=0.85,
            ),
            DataPattern(
                name="phone-international",
                description="International phone number",
                pattern_type=PatternType.REGEX,
                pattern=r"\b\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b",
                category=DataCategory.PII_PHONE,
                confidence=0.8,
            ),
            DataPattern(
                name="date-of-birth",
                description="Date that could be DOB",
                pattern_type=PatternType.REGEX,
                pattern=r"\b(?:19|20)\d{2}[-/](0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])\b",
                category=DataCategory.PII_DOB,
                confidence=0.6,
            ),
            DataPattern(
                name="us-passport",
                description="US passport number",
                pattern_type=PatternType.REGEX,
                pattern=r"\b[A-Z]\d{8}\b",
                category=DataCategory.PII_PASSPORT,
                confidence=0.7,
            ),
            DataPattern(
                name="us-address-zip",
                description="US ZIP code",
                pattern_type=PatternType.REGEX,
                pattern=r"\b\d{5}(?:-\d{4})?\b",
                category=DataCategory.PII_ADDRESS,
                confidence=0.5,
            ),
        ])

        # PCI Patterns
        self._patterns.extend([
            DataPattern(
                name="credit-card-visa",
                description="Visa credit card number",
                pattern_type=PatternType.REGEX,
                pattern=r"\b4[0-9]{12}(?:[0-9]{3})?\b",
                category=DataCategory.PCI_CARD_NUMBER,
                confidence=0.95,
                validation="luhn_check",
            ),
            DataPattern(
                name="credit-card-mastercard",
                description="Mastercard credit card number",
                pattern_type=PatternType.REGEX,
                pattern=r"\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}\b",
                category=DataCategory.PCI_CARD_NUMBER,
                confidence=0.95,
                validation="luhn_check",
            ),
            DataPattern(
                name="credit-card-amex",
                description="American Express card number",
                pattern_type=PatternType.REGEX,
                pattern=r"\b3[47][0-9]{13}\b",
                category=DataCategory.PCI_CARD_NUMBER,
                confidence=0.95,
                validation="luhn_check",
            ),
            DataPattern(
                name="credit-card-discover",
                description="Discover card number",
                pattern_type=PatternType.REGEX,
                pattern=r"\b6(?:011|5[0-9]{2})[0-9]{12}\b",
                category=DataCategory.PCI_CARD_NUMBER,
                confidence=0.95,
                validation="luhn_check",
            ),
            DataPattern(
                name="cvv-code",
                description="Card verification value",
                pattern_type=PatternType.REGEX,
                pattern=r"\b[0-9]{3,4}\b",
                category=DataCategory.PCI_CVV,
                confidence=0.3,  # Low confidence, needs context
            ),
        ])

        # PHI Patterns
        self._patterns.extend([
            DataPattern(
                name="medical-record-number",
                description="Medical record number",
                pattern_type=PatternType.REGEX,
                pattern=r"\b(?:MRN|MR)[:\s#]?\d{6,10}\b",
                category=DataCategory.PHI_MEDICAL_RECORD,
                confidence=0.9,
            ),
            DataPattern(
                name="icd10-code",
                description="ICD-10 diagnosis code",
                pattern_type=PatternType.REGEX,
                pattern=r"\b[A-TV-Z][0-9][0-9AB](?:\.[0-9A-TV-Z]{1,4})?\b",
                category=DataCategory.PHI_DIAGNOSIS,
                confidence=0.85,
            ),
            DataPattern(
                name="npi-number",
                description="National Provider Identifier",
                pattern_type=PatternType.REGEX,
                pattern=r"\b\d{10}\b",
                category=DataCategory.PHI,
                confidence=0.5,  # Needs context
            ),
        ])

        # Financial Patterns
        self._patterns.extend([
            DataPattern(
                name="bank-routing-number",
                description="US bank routing number",
                pattern_type=PatternType.REGEX,
                pattern=r"\b(?:0[1-9]|[1-4][0-9]|5[0-2]|6[1-9]|7[0-2]|8[0-9])\d{7}\b",
                category=DataCategory.FINANCIAL_ROUTING,
                confidence=0.7,
            ),
            DataPattern(
                name="iban",
                description="International Bank Account Number",
                pattern_type=PatternType.REGEX,
                pattern=r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]{0,16})?\b",
                category=DataCategory.FINANCIAL_BANK_ACCOUNT,
                confidence=0.9,
            ),
            DataPattern(
                name="ein",
                description="Employer Identification Number",
                pattern_type=PatternType.REGEX,
                pattern=r"\b\d{2}-\d{7}\b",
                category=DataCategory.FINANCIAL_TAX_ID,
                confidence=0.8,
            ),
        ])

        # Credentials Patterns
        self._patterns.extend([
            DataPattern(
                name="aws-access-key",
                description="AWS access key ID",
                pattern_type=PatternType.REGEX,
                pattern=r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b",
                category=DataCategory.CREDENTIALS_API_KEY,
                confidence=0.98,
            ),
            DataPattern(
                name="aws-secret-key",
                description="AWS secret access key",
                pattern_type=PatternType.REGEX,
                pattern=r"\b[A-Za-z0-9/+=]{40}\b",
                category=DataCategory.CREDENTIALS_API_KEY,
                confidence=0.6,  # Needs context
            ),
            DataPattern(
                name="private-key-header",
                description="Private key header",
                pattern_type=PatternType.REGEX,
                pattern=r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----",
                category=DataCategory.CREDENTIALS_PRIVATE_KEY,
                confidence=0.99,
            ),
            DataPattern(
                name="jwt-token",
                description="JSON Web Token",
                pattern_type=PatternType.REGEX,
                pattern=r"\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b",
                category=DataCategory.CREDENTIALS_TOKEN,
                confidence=0.95,
            ),
        ])

    def add_pattern(self, pattern: DataPattern) -> None:
        """
        Add a custom detection pattern.

        Args:
            pattern: Detection pattern to add
        """
        self._patterns.append(pattern)

    def remove_pattern(self, pattern_name: str) -> bool:
        """
        Remove a detection pattern by name.

        Args:
            pattern_name: Name of pattern to remove

        Returns:
            True if pattern was removed, False if not found
        """
        for i, pattern in enumerate(self._patterns):
            if pattern.name == pattern_name:
                self._patterns.pop(i)
                return True
        return False

    def scan_content(
        self,
        content: str,
        field_name: str | None = None,
        location: dict[str, Any] | None = None,
    ) -> list[PatternMatch]:
        """
        Scan content for sensitive data patterns.

        Args:
            content: Text content to scan
            field_name: Optional field name for context
            location: Location metadata

        Returns:
            List of pattern matches found
        """
        matches: list[PatternMatch] = []
        location = location or {}

        for pattern in self._patterns:
            if not pattern.enabled:
                continue

            if pattern.pattern_type == PatternType.REGEX and pattern._compiled:
                for match in pattern._compiled.finditer(content):
                    value = match.group()

                    # Apply validation if specified
                    confidence = pattern.confidence
                    if pattern.validation == "luhn_check":
                        if not self._luhn_validate(value):
                            confidence *= 0.5

                    # Boost confidence based on field name
                    if field_name:
                        confidence = self._adjust_confidence_by_field(
                            confidence, field_name, pattern.category
                        )

                    if confidence >= 0.5:  # Minimum threshold
                        # Extract context
                        start = max(0, match.start() - 20)
                        end = min(len(content), match.end() + 20)
                        context = content[start:end]

                        matches.append(
                            PatternMatch(
                                pattern_name=pattern.name,
                                category=pattern.category,
                                value=value,
                                location={
                                    **location,
                                    "offset": match.start(),
                                    "field": field_name,
                                },
                                confidence=confidence,
                                context=context,
                            )
                        )

            elif pattern.pattern_type == PatternType.KEYWORD:
                if pattern.pattern.lower() in content.lower():
                    matches.append(
                        PatternMatch(
                            pattern_name=pattern.name,
                            category=pattern.category,
                            value=pattern.pattern,
                            location=location,
                            confidence=pattern.confidence,
                        )
                    )

        return matches

    def scan_records(
        self,
        records: Iterator[dict[str, Any]] | list[dict[str, Any]],
        asset_id: str,
        asset_type: str,
        sample_size: int | None = None,
    ) -> DetectionResult:
        """
        Scan multiple records for sensitive data.

        Args:
            records: Iterator or list of records to scan
            asset_id: Identifier of the asset
            asset_type: Type of asset
            sample_size: Maximum records to scan (None for all)

        Returns:
            Detection result with all matches
        """
        import time

        start_time = time.time()
        all_matches: list[PatternMatch] = []
        categories_found: set[DataCategory] = set()
        record_count = 0

        for record in records:
            if sample_size and record_count >= sample_size:
                break

            record_count += 1

            for field_name, value in record.items():
                if value is None:
                    continue

                content = str(value) if not isinstance(value, str) else value
                matches = self.scan_content(
                    content=content,
                    field_name=field_name,
                    location={"record": record_count},
                )

                all_matches.extend(matches)
                categories_found.update(m.category for m in matches)

        # Determine highest classification
        highest_level = ClassificationLevel.PUBLIC
        for category in categories_found:
            classification = self._classifier.classify(
                field_name=category.value
            )
            if classification.level.severity_score > highest_level.severity_score:
                highest_level = classification.level

        duration_ms = int((time.time() - start_time) * 1000)

        return DetectionResult(
            asset_id=asset_id,
            asset_type=asset_type,
            matches=all_matches,
            total_records_scanned=record_count,
            scan_coverage=100.0 if not sample_size else min(100.0, record_count / sample_size * 100),
            highest_classification=highest_level,
            categories_found=list(categories_found),
            scan_duration_ms=duration_ms,
        )

    def _luhn_validate(self, number: str) -> bool:
        """Validate a number using Luhn algorithm (credit cards, etc.)."""
        digits = [int(d) for d in number if d.isdigit()]
        if len(digits) < 13:
            return False

        checksum = 0
        for i, digit in enumerate(reversed(digits)):
            if i % 2 == 1:
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit

        return checksum % 10 == 0

    def _adjust_confidence_by_field(
        self,
        base_confidence: float,
        field_name: str,
        category: DataCategory,
    ) -> float:
        """Adjust confidence based on field name context."""
        field_lower = field_name.lower()

        # Field name patterns that boost confidence
        boosters = {
            DataCategory.PII_SSN: ["ssn", "social", "tax_id"],
            DataCategory.PII_EMAIL: ["email", "mail"],
            DataCategory.PII_PHONE: ["phone", "mobile", "cell", "tel"],
            DataCategory.PCI_CARD_NUMBER: ["card", "pan", "credit", "payment"],
            DataCategory.PCI_CVV: ["cvv", "cvc", "security_code"],
            DataCategory.CREDENTIALS_PASSWORD: ["password", "passwd", "pwd", "secret"],
            DataCategory.CREDENTIALS_API_KEY: ["api_key", "apikey", "access_key"],
        }

        if category in boosters:
            for pattern in boosters[category]:
                if pattern in field_lower:
                    return min(1.0, base_confidence + 0.2)

        return base_confidence

    def get_patterns(self) -> list[DataPattern]:
        """Get all detection patterns."""
        return self._patterns.copy()

    def get_pattern(self, name: str) -> DataPattern | None:
        """Get a specific pattern by name."""
        for pattern in self._patterns:
            if pattern.name == name:
                return pattern
        return None
