"""
SBOM Attestation and Signing for Supply Chain Security.

Provides cryptographic attestation and verification for SBOMs,
supporting in-toto attestation format and digital signatures.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class AttestationType(Enum):
    """Types of attestations."""

    SBOM = "https://spdx.dev/Document"
    CYCLONEDX = "https://cyclonedx.org/bom"
    IN_TOTO = "https://in-toto.io/Statement/v0.1"
    SLSA_PROVENANCE = "https://slsa.dev/provenance/v0.2"
    CUSTOM = "custom"


class SignatureAlgorithm(Enum):
    """Supported signature algorithms."""

    HMAC_SHA256 = "hmac-sha256"
    HMAC_SHA512 = "hmac-sha512"
    # Note: RSA/ECDSA would require additional crypto libraries
    # These are placeholders for future implementation
    RSA_SHA256 = "rsa-sha256"
    ECDSA_P256 = "ecdsa-p256"
    ED25519 = "ed25519"


class VerificationStatus(Enum):
    """Attestation verification status."""

    VALID = "valid"
    INVALID = "invalid"
    EXPIRED = "expired"
    UNKNOWN_SIGNER = "unknown_signer"
    MISSING_SIGNATURE = "missing_signature"
    UNSUPPORTED_ALGORITHM = "unsupported_algorithm"
    ERROR = "error"


@dataclass
class Signer:
    """Represents a signer identity."""

    id: str
    name: str
    email: str | None = None
    organization: str | None = None
    key_id: str | None = None
    public_key: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "organization": self.organization,
            "key_id": self.key_id,
        }


@dataclass
class Signature:
    """Represents a digital signature."""

    algorithm: SignatureAlgorithm
    value: str  # Base64-encoded signature
    key_id: str | None = None
    signed_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "algorithm": self.algorithm.value,
            "value": self.value,
            "key_id": self.key_id,
            "signed_at": self.signed_at.isoformat(),
        }


@dataclass
class Subject:
    """
    Subject of an attestation (what is being attested).

    Based on in-toto attestation format.
    """

    name: str
    digest: dict[str, str] = field(default_factory=dict)  # algorithm: hash
    content_type: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "digest": self.digest,
            "content_type": self.content_type,
        }


@dataclass
class Predicate:
    """
    Predicate of an attestation (claims about the subject).

    Contains the actual SBOM or metadata being attested.
    """

    predicate_type: str
    content: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "predicateType": self.predicate_type,
            **self.content,
            "_metadata": self.metadata,
        }


@dataclass
class Attestation:
    """
    SBOM Attestation following in-toto format.

    An attestation is a signed statement about software artifacts.
    """

    # Attestation type
    type: AttestationType = AttestationType.IN_TOTO

    # Subject (what is being attested)
    subjects: list[Subject] = field(default_factory=list)

    # Predicate (claims about the subject)
    predicate: Predicate | None = None

    # Signature
    signature: Signature | None = None

    # Signer information
    signer: Signer | None = None

    # Metadata
    id: str = field(default_factory=lambda: f"att-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}")
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: datetime | None = None

    @property
    def is_signed(self) -> bool:
        """Check if attestation has a signature."""
        return self.signature is not None

    @property
    def is_expired(self) -> bool:
        """Check if attestation is expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    def to_envelope(self) -> dict[str, Any]:
        """
        Convert to DSSE (Dead Simple Signing Envelope) format.

        Returns:
            DSSE envelope dictionary
        """
        payload = self._build_statement()
        payload_bytes = json.dumps(payload, sort_keys=True).encode()
        payload_b64 = base64.b64encode(payload_bytes).decode()

        envelope = {
            "payloadType": "application/vnd.in-toto+json",
            "payload": payload_b64,
            "signatures": [],
        }

        if self.signature:
            envelope["signatures"].append({
                "keyid": self.signature.key_id or "",
                "sig": self.signature.value,
            })

        return envelope

    def _build_statement(self) -> dict[str, Any]:
        """Build the in-toto statement."""
        statement = {
            "_type": self.type.value,
            "subject": [s.to_dict() for s in self.subjects],
        }

        if self.predicate:
            statement["predicateType"] = self.predicate.predicate_type
            statement["predicate"] = self.predicate.to_dict()

        return statement

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "type": self.type.value,
            "subjects": [s.to_dict() for s in self.subjects],
            "predicate": self.predicate.to_dict() if self.predicate else None,
            "signature": self.signature.to_dict() if self.signature else None,
            "signer": self.signer.to_dict() if self.signer else None,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_signed": self.is_signed,
            "is_expired": self.is_expired,
        }


@dataclass
class VerificationResult:
    """Result of attestation verification."""

    status: VerificationStatus
    message: str
    verified_at: datetime = field(default_factory=datetime.utcnow)
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def is_valid(self) -> bool:
        """Check if verification was successful."""
        return self.status == VerificationStatus.VALID

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "status": self.status.value,
            "message": self.message,
            "is_valid": self.is_valid,
            "verified_at": self.verified_at.isoformat(),
            "details": self.details,
        }


class AttestationBuilder:
    """
    Builder for creating SBOM attestations.
    """

    def __init__(self):
        """Initialize the attestation builder."""
        self._subjects: list[Subject] = []
        self._predicate: Predicate | None = None
        self._signer: Signer | None = None
        self._type: AttestationType = AttestationType.IN_TOTO
        self._expires_in_days: int | None = None

    def set_type(self, att_type: AttestationType) -> "AttestationBuilder":
        """Set attestation type."""
        self._type = att_type
        return self

    def add_subject(
        self,
        name: str,
        content: bytes | str,
        content_type: str | None = None,
    ) -> "AttestationBuilder":
        """
        Add a subject to the attestation.

        Args:
            name: Subject name (e.g., filename)
            content: Content to hash
            content_type: MIME type of content

        Returns:
            Self for chaining
        """
        if isinstance(content, str):
            content = content.encode()

        digest = {
            "sha256": hashlib.sha256(content).hexdigest(),
            "sha512": hashlib.sha512(content).hexdigest(),
        }

        subject = Subject(
            name=name,
            digest=digest,
            content_type=content_type,
        )
        self._subjects.append(subject)
        return self

    def add_subject_from_file(
        self, file_path: str, content_type: str | None = None
    ) -> "AttestationBuilder":
        """
        Add a subject from a file.

        Args:
            file_path: Path to file
            content_type: MIME type (auto-detected if not provided)

        Returns:
            Self for chaining
        """
        path = Path(file_path)
        content = path.read_bytes()

        if content_type is None:
            # Auto-detect based on extension
            ext = path.suffix.lower()
            content_type_map = {
                ".json": "application/json",
                ".xml": "application/xml",
                ".txt": "text/plain",
            }
            content_type = content_type_map.get(ext, "application/octet-stream")

        return self.add_subject(path.name, content, content_type)

    def set_predicate(
        self,
        predicate_type: str,
        content: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> "AttestationBuilder":
        """
        Set the predicate (claims about subjects).

        Args:
            predicate_type: Type URI for the predicate
            content: Predicate content
            metadata: Additional metadata

        Returns:
            Self for chaining
        """
        self._predicate = Predicate(
            predicate_type=predicate_type,
            content=content,
            metadata=metadata or {},
        )
        return self

    def set_sbom_predicate(self, sbom_data: dict[str, Any]) -> "AttestationBuilder":
        """
        Set an SBOM as the predicate.

        Args:
            sbom_data: SBOM data dictionary

        Returns:
            Self for chaining
        """
        # Detect SBOM format
        if "bomFormat" in sbom_data:
            predicate_type = AttestationType.CYCLONEDX.value
        elif "spdxVersion" in sbom_data:
            predicate_type = AttestationType.SBOM.value
        else:
            predicate_type = "https://stance.dev/sbom"

        return self.set_predicate(
            predicate_type=predicate_type,
            content={"sbom": sbom_data},
            metadata={
                "tool": "mantissa-stance",
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

    def set_signer(
        self,
        signer_id: str,
        name: str,
        email: str | None = None,
        organization: str | None = None,
        key_id: str | None = None,
    ) -> "AttestationBuilder":
        """
        Set signer information.

        Args:
            signer_id: Unique signer identifier
            name: Signer name
            email: Signer email
            organization: Signer organization
            key_id: Key identifier

        Returns:
            Self for chaining
        """
        self._signer = Signer(
            id=signer_id,
            name=name,
            email=email,
            organization=organization,
            key_id=key_id,
        )
        return self

    def set_expiry(self, days: int) -> "AttestationBuilder":
        """
        Set expiry time.

        Args:
            days: Number of days until expiry

        Returns:
            Self for chaining
        """
        self._expires_in_days = days
        return self

    def build(self) -> Attestation:
        """
        Build the attestation.

        Returns:
            Attestation object (unsigned)
        """
        from datetime import timedelta

        expires_at = None
        if self._expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=self._expires_in_days)

        return Attestation(
            type=self._type,
            subjects=self._subjects,
            predicate=self._predicate,
            signer=self._signer,
            expires_at=expires_at,
        )


class AttestationSigner:
    """
    Signs attestations using various algorithms.
    """

    def __init__(self, secret_key: str | bytes | None = None):
        """
        Initialize the signer.

        Args:
            secret_key: Secret key for HMAC signing (required for HMAC algorithms)
        """
        if isinstance(secret_key, str):
            secret_key = secret_key.encode()
        self._secret_key = secret_key

    def sign(
        self,
        attestation: Attestation,
        algorithm: SignatureAlgorithm = SignatureAlgorithm.HMAC_SHA256,
        key_id: str | None = None,
    ) -> Attestation:
        """
        Sign an attestation.

        Args:
            attestation: Attestation to sign
            algorithm: Signature algorithm
            key_id: Key identifier

        Returns:
            Signed attestation
        """
        if algorithm in (SignatureAlgorithm.HMAC_SHA256, SignatureAlgorithm.HMAC_SHA512):
            if not self._secret_key:
                raise ValueError("Secret key required for HMAC signing")

            # Build the statement and serialize
            statement = attestation._build_statement()
            message = json.dumps(statement, sort_keys=True).encode()

            # Sign with HMAC
            if algorithm == SignatureAlgorithm.HMAC_SHA256:
                signature_bytes = hmac.new(
                    self._secret_key, message, hashlib.sha256
                ).digest()
            else:
                signature_bytes = hmac.new(
                    self._secret_key, message, hashlib.sha512
                ).digest()

            signature_b64 = base64.b64encode(signature_bytes).decode()

            attestation.signature = Signature(
                algorithm=algorithm,
                value=signature_b64,
                key_id=key_id,
            )

        else:
            # Placeholder for RSA/ECDSA support
            raise NotImplementedError(
                f"Signature algorithm {algorithm.value} not yet implemented. "
                "Use HMAC_SHA256 or HMAC_SHA512 for now."
            )

        return attestation


class AttestationVerifier:
    """
    Verifies attestation signatures.
    """

    def __init__(self, secret_key: str | bytes | None = None):
        """
        Initialize the verifier.

        Args:
            secret_key: Secret key for HMAC verification
        """
        if isinstance(secret_key, str):
            secret_key = secret_key.encode()
        self._secret_key = secret_key

    def verify(self, attestation: Attestation) -> VerificationResult:
        """
        Verify an attestation signature.

        Args:
            attestation: Attestation to verify

        Returns:
            VerificationResult
        """
        # Check if signed
        if not attestation.signature:
            return VerificationResult(
                status=VerificationStatus.MISSING_SIGNATURE,
                message="Attestation has no signature",
            )

        # Check expiry
        if attestation.is_expired:
            return VerificationResult(
                status=VerificationStatus.EXPIRED,
                message="Attestation has expired",
                details={
                    "expires_at": attestation.expires_at.isoformat()
                    if attestation.expires_at
                    else None
                },
            )

        # Verify based on algorithm
        sig = attestation.signature
        algorithm = sig.algorithm

        try:
            if algorithm in (
                SignatureAlgorithm.HMAC_SHA256,
                SignatureAlgorithm.HMAC_SHA512,
            ):
                return self._verify_hmac(attestation)
            else:
                return VerificationResult(
                    status=VerificationStatus.UNSUPPORTED_ALGORITHM,
                    message=f"Unsupported algorithm: {algorithm.value}",
                )

        except Exception as e:
            logger.exception(f"Verification error: {e}")
            return VerificationResult(
                status=VerificationStatus.ERROR,
                message=f"Verification error: {str(e)}",
            )

    def _verify_hmac(self, attestation: Attestation) -> VerificationResult:
        """Verify HMAC signature."""
        if not self._secret_key:
            return VerificationResult(
                status=VerificationStatus.ERROR,
                message="Secret key required for HMAC verification",
            )

        sig = attestation.signature
        if sig is None:
            return VerificationResult(
                status=VerificationStatus.MISSING_SIGNATURE,
                message="No signature found",
            )

        # Rebuild the statement
        statement = attestation._build_statement()
        message = json.dumps(statement, sort_keys=True).encode()

        # Compute expected signature
        if sig.algorithm == SignatureAlgorithm.HMAC_SHA256:
            expected = hmac.new(self._secret_key, message, hashlib.sha256).digest()
        else:
            expected = hmac.new(self._secret_key, message, hashlib.sha512).digest()

        # Decode actual signature
        try:
            actual = base64.b64decode(sig.value)
        except Exception:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                message="Invalid signature encoding",
            )

        # Compare
        if hmac.compare_digest(expected, actual):
            return VerificationResult(
                status=VerificationStatus.VALID,
                message="Signature verified successfully",
                details={
                    "algorithm": sig.algorithm.value,
                    "key_id": sig.key_id,
                    "signed_at": sig.signed_at.isoformat(),
                },
            )
        else:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                message="Signature does not match",
            )


def create_sbom_attestation(
    sbom_data: dict[str, Any],
    sbom_file_path: str | None = None,
    signer_name: str = "Mantissa Stance",
    secret_key: str | bytes | None = None,
) -> Attestation:
    """
    Convenience function to create a signed SBOM attestation.

    Args:
        sbom_data: SBOM data dictionary
        sbom_file_path: Optional file path for subject
        signer_name: Name of the signer
        secret_key: Secret key for signing (if None, returns unsigned)

    Returns:
        Attestation object
    """
    builder = AttestationBuilder()
    builder.set_type(AttestationType.IN_TOTO)

    # Add SBOM as subject
    sbom_json = json.dumps(sbom_data, sort_keys=True)
    subject_name = sbom_file_path or "sbom.json"
    builder.add_subject(subject_name, sbom_json, "application/json")

    # Set SBOM predicate
    builder.set_sbom_predicate(sbom_data)

    # Set signer
    builder.set_signer(
        signer_id=f"signer:{signer_name.lower().replace(' ', '-')}",
        name=signer_name,
    )

    # Set expiry (90 days default)
    builder.set_expiry(90)

    attestation = builder.build()

    # Sign if key provided
    if secret_key:
        signer = AttestationSigner(secret_key)
        attestation = signer.sign(attestation)

    return attestation


def verify_sbom_attestation(
    attestation: Attestation, secret_key: str | bytes
) -> VerificationResult:
    """
    Convenience function to verify an SBOM attestation.

    Args:
        attestation: Attestation to verify
        secret_key: Secret key for verification

    Returns:
        VerificationResult
    """
    verifier = AttestationVerifier(secret_key)
    return verifier.verify(attestation)
