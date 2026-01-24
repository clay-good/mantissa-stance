"""
User management for Mantissa Stance.

Provides user lifecycle management including registration,
authentication, and profile management.

Part of Phase 92: API Gateway & Authentication
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import struct
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

from stance.auth.models import (
    User,
    UserCredentials,
    UserRole,
    UserStatus,
)


# =============================================================================
# TOTP Implementation (RFC 6238)
# =============================================================================

# TOTP time step in seconds (standard is 30 seconds)
TOTP_TIME_STEP = 30
# Number of time steps to allow for clock drift (1 step before/after = 90 second window)
TOTP_DRIFT_STEPS = 1


def _generate_totp_secret() -> str:
    """
    Generate a random base32-encoded TOTP secret.

    Returns:
        Base32-encoded secret string (20 bytes = 160 bits of entropy)
    """
    # Generate 20 random bytes (160 bits - recommended by RFC 4226)
    random_bytes = secrets.token_bytes(20)
    # Encode as base32 (standard for TOTP secrets)
    return base64.b32encode(random_bytes).decode("utf-8")


def _compute_totp(secret: str, counter: int) -> str:
    """
    Compute TOTP code for a given counter value.

    Implements HOTP (RFC 4226) which TOTP is based on.

    Args:
        secret: Base32-encoded secret key
        counter: Time-based counter value

    Returns:
        6-digit TOTP code as string
    """
    # Decode the base32 secret
    try:
        key = base64.b32decode(secret.upper())
    except Exception:
        # If secret is not valid base32, treat as raw bytes (backward compat)
        key = secret.encode("utf-8")

    # Pack counter as 8-byte big-endian
    counter_bytes = struct.pack(">Q", counter)

    # Compute HMAC-SHA1
    hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()

    # Dynamic truncation (RFC 4226 section 5.4)
    offset = hmac_hash[-1] & 0x0F
    truncated = struct.unpack(">I", hmac_hash[offset : offset + 4])[0]
    truncated &= 0x7FFFFFFF  # Clear the top bit

    # Generate 6-digit code
    code = truncated % 1000000
    return f"{code:06d}"


def _verify_totp(secret: str, code: str, drift_steps: int = TOTP_DRIFT_STEPS) -> bool:
    """
    Verify a TOTP code with time drift tolerance.

    Args:
        secret: Base32-encoded secret key
        code: 6-digit code to verify
        drift_steps: Number of time steps to check before/after current time

    Returns:
        True if code is valid, False otherwise
    """
    # Basic validation
    if not code or len(code) != 6 or not code.isdigit():
        return False

    if not secret:
        return False

    # Get current time counter
    current_time = int(time.time())
    current_counter = current_time // TOTP_TIME_STEP

    # Check codes for current time and allowed drift windows
    # This handles clock drift between server and authenticator app
    for offset in range(-drift_steps, drift_steps + 1):
        counter = current_counter + offset
        expected_code = _compute_totp(secret, counter)

        # Use constant-time comparison to prevent timing attacks
        if hmac.compare_digest(expected_code, code):
            return True

    return False


# =============================================================================
# Exceptions
# =============================================================================

class UserError(Exception):
    """Base user error."""
    pass


class UserNotFoundError(UserError):
    """User not found."""
    pass


class UserExistsError(UserError):
    """User already exists."""
    pass


class InvalidCredentialsError(UserError):
    """Invalid credentials."""
    pass


class AccountLockedError(UserError):
    """Account is locked."""
    pass


class PasswordValidationError(UserError):
    """Password validation failed."""
    pass


class EmailValidationError(UserError):
    """Email validation failed."""
    pass


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class UserConfig:
    """
    User management configuration.

    Attributes:
        password_min_length: Minimum password length
        password_require_uppercase: Require uppercase letter
        password_require_lowercase: Require lowercase letter
        password_require_digit: Require digit
        password_require_special: Require special character
        password_history_count: Number of previous passwords to remember
        max_login_attempts: Maximum failed login attempts before lockout
        lockout_duration_minutes: Lockout duration in minutes
        email_verification_required: Require email verification
        verification_token_expiry_hours: Verification token expiry in hours
        allow_password_reset: Allow password reset
        password_reset_expiry_hours: Password reset token expiry in hours
    """
    password_min_length: int = 12
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_digit: bool = True
    password_require_special: bool = True
    password_history_count: int = 5
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 30
    email_verification_required: bool = True
    verification_token_expiry_hours: int = 24
    allow_password_reset: bool = True
    password_reset_expiry_hours: int = 1


# =============================================================================
# Password Reset Token
# =============================================================================

@dataclass
class PasswordResetToken:
    """Password reset token."""
    token_hash: str
    user_id: str
    expires_at: datetime
    created_at: datetime = field(default_factory=datetime.utcnow)
    used: bool = False


# =============================================================================
# Email Verification Token
# =============================================================================

@dataclass
class EmailVerificationToken:
    """Email verification token."""
    token_hash: str
    user_id: str
    email: str
    expires_at: datetime
    created_at: datetime = field(default_factory=datetime.utcnow)
    used: bool = False


# =============================================================================
# User Manager
# =============================================================================

class UserManager:
    """
    User lifecycle manager.

    Handles user registration, authentication, and profile management.
    Thread-safe for multi-threaded environments.
    """

    def __init__(self, config: Optional[UserConfig] = None):
        """
        Initialize user manager.

        Args:
            config: User configuration
        """
        self.config = config or UserConfig()
        self._users: Dict[str, User] = {}
        self._email_index: Dict[str, str] = {}  # email -> user_id
        self._username_index: Dict[str, str] = {}  # username -> user_id
        self._password_reset_tokens: Dict[str, PasswordResetToken] = {}
        self._email_verification_tokens: Dict[str, EmailVerificationToken] = {}
        self._password_history: Dict[str, List[str]] = {}  # user_id -> [password_hashes]
        self._lock = threading.RLock()  # Reentrant lock for thread safety

    # =========================================================================
    # Registration
    # =========================================================================

    def register_user(
        self,
        email: str,
        username: str,
        password: str,
        display_name: str = "",
        roles: Optional[Set[UserRole]] = None,
        tenant_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> User:
        """
        Register a new user.

        Args:
            email: User email
            username: Username
            password: Password
            display_name: Display name
            roles: User roles
            tenant_id: Tenant ID
            metadata: Additional metadata

        Returns:
            Created User

        Raises:
            UserExistsError: If user already exists
            PasswordValidationError: If password is invalid
            EmailValidationError: If email is invalid
        """
        # Validate email (can be done outside lock)
        self._validate_email(email)

        # Validate password (can be done outside lock)
        self._validate_password(password)

        # Create credentials (can be done outside lock - expensive hashing)
        credentials = UserCredentials.create(password)

        email_lower = email.lower()
        username_lower = username.lower()

        with self._lock:
            # Check for existing user (must be atomic with insert)
            if email_lower in self._email_index:
                raise UserExistsError(f"User with email {email} already exists")

            if username_lower in self._username_index:
                raise UserExistsError(f"User with username {username} already exists")

            # Create user
            user = User(
                id=secrets.token_hex(16),
                email=email,
                username=username,
                display_name=display_name or username,
                credentials=credentials,
                roles=roles or {UserRole.VIEWER},
                status=UserStatus.PENDING if self.config.email_verification_required else UserStatus.ACTIVE,
                tenant_id=tenant_id,
                metadata=metadata or {},
            )

            # Store user atomically
            self._users[user.id] = user
            self._email_index[email_lower] = user.id
            self._username_index[username_lower] = user.id

            # Initialize password history
            self._password_history[user.id] = [credentials.password_hash]

        return user

    def _validate_email(self, email: str) -> None:
        """Validate email format."""
        # Basic email validation
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, email):
            raise EmailValidationError("Invalid email format")

    def _validate_password(
        self,
        password: str,
        user_id: Optional[str] = None,
    ) -> None:
        """Validate password strength."""
        errors = []

        if len(password) < self.config.password_min_length:
            errors.append(
                f"Password must be at least {self.config.password_min_length} characters"
            )

        if self.config.password_require_uppercase and not re.search(r"[A-Z]", password):
            errors.append("Password must contain an uppercase letter")

        if self.config.password_require_lowercase and not re.search(r"[a-z]", password):
            errors.append("Password must contain a lowercase letter")

        if self.config.password_require_digit and not re.search(r"\d", password):
            errors.append("Password must contain a digit")

        if self.config.password_require_special and not re.search(
            r"[!@#$%^&*(),.?\":{}|<>]", password
        ):
            errors.append("Password must contain a special character")

        # Check password history
        if user_id and user_id in self._password_history:
            history = self._password_history[user_id]
            test_creds = UserCredentials.create(password)
            if test_creds.password_hash in history:
                errors.append("Password was recently used")

        if errors:
            raise PasswordValidationError("; ".join(errors))

    # =========================================================================
    # Authentication
    # =========================================================================

    def authenticate(
        self,
        identifier: str,
        password: str,
        ip_address: str = "",
    ) -> User:
        """
        Authenticate a user.

        Args:
            identifier: Email or username
            password: Password
            ip_address: Client IP address

        Returns:
            Authenticated User

        Raises:
            UserNotFoundError: If user not found
            InvalidCredentialsError: If credentials invalid
            AccountLockedError: If account is locked
        """
        with self._lock:
            # Find user
            user = self._find_user_by_identifier(identifier)
            if user is None:
                raise UserNotFoundError("User not found")

            # Check if account is active
            if user.status == UserStatus.SUSPENDED:
                raise AccountLockedError("Account is suspended")

            if user.status == UserStatus.PENDING:
                raise AccountLockedError("Email verification required")

            # Check lockout
            if user.credentials.is_locked():
                raise AccountLockedError(
                    f"Account is locked. Try again in {self.config.lockout_duration_minutes} minutes"
                )

            # Verify password
            if not user.credentials.verify_password(password):
                user.credentials.record_failed_login(
                    lockout_threshold=self.config.max_login_attempts,
                    lockout_duration=self.config.lockout_duration_minutes * 60,
                )
                raise InvalidCredentialsError("Invalid credentials")

            # Clear failed attempts on success
            user.credentials.reset_failed_logins()
            user.last_login_at = datetime.utcnow()
            user.metadata["last_login_ip"] = ip_address

            return user

    def _find_user_by_identifier(self, identifier: str) -> Optional[User]:
        """Find user by email or username. Must be called with lock held."""
        identifier_lower = identifier.lower()

        # Try email first
        user_id = self._email_index.get(identifier_lower)
        if user_id:
            return self._users.get(user_id)

        # Try username
        user_id = self._username_index.get(identifier_lower)
        if user_id:
            return self._users.get(user_id)

        return None

    # =========================================================================
    # Email Verification
    # =========================================================================

    def create_verification_token(self, user_id: str) -> str:
        """
        Create email verification token.

        Args:
            user_id: User ID

        Returns:
            Verification token

        Raises:
            UserNotFoundError: If user not found
        """
        user = self._users.get(user_id)
        if user is None:
            raise UserNotFoundError("User not found")

        token = secrets.token_urlsafe(32)
        token_hash = self._hash_token(token)

        verification = EmailVerificationToken(
            token_hash=token_hash,
            user_id=user_id,
            email=user.email,
            expires_at=datetime.utcnow() + timedelta(
                hours=self.config.verification_token_expiry_hours
            ),
        )

        self._email_verification_tokens[token_hash] = verification

        return token

    def verify_email(self, token: str) -> User:
        """
        Verify user email with token.

        Args:
            token: Verification token

        Returns:
            Verified User

        Raises:
            UserError: If verification fails
        """
        token_hash = self._hash_token(token)
        verification = self._email_verification_tokens.get(token_hash)

        if verification is None:
            raise UserError("Invalid verification token")

        if verification.used:
            raise UserError("Token already used")

        if datetime.utcnow() >= verification.expires_at:
            raise UserError("Verification token expired")

        user = self._users.get(verification.user_id)
        if user is None:
            raise UserNotFoundError("User not found")

        # Mark token as used
        verification.used = True

        # Activate user
        user.status = UserStatus.ACTIVE
        user.email_verified = True
        user.email_verified_at = datetime.utcnow()

        return user

    # =========================================================================
    # Password Reset
    # =========================================================================

    def create_password_reset_token(self, email: str) -> Optional[str]:
        """
        Create password reset token.

        Args:
            email: User email

        Returns:
            Reset token or None if user not found
        """
        if not self.config.allow_password_reset:
            return None

        email_lower = email.lower()
        user_id = self._email_index.get(email_lower)

        if user_id is None:
            # Don't reveal if user exists
            return None

        token = secrets.token_urlsafe(32)
        token_hash = self._hash_token(token)

        reset = PasswordResetToken(
            token_hash=token_hash,
            user_id=user_id,
            expires_at=datetime.utcnow() + timedelta(
                hours=self.config.password_reset_expiry_hours
            ),
        )

        self._password_reset_tokens[token_hash] = reset

        return token

    def reset_password(self, token: str, new_password: str) -> User:
        """
        Reset password with token.

        Args:
            token: Reset token
            new_password: New password

        Returns:
            Updated User

        Raises:
            UserError: If reset fails
        """
        token_hash = self._hash_token(token)
        reset = self._password_reset_tokens.get(token_hash)

        if reset is None:
            raise UserError("Invalid reset token")

        if reset.used:
            raise UserError("Token already used")

        if datetime.utcnow() >= reset.expires_at:
            raise UserError("Reset token expired")

        user = self._users.get(reset.user_id)
        if user is None:
            raise UserNotFoundError("User not found")

        # Validate new password (check history)
        self._validate_password(new_password, user.id)

        # Mark token as used
        reset.used = True

        # Update password
        user.credentials.update_password(new_password)
        user.credentials.reset_failed_logins()

        # Update password history
        history = self._password_history.get(user.id, [])
        history.append(user.credentials.password_hash)
        if len(history) > self.config.password_history_count:
            history = history[-self.config.password_history_count:]
        self._password_history[user.id] = history

        return user

    def change_password(
        self,
        user_id: str,
        current_password: str,
        new_password: str,
    ) -> User:
        """
        Change user password.

        Args:
            user_id: User ID
            current_password: Current password
            new_password: New password

        Returns:
            Updated User

        Raises:
            UserNotFoundError: If user not found
            InvalidCredentialsError: If current password invalid
            PasswordValidationError: If new password invalid
        """
        user = self._users.get(user_id)
        if user is None:
            raise UserNotFoundError("User not found")

        # Verify current password
        if not user.credentials.verify_password(current_password):
            raise InvalidCredentialsError("Current password is incorrect")

        # Validate new password
        self._validate_password(new_password, user_id)

        # Update password
        user.credentials.update_password(new_password)

        # Update password history
        history = self._password_history.get(user_id, [])
        history.append(user.credentials.password_hash)
        if len(history) > self.config.password_history_count:
            history = history[-self.config.password_history_count:]
        self._password_history[user_id] = history

        return user

    def _hash_token(self, token: str) -> str:
        """Hash a token for storage."""
        import hashlib
        return hashlib.sha256(token.encode()).hexdigest()

    # =========================================================================
    # User Management
    # =========================================================================

    def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        with self._lock:
            return self._users.get(user_id)

    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        with self._lock:
            user_id = self._email_index.get(email.lower())
            if user_id:
                return self._users.get(user_id)
            return None

    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username."""
        with self._lock:
            user_id = self._username_index.get(username.lower())
            if user_id:
                return self._users.get(user_id)
            return None

    def update_user(
        self,
        user_id: str,
        display_name: Optional[str] = None,
        email: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> User:
        """
        Update user profile.

        Args:
            user_id: User ID
            display_name: New display name
            email: New email
            metadata: Metadata to merge

        Returns:
            Updated User

        Raises:
            UserNotFoundError: If user not found
            UserExistsError: If new email already exists
        """
        # Validate email outside lock if provided
        if email:
            self._validate_email(email)

        with self._lock:
            user = self._users.get(user_id)
            if user is None:
                raise UserNotFoundError("User not found")

            if display_name:
                user.display_name = display_name

            if email and email.lower() != user.email.lower():
                email_lower = email.lower()

                if email_lower in self._email_index:
                    raise UserExistsError(f"Email {email} already in use")

                # Update email index atomically
                del self._email_index[user.email.lower()]
                self._email_index[email_lower] = user_id

                user.email = email
                user.email_verified = False
                user.email_verified_at = None

            if metadata:
                user.metadata.update(metadata)

            user.updated_at = datetime.utcnow()

            return user

    def update_user_roles(
        self,
        user_id: str,
        roles: Set[UserRole],
    ) -> User:
        """
        Update user roles.

        Args:
            user_id: User ID
            roles: New roles

        Returns:
            Updated User

        Raises:
            UserNotFoundError: If user not found
        """
        with self._lock:
            user = self._users.get(user_id)
            if user is None:
                raise UserNotFoundError("User not found")

            user.roles = roles
            user.updated_at = datetime.utcnow()

        return user

    def add_user_role(self, user_id: str, role: UserRole) -> User:
        """Add a role to user."""
        with self._lock:
            user = self._users.get(user_id)
            if user is None:
                raise UserNotFoundError("User not found")

            user.roles.add(role)
            user.updated_at = datetime.utcnow()

            return user

    def remove_user_role(self, user_id: str, role: UserRole) -> User:
        """Remove a role from user."""
        with self._lock:
            user = self._users.get(user_id)
            if user is None:
                raise UserNotFoundError("User not found")

            user.roles.discard(role)
            user.updated_at = datetime.utcnow()

            return user

    def suspend_user(self, user_id: str, reason: str = "") -> User:
        """
        Suspend a user.

        Args:
            user_id: User ID
            reason: Suspension reason

        Returns:
            Updated User
        """
        user = self._users.get(user_id)
        if user is None:
            raise UserNotFoundError("User not found")

        user.status = UserStatus.SUSPENDED
        user.metadata["suspension_reason"] = reason
        user.metadata["suspended_at"] = datetime.utcnow().isoformat()
        user.updated_at = datetime.utcnow()

        return user

    def reactivate_user(self, user_id: str) -> User:
        """
        Reactivate a suspended user.

        Args:
            user_id: User ID

        Returns:
            Updated User
        """
        user = self._users.get(user_id)
        if user is None:
            raise UserNotFoundError("User not found")

        user.status = UserStatus.ACTIVE
        user.metadata.pop("suspension_reason", None)
        user.metadata.pop("suspended_at", None)
        user.updated_at = datetime.utcnow()

        return user

    def delete_user(self, user_id: str) -> bool:
        """
        Delete a user.

        Args:
            user_id: User ID

        Returns:
            True if deleted
        """
        with self._lock:
            user = self._users.get(user_id)
            if user is None:
                return False

            # Remove from indexes atomically using pop to avoid KeyError
            # if indexes are out of sync (defensive programming)
            self._email_index.pop(user.email.lower(), None)
            self._username_index.pop(user.username.lower(), None)
            self._users.pop(user_id, None)

            # Clean up password history
            self._password_history.pop(user_id, None)

            return True

    # =========================================================================
    # Query Methods
    # =========================================================================

    def list_users(
        self,
        tenant_id: Optional[str] = None,
        status: Optional[UserStatus] = None,
        role: Optional[UserRole] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[User]:
        """
        List users with filters.

        Args:
            tenant_id: Filter by tenant
            status: Filter by status
            role: Filter by role
            limit: Maximum results
            offset: Offset for pagination

        Returns:
            List of Users
        """
        with self._lock:
            results = []

            for user in self._users.values():
                if tenant_id and user.tenant_id != tenant_id:
                    continue
                if status and user.status != status:
                    continue
                if role and role not in user.roles:
                    continue
                results.append(user)

            # Sort by created_at descending
            results.sort(key=lambda u: u.created_at, reverse=True)

            return results[offset:offset + limit]

    def search_users(
        self,
        query: str,
        tenant_id: Optional[str] = None,
        limit: int = 20,
    ) -> List[User]:
        """
        Search users by email, username, or display name.

        Args:
            query: Search query
            tenant_id: Filter by tenant
            limit: Maximum results

        Returns:
            Matching Users
        """
        # Handle empty or whitespace-only queries
        query_stripped = query.strip()
        if not query_stripped:
            return []

        query_lower = query_stripped.lower()
        with self._lock:
            results = []

            for user in self._users.values():
                if tenant_id and user.tenant_id != tenant_id:
                    continue

                if (
                    query_lower in user.email.lower()
                    or query_lower in user.username.lower()
                    or query_lower in user.display_name.lower()
                ):
                    results.append(user)

                    if len(results) >= limit:
                        break

        return results

    def get_stats(self) -> Dict[str, Any]:
        """Get user statistics."""
        with self._lock:
            status_counts: Dict[str, int] = {}
            role_counts: Dict[str, int] = {}

            for user in self._users.values():
                status = user.status.value
                status_counts[status] = status_counts.get(status, 0) + 1

                for role in user.roles:
                    role_name = role.value
                    role_counts[role_name] = role_counts.get(role_name, 0) + 1

            return {
                "total_users": len(self._users),
                "status_counts": status_counts,
                "role_counts": role_counts,
                "pending_verifications": sum(
                    1 for u in self._users.values()
                    if u.status == UserStatus.PENDING
                ),
            }

    # =========================================================================
    # MFA Support (placeholder for future)
    # =========================================================================

    def enable_mfa(self, user_id: str, method: str = "totp") -> Dict[str, Any]:
        """
        Enable MFA for user.

        Args:
            user_id: User ID
            method: MFA method

        Returns:
            MFA setup data (secret, QR code, etc.)
        """
        user = self._users.get(user_id)
        if user is None:
            raise UserNotFoundError("User not found")

        # Generate proper base32-encoded TOTP secret
        secret = _generate_totp_secret()

        user.credentials.mfa_enabled = True
        user.credentials.mfa_secret = secret
        user.updated_at = datetime.utcnow()

        # Build otpauth URI for QR code generation
        # Format: otpauth://totp/LABEL?secret=SECRET&issuer=ISSUER
        otpauth_uri = (
            f"otpauth://totp/MantissaStance:{user.email}"
            f"?secret={secret}&issuer=MantissaStance&algorithm=SHA1&digits=6&period=30"
        )

        return {
            "method": method,
            "secret": secret,
            "otpauth_uri": otpauth_uri,
            "message": "MFA enabled - use authenticator app to scan QR code",
        }

    def disable_mfa(self, user_id: str) -> User:
        """Disable MFA for user."""
        user = self._users.get(user_id)
        if user is None:
            raise UserNotFoundError("User not found")

        user.credentials.mfa_enabled = False
        user.credentials.mfa_secret = None
        user.updated_at = datetime.utcnow()

        return user

    def verify_mfa(self, user_id: str, code: str) -> bool:
        """
        Verify MFA code.

        Args:
            user_id: User ID
            code: MFA code

        Returns:
            True if valid
        """
        user = self._users.get(user_id)
        if user is None:
            raise UserNotFoundError("User not found")

        if not user.credentials.mfa_enabled or not user.credentials.mfa_secret:
            return False

        # Verify TOTP code using RFC 6238 implementation
        return _verify_totp(user.credentials.mfa_secret, code)


def create_user_manager(
    password_min_length: int = 12,
    max_login_attempts: int = 5,
    lockout_duration_minutes: int = 30,
    email_verification_required: bool = True,
) -> UserManager:
    """Factory function to create user manager."""
    config = UserConfig(
        password_min_length=password_min_length,
        max_login_attempts=max_login_attempts,
        lockout_duration_minutes=lockout_duration_minutes,
        email_verification_required=email_verification_required,
    )
    return UserManager(config)
