"""
User management for Mantissa Stance.

Provides user lifecycle management including registration,
authentication, and profile management.

Part of Phase 92: API Gateway & Authentication
"""

from __future__ import annotations

import re
import secrets
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
        # Validate email
        self._validate_email(email)

        # Check for existing user
        email_lower = email.lower()
        username_lower = username.lower()

        if email_lower in self._email_index:
            raise UserExistsError(f"User with email {email} already exists")

        if username_lower in self._username_index:
            raise UserExistsError(f"User with username {username} already exists")

        # Validate password
        self._validate_password(password)

        # Create credentials
        credentials = UserCredentials(
            max_login_attempts=self.config.max_login_attempts,
            lockout_duration_minutes=self.config.lockout_duration_minutes,
        )
        credentials.set_password(password)

        # Create user
        user = User(
            id=secrets.token_hex(16),
            email=email,
            username=username,
            display_name=display_name or username,
            credentials=credentials,
            roles=roles or {UserRole.VIEWER},
            status=UserStatus.PENDING_VERIFICATION if self.config.email_verification_required else UserStatus.ACTIVE,
            tenant_id=tenant_id,
            metadata=metadata or {},
        )

        # Store user
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
            test_creds = UserCredentials()
            test_creds.set_password(password)
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
        # Find user
        user = self._find_user_by_identifier(identifier)
        if user is None:
            raise UserNotFoundError("User not found")

        # Check if account is active
        if user.status == UserStatus.SUSPENDED:
            raise AccountLockedError("Account is suspended")

        if user.status == UserStatus.PENDING_VERIFICATION:
            raise AccountLockedError("Email verification required")

        # Check lockout
        if user.credentials.is_locked():
            raise AccountLockedError(
                f"Account is locked. Try again in {self.config.lockout_duration_minutes} minutes"
            )

        # Verify password
        if not user.credentials.verify_password(password):
            user.credentials.record_failed_attempt()
            raise InvalidCredentialsError("Invalid credentials")

        # Clear failed attempts on success
        user.credentials.failed_attempts = 0
        user.credentials.lockout_until = None
        user.last_login_at = datetime.utcnow()
        user.last_login_ip = ip_address

        return user

    def _find_user_by_identifier(self, identifier: str) -> Optional[User]:
        """Find user by email or username."""
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
        user.credentials.set_password(new_password)
        user.credentials.password_changed_at = datetime.utcnow()
        user.credentials.failed_attempts = 0
        user.credentials.lockout_until = None

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
        user.credentials.set_password(new_password)
        user.credentials.password_changed_at = datetime.utcnow()

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
        return self._users.get(user_id)

    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        user_id = self._email_index.get(email.lower())
        if user_id:
            return self._users.get(user_id)
        return None

    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username."""
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
        user = self._users.get(user_id)
        if user is None:
            raise UserNotFoundError("User not found")

        if display_name:
            user.display_name = display_name

        if email and email.lower() != user.email.lower():
            self._validate_email(email)
            email_lower = email.lower()

            if email_lower in self._email_index:
                raise UserExistsError(f"Email {email} already in use")

            # Update email index
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
        user = self._users.get(user_id)
        if user is None:
            raise UserNotFoundError("User not found")

        user.roles = roles
        user.updated_at = datetime.utcnow()

        return user

    def add_user_role(self, user_id: str, role: UserRole) -> User:
        """Add a role to user."""
        user = self._users.get(user_id)
        if user is None:
            raise UserNotFoundError("User not found")

        user.roles.add(role)
        user.updated_at = datetime.utcnow()

        return user

    def remove_user_role(self, user_id: str, role: UserRole) -> User:
        """Remove a role from user."""
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
        user = self._users.get(user_id)
        if user is None:
            return False

        # Remove from indexes
        del self._email_index[user.email.lower()]
        del self._username_index[user.username.lower()]
        del self._users[user_id]

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
        query_lower = query.lower()
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
        status_counts = {}
        role_counts = {}

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
                if u.status == UserStatus.PENDING_VERIFICATION
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

        # Generate TOTP secret (placeholder)
        secret = secrets.token_hex(20)

        user.credentials.mfa_enabled = True
        user.credentials.mfa_secret = secret
        user.updated_at = datetime.utcnow()

        return {
            "method": method,
            "secret": secret,
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

        # Placeholder TOTP verification
        # In production, use pyotp or similar library
        # For now, accept any 6-digit code for testing
        return len(code) == 6 and code.isdigit()


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
