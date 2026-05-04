"""User-based Security Model (USM) — RFC 3414.

Provides:
- SecurityLevel: noAuthNoPriv, authNoPriv, authPriv
- AuthProtocol: None, MD5, SHA, SHA96
- PrivProtocol: None, DES, AES128, AES192, AES256
- USMUser: User security credentials (username, auth, privacy)
- USMUserDatabase: User database for authentication
- SecurityParameters: USM security parameters (RFC 3414 §5)

RFC 3414 (User-based Security Model (USM) for Protocol
Processing Model (SPM) for SNMPv3):
    Defines the security model for SNMPv3 with:
    - Authentication: MD5, SHA, HMAC/SHA-256
    - Privacy: DES Encryption (CBC), AES (CBC/AES128/AES192/AES256)
    - Security levels: noAuthNoPriv, authNoPriv, authPriv
"""

from __future__ import annotations

import os
from enum import Enum
from hashlib import md5, sha1, sha256
from typing import ClassVar, Optional


# =============================================================================
# Security Levels
# =============================================================================

class SecurityLevel(Enum):
    """SNMPv3 security levels per RFC 3414 §5.1.

    Attributes:
        NO_AUTH_NO_PRIV: No authentication or privacy (level 0).
        AUTH_NO_PRIV: Authentication only, no privacy (level 1).
        AUTH_PRIV: Authentication and privacy (level 2).
    """

    NO_AUTH_NO_PRIV = 0
    AUTH_NO_PRIV = 1
    AUTH_PRIV = 2

    @classmethod
    def from_int(cls, level: int) -> SecurityLevel:
        """Create SecurityLevel from integer.

        Args:
            level: Integer security level (0, 1, or 2).

        Returns:
            The corresponding SecurityLevel enum value.
        """
        return cls(level)


# =============================================================================
# Authentication Protocols
# =============================================================================

class AuthProtocol(Enum):
    """Authentication protocols per RFC 3414 §3.2.

    Attributes:
        NONE: No authentication protocol (RFC 3414 §3.2).
        MD5: MD5 authentication protocol (RFC 3414 §3.2.1).
        SHA: SHA-1 authentication protocol (RFC 3414 §3.2.2).
        SHA96: SHA-96 authentication protocol (RFC 3414 §3.2.2).
        SHA256: SHA-256 authentication protocol (RFC 7860).
        SHA384: SHA-384 authentication protocol (RFC 7860).
        SHA512: SHA-512 authentication protocol (RFC 7860).
    """

    NONE: str = "none"
    MD5: str = "MD5"
    SHA: str = "SHA"
    SHA96: str = "SHA96"
    SHA256: str = "SHA256"
    SHA384: str = "SHA384"
    SHA512: str = "SHA512"

    _AUTH_DIGEST_LENGTHS: ClassVar[dict[str, int]] = {
        "none": 0,
        "MD5": 16,
        "SHA": 20,
        "SHA96": 12,
        "SHA256": 32,
        "SHA384": 48,
        "SHA512": 64,
    }

    def get_digest_length(self) -> int:
        """Get the authentication digest length in bytes.

        Returns:
            Digest length in bytes for this protocol.
        """
        return self._AUTH_DIGEST_LENGTHS.get(self.value, 0)


# =============================================================================
# Privacy Protocols
# =============================================================================

class PrivProtocol(Enum):
    """Privacy protocols per RFC 3414 §3.3.

    Attributes:
        NONE: No privacy protocol (encryption disabled).
        DES: DES encryption (RFC 3414 §3.3).
        AES: AES encryption (RFC 3826 / RFC 3827 / RFC 3828).
        AES128: AES-128 encryption (RFC 3826).
        AES192: AES-192 encryption (RFC 3827).
        AES256: AES-256 encryption (RFC 3828).
    """

    NONE: str = "none"
    DES: str = "DES"
    AES: str = "AES"
    AES128: str = "AES128"
    AES192: str = "AES192"
    AES256: str = "AES256"

    _PRIV_KEY_LENGTHS: ClassVar[dict[str, int]] = {
        "none": 0,
        "DES": 8,
        "AES128": 16,
        "AES192": 24,
        "AES256": 32,
    }

    def get_key_length(self) -> int:
        """Get the privacy key length in bytes.

        Returns:
            Key length in bytes for this protocol.
        """
        return self._PRIV_KEY_LENGTHS.get(self.value, 0)


# =============================================================================
# USM User Credentials
# =============================================================================

class USMUser:
    """SNMPv3 user credentials per RFC 3414 §2.

    Attributes:
        username: The user's SNMPv3 username (up to 32 octets).
        auth_protocol: Authentication protocol (NONE, MD5, SHA, etc.).
        auth_passphrase: Authentication pass phrase (up to 64 octets).
        priv_protocol: Privacy protocol (NONE, DES, AES, etc.).
        priv_passphrase: Privacy pass phrase (up to 64 octets).
        security_engine_id: The SNMP engine this user was discovered with.
    """

    MAX_USERNAME_LEN: int = 32
    MAX_PASSPHRASE_LEN: int = 64

    def __init__(
        self,
        username: str,
        auth_protocol: AuthProtocol = AuthProtocol.NONE,
        auth_passphrase: Optional[str] = None,
        priv_protocol: PrivProtocol = PrivProtocol.NONE,
        priv_passphrase: Optional[str] = None,
        security_engine_id: Optional[bytes] = None,
    ) -> None:
        """Initialize USM user credentials.

        Args:
            username: The user's SNMPv3 username (up to 32 octets).
            auth_protocol: Authentication protocol.
            auth_passphrase: Authentication pass phrase (up to 64 octets).
            priv_protocol: Privacy protocol.
            priv_passphrase: Privacy pass phrase (up to 64 octets).
            security_engine_id: The SNMP engine this user was discovered with.

        Raises:
            ValueError: If username or passphrase exceeds maximum length.
        """
        if not username or len(username.encode("utf-8")) > self.MAX_USERNAME_LEN:
            raise ValueError(
                f"Username must be 1-{self.MAX_USERNAME_LEN} octets, "
                f"got {len(username.encode('utf-8'))} octets"
            )

        if auth_passphrase and len(auth_passphrase.encode("utf-8")) > self.MAX_PASSPHRASE_LEN:
            raise ValueError("Auth passphrase must be <= 64 octets")

        if priv_passphrase and len(priv_passphrase.encode("utf-8")) > self.MAX_PASSPHRASE_LEN:
            raise ValueError("Priv passphrase must be <= 64 octets")

        self.username = username
        self.auth_protocol = auth_protocol
        self.auth_passphrase = auth_passphrase
        self.priv_protocol = priv_protocol
        self.priv_passphrase = priv_passphrase
        self.security_engine_id = security_engine_id

    @property
    def security_level(self) -> SecurityLevel:
        """Compute the security level for this user.

        Returns:
            SecurityLevel based on auth and privacy protocols.
        """
        if self.auth_protocol == AuthProtocol.NONE and self.priv_protocol == PrivProtocol.NONE:
            return SecurityLevel.NO_AUTH_NO_PRIV
        if self.auth_protocol != AuthProtocol.NONE and self.priv_protocol == PrivProtocol.NONE:
            return SecurityLevel.AUTH_NO_PRIV
        return SecurityLevel.AUTH_PRIV

    def get_security_parameters(self) -> bytes:
        """Get the security parameters (engine ID) as bytes.

        Returns:
            Security engine ID bytes, or empty bytes if not set.
        """
        if self.security_engine_id:
            return self.security_engine_id
        return b""

    def is_authenticated(self) -> bool:
        """Check if this user has authentication configured.

        Returns:
            True if authentication protocol is set.
        """
        return self.auth_protocol != AuthProtocol.NONE

    def is_privacy_enabled(self) -> bool:
        """Check if this user has privacy (encryption) configured.

        Returns:
            True if privacy protocol is set.
        """
        return self.priv_protocol != PrivProtocol.NONE

    def __repr__(self) -> str:
        level = self.security_level.name
        return (
            f"USMUser(username={self.username!r}, "
            f"auth={self.auth_protocol.value}, "
            f"priv={self.priv_protocol.value}, "
            f"level={level})"
        )


# =============================================================================
# USM User Database
# =============================================================================

class USMUserDatabase:
    """USM user database for storing and retrieving user credentials.

    RFC 3414 §2: The local user table stores the list of users,
    their security settings, and associated key maturation values.
    """

    def __init__(self) -> None:
        self._users: dict[str, USMUser] = {}

    def add_user(self, user: USMUser) -> None:
        """Add or update a user.

        Args:
            user: The USMUser to add or update.
        """
        self._users[user.username] = user

    def remove_user(self, username: str) -> bool:
        """Remove a user from the database.

        Args:
            username: The username to remove.

        Returns:
            True if the user was removed, False if not found.
        """
        if username in self._users:
            del self._users[username]
            return True
        return False

    def get_user(self, username: str) -> Optional[USMUser]:
        """Get user credentials by username.

        Args:
            username: The username to look up.

        Returns:
            The USMUser, or None if not found.
        """
        return self._users.get(username)

    def list_users(self) -> list[str]:
        """List all usernames in the database.

        Returns:
            List of usernames.
        """
        return list(self._users.keys())

    def has_user(self, username: str) -> bool:
        """Check if a username exists in the database.

        Args:
            username: The username to check.

        Returns:
            True if the user exists.
        """
        return username in self._users

    def clear(self) -> None:
        """Remove all users from the database."""
        self._users.clear()


# =============================================================================
# Security Parameters
# =============================================================================

class SecurityParameters:
    """USM security parameters per RFC 3414 §5.

    Contains all the security parameters used in USM processing:
    - engine_id: The ID of the sending/receiving engine.
    - username: The name of the security principal.
    - security_level: The requested security level.
    - security_model: The security model ID (USM = 3).
    """

    USM_SECURITY_MODEL: int = 3

    def __init__(
        self,
        engine_id: bytes = b"",
        username: str = "",
        security_level: int = SecurityLevel.NO_AUTH_NO_PRIV.value,
        authentication_key: bytes = b"",
        privacy_key: bytes = b"",
        auth_protocol: str = "",
        priv_protocol: str = "",
    ) -> None:
        """Initialize USM security parameters.

        Args:
            engine_id: The engine ID.
            username: The security principal.
            security_level: The security level (0=noAuthNoPriv, 1=authNoPriv, 2=authPriv).
            authentication_key: Pre-matured authentication key for MIC calculation.
            privacy_key: Pre-matured privacy key for encryption.
            auth_protocol: Authentication protocol (CBC-SHA-96, HMAC-SHA-256, etc.).
            priv_protocol: Privacy protocol (DES, AES128, AES192, AES256).
        """
        self.engine_id: bytes = engine_id
        self.username: str = username
        self.security_level: int = security_level
        self.security_model: int = self.USM_SECURITY_MODEL
        self.authentication_key: bytes = authentication_key
        self.privacy_key: bytes = privacy_key
        self.auth_protocol: str = auth_protocol
        self.priv_protocol: str = priv_protocol

    @property
    def security_level_name(self) -> str:
        """Get the security level as a string name.

        Returns:
            String name for the security level.
        """
        levels: dict[int, str] = {0: "noAuthNoPriv", 1: "authNoPriv", 2: "authPriv"}
        return levels.get(self.security_level, "unknown")

    def __repr__(self) -> str:
        return (
            f"SecurityParameters("
            f"engine_id={self.engine_id.hex()[:24]}... "
            f"name={self.username!r} "
            f"level={self.security_level_name})"
        )


# =============================================================================
# Key Maturation
# =============================================================================


def localize_passphrase(
    passphrase: str,
    engine_id: bytes,
    auth_protocol: AuthProtocol = AuthProtocol.MD5,
) -> bytes:
    """Localize a passphrase with the engine ID.

    RFC 3414 §5.2.2: The localization procedure ensures that
    the same passphrase produces different key material for
    different engines.

    Args:
        passphrase: The user's passphrase (up to 64 octets).
        engine_id: The remote engine's engine ID.
        auth_protocol: The authentication protocol to use.

    Returns:
        Localized key material (bytes).

    Raises:
        ValueError: If engine_id is less than 5 octets.
    """
    passphrase_bytes = passphrase.encode("utf-8")[:64]

    if not engine_id or len(engine_id) < 5:
        raise ValueError("Engine ID must be at least 5 octets")

    if auth_protocol == AuthProtocol.MD5:
        hash_fn = md5
    elif auth_protocol == AuthProtocol.SHA:
        hash_fn = sha1
    elif auth_protocol == AuthProtocol.SHA256:
        hash_fn = sha256
    else:
        hash_fn = md5

    localized = b""
    for _ in range(10000):
        localized += hash_fn(engine_id + passphrase_bytes + engine_id).digest()

    return localized[:auth_protocol.get_digest_length()]


# =============================================================================
# Exported Names
# =============================================================================

__all__ = [
    "SecurityLevel",
    "AuthProtocol",
    "PrivProtocol",
    "USMUser",
    "USMUserDatabase",
    "SecurityParameters",
    "localize_passphrase",
]