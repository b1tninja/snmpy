"""SNMPv3 Message Authentication — RFC 3414 §6/§7, RFC 7860.

Provides:
- HMAC-MD5-96 authentication digest (RFC 3414 §6)
- HMAC-SHA-96 authentication digest (RFC 3414 §7; "CBC-SHA-96" here)
- HMAC-SHA-224/256/384/512 authentication digests (RFC 7860)
- Message Integrity Check (MIC) calculation
- Authentication verification on incoming messages

RFC 3414 §6 (HMAC-MD5-96) / §7 (HMAC-SHA-96):
    The authentication protocol provides message integrity and
    authentication. The algorithm computes a message integrity
    check (MIC) using MD5 or SHA-1, truncated to 12 octets.

RFC 7860 (HMAC-SHA-2 Authentication Protocols in USM for SNMPv3):
    Defines HMAC-SHA-224/256/384/512 authentication protocols.
    The MAC is truncated to 16/24/32/48 octets respectively
    (RFC 7860 §4) — not to the full digest size.

Usage:
    >>> from snmp.auth import calculate_mic, verify_mic
    >>> mic = calculate_mic(raw_message, auth_key, "CBC-SHA-96", engine_id)
    >>> valid = verify_mic(raw_message, mic, auth_key, "CBC-SHA-96", engine_id)
"""

from __future__ import annotations

import hashlib
import hmac as hmac_lib
from typing import Optional


# =============================================================================
# Authentication Protocol Constants
# =============================================================================

class AuthProtocol:
    """SNMPv3 authentication protocol identifiers."""
    CBC_SHA_96: str = "CBC-SHA-96"
    HMAC_SHA_256: str = "HMAC-SHA-256"
    HMAC_SHA_224: str = "HMAC-SHA-224"
    HMAC_SHA_384: str = "HMAC-SHA-384"
    HMAC_SHA_512: str = "HMAC-SHA-512"
    CBC_MD5: str = "CBC-MD5"

# Truncated MAC lengths per protocol:
# - HMAC-MD5-96 / HMAC-SHA-96: first 12 octets (RFC 3414 §6.3.1 / §7.3.1)
# - HMAC-SHA-2 family: RFC 7860 §4 truncates to 128/192/256/384 bits,
#   NOT to the full digest size.
_AUTH_DIGEST_LENGTHS: dict[str, int] = {
    AuthProtocol.CBC_SHA_96: 12,  # 96 bits = 12 bytes (RFC 3414 §7.3.1)
    AuthProtocol.HMAC_SHA_256: 24,  # 192 bits (RFC 7860 §4)
    AuthProtocol.HMAC_SHA_224: 16,  # 128 bits (RFC 7860 §4)
    AuthProtocol.HMAC_SHA_384: 32,  # 256 bits (RFC 7860 §4)
    AuthProtocol.HMAC_SHA_512: 48,  # 384 bits (RFC 7860 §4)
    AuthProtocol.CBC_MD5: 12,  # 96 bits = 12 bytes (RFC 3414 §6.3.1)
}

# Hash function names
_AUTH_HASH_FUNCTIONS: dict[str, str] = {
    AuthProtocol.CBC_SHA_96: "sha1",
    AuthProtocol.HMAC_SHA_256: "sha256",
    AuthProtocol.HMAC_SHA_224: "sha224",
    AuthProtocol.HMAC_SHA_384: "sha384",
    AuthProtocol.HMAC_SHA_512: "sha512",
    AuthProtocol.CBC_MD5: "md5",
}

# Required key lengths (pre-matured auth key)
_AUTH_KEY_LENGTHS: dict[str, int] = {
    AuthProtocol.CBC_SHA_96: 20,  # SHA-1 produces 20 bytes
    AuthProtocol.HMAC_SHA_256: 32,  # SHA-256 needs 32 bytes
    AuthProtocol.HMAC_SHA_224: 28,
    AuthProtocol.HMAC_SHA_384: 48,
    AuthProtocol.HMAC_SHA_512: 64,
    AuthProtocol.CBC_MD5: 16,  # MD5 produces 16 bytes
}


# =============================================================================
# MIC Calculation
# =============================================================================

def _get_hash_func(protocol: str):
    """Get the hashlib hash function for a protocol."""
    hash_name = _AUTH_HASH_FUNCTIONS.get(protocol)
    if not hash_name:
        raise ValueError(f"Unknown auth protocol: {protocol}")
    return getattr(hashlib, hash_name)


def calculate_mic(
    message: bytes,
    auth_key: bytes,
    protocol: str = AuthProtocol.CBC_SHA_96,
    engine_id: bytes = b"",
) -> bytes:
    """Calculate an SNMPv3 message integrity check (MIC).

    Computes a MAC over the message using the specified authentication
    protocol and truncated to the protocol's digest length.

    Args:
        message: The message bytes to authenticate.
        auth_key: Pre-matured authentication key.
        protocol: Authentication protocol (e.g., CBC-SHA-96, HMAC-SHA-256).
        engine_id: The sender's engine ID (for context).

    Returns:
        Truncated MIC bytes.
    """
    digest_length = _AUTH_DIGEST_LENGTHS.get(protocol, 12)
    hash_func = _get_hash_func(protocol)

    mac = hmac_lib.new(auth_key, message, hash_func)
    full_mac = mac.digest()

    return full_mac[:digest_length]


def verify_mic(
    message: bytes,
    expected_mic: bytes,
    auth_key: bytes,
    protocol: str = AuthProtocol.CBC_SHA_96,
    engine_id: bytes = b"",
) -> bool:
    """Verify an SNMPv3 message integrity check.

    Uses constant-time comparison to prevent timing attacks.

    Args:
        message: The message to verify.
        expected_mic: The MIC from the message.
        auth_key: The authentication key.
        protocol: Authentication protocol.
        engine_id: The sender's engine ID.

    Returns:
        True if the MIC is valid.
    """
    calculated_mic = calculate_mic(message, auth_key, protocol, engine_id)
    return hmac_lib.compare_digest(calculated_mic, expected_mic)


# =============================================================================
# CBC-SHA-96 Specific (RFC 3414 §7 — HMAC-SHA-96)
# =============================================================================

def calculate_sha96_mic(message: bytes, auth_key: bytes, engine_id: bytes = b"") -> bytes:
    """Calculate a CBC-SHA-96 MIC (RFC 3414 §7.3.1).

    SHA-1 based authentication truncated to 96 bits.

    Args:
        message: The message to authenticate.
        auth_key: 20-byte authentication key.
        engine_id: The sender's engine ID.

    Returns:
        12-byte MIC.
    """
    return calculate_mic(message, auth_key, AuthProtocol.CBC_SHA_96, engine_id)


def verify_sha96_mic(message: bytes, expected_mic: bytes, auth_key: bytes, engine_id: bytes = b"") -> bool:
    """Verify a CBC-SHA-96 MIC.

    Args:
        message: The message to verify.
        expected_mic: Expected MIC.
        auth_key: Authentication key.
        engine_id: Engine ID.

    Returns:
        True if valid.
    """
    return verify_mic(message, expected_mic, auth_key, AuthProtocol.CBC_SHA_96, engine_id)


# =============================================================================
# HMAC-SHA-256 (RFC 7860)
# =============================================================================

def calculate_hmac_sha256_mic(message: bytes, auth_key: bytes, engine_id: bytes = b"") -> bytes:
    """Calculate HMAC-SHA-256 MIC (RFC 7860).

    Args:
        message: The message to authenticate.
        auth_key: 32-byte authentication key.
        engine_id: The sender's engine ID.

    Returns:
        24-byte MIC (RFC 7860 §4 truncates SHA-256 HMAC to 192 bits).
    """
    return calculate_mic(message, auth_key, AuthProtocol.HMAC_SHA_256, engine_id)


def verify_hmac_sha256_mic(message: bytes, expected_mic: bytes, auth_key: bytes, engine_id: bytes = b"") -> bool:
    """Verify a HMAC-SHA-256 MIC.

    Args:
        message: The message to verify.
        expected_mic: Expected MIC.
        auth_key: Authentication key.
        engine_id: Engine ID.

    Returns:
        True if valid.
    """
    return verify_mic(message, expected_mic, auth_key, AuthProtocol.HMAC_SHA_256, engine_id)


# =============================================================================
# HMAC-SHA-384/512 (RFC 7860)
# =============================================================================

def calculate_hmac_sha384_mic(message: bytes, auth_key: bytes, engine_id: bytes = b"") -> bytes:
    """Calculate HMAC-SHA-384 MIC (RFC 7860)."""
    return calculate_mic(message, auth_key, AuthProtocol.HMAC_SHA_384, engine_id)


def calculate_hmac_sha512_mic(message: bytes, auth_key: bytes, engine_id: bytes = b"") -> bytes:
    """Calculate HMAC-SHA-512 MIC (RFC 7860)."""
    return calculate_mic(message, auth_key, AuthProtocol.HMAC_SHA_512, engine_id)


# =============================================================================
# CBC-MD5 (RFC 3414 §6 — HMAC-MD5-96, deprecated in favor of SHA)
# =============================================================================

def calculate_md5_mic(message: bytes, auth_key: bytes, engine_id: bytes = b"") -> bytes:
    """Calculate CBC-MD5 MIC (RFC 3414 §6.3.1).

    MD5-based HMAC truncated to 96 bits (12 octets) — HMAC-MD5-96.
    Deprecated in favor of SHA-96.
    """
    return calculate_mic(message, auth_key, AuthProtocol.CBC_MD5, engine_id)


def verify_md5_mic(message: bytes, expected_mic: bytes, auth_key: bytes, engine_id: bytes = b"") -> bool:
    """Verify a CBC-MD5 MIC."""
    return verify_mic(message, expected_mic, auth_key, AuthProtocol.CBC_MD5, engine_id)


# =============================================================================
# Authentication Context
# =============================================================================

class AuthenticationContext:
    """Authentication context for SNMPv3 message processing.

    Stores the authentication state and provides methods for
    computing and verifying MICs on SNMPv3 messages.

    Usage:
        >>> from snmp.auth import AuthenticationContext
        >>> ctx = AuthenticationContext(protocol="CBC-SHA-96", auth_key=key_bytes)
        >>> mic = ctx.compute_mic(raw_message, engine_id)
        >>> valid = ctx.verify_mic(raw_message, received_mic, engine_id)
    """

    def __init__(
        self,
        protocol: str = AuthProtocol.CBC_SHA_96,
        auth_key: bytes = b"",
        engine_id: bytes = b"",
    ) -> None:
        """Initialize authentication context.

        Args:
            protocol: Authentication protocol.
            auth_key: Pre-matured authentication key.
            engine_id: Local engine ID.
        """
        self.protocol = protocol
        self.auth_key = auth_key
        self.engine_id = engine_id

    @property
    def digest_length(self) -> int:
        """Get the digest length for this protocol."""
        return _AUTH_DIGEST_LENGTHS.get(self.protocol, 12)

    @property
    def key_length(self) -> int:
        """Get the required key length for this protocol."""
        return _AUTH_KEY_LENGTHS.get(self.protocol, 20)

    def compute_mic(self, message: bytes, remote_engine_id: bytes = b"") -> bytes:
        """Compute the MIC for a message.

        Args:
            message: The message to authenticate.
            remote_engine_id: The remote engine's ID (for context).

        Returns:
            The computed MIC.
        """
        return calculate_mic(message, self.auth_key, self.protocol, remote_engine_id)

    def verify_mic(self, message: bytes, expected_mic: bytes, remote_engine_id: bytes = b"") -> bool:
        """Verify the MIC on a message.

        Args:
            message: The message to verify.
            expected_mic: Expected MIC.
            remote_engine_id: Remote engine ID.

        Returns:
            True if valid.
        """
        return verify_mic(message, expected_mic, self.auth_key, self.protocol, remote_engine_id)

    def __repr__(self) -> str:
        return (
            f"AuthenticationContext("
            f"protocol={self.protocol!r}, "
            f"digest_length={self.digest_length})"
        )


# =============================================================================
# Exported Names
# =============================================================================

__all__ = [
    "AuthProtocol",
    "calculate_mic",
    "verify_mic",
    "calculate_sha96_mic",
    "verify_sha96_mic",
    "calculate_hmac_sha256_mic",
    "verify_hmac_sha256_mic",
    "calculate_hmac_sha384_mic",
    "calculate_hmac_sha512_mic",
    "calculate_md5_mic",
    "verify_md5_mic",
    "AuthenticationContext",
]