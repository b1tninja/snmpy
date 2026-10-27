"""User-based Security Model (USM) — RFC 3414.

Provides:
- SecurityLevel: noAuthNoPriv, authNoPriv, authPriv
- AuthProtocol: None, MD5, SHA/SHA96, SHA224, SHA256, SHA384, SHA512
- PrivProtocol: None, DES, AES128, AES192, AES256
- USMUser: User security credentials (username, auth, privacy)
- USMUserDatabase: User database for authentication
- SecurityParameters: USM msgSecurityParameters (RFC 3414 §2.4, A.4)
- password_to_key / localize_key / localize_passphrase (RFC 3414 §2.6, A.2)

RFC 3414 (User-based Security Model (USM) for SNMPv3):
    Defines the security model for SNMPv3 with:
    - Authentication: HMAC-MD5-96 and HMAC-SHA-96 (RFC 3414 §6/§7) plus
      the HMAC-SHA-2 family (RFC 7860 §4)
    - Privacy: DES-CBC (RFC 3414 §8) and AES-128-CFB128 (RFC 3826);
      AES-192/AES-256 CFB variants per draft-reeder-snmpv3-usm-3desede-aes
    - Security levels: noAuthNoPriv, authNoPriv, authPriv
"""

from __future__ import annotations

from collections.abc import Callable
from enum import Enum
from hashlib import md5, sha1, sha224, sha256, sha384, sha512

from ber.object import Integer, Object, OctetString, Sequence

# =============================================================================
# Security Levels
# =============================================================================

class SecurityLevel(Enum):
    """SNMPv3 security levels per RFC 3414 §5 (SnmpSecurityLevel).

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

# Length of the truncated MAC carried in msgAuthenticationParameters.
# RFC 3414 §6.3.1/§7.3.1 truncate to 12 octets; RFC 7860 §4 truncates
# the SHA-2 based MACs to 16/24/32/48 octets (not to the full digest).
# Module scope on purpose: a single-underscore name inside an Enum body
# becomes an enum member instead of a class attribute.
_AUTH_MAC_LENGTHS: dict[str, int] = {
    "none": 0,
    "MD5": 12,
    "SHA": 12,
    "SHA96": 12,
    "SHA224": 16,
    "SHA256": 24,
    "SHA384": 32,
    "SHA512": 48,
}

# Localized key length == the digest size of the hash used for both
# password_to_key and the HMAC (RFC 3414 §2.6, RFC 7860 §4.1).
_AUTH_KEY_LENGTHS: dict[str, int] = {
    "none": 0,
    "MD5": 16,
    "SHA": 20,
    "SHA96": 20,
    "SHA224": 28,
    "SHA256": 32,
    "SHA384": 48,
    "SHA512": 64,
}

# Hash algorithm used for key localization and for the HMAC.
_AUTH_HASH_NAMES: dict[str, str] = {
    "MD5": "md5",
    "SHA": "sha1",
    "SHA96": "sha1",
    "SHA224": "sha224",
    "SHA256": "sha256",
    "SHA384": "sha384",
    "SHA512": "sha512",
}


class AuthProtocol(Enum):
    """Authentication protocols per RFC 3414 §6/§7 and RFC 7860 §4.

    Attributes:
        NONE: No authentication protocol.
        MD5: HMAC-MD5-96 authentication protocol (RFC 3414 §6).
        SHA: HMAC-SHA-96 authentication protocol (RFC 3414 §7).
        SHA96: Synonym of SHA (both are the 96-bit truncated SHA-1 MAC).
        SHA224: HMAC-SHA-224 authentication protocol (RFC 7860 §4).
        SHA256: HMAC-SHA-256 authentication protocol (RFC 7860 §4).
        SHA384: HMAC-SHA-384 authentication protocol (RFC 7860 §4).
        SHA512: HMAC-SHA-512 authentication protocol (RFC 7860 §4).
    """

    NONE: str = "none"
    MD5: str = "MD5"
    SHA: str = "SHA"
    SHA96: str = "SHA96"
    SHA224: str = "SHA224"
    SHA256: str = "SHA256"
    SHA384: str = "SHA384"
    SHA512: str = "SHA512"

    def get_mac_length(self) -> int:
        """Get the on-the-wire (truncated) MAC length in octets.

        Returns:
            MAC length in octets for this protocol.
        """
        return _AUTH_MAC_LENGTHS.get(self.value, 0)

    def get_digest_length(self) -> int:
        """Backwards-compatible alias for :meth:`get_mac_length`."""
        return self.get_mac_length()

    def get_key_length(self) -> int:
        """Get the localized key length in octets.

        Returns:
            Key length in octets (the hash digest size) for this protocol.
        """
        return _AUTH_KEY_LENGTHS.get(self.value, 0)

    @property
    def hash_name(self) -> str:
        """Name of the hash algorithm used by this protocol (empty for NONE)."""
        return _AUTH_HASH_NAMES.get(self.value, "")


# =============================================================================
# Privacy Protocols
# =============================================================================

# Length of the localized privacy key.  For DES this is 16 octets even
# though only 8 are used as the DES key: the first 8 form the (odd
# parity adjusted) key and the last 8 the pre-IV (RFC 3414 §8.1.1.1).
# For AES the localized key is used as the cipher key (RFC 3826 §3.1.2.1).
# Module scope on purpose: a single-underscore name inside an Enum body
# becomes an enum member instead of a class attribute.
_PRIV_KEY_LENGTHS: dict[str, int] = {
    "none": 0,
    "DES": 16,
    "AES": 16,
    "AES128": 16,
    "AES192": 24,
    "AES256": 32,
}

# Length of msgPrivacyParameters: the 8-octet IV for DES
# (RFC 3414 §8.2.3) and the 8-octet salt for AES (RFC 3826 §3.2.3).
_PRIV_PARAM_LENGTHS: dict[str, int] = {
    "DES": 8,
    "AES": 8,
    "AES128": 8,
    "AES192": 8,
    "AES256": 8,
}


class PrivProtocol(Enum):
    """Privacy protocols per RFC 3414 §8 and RFC 3826.

    Attributes:
        NONE: No privacy protocol (encryption disabled).
        DES: CBC-DES encryption with a 64-bit salt-derived IV (RFC 3414 §8).
        AES: Alias of AES128 — CFB128-AES-128 (RFC 3826).
        AES128: CFB128-AES-128 encryption (RFC 3826).
        AES192: CFB128-AES-192 encryption (draft-reeder-snmpv3-usm-3desede-aes).
        AES256: CFB128-AES-256 encryption (draft-reeder-snmpv3-usm-3desede-aes).
    """

    NONE: str = "none"
    DES: str = "DES"
    AES: str = "AES"
    AES128: str = "AES128"
    AES192: str = "AES192"
    AES256: str = "AES256"

    def get_key_length(self) -> int:
        """Get the privacy key length in bytes.

        Returns:
            Key length in bytes for this protocol.
        """
        return _PRIV_KEY_LENGTHS.get(self.value, 0)

    def get_priv_param_length(self) -> int:
        """Get the msgPrivacyParameters length in octets (0 if unsupported)."""
        return _PRIV_PARAM_LENGTHS.get(self.value, 0)


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
        auth_key: Pre-localized authentication key.  When set it is used
            as-is and the pass phrase is not consulted — required for users
            configured via usmUserAuthKeyChange, and a way to skip the
            1-megabyte password-to-key stretch on every message.
        priv_key: Pre-localized privacy key; same rules as ``auth_key``.
    """

    MAX_USERNAME_LEN: int = 32
    MAX_PASSPHRASE_LEN: int = 64

    def __init__(
        self,
        username: str,
        auth_protocol: AuthProtocol = AuthProtocol.NONE,
        auth_passphrase: str | None = None,
        priv_protocol: PrivProtocol = PrivProtocol.NONE,
        priv_passphrase: str | None = None,
        security_engine_id: bytes | None = None,
        auth_key: bytes | None = None,
        priv_key: bytes | None = None,
    ) -> None:
        """Initialize USM user credentials.

        Args:
            username: The user's SNMPv3 username (up to 32 octets).
            auth_protocol: Authentication protocol.
            auth_passphrase: Authentication pass phrase (up to 64 octets).
            priv_protocol: Privacy protocol.
            priv_passphrase: Privacy pass phrase (up to 64 octets).
            security_engine_id: The SNMP engine this user was discovered with.
            auth_key: Pre-localized authentication key (RFC 3414 §2.6), used
                instead of localizing ``auth_passphrase``.
            priv_key: Pre-localized privacy key, used instead of localizing
                ``priv_passphrase``.

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
        self.auth_key = auth_key
        self.priv_key = priv_key

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

    def get_user(self, username: str) -> USMUser | None:
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
    """USM security parameters per RFC 3414 §2.4 (msgSecurityParameters).

    Wire fields (RFC 3414 §2.4, sample encoding in §A.4):
    - engine_id: msgAuthoritativeEngineID.
    - engine_boots: msgAuthoritativeEngineBoots.
    - engine_time: msgAuthoritativeEngineTime.
    - username: msgUserName.
    - mac: msgAuthenticationParameters (the truncated MAC / MIC).
    - priv_parameters: msgPrivacyParameters (DES IV or AES salt).

    Local-only helpers (never carried on the wire):
    - security_level / security_model: dispatch information.
    - authentication_key / privacy_key / auth_protocol / priv_protocol:
      the user's localized keys and protocol selection.
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
        engine_boots: int = 0,
        engine_time: int = 0,
        priv_parameters: bytes = b"",
        mac: bytes = b"",
    ) -> None:
        """Initialize USM security parameters.

        Args:
            engine_id: The (authoritative) engine ID.
            username: The security principal.
            security_level: The security level (0=noAuthNoPriv, 1=authNoPriv, 2=authPriv).
            authentication_key: Localized authentication key for MIC calculation.
            privacy_key: Localized privacy key for encryption.
            auth_protocol: Authentication protocol (CBC-SHA-96, HMAC-SHA-256, etc.).
            priv_protocol: Privacy protocol (DES, AES128, AES192, AES256).
            engine_boots: msgAuthoritativeEngineBoots (RFC 3414 §2.4).
            engine_time: msgAuthoritativeEngineTime (RFC 3414 §2.4).
            priv_parameters: msgPrivacyParameters (DES IV / AES salt).
            mac: msgAuthenticationParameters (the MIC as carried on the wire).
        """
        self.engine_id: bytes = engine_id
        self.username: str = username
        self.security_level: int = security_level
        self.security_model: int = self.USM_SECURITY_MODEL
        self.authentication_key: bytes = authentication_key
        self.privacy_key: bytes = privacy_key
        self.auth_protocol: str = auth_protocol
        self.priv_protocol: str = priv_protocol
        self.engine_boots: int = engine_boots
        self.engine_time: int = engine_time
        self.priv_parameters: bytes = priv_parameters
        self.mac: bytes = mac

    @property
    def security_level_name(self) -> str:
        """Get the security level as a string name.

        Returns:
            String name for the security level.
        """
        levels: dict[int, str] = {0: "noAuthNoPriv", 1: "authNoPriv", 2: "authPriv"}
        return levels.get(self.security_level, "unknown")

    def encode(self) -> bytes:
        """Serialize as the USM msgSecurityParameters SEQUENCE.

        RFC 3414 §2.4 / §A.4::

            msgSecurityParameters ::= SEQUENCE {
                msgAuthoritativeEngineID    OCTET STRING,
                msgAuthoritativeEngineBoots INTEGER,
                msgAuthoritativeEngineTime  INTEGER,
                msgUserName                 OCTET STRING,
                msgAuthenticationParameters OCTET STRING,
                msgPrivacyParameters        OCTET STRING
            }

        Returns:
            BER-encoded SEQUENCE (placed in the message as an OCTET STRING).
        """
        return bytes(
            Sequence.from_list(
                [
                    OctetString(self.engine_id).get_object(),
                    Integer.from_int(self.engine_boots).get_object(),
                    Integer.from_int(self.engine_time).get_object(),
                    OctetString(self.username.encode("utf-8")).get_object(),
                    OctetString(self.mac).get_object(),
                    OctetString(self.priv_parameters).get_object(),
                ]
            )
        )

    @classmethod
    def decode(cls, data: bytes) -> SecurityParameters:
        """Decode a msgSecurityParameters SEQUENCE (RFC 3414 §2.4).

        Args:
            data: BER-encoded SEQUENCE from the msgSecurityParameters
                OCTET STRING.

        Returns:
            The decoded SecurityParameters; an empty instance if the
            SEQUENCE does not carry the six USM fields.
        """
        params = cls()
        if not data:
            return params
        obj, _ = Object.decode(data, 0)
        fields = obj.value if isinstance(obj.value, list) else []
        if len(fields) < 6:
            return params
        params.engine_id = bytes(fields[0].value)
        params.engine_boots = int(fields[1])
        params.engine_time = int(fields[2])
        params.username = bytes(fields[3].value).decode("utf-8", "replace")
        params.mac = bytes(fields[4].value)
        params.priv_parameters = bytes(fields[5].value)
        return params

    def __repr__(self) -> str:
        return (
            f"SecurityParameters("
            f"engine_id={self.engine_id.hex()[:24]}... "
            f"name={self.username!r} "
            f"level={self.security_level_name} "
            f"boots={self.engine_boots} time={self.engine_time})"
        )


# =============================================================================
# Key Maturation (RFC 3414 §2.6, §A.2)
# =============================================================================

#: Hash constructors usable for key localization and MAC calculation.
_HASHES: dict[str, Callable[..., object]] = {
    "md5": md5,
    "sha1": sha1,
    "sha224": sha224,
    "sha256": sha256,
    "sha384": sha384,
    "sha512": sha512,
}

#: Length of the repeated-password string fed to the hash (RFC 3414 §2.6, §A.2).
_PASSWORD_LENGTH: int = 1_048_576

#: Maximum password length considered by password_to_key (RFC 3414 §A.2).
_MAX_PASSWORD_LENGTH: int = 255

#: snmpEngineID bounds per RFC 3411 §5 (SnmpEngineID SIZE(5..32)).
_MIN_ENGINE_ID_LENGTH: int = 5
_MAX_ENGINE_ID_LENGTH: int = 32


def _get_hash(hash_name: str) -> Callable[..., object]:
    """Return the hashlib constructor for a hash name.

    Args:
        hash_name: Hash name such as "md5" or "sha256".

    Returns:
        A hashlib hash constructor.

    Raises:
        ValueError: If the hash name is not supported.
    """
    try:
        return _HASHES[hash_name]
    except KeyError:
        raise ValueError(f"Unsupported hash algorithm: {hash_name!r}") from None


def password_to_key(passphrase: bytes, hash_name: str = "md5") -> bytes:
    """Convert a passphrase into a non-localized key (RFC 3414 §2.6, §A.2).

    The passphrase is repeated to a 1,048,576-octet string which is hashed;
    the resulting digest ("digest1" / Ku) is the intermediate key.

    Args:
        passphrase: The user's passphrase (truncated to 255 octets).
        hash_name: Hash algorithm to use ("md5", "sha1", "sha224", ...).

    Returns:
        The intermediate key Ku (digest size of the hash).

    Raises:
        ValueError: If the passphrase is empty or the hash is unsupported.
    """
    if not passphrase:
        raise ValueError("Passphrase must not be empty")
    hash_fn = _get_hash(hash_name)
    password = passphrase[:_MAX_PASSWORD_LENGTH]
    repeats = -(-_PASSWORD_LENGTH // len(password))  # ceil division
    extended = (password * repeats)[:_PASSWORD_LENGTH]
    return hash_fn(extended).digest()


def localize_key(
    key: bytes,
    engine_id: bytes,
    hash_name: str = "md5",
    key_length: int | None = None,
) -> bytes:
    """Localize a key to a specific snmpEngineID (RFC 3414 §2.6).

    ``Kh = H(Ku || snmpEngineID || Ku)``; the localized key is the first
    ``key_length`` octets of ``Kh``.

    Args:
        key: Non-localized key (output of :func:`password_to_key`).
        engine_id: The authoritative SNMP engine's snmpEngineID.
        hash_name: Hash algorithm to use.
        key_length: Desired localized key length; defaults to the digest size.

    Returns:
        The localized key.

    Raises:
        ValueError: If the engine ID length is outside 5-32 octets.
    """
    if not _MIN_ENGINE_ID_LENGTH <= len(engine_id) <= _MAX_ENGINE_ID_LENGTH:
        raise ValueError(
            f"Engine ID must be {_MIN_ENGINE_ID_LENGTH}-{_MAX_ENGINE_ID_LENGTH} octets, "
            f"got {len(engine_id)}"
        )
    hash_fn = _get_hash(hash_name)
    digest = hash_fn(key + engine_id + key).digest()
    return digest if key_length is None else digest[:key_length]


def localize_passphrase(
    passphrase: str | bytes,
    engine_id: bytes,
    auth_protocol: AuthProtocol = AuthProtocol.MD5,
    key_length: int | None = None,
) -> bytes:
    """Localize a passphrase to a specific SNMP engine.

    RFC 3414 §2.6 / §A.2: the passphrase is first converted to a key with
    the password-to-key algorithm of the user's authentication protocol and
    then localized with the engine's snmpEngineID, so that the same
    passphrase yields different key material per engine.

    The hash of the *authentication* protocol is also used for privacy key
    localization (RFC 3826 §1.2); pass ``key_length`` to truncate the result
    to the size required by a privacy protocol.

    Args:
        passphrase: The user's passphrase (up to 255 octets are used).
        engine_id: The remote engine's snmpEngineID (5-32 octets).
        auth_protocol: The authentication protocol providing the hash.
        key_length: Desired key length; defaults to the auth key length.

    Returns:
        The localized key material.

    Raises:
        ValueError: If the protocol, passphrase or engine ID is invalid.
    """
    if auth_protocol == AuthProtocol.NONE:
        raise ValueError("Cannot localize a passphrase without an authentication protocol")
    if isinstance(passphrase, str):
        passphrase = passphrase.encode("utf-8")
    hash_name = auth_protocol.hash_name
    ku = password_to_key(passphrase, hash_name)
    if key_length is None:
        key_length = auth_protocol.get_key_length()
    return localize_key(ku, engine_id, hash_name, key_length)


# =============================================================================
# Exported Names
# =============================================================================

__all__ = [
    "AuthProtocol",
    "PrivProtocol",
    "SecurityLevel",
    "SecurityParameters",
    "USMUser",
    "USMUserDatabase",
    "localize_key",
    "localize_passphrase",
    "password_to_key",
]