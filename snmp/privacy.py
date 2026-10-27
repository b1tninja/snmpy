"""SNMP privacy (encryption) for SNMPv3 USM.

Implements the privacy protocols of RFC 3414 section 8 (CBC-DES),
RFC 3826 (CFB128-AES-128) and RFC 7860 section 2.2 (AES-192/AES-256).

Key material
------------
Both protocols encrypt with a *localized* privacy key - the privacy key
derived from the user's pass phrase and the authoritative SNMP engine's
EngineID (RFC 3414 section 2.6).  The key is always localized with the
user's *authentication* digest (MD5 or SHA), never with an AES digest,
even when the authentication protocol is one of the AES flavors::

    >>> key = localize_privacy_key(
    ...     "maplesyrup", engine_id, PrivProtocol.AES256, AuthProtocol.SHA)

Wire parameters
---------------
Both protocols carry an 8-octet "salt" in ``msgPrivacyParameters`` so the
receiver can rebuild the IV (RFC 3414 section 8.1.1.1, RFC 3826 section
3.1.2.1):

========  =====================================  ==========================
Protocol  IV                                     msgPrivacyParameters
========  =====================================  ==========================
DES       ``salt XOR Kul[8:16]``  (the pre-IV)    the 8-octet salt
AES*      ``Boots || Time || salt``  (16 octets)  the 8-octet salt
========  =====================================  ==========================

AES never truncates or pads its IV - boots, time and salt are exactly
4 + 4 + 8 octets - and AES ciphertext has the length of the plaintext.
DES plaintext is zero-padded to an integral multiple of 8 octets before
encryption (RFC 3414 section 8.1.1.2: "the actual pad value is
irrelevant"), so DES ciphertext is always a multiple of 8 octets long and
the trailing pad octets are ignored after decryption
(RFC 3414 section 8.1.1.3).

Usage:
    >>> ciphertext, salt = encrypt(PrivProtocol.AES128, key, plaintext,
    ...                            engine_boots=1, engine_time=42)
    >>> decrypt(PrivProtocol.AES128, key, ciphertext, salt,
    ...         engine_boots=1, engine_time=42) == plaintext
    True

The crypto backend is the ``cryptography`` package (install with
``pip install snmpy[crypto]``).  It is imported lazily so the rest of the
library keeps working without it - only the privacy transforms need it.
"""

from __future__ import annotations

import os
import struct
import warnings
from typing import Any

from snmp.exceptions import SNMPProtocolError
from snmp.usm import AuthProtocol, PrivProtocol, localize_passphrase

__all__ = [
    "AES_BLOCK_SIZE",
    "AES_SALT_LENGTH",
    "DES_BLOCK_SIZE",
    "DES_SALT_LENGTH",
    "PrivacyContext",
    "PrivacyError",
    "decrypt",
    "encrypt",
    "generate_salt",
    "localize_privacy_key",
    "priv_block_size",
    "priv_key_length",
    "priv_param_length",
    "resolve_protocol",
]

PrivProtocolLike = PrivProtocol | str | None

# DES (RFC 3414 section 8.1.1): 64-bit block, 8-octet salt, and the pre-IV
# that follows the 8-octet DES key inside the localized key.
DES_BLOCK_SIZE: int = 8
DES_SALT_LENGTH: int = 8
DES_KEY_OCTETS: int = 8

# AES (RFC 3826 / RFC 7860): 128-bit block, 8-octet salt.
AES_BLOCK_SIZE: int = 16
AES_SALT_LENGTH: int = 8


class PrivacyError(SNMPProtocolError):
    """Raised when a privacy transform cannot be applied.

    Covers unsupported protocols, wrong-size key material, bad wire
    parameters (salt length, non-block-aligned DES ciphertext) and a
    missing crypto backend.
    """


# ---------------------------------------------------------------------------
# Protocol resolution / sizing
# ---------------------------------------------------------------------------

_PRIV_ALIASES: dict[str, PrivProtocol] = {
    "": PrivProtocol.NONE,
    "none": PrivProtocol.NONE,
    "nopriv": PrivProtocol.NONE,
    "priv-none": PrivProtocol.NONE,
    "usmnoprivprotocol": PrivProtocol.NONE,
    "1.3.6.1.6.3.10.1.2.1": PrivProtocol.NONE,  # usmNoPrivProtocol
    "des": PrivProtocol.DES,
    "cbc-des": PrivProtocol.DES,
    "des-cbc": PrivProtocol.DES,
    "priv-cbc-des": PrivProtocol.DES,
    "priv-des": PrivProtocol.DES,
    "usmdes": PrivProtocol.DES,
    "usmdesprivprotocol": PrivProtocol.DES,
    "1.3.6.1.6.3.10.1.2.2": PrivProtocol.DES,  # usmDESPrivProtocol
    "aes": PrivProtocol.AES128,
    "aes128": PrivProtocol.AES128,
    "priv-aes-128": PrivProtocol.AES128,
    "usmaes128": PrivProtocol.AES128,
    "1.3.6.1.6.3.10.1.2.4": PrivProtocol.AES128,
    "aes192": PrivProtocol.AES192,
    "priv-aes-192": PrivProtocol.AES192,
    "usmaes192": PrivProtocol.AES192,
    "1.3.6.1.6.3.10.1.2.5": PrivProtocol.AES192,
    "aes256": PrivProtocol.AES256,
    "priv-aes-256": PrivProtocol.AES256,
    "usmaes256": PrivProtocol.AES256,
    "1.3.6.1.6.3.10.1.2.6": PrivProtocol.AES256,
}

# Separator-free view of the table so hyphen-free wire names such as
# "privAES128" match the hyphenated configuration spellings.
_PRIV_ALIASES_COMPACT: dict[str, PrivProtocol] = {
    key.replace("-", ""): value for key, value in _PRIV_ALIASES.items()
}


def resolve_protocol(protocol: PrivProtocolLike) -> PrivProtocol:
    """Normalize a privacy protocol name, OID or enum to a PrivProtocol.

    Accepts the spellings used on the wire (``privAES128``, a privacy
    OID), in configuration (``aes-128``, ``aes128``) and by this library
    (``PrivProtocol.AES128``).  Case and ``_``/``-`` separators are
    ignored.  ``None`` and the empty string mean "no privacy protocol".

    Args:
        protocol: The protocol to resolve.

    Returns:
        The matching PrivProtocol.

    Raises:
        PrivacyError: If the protocol is not supported.
    """
    if protocol is None:
        return PrivProtocol.NONE
    if isinstance(protocol, PrivProtocol):
        resolved: PrivProtocol | None = protocol
    elif isinstance(protocol, str):
        key = protocol.strip().lower().replace("_", "-")
        resolved = _PRIV_ALIASES.get(key) or _PRIV_ALIASES_COMPACT.get(key.replace("-", ""))
        if resolved is None:
            raise PrivacyError(f"Unsupported privacy protocol: {protocol!r}")
    else:
        raise PrivacyError(f"Unsupported privacy protocol: {protocol!r}")
    if resolved is None:  # pragma: no cover - defensive, both branches raise
        raise PrivacyError(f"Unsupported privacy protocol: {protocol!r}")

    # PrivProtocol.AES is the legacy spelling of the 128-bit variant.
    return PrivProtocol.AES128 if resolved == PrivProtocol.AES else resolved


def priv_key_length(protocol: PrivProtocolLike) -> int:
    """Get the number of localized-key octets a protocol encrypts with.

    RFC 3826 section 3.1.2.1 uses the first 128 bits of the localized key
    as the AES key and RFC 7860 section 2.2 extends this to 192/256 bits.
    RFC 3414 section 8.1.1.1 uses the first 8 octets as the DES key and
    octets 8-15 as the pre-IV.

    Args:
        protocol: The privacy protocol.

    Returns:
        Required key length in octets (0 for noPriv).

    Raises:
        PrivacyError: If the protocol is not supported.
    """
    proto = resolve_protocol(protocol)
    lengths: dict[PrivProtocol, int] = {
        PrivProtocol.NONE: 0,
        PrivProtocol.DES: DES_KEY_OCTETS + DES_SALT_LENGTH,  # key + pre-IV
        PrivProtocol.AES128: 16,
        PrivProtocol.AES192: 24,
        PrivProtocol.AES256: 32,
    }
    return lengths[proto]


def priv_param_length(protocol: PrivProtocolLike) -> int:
    """Get the length of a protocol's msgPrivacyParameters (its salt).

    Args:
        protocol: The privacy protocol.

    Returns:
        Salt length in octets - 0 for noPriv, 8 for DES and every AES size.

    Raises:
        PrivacyError: If the protocol is not supported.
    """
    return 0 if resolve_protocol(protocol) == PrivProtocol.NONE else DES_SALT_LENGTH


def priv_block_size(protocol: PrivProtocolLike) -> int:
    """Get the cipher block size of a privacy protocol in octets.

    Args:
        protocol: The privacy protocol.

    Returns:
        Block size in octets - 1 for noPriv, 8 for DES, 16 for AES.

    Raises:
        PrivacyError: If the protocol is not supported.
    """
    proto = resolve_protocol(protocol)
    if proto == PrivProtocol.NONE:
        return 1
    return DES_BLOCK_SIZE if proto == PrivProtocol.DES else AES_BLOCK_SIZE


def generate_salt(protocol: PrivProtocolLike) -> bytes:
    """Generate a random salt for msgPrivacyParameters.

    Both protocols require the salt (the IV modifier) never to repeat for
    a given key.  RFC 3826 section 3.1.2.1 suggests boots/time plus a
    counter and RFC 3414 section 8.1.1.1 allows any scheme that avoids
    duplicate IVs; this implementation uses 8 random octets.

    Args:
        protocol: The privacy protocol.

    Returns:
        Freshly generated salt octets, or empty bytes for noPriv.

    Raises:
        PrivacyError: If the protocol is not supported.
    """
    length = priv_param_length(protocol)
    return os.urandom(length) if length else b""


_AUTH_ALIASES: dict[str, AuthProtocol] = {
    "": AuthProtocol.NONE,
    "none": AuthProtocol.NONE,
    "noauth": AuthProtocol.NONE,
    "usmnoauthprotocol": AuthProtocol.NONE,
    "1.3.6.1.6.3.10.1.1.1": AuthProtocol.NONE,  # usmNoAuthProtocol
    "md5": AuthProtocol.MD5,
    "hmacmd5": AuthProtocol.MD5,
    "hmacmd596": AuthProtocol.MD5,
    "usmhmacmd5authprotocol": AuthProtocol.MD5,
    "1.3.6.1.6.3.10.1.1.2": AuthProtocol.MD5,  # usmHMACMD5AuthProtocol
    "sha": AuthProtocol.SHA,
    "sha1": AuthProtocol.SHA,
    "sha96": AuthProtocol.SHA,
    "hmacsha": AuthProtocol.SHA,
    "hmacsha96": AuthProtocol.SHA,
    "usmhmacshaauthprotocol": AuthProtocol.SHA,
    "usmhmac128shato96authprotocol": AuthProtocol.SHA,
    "1.3.6.1.6.3.10.1.1.3": AuthProtocol.SHA,  # usmHMACSHAAuthProtocol
    "sha224": AuthProtocol.SHA224,
    "hmacsha224": AuthProtocol.SHA224,
    "usmhmac128sha224authprotocol": AuthProtocol.SHA224,
    "1.3.6.1.6.3.10.1.1.4": AuthProtocol.SHA224,  # usmHMAC128SHA224AuthProtocol
    "sha256": AuthProtocol.SHA256,
    "hmacsha256": AuthProtocol.SHA256,
    "usmhmac192sha256authprotocol": AuthProtocol.SHA256,
    "1.3.6.1.6.3.10.1.1.5": AuthProtocol.SHA256,  # usmHMAC192SHA256AuthProtocol
    "sha384": AuthProtocol.SHA384,
    "hmacsha384": AuthProtocol.SHA384,
    "usmhmac256sha384authprotocol": AuthProtocol.SHA384,
    "1.3.6.1.6.3.10.1.1.6": AuthProtocol.SHA384,  # usmHMAC256SHA384AuthProtocol
    "sha512": AuthProtocol.SHA512,
    "hmacsha512": AuthProtocol.SHA512,
    "usmhmac384sha512authprotocol": AuthProtocol.SHA512,
    "1.3.6.1.6.3.10.1.1.7": AuthProtocol.SHA512,  # usmHMAC384SHA512AuthProtocol
}


def _resolve_auth_protocol(protocol: AuthProtocol | str) -> AuthProtocol:
    """Normalize an authentication protocol name or enum to AuthProtocol.

    Args:
        protocol: The authentication protocol to resolve.

    Returns:
        The matching AuthProtocol.

    Raises:
        PrivacyError: If the protocol is not supported.
    """
    if isinstance(protocol, AuthProtocol):
        return protocol
    if not isinstance(protocol, str):
        raise PrivacyError(f"Unsupported authentication protocol: {protocol!r}")
    key = protocol.strip().lower().replace("_", "").replace("-", "").replace(" ", "")
    resolved = _AUTH_ALIASES.get(key)
    if resolved is None:
        raise PrivacyError(f"Unsupported authentication protocol: {protocol!r}")
    return resolved


def localize_privacy_key(
    passphrase: str,
    engine_id: bytes,
    priv_protocol: PrivProtocolLike,
    auth_protocol: AuthProtocol | str = AuthProtocol.SHA,
) -> bytes:
    """Derive the localized privacy key for a pass phrase and engine ID.

    RFC 3414 section 2.6 localizes the privacy key with the *auth*
    protocol's digest (MD5 or SHA) - never with an AES digest - and the
    privacy protocol then takes the key material it needs (first 8 octets
    plus the 8-octet pre-IV for DES, first 16/24/32 octets for
    AES-128/192/256).

    Args:
        passphrase: The user's privacy pass phrase (8-64 octets).
        engine_id: The authoritative engine's EngineID (5-32 octets).
        priv_protocol: The privacy protocol the key will be used with.
        auth_protocol: The user's authentication protocol providing the
            localization digest - an AuthProtocol or a name such as "MD5",
            "SHA", "SHA-96" or "HMAC-SHA-256".  RFC 3414 section 2.6 and
            RFC 3826 section 3.2 interoperate with MD5 or SHA-96.

    Returns:
        The localized privacy key, sized for priv_protocol.

    Raises:
        PrivacyError: If a protocol is unsupported or unusable.
        ValueError: If the pass phrase or engine ID is out of range.
    """
    auth = _resolve_auth_protocol(auth_protocol)
    if auth == AuthProtocol.NONE:
        raise PrivacyError(f"Cannot localize a privacy key without an authentication digest: {auth!r}")

    # Localize enough key material for the protocol (DES needs key + pre-IV).
    key_length = max(priv_key_length(priv_protocol), 2 * DES_SALT_LENGTH)
    localized = localize_passphrase(passphrase, engine_id, auth, key_length)
    if len(localized) < key_length:
        raise PrivacyError(
            f"{auth.name} localization produced {len(localized)} octets, "
            f"fewer than the {key_length} required by {resolve_protocol(priv_protocol).name}"
        )
    return localized[:key_length]


# ---------------------------------------------------------------------------
# Crypto backend (cryptography)
# ---------------------------------------------------------------------------

_Cipher: Any = None
_algorithms: Any = None
_modes: Any = None
_TripleDES: Any = None
_backend_error: str | None = None


def _load_backend() -> None:
    """Import the ``cryptography`` backend on first use.

    Raises:
        PrivacyError: If the package is not installed.
    """
    global _Cipher, _algorithms, _modes, _TripleDES, _backend_error
    if _Cipher is not None:
        return
    if _backend_error is not None:
        raise PrivacyError(_backend_error)
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        try:
            # cryptography >= 46 moved legacy algorithms out of hazmat.primitives.
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        except ImportError:  # pragma: no cover - older cryptography
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                from cryptography.hazmat.primitives.ciphers.algorithms import (  # type: ignore[attr-defined,no-redef]
                    TripleDES,
                )
    except ImportError as exc:
        _backend_error = (
            "SNMP privacy requires the 'cryptography' package "
            "(pip install snmpy[crypto] or pip install cryptography)"
        )
        raise PrivacyError(_backend_error) from exc

    _Cipher, _algorithms, _modes, _TripleDES = Cipher, algorithms, modes, TripleDES


def _cfb128_mode(iv: bytes) -> Any:
    """Build a 128-bit segment CFB mode object.

    RFC 3826 section 3.1.3 requires CFB with the feedback parameter s set
    to 128 (a full block).  ``cryptography`` >= 45 only implements that
    variant; older releases accepted an explicit segment size and defaulted
    to 8-bit CFB, which would silently produce non-interoperable output.

    Args:
        iv: The 16-octet initialization vector.

    Returns:
        A mode object usable as ``Cipher(algorithms.AES(key), mode)``.
    """
    try:
        return _modes.CFB(iv, AES_BLOCK_SIZE * 8)
    except TypeError:  # cryptography >= 45: CFB is always 128-bit
        return _modes.CFB(iv)


def _run_cipher(algorithm: Any, mode: Any, data: bytes, *, decrypt: bool = False) -> bytes:
    """Run a one-shot cipher over ``data``.

    Args:
        algorithm: A ``cryptography`` cipher algorithm instance.
        mode: A ``cryptography`` cipher mode instance.
        data: The octets to process.
        decrypt: Decrypt instead of encrypt when True.

    Returns:
        The processed octets.
    """
    factory = _Cipher(algorithm, mode).decryptor if decrypt else _Cipher(algorithm, mode).encryptor
    context = factory()
    processed: bytes = context.update(data) + context.finalize()
    return processed


# ---------------------------------------------------------------------------
# DES-CBC (RFC 3414 section 8.1) and AES-CFB128 (RFC 3826, RFC 7860)
# ---------------------------------------------------------------------------


def _des_components(key: bytes) -> tuple[bytes, bytes]:
    """Split a localized key into the DES key and the pre-IV.

    RFC 3414 section 8.1.1.1: the first 8 octets of the localized key form
    the DES key (the least significant bit of each octet is disregarded by
    DES) and the next 8 octets are the pre-IV.  That low bit is set here so
    every octet carries odd parity, matching the convention used by other
    implementations; it leaves the effective 56-bit key unchanged.

    Args:
        key: The localized privacy key (at least 16 octets).

    Returns:
        Tuple of (odd-parity DES key, 8-octet pre-IV).
    """
    des_key = bytearray()
    for octet in key[:DES_KEY_OCTETS]:
        body = octet & 0xFE
        des_key.append(body | ((bin(body).count("1") + 1) % 2))
    pre_iv = key[DES_KEY_OCTETS : 2 * DES_KEY_OCTETS]
    return bytes(des_key), pre_iv


def _des_cipher(key: bytes, iv: bytes, data: bytes, *, decrypt: bool) -> bytes:
    """Run single DES in CBC mode over block-aligned data.

    ``cryptography`` no longer exposes single DES.  A 2-key TripleDES key
    with identical halves evaluates ``E(K1, D(K1, E(K1, x)))``, which
    reduces to single DES.  No padding scheme is involved: RFC 3414 section
    8.1.1.3 pads the *plaintext* to a multiple of the block size before
    encryption (done by encrypt()), so the cipher always sees whole blocks.

    Args:
        key: The 8-octet DES key.
        iv: The 8-octet initialization vector.
        data: The octets to process.
        decrypt: Decrypt instead of encrypt when True.

    Returns:
        The processed octets.
    """
    return _run_cipher(_TripleDES(key + key), _modes.CBC(iv), data, decrypt=decrypt)


def _aes_cipher(key: bytes, iv: bytes, data: bytes, *, decrypt: bool) -> bytes:
    """Run AES in 128-bit CFB mode over data of any length.

    Args:
        key: The 16, 24 or 32-octet AES key.
        iv: The 16-octet initialization vector.
        data: The octets to process.
        decrypt: Decrypt instead of encrypt when True.

    Returns:
        The processed octets (same length as ``data``).
    """
    return _run_cipher(_algorithms.AES(key), _cfb128_mode(iv), data, decrypt=decrypt)


# ---------------------------------------------------------------------------
# Parameter validation and IV construction
# ---------------------------------------------------------------------------


def _validate_key(protocol: PrivProtocol, key: bytes) -> None:
    """Check that a localized privacy key is large enough for a protocol.

    Args:
        protocol: The privacy protocol.
        key: The localized privacy key.

    Raises:
        PrivacyError: If the key is too short.
    """
    required = priv_key_length(protocol)
    if len(key) < required:
        raise PrivacyError(
            f"{protocol.value} needs a {required}-octet localized privacy key, got {len(key)} "
            "(derive it with localize_privacy_key())"
        )


def _validate_salt(protocol: PrivProtocol, salt: bytes) -> bytes:
    """Check the msgPrivacyParameters (salt) length for a protocol.

    Args:
        protocol: The privacy protocol.
        salt: The salt taken from (or to be placed in) msgPrivacyParameters.

    Returns:
        The validated salt.

    Raises:
        PrivacyError: If the salt has the wrong length.
    """
    expected = priv_param_length(protocol)
    if len(salt) != expected:
        raise PrivacyError(f"{protocol.value} requires a {expected}-octet privacy parameter, got {len(salt)}")
    return salt


def _aes_iv(engine_boots: int, engine_time: int, salt: bytes) -> bytes:
    """Build an AES initialization vector (RFC 3826 section 3.1.2.1).

    IV = snmpEngineBoots (4 octets, MSB first) || snmpEngineTime (4 octets,
    MSB first) || salt (8 octets, MSB first).

    Args:
        engine_boots: The authoritative engine's boots counter.
        engine_time: The authoritative engine's time counter.
        salt: The 8-octet salt from msgPrivacyParameters.

    Returns:
        The 16-octet IV.
    """
    return struct.pack(">II", engine_boots & 0xFFFFFFFF, engine_time & 0xFFFFFFFF) + salt


def _des_iv(key: bytes, salt: bytes) -> bytes:
    """Build a DES initialization vector (RFC 3414 section 8.1.1.1).

    IV = salt XOR pre-IV, where the pre-IV is localized key octets 8-15.

    Args:
        key: The localized privacy key (at least 16 octets).
        salt: The 8-octet salt from msgPrivacyParameters.

    Returns:
        The 8-octet IV.
    """
    _, pre_iv = _des_components(key)
    return bytes(a ^ b for a, b in zip(salt, pre_iv, strict=True))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def encrypt(
    protocol: PrivProtocolLike,
    key: bytes,
    plaintext: bytes,
    *,
    engine_boots: int = 0,
    engine_time: int = 0,
    salt: bytes | None = None,
) -> tuple[bytes, bytes]:
    """Encrypt plaintext with a USM privacy protocol.

    Args:
        protocol: The privacy protocol (name, OID or PrivProtocol).
        key: The localized privacy key (see localize_privacy_key()).
        plaintext: The octets to encrypt - the encoded ScopedPDU.
        engine_boots: The authoritative engine's boots counter; part of the
            AES IV and ignored by DES.
        engine_time: The authoritative engine's time counter; part of the AES
            IV and ignored by DES.
        salt: The salt to use, generated randomly when omitted.  Pass a known
            value only for testing - it must never repeat for a key.

    Returns:
        Tuple of (ciphertext, salt); the salt is what belongs in
        msgPrivacyParameters.  DES zero-pads the plaintext to a multiple of 8
        octets, so its ciphertext can be longer than the plaintext.

    Raises:
        PrivacyError: If the protocol is unsupported, the key or salt has the
            wrong size, or the crypto backend is missing.
    """
    proto = resolve_protocol(protocol)
    if proto == PrivProtocol.NONE:
        return plaintext, b""

    _load_backend()
    _validate_key(proto, key)
    parameters = _validate_salt(proto, generate_salt(proto) if salt is None else salt)

    if proto == PrivProtocol.DES:
        # RFC 3414 section 8.1.1.2: pad to a multiple of 8, pad value irrelevant.
        des_key, _ = _des_components(key)
        padded = plaintext + bytes((-len(plaintext)) % DES_BLOCK_SIZE)
        return _des_cipher(des_key, _des_iv(key, parameters), padded, decrypt=False), parameters

    aes_key = key[: priv_key_length(proto)]
    iv = _aes_iv(engine_boots, engine_time, parameters)
    return _aes_cipher(aes_key, iv, plaintext, decrypt=False), parameters


def decrypt(
    protocol: PrivProtocolLike,
    key: bytes,
    ciphertext: bytes,
    priv_parameters: bytes,
    *,
    engine_boots: int = 0,
    engine_time: int = 0,
) -> bytes:
    """Decrypt ciphertext produced by encrypt().

    Args:
        protocol: The privacy protocol (name, OID or PrivProtocol).
        key: The localized privacy key (see localize_privacy_key()).
        ciphertext: The encrypted scoped PDU.
        priv_parameters: msgPrivacyParameters - the 8-octet salt the sender
            used to build the IV.
        engine_boots: The authoritative engine's boots counter; part of the
            AES IV and ignored by DES.
        engine_time: The authoritative engine's time counter; part of the AES
            IV and ignored by DES.

    Returns:
        The plaintext.  For DES the result carries the irrelevant trailing pad
        octets, and callers must not require an exact length match - a BER
        parser stops at the encoded PDU length.

    Raises:
        PrivacyError: If the protocol is unsupported, the key or salt has the
            wrong size, DES ciphertext is not block aligned, or the crypto
            backend is missing.
    """
    proto = resolve_protocol(protocol)
    if proto == PrivProtocol.NONE:
        return ciphertext

    _load_backend()
    _validate_key(proto, key)
    parameters = _validate_salt(proto, priv_parameters)

    if proto == PrivProtocol.DES:
        if len(ciphertext) % DES_BLOCK_SIZE:
            raise PrivacyError(
                f"DES ciphertext must be a multiple of {DES_BLOCK_SIZE} octets, got {len(ciphertext)}"
            )
        des_key, _ = _des_components(key)
        return _des_cipher(des_key, _des_iv(key, parameters), ciphertext, decrypt=True)

    aes_key = key[: priv_key_length(proto)]
    iv = _aes_iv(engine_boots, engine_time, parameters)
    return _aes_cipher(aes_key, iv, ciphertext, decrypt=True)


class PrivacyContext:
    """Stateful privacy helper for one user at one authoritative engine.

    Wraps encrypt()/decrypt() and remembers the salt (msgPrivacyParameters)
    of the last encrypted message so it can be copied into
    SecurityParameters.  The pass phrase must already have been localized
    with the authoritative engine's EngineID before constructing this.

    Usage:
        >>> context = PrivacyContext(PrivProtocol.AES128, localized_key,
        ...                          engine_boots=1, engine_time=42)
        >>> ciphertext = context.encrypt(plaintext)
        >>> context.priv_parameters  # the salt that goes on the wire
        b'\\x00...'
        >>> context.decrypt(ciphertext, context.priv_parameters) == plaintext
        True
    """

    def __init__(
        self,
        protocol: PrivProtocolLike,
        privacy_key: bytes,
        *,
        engine_boots: int = 0,
        engine_time: int = 0,
    ) -> None:
        """Initialize the privacy context.

        Args:
            protocol: The privacy protocol.
            privacy_key: The localized privacy key.
            engine_boots: The authoritative engine's boots counter.
            engine_time: The authoritative engine's time counter.

        Raises:
            PrivacyError: If the protocol is unsupported.
        """
        self.protocol: PrivProtocol = resolve_protocol(protocol)
        self.privacy_key: bytes = privacy_key
        self.engine_boots: int = engine_boots
        self.engine_time: int = engine_time
        self.priv_parameters: bytes = b""

    @property
    def key_size(self) -> int:
        """Get the localized privacy key size in octets."""
        return priv_key_length(self.protocol)

    @property
    def block_size(self) -> int:
        """Get the cipher block size in octets."""
        return priv_block_size(self.protocol)

    def encrypt(self, plaintext: bytes, salt: bytes | None = None) -> bytes:
        """Encrypt plaintext and remember the salt that was used.

        Args:
            plaintext: The octets to encrypt.
            salt: Optional explicit salt (testing only).

        Returns:
            The ciphertext.
        """
        ciphertext, self.priv_parameters = encrypt(
            self.protocol,
            self.privacy_key,
            plaintext,
            engine_boots=self.engine_boots,
            engine_time=self.engine_time,
            salt=salt,
        )
        return ciphertext

    def decrypt(self, ciphertext: bytes, priv_parameters: bytes | None = None) -> bytes:
        """Decrypt ciphertext.

        Args:
            ciphertext: The octets to decrypt.
            priv_parameters: The salt carried by the message; falls back to
                the salt of the most recent encrypt() call.

        Returns:
            The plaintext.
        """
        return decrypt(
            self.protocol,
            self.privacy_key,
            ciphertext,
            self.priv_parameters if priv_parameters is None else priv_parameters,
            engine_boots=self.engine_boots,
            engine_time=self.engine_time,
        )

    def __repr__(self) -> str:
        return (
            f"PrivacyContext(protocol={self.protocol.value}, key_size={self.key_size}, "
            f"engine_boots={self.engine_boots}, engine_time={self.engine_time})"
        )
