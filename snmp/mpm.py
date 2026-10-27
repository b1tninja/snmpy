"""SNMPv3 Message Processing Model (MPM) — RFC 3412 §3.

Provides:
- SNMPv3 Message Processing Model for message dispatching
- MPv1, MPv2c, MPv3 implementations
- Message encoding/decoding for SNMPv3 messages

RFC 3412 §3 (Message Processing):
    The MPM is responsible for:
    - Generating outgoing messages from application requests/responses/notifications
    - Processing incoming messages and delivering to the appropriate component
    - Determining security model, message priority, and message format

    Key responsibilities:
    - MPv1: Process SNMPv1 messages (RFC 1157)
    - MPv2c: Process SNMPv2c messages (RFC 1901/1906)
    - MPv3: Process SNMPv3 messages with USM security (RFC 3414)
    - Message format: header + securityParameters + data

Usage:
    >>> from snmp.mpm import MPv3, MessageProcessor
    >>> mpm = MPv3(engine_id=b"\\x01\\x00\\x00\\x01\\x01")
    >>> msg = mpm.process_incoming(raw_bytes, 161)
    >>> response = mpm.process_outgoing(msg)
"""

from __future__ import annotations

import time
from collections.abc import Callable

from ber.enums import TagClassEnum, UniversalClassTags
from ber.object import (
    Integer,
    Object,
    ObjectLength,
    ObjectTag,
    OctetString,
    Sequence,
)
from snmp.auth import AuthProtocol as AuthProtocolName
from snmp.auth import calculate_mic, verify_mic
from snmp.datagram import SNMPDatagram
from snmp.enums import SNMPVersion
from snmp.exceptions import SNMPProtocolError
from snmp.pdus import InformRequest, Report, Request
from snmp.privacy import (
    PrivacyContext,
    PrivacyError,
    localize_privacy_key,
    resolve_auth_protocol,
)
from snmp.scoped_pdu import ScopedPDU
from snmp.usm import (
    AuthProtocol,
    PrivProtocol,
    SecurityParameters,
    USMUser,
    USMUserDatabase,
    localize_passphrase,
)

# ---------------------------------------------------------------------------
# SNMPv3 Message Processing Constants
# ---------------------------------------------------------------------------

SNMPv3_VERSION: int = 3

# Message security levels, numbered as SecurityLevel / SecurityParameters do.
# On the wire they are the low two bits of msgFlags (RFC 3412 §6.4):
# noAuthNoPriv = 0b00, authNoPriv = 0b01, authPriv = 0b11.  The 0b10
# combination carries privFlag without authFlag, is reserved, and MUST NOT
# be sent -- which is why the level numbers are not the flag values.
MSG_SECURITY_LEVEL_NO_AUTH_NO_PRIV: int = 0
MSG_SECURITY_LEVEL_AUTH_NO_PRIV: int = 1
MSG_SECURITY_LEVEL_AUTH_PRIV: int = 2

# msgFlags bits (RFC 3412 §6.4)
AUTH_FLAG: int = 0x01
PRIV_FLAG: int = 0x02
REPORTABLE_FLAG: int = 0x04

# Security level <-> msgFlags bit pattern (RFC 3412 §6.4)
_SECURITY_LEVEL_TO_FLAGS: dict[int, int] = {
    MSG_SECURITY_LEVEL_NO_AUTH_NO_PRIV: 0x00,
    MSG_SECURITY_LEVEL_AUTH_NO_PRIV: 0x01,
    MSG_SECURITY_LEVEL_AUTH_PRIV: 0x03,
}
_FLAGS_TO_SECURITY_LEVEL: dict[int, int] = {
    flags: level for level, flags in _SECURITY_LEVEL_TO_FLAGS.items()
}

# Message processing priority
MSG_PRIORITY_NORMAL: int = 0
MSG_PRIORITY_HIGH: int = 1
MSG_PRIORITY_CRITICAL: int = 2

# BER tag of the constructed universal SEQUENCE that frames every SNMPv3
# message, msgGlobalData and msgSecurityParameters.
_SEQUENCE_TAG = ObjectTag(TagClassEnum.universal, True, UniversalClassTags.sequence_of)

# The security model USM owns: msgSecurityModel == usm(3) (RFC 3414 §5.1).
# MPv3 must refuse anything else (RFC 3412 §3.1.1).
USM_SECURITY_MODEL: int = 3

# The RFC 3414 §2.2 time window in seconds: a message whose
# msgAuthoritativeEngineTime differs from the local snmpEngineTime by more
# than this is rejected as a possible replay.
DEFAULT_TIME_WINDOW: int = 150

# snmpEngineBoots saturates at 2147483647 (RFC 3414 §2.2).  An engine that has
# reached it cannot advance its boots counter again, so §3.2 step 7 requires
# that every authenticated message it receives be treated as outside the
# window until the engine is restarted with a fresh snmpEngineID.
MAX_ENGINE_BOOTS: int = 2147483647

# usmStats counters an agent reports for each failure below (RFC 3414 §14).
# usmStats ::= { usmMIBObjects 1 }, usmMIBObjects ::= { snmpUsmMIB 1 } and
# snmpUsmMIB ::= { snmpModules 15 }, i.e. the 1.3.6.1.6.3.15.1.1 subtree.
USM_STATS_PREFIX: str = "1.3.6.1.6.3.15.1.1"
USM_STATS_UNSUPPORTED_SEC_LEVELS: str = f"{USM_STATS_PREFIX}.1"
USM_STATS_NOT_IN_TIME_WINDOWS: str = f"{USM_STATS_PREFIX}.2"
USM_STATS_UNKNOWN_USER_NAMES: str = f"{USM_STATS_PREFIX}.3"
USM_STATS_UNKNOWN_ENGINE_IDS: str = f"{USM_STATS_PREFIX}.4"
USM_STATS_WRONG_DIGESTS: str = f"{USM_STATS_PREFIX}.5"
USM_STATS_DECRYPTION_ERRORS: str = f"{USM_STATS_PREFIX}.6"

USM_STATS_OIDS: tuple[str, ...] = (
    USM_STATS_UNSUPPORTED_SEC_LEVELS,
    USM_STATS_NOT_IN_TIME_WINDOWS,
    USM_STATS_UNKNOWN_USER_NAMES,
    USM_STATS_UNKNOWN_ENGINE_IDS,
    USM_STATS_WRONG_DIGESTS,
    USM_STATS_DECRYPTION_ERRORS,
)


class USMError(SNMPProtocolError):
    """A USM security failure on an incoming message (RFC 3414 §2.5.2).

    RFC 3414 §2.5.2 lets an implementation either report the failure with a
    Report PDU carrying the matching usmStats counter or simply discard the
    message, so MPv3 raises instead of choosing: ``stat`` names the counter to
    report and :attr:`MPv3.stats` keeps the running value.

    Attributes:
        stat: OID of the usmStats counter for this failure, or ``""`` when
            the RFC defines no counter for it.
    """

    def __init__(self, message: str, stat: str = "") -> None:
        """Initialize a USM failure.

        Args:
            message: Human-readable description of the failure.
            stat: OID of the usmStats counter to report, if any.
        """
        super().__init__(message)
        self.stat = stat


def engine_time_clock(boots: int = 0) -> Callable[[], tuple[int, int]]:
    """Build an ``(snmpEngineBoots, snmpEngineTime)`` source (RFC 3414 §2.2).

    Pass the result as ``MPv3(engine_time_source=...)`` to enable the
    time-window check: snmpEngineTime counts the seconds since this SNMP
    engine was started, and snmpEngineBoots increments on every restart.

    Args:
        boots: The boot counter to report; increment it when the process
            restarts so old messages fall outside the window.

    Returns:
        A callable returning the current ``(boots, time)`` pair, with time
        wrapped into the 31-bit range SNMP mandates.
    """
    started = time.monotonic()

    def now() -> tuple[int, int]:
        elapsed = int(time.monotonic() - started) % 0x7FFFFFFF
        return boots, elapsed

    return now

# snmp.auth keys its MAC-length and hash-function tables on the exact names
# exposed by snmp.auth.AuthProtocol, so a USM AuthProtocol has to be
# translated before a MIC is calculated: an un-normalized name silently keeps
# the default digest length while the hash lookup still needs the canonical
# key to hit.
_MIC_PROTOCOL_NAMES: dict[str, str] = {
    AuthProtocol.NONE.value: "",
    AuthProtocol.MD5.value: AuthProtocolName.CBC_MD5,
    AuthProtocol.SHA.value: AuthProtocolName.CBC_SHA_96,
    AuthProtocol.SHA96.value: AuthProtocolName.CBC_SHA_96,
    AuthProtocol.SHA224.value: AuthProtocolName.HMAC_SHA_224,
    AuthProtocol.SHA256.value: AuthProtocolName.HMAC_SHA_256,
    AuthProtocol.SHA384.value: AuthProtocolName.HMAC_SHA_384,
    AuthProtocol.SHA512.value: AuthProtocolName.HMAC_SHA_512,
}


def _mic_protocol(protocol: AuthProtocol | str) -> str:
    """Translate any accepted auth-protocol spelling into snmp.auth's name.

    Accepts everything :func:`snmp.privacy.resolve_auth_protocol` handles,
    i.e. ``MD5``, ``SHA``, ``HMAC-SHA-96``, ``SHA256`` and the
    ``usm*AuthProtocol`` OIDs.

    Args:
        protocol: The authentication protocol to resolve.

    Returns:
        The canonical protocol name understood by calculate_mic().

    Raises:
        PrivacyError: If the protocol is not supported.
        ValueError: If no authentication protocol was selected.
    """
    resolved = resolve_auth_protocol(protocol)
    name = _MIC_PROTOCOL_NAMES.get(resolved.value, "")
    if not name:
        raise ValueError("An authenticated message requires an authentication protocol")
    return name


def _encode_tlv(tag: ObjectTag, content: bytes) -> bytes:
    """Frame exact content bytes as a BER TLV.

    ``bytes(Sequence.from_list(...))`` re-serializes its children, which can
    move byte offsets around.  The MAC of RFC 3414 §6.3.1/§7.3.1 is defined
    over the final octets of the whole message, so the frames surrounding the
    MAC placeholder must be built from exact bytes.

    Args:
        tag: The tag to prepend.
        content: The already-encoded content octets.

    Returns:
        Tag, definite length and content.
    """
    return bytes(Object(tag, content))


def _tlv_content(buffer: bytes, offset: int = 0) -> tuple[int, int]:
    """Locate the content octets of the TLV starting at offset.

    Args:
        buffer: Buffer holding the TLV.
        offset: Where the TLV starts.

    Returns:
        Half-open range (start, stop) of the value octets.
    """
    _, offset = ObjectTag.decode(buffer, offset)
    length, offset = ObjectLength.decode(buffer, offset)
    return offset, offset + length


def _encode_security_parameters(
    params: SecurityParameters,
    mac_length: int,
) -> tuple[bytes, int]:
    """Encode the USM msgSecurityParameters SEQUENCE (RFC 3414 §2.4, §A.4).

    msgAuthenticationParameters is emitted as ``mac_length`` zero octets:
    the field must already carry its final length while the digest is taken,
    which is the shape of the §A.4 sample encoding.

    Args:
        params: The security parameters to serialize.
        mac_length: Length of the MAC field, 0 when unauthenticated.

    Returns:
        Tuple of the encoded SEQUENCE and the offset of the
        msgAuthenticationParameters value within it.
    """
    fields = [
        bytes(OctetString(params.engine_id).get_object()),
        bytes(Integer.from_int(params.engine_boots).get_object()),
        bytes(Integer.from_int(params.engine_time).get_object()),
        bytes(OctetString(params.username.encode("utf-8")).get_object()),
        bytes(OctetString(bytes(mac_length)).get_object()),
        bytes(OctetString(params.priv_parameters).get_object()),
    ]
    sequence = _encode_tlv(_SEQUENCE_TAG, b"".join(fields))
    mac_offset = len(sequence) - len(fields[5]) - mac_length
    return sequence, mac_offset


def split_message_mic(raw: bytes) -> tuple[bytes, bytes]:
    """Split a raw SNMPv3 message into its MAC and the MAC-zeroed message.

    RFC 3414 §6.3.1/§7.3.1 (with the corrected step reference of Errata 278)
    and RFC 7860 §4 define the MAC over the whole message with
    msgAuthenticationParameters replaced by zero octets, so verifying an
    incoming message means blanking that field in place.  The offset is
    walked from the BER structure instead of searched for, so payload bytes
    can never be mistaken for the MAC.

    Args:
        raw: The complete message as received.

    Returns:
        Tuple of (the MAC as carried on the wire, the message with those
        MAC octets replaced by zeros).

    Raises:
        SNMPProtocolError: If the message or its security parameters are
            malformed.
    """
    try:
        offset, _ = _tlv_content(raw, 0)
        # Skip msgVersion and msgGlobalData to reach msgSecurityParameters.
        _, offset = Object.decode(raw, offset)
        _, offset = Object.decode(raw, offset)
        sec_start, sec_stop = _tlv_content(raw, offset)
        # Step to msgAuthenticationParameters: after engineID, boots,
        # time and userName inside the USM SEQUENCE.
        seq_start, _ = _tlv_content(raw[sec_start:sec_stop], 0)
        position = sec_start + seq_start
        for _ in range(4):
            _, position = Object.decode(raw, position)
        mac_start, mac_stop = _tlv_content(raw, position)
    except (IndexError, ValueError, AssertionError, TypeError) as exc:
        raise SNMPProtocolError(f"Malformed SNMPv3 security parameters: {exc}") from exc
    mac = raw[mac_start:mac_stop]
    zeroed = raw[:mac_start] + bytes(mac_stop - mac_start) + raw[mac_stop:]
    return mac, zeroed


class SNMPv3Message:
    """SNMPv3 message structure per RFC 3412 §7.1.

    The SNMPv3 message format::

        SNMPv3Message ::= SEQUENCE {
            msgVersion            INTEGER (3),
            msgGlobalData         HeaderData,
            msgSecurityParameters OCTET STRING,
            msgData               ScopedPduData
        }

        HeaderData ::= SEQUENCE {
            msgID             INTEGER,
            msgMaxSize        INTEGER,
            msgFlags          OCTET STRING (SIZE(1)),
            msgSecurityModel  INTEGER
        }

        ScopedPduData ::= CHOICE {
            plaintext    ScopedPDU,
            encryptedPDU OCTET STRING
        }

    msgVersion sits in the same position as in SNMPv1/v2c so that a parser
    can recognize the version before decoding the rest (RFC 3412 §5.1), and
    msgSecurityParameters is an OCTET STRING that is opaque outside USM.

    Attributes:
        msg_id: Message ID (arbitrary, for correlation).
        msg_max_size: Maximum message size (default 65535).
        msg_flags: The msgFlags octet as sent: authFlag 0x01, privFlag 0x02,
            reportableFlag 0x04 -- so noAuthNoPriv is 0x00 (or 0x04),
            authNoPriv 0x01 (or 0x05) and authPriv 0x03 (or 0x07).
        msg_security_model: Security model ID (USM=3).
        reportable: Whether the reportableFlag bit is set (confirmed PDUs).
        security_parameters: USM security parameters.
        scoped_pdu: The plaintext scoped PDU data (None when encrypted).
        encrypted_data: The encryptedPDU octets of an authPriv message.
    """

    DEFAULT_MAX_SIZE: int = 65535

    def __init__(
        self,
        msg_id: int = 0,
        msg_max_size: int = DEFAULT_MAX_SIZE,
        msg_flags: int = 0x00,
        msg_security_model: int = 3,  # USM
        reportable: bool = True,
    ) -> None:
        self.msg_version: int = SNMPv3_VERSION
        self.msg_id = msg_id
        self.msg_max_size = msg_max_size
        self.msg_flags = msg_flags
        self.msg_security_model = msg_security_model
        self.reportable = reportable
        self.security_parameters: SecurityParameters | None = None
        self.scoped_pdu: ScopedPDU | None = None
        self.encrypted_data: bytes = b""

    @property
    def security_level(self) -> int:
        """The security level as numbered by SecurityLevel (0, 1, 2).

        The reserved 0b10 combination (privFlag without authFlag) is read
        back as authPriv, since carrying a privacy parameter without an
        authentication parameter cannot mean anything else.
        """
        bits = self.msg_flags & (AUTH_FLAG | PRIV_FLAG)
        return _FLAGS_TO_SECURITY_LEVEL.get(bits, MSG_SECURITY_LEVEL_AUTH_PRIV)

    @property
    def wire_flags(self) -> int:
        """The msgFlags octet to put on the wire (RFC 3412 §6.4)."""
        flags = _SECURITY_LEVEL_TO_FLAGS[self.security_level]
        if self.reportable:
            flags |= REPORTABLE_FLAG
        return flags

    @property
    def is_privacy_enabled(self) -> bool:
        """Check if privacy (encryption) is enabled."""
        return self.security_level == MSG_SECURITY_LEVEL_AUTH_PRIV

    @property
    def is_authentication_enabled(self) -> bool:
        """Check if authentication is enabled."""
        return self.security_level != MSG_SECURITY_LEVEL_NO_AUTH_NO_PRIV

    @property
    def is_encrypted(self) -> bool:
        """True when msgData carried an encryptedPDU rather than a ScopedPDU."""
        return bool(self.msg_flags & PRIV_FLAG)

    def __repr__(self) -> str:
        level = {
            MSG_SECURITY_LEVEL_NO_AUTH_NO_PRIV: "noAuthNoPriv",
            MSG_SECURITY_LEVEL_AUTH_NO_PRIV: "authNoPriv",
            MSG_SECURITY_LEVEL_AUTH_PRIV: "authPriv",
        }.get(self.security_level, "unknown")
        return (
            f"SNMPv3Message(msg_id={self.msg_id}, "
            f"security_level={level}, "
            f"max_size={self.msg_max_size})"
        )


# ---------------------------------------------------------------------------
# MPv3 — SNMPv3 Message Processing
# ---------------------------------------------------------------------------


class _EngineTime:
    """The Local Configuration Datastore's view of one engine's clock.

    RFC 3414 §3.2 step 7 keeps three values per authoritative engine:
    ``snmpEngineBoots``/``snmpEngineTime`` are the notion last synchronized,
    and ``latest_received`` is the highest engineTime seen, which is what makes
    a replayed message detectable even when it falls inside the window.
    """

    __slots__ = ("boots", "latest_received", "time")

    def __init__(self, boots: int = 0, time_value: int = 0) -> None:
        self.boots: int = boots
        self.time: int = time_value
        self.latest_received: int = time_value


def _is_request(pdu: object) -> bool:
    """Whether a PDU must be answered, i.e. whether we own the clock for it.

    RFC 3414 §3.2 steps 3 and 7 both split on exactly this: for a Request the
    processing engine is the authoritative one and supplies snmpEngineBoots/
    snmpEngineTime, whereas for a Response or Report the peer is.  snmp.pdus
    groups Get/GetNext/Set/GetBulk under Request; InformRequest is a
    notification but still expects a reply, so the responder is authoritative
    for it too.

    Args:
        pdu: The decoded PDU, or None when the message carried none.

    Returns:
        True for Request and Inform PDUs, False for responses and Reports.
    """
    return isinstance(pdu, (Request, InformRequest))


class MPv3:
    """SNMPv3 Message Processing Model per RFC 3412 §3.1.

    MPv3 handles:
    - Encoding outgoing SNMPv3 messages with USM security parameters
    - Decoding incoming SNMPv3 messages and extracting security parameters
    - Scoped PDU processing for SNMPv3

    Usage:
        >>> mpm = MPv3(engine_id=b"\\x01\\x00\\x00\\x01\\x01")
        >>> message = SNMPv3Message(msg_id=42)
        >>> message.security_parameters = SecurityParameters(
        ...     engine_id=b"\\x01\\x00\\x00\\x01\\x01",
        ...     username="public",
        ...     security_level=0,
        ... )
        >>> message.scoped_pdu = ScopedPDU(
        ...     context_engine_id=b"\\x01\\x00\\x00\\x01\\x01",
        ...     context_name="",
        ...     pdu=GetRequest.from_oid("1.3.6.1.2.1.1.1.0"),
        ... )
        >>> encoded = mpm.encode(message)
        >>> decoded = mpm.decode(encoded)
    """

    def __init__(
        self,
        engine_id: bytes,
        user_db: USMUserDatabase | None = None,
        *,
        engine_time_source: Callable[[], tuple[int, int]] | None = None,
        time_window: int = DEFAULT_TIME_WINDOW,
    ) -> None:
        """Initialize MPv3.

        Args:
            engine_id: The local SNMP engine ID.
            user_db: USM user database consulted by :meth:`authenticate_incoming`.
            engine_time_source: Source of this engine's ``(snmpEngineBoots,
                snmpEngineTime)``; defaults to a clock started now with boots 0
                (see :func:`engine_time_clock`).  Only needed when the process
                must report the same counters across restarts.
            time_window: Seconds of tolerance for the time-window check of
                RFC 3414 §3.2 step 7.
        """
        if isinstance(engine_id, str):
            engine_id = bytes.fromhex(engine_id)
        self.engine_id: bytes = engine_id if isinstance(engine_id, bytes) else engine_id.encode()
        self.user_db: USMUserDatabase = user_db or USMUserDatabase()
        self.engine_time_source: Callable[[], tuple[int, int]] = (
            engine_time_source or engine_time_clock()
        )
        self.time_window: int = time_window
        # usmStats counters, one per failure an agent may report (RFC 3414 §14).
        self.stats: dict[str, int] = {oid: 0 for oid in USM_STATS_OIDS}
        # LCD clock state for engines that are not us (RFC 3414 §3.2 step 7b).
        self._engine_times: dict[bytes, _EngineTime] = {}
        # Password-to-key costs a megabyte of hashing per passphrase, so the
        # localized keys are derived once per user and reused.
        self._auth_keys: dict[str, bytes] = {}
        self._priv_keys: dict[str, bytes] = {}

    def encode(self, message: SNMPv3Message) -> bytes:
        """Encode an SNMPv3 message to bytes with optional auth + privacy.

        RFC 3412 §7.1 defines the frame (see SNMPv3Message); RFC 3414 §2.5.1
        defines what USM puts into it:

        1. Encode the ScopedPDU.
        2. Encrypt that ScopedPDU when authPriv is requested (RFC 3414
           §8.3.1) and copy the salt into msgPrivacyParameters.
        3. Build msgSecurityParameters with msgAuthenticationParameters set
           to as many zero octets as the MAC is long (RFC 3414 §2.4, §A.4).
        4. Take the MAC over exactly those octets (RFC 3414 §6.3.1/§7.3.1,
           RFC 7860 §4) and splice it into the placeholder.

        Args:
            message: The SNMPv3 message to encode.

        Returns:
            BER-encoded message bytes.

        Raises:
            ValueError: If the PDU, the security parameters, or the keys the
                requested security level needs are missing.
            PrivacyError: If the authentication or privacy protocol is
                not supported.
        """
        if not message.scoped_pdu or not message.security_parameters:
            raise ValueError("Scoped PDU and security parameters required")

        sec_params = message.security_parameters
        level = message.security_level

        # Step 1: the ScopedPDU is the plaintext of msgData (RFC 3411 §3.3.4).
        scoped_pdu_bytes = message.scoped_pdu.encode()

        # Step 2: privacy encrypts the whole ScopedPDU (RFC 3414 §8.3.1).
        encrypted_data = scoped_pdu_bytes
        if level == MSG_SECURITY_LEVEL_AUTH_PRIV:
            if not sec_params.privacy_key or not sec_params.priv_protocol:
                raise ValueError(
                    "authPriv requested but a privacy key and protocol are required"
                )
            privacy_ctx = PrivacyContext(
                protocol=sec_params.priv_protocol,
                privacy_key=sec_params.privacy_key,
                engine_boots=sec_params.engine_boots,
                engine_time=sec_params.engine_time,
            )
            encrypted_data = privacy_ctx.encrypt(scoped_pdu_bytes)
            # msgPrivacyParameters carries the salt that built the IV.
            sec_params.priv_parameters = privacy_ctx.priv_parameters

        # Step 3: resolve the authentication protocol and its MAC length.
        auth_protocol = ""
        mac_length = 0
        if message.is_authentication_enabled:
            if not sec_params.authentication_key:
                raise ValueError(
                    "Authentication requested but no authentication key is configured"
                )
            resolved_auth = resolve_auth_protocol(sec_params.auth_protocol)
            auth_protocol = _mic_protocol(resolved_auth)
            mac_length = resolved_auth.get_mac_length()

        # Step 4: msgSecurityParameters with a zero-filled MAC placeholder,
        # and msgData as either the plaintext ScopedPDU or — once privacy has
        # run — the encryptedPDU OCTET STRING (RFC 3412 §7.1 ScopedPduData).
        wire_flags = message.wire_flags
        message.msg_flags = wire_flags
        sec_params.security_level = level
        sec_seq, mac_offset = _encode_security_parameters(sec_params, mac_length)
        if encrypted_data is scoped_pdu_bytes:
            data_bytes = scoped_pdu_bytes
        else:
            data_bytes = bytes(OctetString(encrypted_data).get_object())

        global_data = bytes(
            Sequence.from_list(
                [
                    Integer.from_int(message.msg_id).get_object(),
                    Integer.from_int(message.msg_max_size).get_object(),
                    OctetString(bytes([wire_flags])).get_object(),
                    Integer.from_int(message.msg_security_model).get_object(),
                ]
            )
        )

        # Step 5: MAC over the complete message (RFC 3414 §2.5.1 step 4),
        # spliced into the placeholder built in step 4.
        version_bytes = bytes(Integer.from_int(message.msg_version).get_object())
        sec_frame = bytes(OctetString(sec_seq).get_object())
        body = version_bytes + global_data + sec_frame + data_bytes
        message_bytes = _encode_tlv(_SEQUENCE_TAG, body)

        if mac_length:
            mic = calculate_mic(
                message_bytes,
                sec_params.authentication_key,
                auth_protocol,
                self.engine_id,
            )
            # The MAC sits at mac_offset inside the SEQUENCE, which itself sits
            # inside the OCTET STRING framing of msgSecurityParameters.  Every
            # surrounding length is already final, so the position is exact
            # arithmetic rather than a byte search that a payload could shadow.
            start = (
                (len(message_bytes) - len(body))
                + len(version_bytes)
                + len(global_data)
                + (len(sec_frame) - len(sec_seq))
                + mac_offset
            )
            message_bytes = (
                message_bytes[:start] + mic + message_bytes[start + mac_length :]
            )
            sec_params.mac = mic

        return message_bytes

    def decode(self, raw: bytes) -> SNMPv3Message:
        """Decode raw bytes into an SNMPv3 message.

        RFC 3414 §2.5.2 describes what USM does with an incoming message;
        this method lifts the octets into a SNMPv3Message:

        1. Split msgVersion, msgGlobalData, msgSecurityParameters, msgData.
        2. Read msgFlags: the security level sits in the low two bits, and
           the privFlag bit decides whether msgData holds a plaintext
           ScopedPDU or an encryptedPDU OCTET STRING.
        3. Decode the USM SEQUENCE: authoritative engine ID, boots and time,
           user name, MAC and privacy parameters (RFC 3414 §2.4).

        Note: MIC verification and decryption are left to the caller.
        Use verify_message_mic() with the user's localized authentication
        key, then PrivacyContext.decrypt() with the message's privacy
        parameters to obtain the ScopedPDU of an authPriv message.

        Args:
            raw: BER-encoded message bytes.

        Returns:
            Decoded SNMPv3Message.

        Raises:
            SNMPProtocolError: If the bytes are not a well-formed SNMPv3
                message.
        """
        try:
            outer, _ = Object.decode(raw, 0)
        except (IndexError, ValueError, AssertionError, TypeError) as exc:
            raise SNMPProtocolError(f"Malformed SNMPv3 message: {exc}") from exc

        fields = outer.value if isinstance(outer.value, list) else []
        if len(fields) < 4:
            raise SNMPProtocolError(
                f"Malformed SNMPv3 message: expected 4 fields, found {len(fields)}"
            )
        header_fields = fields[1].value if isinstance(fields[1].value, list) else []
        if len(header_fields) < 4:
            raise SNMPProtocolError(
                f"Malformed msgGlobalData: expected 4 fields, found {len(header_fields)}"
            )

        message = SNMPv3Message()
        message.msg_version = int(fields[0])
        message.msg_id = int(header_fields[0])
        message.msg_max_size = int(header_fields[1])
        raw_flags = header_fields[2].value
        flags = raw_flags if isinstance(raw_flags, bytes) else b""
        message.msg_flags = flags[0] if flags else 0
        message.reportable = bool(message.msg_flags & REPORTABLE_FLAG)
        message.msg_security_model = int(header_fields[3])

        raw_sec = fields[2].value if isinstance(fields[2].value, bytes) else b""
        params = SecurityParameters.decode(bytes(raw_sec))
        params.security_level = message.security_level
        message.security_parameters = params

        if message.is_encrypted:
            ciphertext = fields[3].value
            message.encrypted_data = ciphertext if isinstance(ciphertext, bytes) else b""
        else:
            scoped = ScopedPDU()
            scoped.decode(bytes(fields[3]))
            message.scoped_pdu = scoped

        return message

    def verify_message_mic(
        self,
        raw: bytes,
        auth_key: bytes,
        protocol: AuthProtocol | str,
    ) -> bool:
        """Verify the MAC of a received message (RFC 3414 §2.5.2 step 4).

        RFC 3414 §2.5.2 explicitly permits discarding the message instead of
        reporting authentication failure when the security parameters cannot
        be parsed; a bare False keeps that option open for the caller.

        Args:
            raw: The message exactly as received.
            auth_key: Localized authentication key of the named user.
            protocol: That user's authentication protocol.

        Returns:
            True if the MAC matches.
        """
        mac, zeroed = split_message_mic(raw)
        if not mac:
            return False
        return verify_mic(zeroed, mac, auth_key, _mic_protocol(protocol))

    def authenticate_incoming(self, raw: bytes) -> SNMPv3Message:
        """Run the USM receive procedure over a message (RFC 3414 §3.2).

        Steps 1-8 are applied in the order the RFC gives them: parse the
        security parameters, insist on our own snmpEngineID, find the user,
        check that the user supports the requested securityLevel, verify the
        MAC, apply the time window, then decrypt an authPriv payload.  Each
        failure increments the matching usmStats counter in :attr:`stats` and
        raises :class:`USMError` carrying that counter's OID in ``stat``, which
        is what a Report PDU would name.

        Two messages are returned without verification because the standard
        requires that they be accepted before a security context exists: an
        engineID discovery request (§3.2 step 3a, empty authoritative engineID
        and empty user name at noAuthNoPriv), and an unauthenticated Report
        (§11.4), which is how a peer reports one of these failures back to us.

        Args:
            raw: The message exactly as received.

        Returns:
            The decoded message; on authPriv with ``scoped_pdu`` decrypted, and
            with the keys that were used recorded in ``security_parameters``.

        Raises:
            USMError: On any §3.2 failure.
            SNMPProtocolError: If the bytes are not a well-formed message.
        """
        message = self.decode(raw)
        params = message.security_parameters
        if params is None:  # step 1
            raise self._fail('Message carries no msgSecurityParameters', '')

        level = message.security_level
        pdu = message.scoped_pdu.pdu if message.scoped_pdu else None

        # Discovery requests and unauthenticated Reports arrive before any
        # security context exists (RFC 3414 §3.2 step 3a, §11.4).
        if level == MSG_SECURITY_LEVEL_NO_AUTH_NO_PRIV:
            if isinstance(pdu, Report):
                return message
            if not params.engine_id and not params.username:
                return message

        # Step 3: msgAuthoritativeEngineID must be known.  A zero-length value
        # always fails (§3.2 step 3's closing note), which is what makes
        # engineID discovery work.  For a Request this engine must be the
        # authoritative one; for a Response or Report the peer is, and step 3a
        # lets a non-authoritative engine cache the peer's ID and carry on.
        if not params.engine_id:
            raise self._fail(
                "Message carried a zero-length msgAuthoritativeEngineID",
                USM_STATS_UNKNOWN_ENGINE_IDS,
            )
        authoritative = params.engine_id == self.engine_id
        if not authoritative and _is_request(pdu):
            raise self._fail(
                "Request names engine "
                + params.engine_id.hex()
                + ", not this engine "
                + self.engine_id.hex(),
                USM_STATS_UNKNOWN_ENGINE_IDS,
            )

        # Step 4: the user must exist.
        user = self.user_db.get_user(params.username)
        if user is None:
            raise self._fail(
                f'No USM user named {params.username!r}',
                USM_STATS_UNKNOWN_USER_NAMES,
            )

        # Step 5: the user must support the level the message asks for.
        if level > int(user.security_level.value):
            raise self._fail(
                f'USM user {params.username!r} supports level '
                f'{user.security_level.name}, message requested {level}',
                USM_STATS_UNSUPPORTED_SEC_LEVELS,
            )

        # Steps 6 and 7: the MAC, then the time window the MAC protects.
        if level != MSG_SECURITY_LEVEL_NO_AUTH_NO_PRIV:
            self._authenticate(raw, message, user)
            self._check_time_window(params, authoritative=authoritative)

        # Step 8: privacy.
        if level == MSG_SECURITY_LEVEL_AUTH_PRIV:
            self._decrypt_payload(message, user)

        params.security_level = level
        return message


    def process_incoming(
        self,
        raw: bytes,
        source_addr: str = "0.0.0.0",
        source_port: int = 0,
    ) -> SNMPv3Message:
        """Process an incoming SNMPv3 message by running USM over it.

        RFC 3414 §3.2 is the whole of what an SNMP engine does with a received
        v3 message, so this is :meth:`authenticate_incoming` plus bookkeeping —
        it does not merely decode.

        Args:
            raw: BER-encoded message bytes.
            source_addr: Source address (for logging).
            source_port: Source port.

        Returns:
            Decoded and authenticated SNMPv3Message.

        Raises:
            USMError: On any RFC 3414 §3.2 failure.
            SNMPProtocolError: If the bytes are not a well-formed message.
        """
        message = self.authenticate_incoming(raw)
        if message.security_parameters:
            message.security_parameters.security_model = self._detect_security_model(
                source_addr
            )
        return message

    def process_outgoing(self, message: SNMPv3Message) -> bytes:
        """Process an outgoing SNMPv3 message.

        Args:
            message: The message to encode and process.

        Returns:
            BER-encoded message bytes.
        """
        return self.encode(message)

    def _detect_security_model(self, source_addr: str) -> int:
        """Detect the security model based on source address.

        Returns:
            Security model ID (3 = USM).
        """
        return 3  # USM

    def _fail(self, reason: str, stat: str) -> USMError:
        """Count a USM failure and build the error to raise for it.

        RFC 3414 §2.5.2 leaves the choice between reporting and discarding to
        the implementation, so the counter is incremented here and the caller
        decides by catching the returned error.

        Args:
            reason: Human-readable description of the failure.
            stat: usmStats counter OID for this failure, or ``""``.

        Returns:
            The USMError the caller should raise.
        """
        if stat:
            self.stats[stat] = self.stats.get(stat, 0) + 1
        return USMError(reason, stat)

    def _auth_key_for(self, user: USMUser) -> bytes:
        """The user's authentication key localized for this engine (RFC 3414 §2.6).

        A user configured with a key (usmUserAuthKeyChange) keeps it; one
        configured with a pass phrase is localized once and cached, because the
        password-to-key algorithm of §2.7 hashes a megabyte per derivation.

        Args:
            user: The user whose key is needed.

        Returns:
            The localized authentication key.

        Raises:
            USMError: If the user has neither a key nor a pass phrase.
        """
        cached = self._auth_keys.get(user.username)
        if cached is not None:
            return cached
        if user.auth_key:
            key = bytes(user.auth_key)
        elif user.auth_passphrase:
            key = localize_passphrase(
                user.auth_passphrase, self.engine_id, user.auth_protocol
            )
        else:
            raise self._fail(
                f"USM user {user.username!r} has no authentication key or pass phrase",
                USM_STATS_WRONG_DIGESTS,
            )
        self._auth_keys[user.username] = key
        return key

    def _priv_key_for(self, user: USMUser) -> bytes:
        """The user's privacy key localized for this engine (RFC 3414 §2.6).

        Args:
            user: The user whose key is needed.

        Returns:
            The localized privacy key.

        Raises:
            USMError: If the user has neither a key nor a pass phrase.
        """
        cached = self._priv_keys.get(user.username)
        if cached is not None:
            return cached
        if user.priv_key:
            key = bytes(user.priv_key)
        elif user.priv_passphrase:
            key = localize_privacy_key(
                user.priv_passphrase,
                self.engine_id,
                user.priv_protocol,
                user.auth_protocol,
            )
        else:
            raise self._fail(
                f"USM user {user.username!r} has no privacy key or pass phrase",
                USM_STATS_DECRYPTION_ERRORS,
            )
        self._priv_keys[user.username] = key
        return key

    def _authenticate(
        self,
        raw: bytes,
        message: SNMPv3Message,
        user: USMUser,
    ) -> None:
        """Verify the message's MAC with the user's key (RFC 3414 §3.2 step 6).

        This is the ``authenticateIncomingMsg`` primitive: the MAC is taken over
        the whole message as received with msgAuthenticationParameters zeroed,
        so the bytes must not be re-encoded between here and the wire.

        Args:
            raw: The message exactly as received.
            message: Its decoded form.
            user: The user the message names.

        Raises:
            USMError: On a missing MAC or a mismatch
                (usmStatsWrongDigests / authenticationFailure), or when the
                user has no authentication protocol
                (usmStatsUnsupportedSecLevels).
        """
        params = message.security_parameters
        if params is None:
            raise self._fail("Message carries no msgSecurityParameters", "")
        if user.auth_protocol == AuthProtocol.NONE:
            raise self._fail(
                f"USM user {user.username!r} has no authentication protocol "
                "but the message is authenticated",
                USM_STATS_UNSUPPORTED_SEC_LEVELS,
            )
        key = self._auth_key_for(user)
        if not params.mac:
            raise self._fail(
                "Authenticated message carried an empty msgAuthenticationParameters",
                USM_STATS_WRONG_DIGESTS,
            )
        if not self.verify_message_mic(raw, key, user.auth_protocol):
            raise self._fail(
                f"MAC verification failed for USM user {user.username!r}",
                USM_STATS_WRONG_DIGESTS,
            )
        params.authentication_key = key
        params.auth_protocol = user.auth_protocol.value

    def _decrypt_payload(self, message: SNMPv3Message, user: USMUser) -> None:
        """Decrypt an authPriv message's msgData (RFC 3414 §3.2 step 8).

        This is the ``decryptData`` primitive: the localized privacy key, the
        msgPrivacyParameters from the wire and the encryptedPDU produce the
        serialized scopedPDU.

        Args:
            message: The decoded, authenticated message.
            user: The user the message names.

        Raises:
            USMError: When the user has no privacy protocol
                (usmStatsUnsupportedSecLevels) or decryption fails
                (usmStatsDecryptionErrors).
        """
        params = message.security_parameters
        if params is None:
            raise self._fail("Message carries no msgSecurityParameters", "")
        if user.priv_protocol == PrivProtocol.NONE:
            raise self._fail(
                f"USM user {user.username!r} has no privacy protocol "
                "but the message is encrypted",
                USM_STATS_UNSUPPORTED_SEC_LEVELS,
            )
        if not message.encrypted_data:
            raise self._fail(
                "authPriv message carried no encryptedPDU",
                USM_STATS_DECRYPTION_ERRORS,
            )
        key = self._priv_key_for(user)
        try:
            context = PrivacyContext(
                protocol=user.priv_protocol,
                privacy_key=key,
                engine_boots=params.engine_boots,
                engine_time=params.engine_time,
            )
            plaintext = context.decrypt(message.encrypted_data, params.priv_parameters)
            scoped = ScopedPDU()
            scoped.decode(plaintext)
        except (
            PrivacyError,
            SNMPProtocolError,
            IndexError,
            ValueError,
            AssertionError,
            TypeError,
        ) as exc:
            raise self._fail(
                f"Unable to decrypt msgData: {exc}",
                USM_STATS_DECRYPTION_ERRORS,
            ) from exc
        message.scoped_pdu = scoped
        params.privacy_key = key
        params.priv_protocol = user.priv_protocol.value


    def _check_time_window(
        self, params: SecurityParameters, *, authoritative: bool
    ) -> None:
        """Apply the Time Window of RFC 3414 §3.2 step 7.

        Replaying a message is only harmless while its freshness values stay
        plausible, so an authenticated message must agree with this engine's
        notion of the authoritative clock.  Both rules are implemented:

        * step 7a, when this engine is authoritative — boots must match
          exactly and engineTime must be within ``time_window`` seconds;
        * step 7b, when the peer is — the peer's clock is remembered per
          engine ID, advanced by anything newer, and a message older than that
          notion is rejected.  There is no per-message cache, so this rejects
          anything the peer's clock has moved past rather than every replay.

        Args:
            params: The message's security parameters, whose engineBoots and
                engineTime are the values under test.
            authoritative: Whether this engine owns the clock the message
                names, as determined from the PDU type.

        Raises:
            USMError: usmStatsNotInTimeWindows when the message falls outside
                the window, or when the relevant boots counter has saturated
                at 2147483647 and can no longer be trusted.
        """
        boots = params.engine_boots
        engine_time = params.engine_time

        if authoritative:
            local_boots, local_time = self.engine_time_source()
            if (
                local_boots >= MAX_ENGINE_BOOTS
                or boots != local_boots
                or abs(engine_time - local_time) > self.time_window
            ):
                raise self._fail(
                    f"msgAuthoritativeEngineBoots/Time {boots}/{engine_time} "
                    f"outside the time window for {local_boots}/{local_time}",
                    USM_STATS_NOT_IN_TIME_WINDOWS,
                )
            return

        entry = self._engine_times.get(params.engine_id)
        if entry is None:
            # First sight of this engine (RFC 3414 §3.2 steps 3a and 7b):
            # there is no prior notion to compare against, so adopt its clock.
            self._engine_times[params.engine_id] = _EngineTime(boots, engine_time)
            return

        if boots > entry.boots or (
            boots == entry.boots and engine_time > entry.latest_received
        ):
            entry.boots = boots
            entry.time = engine_time
            entry.latest_received = engine_time

        if (
            entry.boots >= MAX_ENGINE_BOOTS
            or boots < entry.boots
            or (boots == entry.boots and engine_time < entry.time - self.time_window)
        ):
            raise self._fail(
                f"msgAuthoritativeEngineBoots/Time {boots}/{engine_time} is "
                f"older than the last value seen for engine "
                f"{params.engine_id.hex()} ({entry.boots}/{entry.time})",
                USM_STATS_NOT_IN_TIME_WINDOWS,
            )


# ---------------------------------------------------------------------------
# MPv2c — SNMPv2c Message Processing
# ---------------------------------------------------------------------------


class MPv2c:
    """SNMPv2c Message Processing Model per RFC 3412 §3.2.

    MPv2c handles SNMPv2c messages with community-based security.

    Usage:
        >>> mpm = MPv2c()
        >>> datagram = mpm.decode(raw_bytes)
        >>> encoded = mpm.encode(datagram)
    """

    def __init__(self) -> None:
        """Initialize MPv2c."""
        pass

    def decode(self, raw: bytes) -> SNMPDatagram:
        """Decode raw bytes into an SNMP datagram.

        Args:
            raw: BER-encoded datagram bytes.

        Returns:
            Decoded SNMPDatagram.
        """
        return SNMPDatagram.decode(raw)

    def encode(self, datagram: SNMPDatagram) -> bytes:
        """Encode an SNMP datagram to bytes.

        Args:
            datagram: The datagram to encode.

        Returns:
            BER-encoded bytes.
        """
        return datagram.encode()

    def process_incoming(self, raw: bytes, source_addr: str = "0.0.0.0", source_port: int = 0) -> SNMPDatagram:
        """Process an incoming SNMPv2c message.

        Args:
            raw: BER-encoded message bytes.
            source_addr: Source address.
            source_port: Source port.

        Returns:
            Decoded SNMPDatagram.
        """
        return self.decode(raw)

    def process_outgoing(self, datagram: SNMPDatagram) -> bytes:
        """Process an outgoing SNMPv2c message.

        Args:
            datagram: The datagram to encode.

        Returns:
            BER-encoded bytes.
        """
        return self.encode(datagram)


# ---------------------------------------------------------------------------
# MPv1 — SNMPv1 Message Processing
# ---------------------------------------------------------------------------


class MPv1:
    """SNMPv1 Message Processing Model per RFC 3412 §3.3.

    MPv1 handles SNMPv1 messages with community-based security.
    This is effectively the same as MPv2c for protocol processing.

    Usage:
        >>> mpm = MPv1()
        >>> datagram = mpm.decode(raw_bytes)
    """

    def __init__(self) -> None:
        """Initialize MPv1."""
        self.mpv2c = MPv2c()

    def decode(self, raw: bytes) -> SNMPDatagram:
        """Decode raw bytes into an SNMP datagram."""
        return self.mpv2c.decode(raw)

    def encode(self, datagram: SNMPDatagram) -> bytes:
        """Encode an SNMP datagram to bytes."""
        return self.mpv2c.encode(datagram)

    def process_incoming(self, raw: bytes, source_addr: str = "0.0.0.0", source_port: int = 0) -> SNMPDatagram:
        """Process an incoming SNMPv1 message."""
        return self.decode(raw)

    def process_outgoing(self, datagram: SNMPDatagram) -> bytes:
        """Process an outgoing SNMPv1 message."""
        return self.encode(datagram)


# ---------------------------------------------------------------------------
# MessageProcessor — Unified Interface
# ---------------------------------------------------------------------------


class MessageProcessor:
    """Unified message processor for all SNMP versions.

    Routes messages to the appropriate MPM based on version.

    Usage:
        >>> from snmp.mpm import MessageProcessor
        >>> proc = MessageProcessor()
        >>> # Process incoming v1 message
        >>> datagram = proc.process_incoming(raw_bytes, SNMPVersion.v1)
        >>> # Process incoming v3 message
        >>> message = proc.process_incoming(raw_bytes, SNMPVersion.v3)
    """

    def __init__(
        self,
        engine_id: bytes = b"",
        user_db: USMUserDatabase | None = None,
    ) -> None:
        """Initialize the message processor.

        Args:
            engine_id: The local SNMP engine ID (for SNMPv3).
            user_db: USM user database (for SNMPv3).
        """
        self.mpv1 = MPv1()
        self.mpv2c = MPv2c()
        self.mpv3 = MPv3(engine_id, user_db)

    def process_incoming(
        self,
        raw: bytes,
        version: SNMPVersion,
        source_addr: str = "0.0.0.0",
        source_port: int = 0,
    ) -> SNMPDatagram | SNMPv3Message:
        """Process an incoming message based on SNMP version.

        Args:
            raw: Raw message bytes.
            version: SNMP version.
            source_addr: Source address.
            source_port: Source port.

        Returns:
            SNMPDatagram for v1/v2c, SNMPv3Message for v3.
        """
        if version == SNMPVersion.v1:
            return self.mpv1.process_incoming(raw, source_addr, source_port)
        # SNMPVersion only numbers v1/v2c/v3 (RFC 1901/1906 folded SNMPv2 into
        # v2c), so there is no "v2" member to test for here.
        if version == SNMPVersion.v2c:
            return self.mpv2c.process_incoming(raw, source_addr, source_port)
        if version == SNMPVersion.v3:
            return self.mpv3.process_incoming(raw, source_addr, source_port)

        raise ValueError(f"Unsupported SNMP version: {version}")

    def process_outgoing(self, message: SNMPDatagram | SNMPv3Message) -> bytes:
        """Process an outgoing message based on its type.

        Args:
            message: SNMPDatagram or SNMPv3Message.

        Returns:
            BER-encoded bytes.
        """
        if isinstance(message, SNMPDatagram):
            return self.mpv2c.process_outgoing(message)
        if isinstance(message, SNMPv3Message):
            return self.mpv3.process_outgoing(message)

        raise TypeError(f"Unsupported message type: {type(message)}")


# ---------------------------------------------------------------------------
# Exported Names
# ---------------------------------------------------------------------------

__all__ = [
    "DEFAULT_TIME_WINDOW",
    "MAX_ENGINE_BOOTS",
    "USM_STATS_OIDS",
    "MPv1",
    "MPv2c",
    "MPv3",
    "MessageProcessor",
    "SNMPv3Message",
    "USMError",
    "engine_time_clock",
    "split_message_mic",
]