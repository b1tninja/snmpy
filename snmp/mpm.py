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

import os
import struct
from typing import Optional, Union

from ber.object import (
    Object,
    ObjectIdentifier,
    OctetString,
    Integer,
    Sequence,
    Null,
)
from snmp.datagram import SNMPDatagram
from snmp.pdus import GetRequest, GetNextRequest, GetResponse, SetRequest, Report, SNMPv2Trap, InformRequest
from snmp.enums import SNMPVersion
from snmp.usm import SecurityParameters, USMUser, USMUserDatabase
from snmp.engine_id import SnmpEngineID, SnmpEngineIDGenerator
from snmp.scoped_pdu import ScopedPDU
from snmp.auth import calculate_mic, verify_mic, AuthenticationContext
from snmp.privacy import PrivacyContext

# ---------------------------------------------------------------------------
# SNMPv3 Message Processing Constants
# ---------------------------------------------------------------------------

SNMPv3_VERSION: int = 3

# Message security levels
MSG_SECURITY_LEVEL_NO_AUTH_NO_PRIV: int = 0
MSG_SECURITY_LEVEL_AUTH_NO_PRIV: int = 1
MSG_SECURITY_LEVEL_AUTH_PRIV: int = 2

# Message processing priority
MSG_PRIORITY_NORMAL: int = 0
MSG_PRIORITY_HIGH: int = 1
MSG_PRIORITY_CRITICAL: int = 2


class SNMPv3Message:
    """SNMPv3 message structure per RFC 3412 §5.1.

    The SNMPv3 message format:
        SNMPv3Message ::= SEQUENCE {
            header          SNMPv3MessageHeader
            securityParameters  OCTET STRING
            data            OCTET STRING
        }

    SNMPv3MessageHeader ::= SEQUENCE {
        msgID             INTEGER,
        msgMaxSize        INTEGER,
        msgFlags          OCTET STRING,
        msgSecurityModel  INTEGER
    }

    Attributes:
        msg_id: Message ID (arbitrary, for correlation).
        msg_max_size: Maximum message size (default 65535).
        msg_flags: Security flags (noAuthNoPriv=0x01, authNoPriv=0x02, authPriv=0x03).
        msg_security_model: Security model ID (USM=3).
        security_parameters: USM security parameters.
        scoped_pdu: The scoped PDU data.
    """

    DEFAULT_MAX_SIZE: int = 65535

    def __init__(
        self,
        msg_id: int = 0,
        msg_max_size: int = DEFAULT_MAX_SIZE,
        msg_flags: int = MSG_SECURITY_LEVEL_NO_AUTH_NO_PRIV,
        msg_security_model: int = 3,  # USM
    ) -> None:
        self.msg_id = msg_id
        self.msg_max_size = msg_max_size
        self.msg_flags = msg_flags
        self.msg_security_model = msg_security_model
        self.security_parameters: Optional[SecurityParameters] = None
        self.scoped_pdu: Optional[ScopedPDU] = None

    @property
    def security_level(self) -> int:
        """Get the security level from flags."""
        return self.msg_flags & 0x03

    @property
    def is_privacy_enabled(self) -> bool:
        """Check if privacy (encryption) is enabled."""
        return (self.msg_flags & 0x03) == MSG_SECURITY_LEVEL_AUTH_PRIV

    @property
    def is_authentication_enabled(self) -> bool:
        """Check if authentication is enabled."""
        return (self.msg_flags & 0x03) in (MSG_SECURITY_LEVEL_AUTH_NO_PRIV, MSG_SECURITY_LEVEL_AUTH_PRIV)

    def __repr__(self) -> str:
        level = {0: "noAuthNoPriv", 1: "authNoPriv", 2: "authPriv"}.get(self.msg_flags & 0x03, "unknown")
        return (
            f"SNMPv3Message(msg_id={self.msg_id}, "
            f"security_level={level}, "
            f"max_size={self.msg_max_size})"
        )


# ---------------------------------------------------------------------------
# MPv3 — SNMPv3 Message Processing
# ---------------------------------------------------------------------------


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
        user_db: Optional[USMUserDatabase] = None,
    ) -> None:
        """Initialize MPv3.

        Args:
            engine_id: The local SNMP engine ID.
            user_db: USM user database for authentication.
        """
        if isinstance(engine_id, str):
            engine_id = bytes.fromhex(engine_id)
        self.engine_id: bytes = engine_id if isinstance(engine_id, bytes) else engine_id.encode()
        self.user_db: USMUserDatabase = user_db or USMUserDatabase()

    def encode(self, message: SNMPv3Message) -> bytes:
        """Encode an SNMPv3 message to bytes with optional auth + privacy.

        RFC 3412 §5.1: The SNMPv3 message format with security parameters.
        RFC 3414 §5: Authentication and Privacy processing.

        The encoding process:
        1. Apply privacy (encryption) to the ScopedPDU if privacy is enabled.
        2. Compute MIC over the message body (header + secParams + data) if auth is enabled.
        3. Build the final message with optional MAC in securityParameters.

        Args:
            message: The SNMPv3 message to encode.

        Returns:
            BER-encoded message bytes.
        """
        if not message.scoped_pdu or not message.security_parameters:
            raise ValueError("Scoped PDU and security parameters required")

        sec_params = message.security_parameters
        auth_key = sec_params.authentication_key or b""
        priv_key = sec_params.privacy_key or b""
        auth_protocol = sec_params.auth_protocol or ""
        priv_protocol = sec_params.priv_protocol or ""

        # Step 1: Encode the ScopedPDU to bytes
        scoped_pdu_bytes = message.scoped_pdu.encode()

        # Step 2: Apply privacy (encryption) to scoped PDU if enabled
        if message.is_privacy_enabled and priv_key:
            priv_proto = priv_protocol or "des"
            privacy_ctx = PrivacyContext(
                protocol=priv_proto,
                privacy_key=priv_key,
                engine_id=self.engine_id,
            )
            encrypted_data = privacy_ctx.encrypt(scoped_pdu_bytes)
        else:
            encrypted_data = scoped_pdu_bytes

        # Step 3: Build security parameters SEQUENCE (without MAC)
        sec_bytes = sec_params.engine_id if sec_params.engine_id else b""
        sec_id = OctetString(sec_bytes).get_object() if sec_bytes else Null().get_object()
        sec_name = OctetString(sec_params.username.encode() if sec_params.username else b"").get_object()
        sec_level = Integer.from_int(sec_params.security_level).get_object()
        sec_model = Integer.from_int(sec_params.security_model).get_object()

        sec_params_seq = Sequence.from_list([
            sec_id,
            sec_name,
            sec_level,
            sec_model,
        ])

        # Encode data (the encrypted scoped PDU as OCTET STRING)
        data = OctetString(encrypted_data).get_object()

        # Step 4: Compute MIC over message body if authentication is enabled
        mic = b""
        if auth_key and message.is_authentication_enabled:
            auth_proto = auth_protocol or "cbc-sha-96"

            # Build header for MIC computation
            header_for_mic = Sequence.from_list([
                Integer.from_int(message.msg_id).get_object(),
                Integer.from_int(message.msg_max_size).get_object(),
                OctetString(bytes([message.msg_flags])).get_object(),
                Integer.from_int(message.msg_security_model).get_object(),
            ])

            # Build body for MIC computation
            body_for_mic = Sequence.from_list([
                header_for_mic,
                sec_params_seq.get_object(),
                data,
            ])

            mic = calculate_mic(bytes(body_for_mic), auth_key, auth_proto, self.engine_id)

        # Step 5: Build security parameters with optional MAC
        if mic:
            sec_params_with_mac = bytes(Sequence.from_list([
                sec_id,
                sec_name,
                sec_level,
                sec_model,
                OctetString(mic).get_object(),  # MAC
            ]))
        else:
            sec_params_with_mac = bytes(sec_params_seq)

        # Wrap security parameters as OCTET STRING for BER encoding
        sec_params_octet = OctetString(sec_params_with_mac).get_object()

        # Step 6: Build full message
        header = Sequence.from_list([
            Integer.from_int(message.msg_id).get_object(),
            Integer.from_int(message.msg_max_size).get_object(),
            OctetString(bytes([message.msg_flags])).get_object(),
            Integer.from_int(message.msg_security_model).get_object(),
        ])

        msg_seq = Sequence.from_list([
            header,
            sec_params_octet,
            data,
        ])

        return bytes(msg_seq)

    def decode(self, raw: bytes) -> SNMPv3Message:
        """Decode raw bytes into an SNMPv3 message.

        RFC 3414 §5: Authentication and Privacy processing.

        The decoding process:
        1. Parse the message header, security parameters, and data.
        2. Extract the security parameters (engine ID, username, level, MAC).
        3. Verify MIC if authentication is enabled (user must provide auth_key).
        4. Decrypt the scoped PDU if privacy is enabled (user must provide priv_key).

        Note: MIC verification and decryption are left to the caller.
        The decode method extracts all fields; verify_mic() and decrypt()
        must be called separately with the appropriate keys.

        Args:
            raw: BER-encoded message bytes.

        Returns:
            Decoded SNMPv3Message.
        """
        # Use Object.decode for proper BER parsing
        obj, _ = Object.decode(raw, 0)
        msg_seq = obj

        message = SNMPv3Message()

        if msg_seq.value and len(msg_seq.value) >= 3:
            header = msg_seq.value[0]
            sec_params = msg_seq.value[1]
            data = msg_seq.value[2]

            # Decode header — all Integer/Object fields use __int__/__bytes__ directly
            if header and hasattr(header, 'value') and len(header.value) >= 4:
                message.msg_id = int(header.value[0])
                message.msg_max_size = int(header.value[1])
                message.msg_flags = int(header.value[2])
                message.msg_security_model = int(header.value[3])

            # Decode security parameters
            if sec_params and hasattr(sec_params, 'value') and isinstance(sec_params.value, bytes):
                raw_sec = sec_params.value
                # Parse the inner SEQUENCE from the raw bytes
                if len(raw_sec) >= 10:
                    inner_seq = Sequence.from_list([])
                    inner_seq.decode(raw_sec)
                    if inner_seq.value and len(inner_seq.value) >= 3:
                        sec_id_obj = inner_seq.value[0]
                        sec_name_obj = inner_seq.value[1]
                        sec_level_obj = inner_seq.value[2]

                        engine_id_bytes = bytes(sec_id_obj) if sec_id_obj else b""
                        username = str(sec_name_obj) if sec_name_obj else ""
                        security_level = int(sec_level_obj)

                        message.security_parameters = SecurityParameters(
                            engine_id=engine_id_bytes,
                            username=username,
                            security_level=security_level,
                        )

            # Decode scoped PDU — data is an OctetString/Object with __bytes__
            if data and hasattr(data, 'value') and isinstance(data.value, bytes):
                raw_data = data.value
                scoped = ScopedPDU()
                scoped.decode(raw_data)
                message.scoped_pdu = scoped

        return message

    def process_incoming(self, raw: bytes, source_addr: str = "0.0.0.0", source_port: int = 0) -> SNMPv3Message:
        """Process an incoming SNMPv3 message.

        Args:
            raw: BER-encoded message bytes.
            source_addr: Source address (for logging).
            source_port: Source port.

        Returns:
            Decoded SNMPv3Message.
        """
        message = self.decode(raw)
        if message.security_parameters:
            message.security_parameters.security_model = self._detect_security_model(source_addr)
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

    def _authenticate(
        self,
        message: SNMPv3Message,
        user: Optional[USMUser] = None,
    ) -> bool:
        """Authenticate an SNMPv3 message using USM.

        Args:
            message: The message to authenticate.
            user: The user credentials to use.

        Returns:
            True if authenticated successfully.
        """
        if not user or not message.security_parameters:
            return False

        if user.auth_protocol == "none":
            return True  # No authentication required

        # TODO: Implement actual authentication (RFC 3414 §5)
        # - CBC-SHA-96 (RFC 3414 §5)
        # - HMAC-SHA-256 (RFC 7860)
        return True

    def _encrypt(
        self,
        message: SNMPv3Message,
        user: Optional[USMUser] = None,
    ) -> bool:
        """Encrypt an SNMPv3 message using USM.

        Args:
            message: The message to encrypt.
            user: The user credentials to use.

        Returns:
            True if encryption successful.
        """
        if not user or not user.privacy_enabled or not message.security_parameters:
            return False

        # TODO: Implement actual encryption (RFC 3414 §5)
        # - DES-CBC (RFC 3414 §3.3)
        # - AES-CBC (RFC 3826-3828)
        return True


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
        user_db: Optional[USMUserDatabase] = None,
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
        if version in (SNMPVersion.v2c, SNMPVersion.v2):
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
    "SNMPv3Message",
    "MPv1",
    "MPv2c",
    "MPv3",
    "MessageProcessor",
]