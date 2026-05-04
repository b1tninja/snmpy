"""Custom SNMP exception hierarchy.

This module provides a set of exceptions for SNMP operations, organized in a
hierarchy that allows catching broad or specific error categories:

    SNMPError                     # Base for all SNMP errors
    ├── SNMPTimeoutError          # Request timed out
    ├── SNMPCommunityError        # Bad community string (SNMPv1/v2c)
    ├── SNMPNoSuchObject          # PDU error: NoSuchObject
    ├── SNMPNoSuchInstance        # PDU error: NoSuchInstance
    ├── SNMPNoSuchName            # PDU error: NoSuchName (legacy)
    ├── SNMPTooBig                # PDU error: TooBig
    ├── SNMPGeneralError          # PDU error: GenError (SNMPv1)
    ├── SNMPErrorStatus           # SNMP error status (v1) / genericErr (v2c+)
    ├── BERDecodeError            # BER encoding/decoding failure
    └── SNMPProtocolError         # Protocol-level violation

Usage:

    >>> try:
    ...     result = await client.get(host, oid, port)
    ... except SNMPTimeoutError:
    ...     logging.warning("Request timed out")
    ... except SNMPNoSuchObject:
    ...     logging.debug("OID not available on device")
    ... except SNMPError:
    ...     logging.error("General SNMP error")

All exceptions carry a ``context`` attribute providing additional information:

    >>> try:
    ...     ...
    ... except SNMPError as exc:
    ...     print(f"Error at {exc.context}")

Module: ``snmp.exceptions``
"""

from __future__ import annotations

import logging
from typing import Optional, Any

logger = logging.getLogger(__name__)

# ===========================================================================
# Exception hierarchy
# ===========================================================================


class SNMPError(Exception):
    """Base exception for all SNMP-related errors.

    Attributes:
        message: Human-readable error message.
        context: Additional context about where/why the error occurred.
        raw: Original raw data (if any) that caused the error.
        code: SNMP error code or status (if applicable).
    """

    def __init__(
        self,
        message: str,
        context: Optional[str] = None,
        raw: Optional[Any] = None,
        code: Optional[int] = None,
    ) -> None:
        """Initialize the SNMP error.

        Args:
            message: Human-readable error message.
            context: Additional context (e.g., "host=192.168.1.1:161 oid=1.3.6.1.2.1.1.1.0").
            raw: Raw data that caused the error (if applicable).
            code: SNMP error code or status (if applicable).
        """
        self.message = message
        self.context = context
        self.raw = raw
        self.code = code
        parts = [message]
        if context:
            parts.append(f"(context: {context})")
        super().__init__(self.message, context, raw, code)

    def __str__(self) -> str:
        if self.context:
            return f"{self.message} [context: {self.context}]"
        return self.message


class SNMPTimeoutError(SNMPError):
    """Exception raised when an SNMP request times out.

    This typically indicates:
    - The target host is unreachable
    - A firewall is dropping packets
    - The SNMP agent is overloaded
    - The community string is wrong (v1/v2c drops unknown communities)

    Attributes:
        host: Target host address.
        port: Target UDP port.
        timeout: The timeout value that was exceeded (seconds).
        retries: Number of retries attempted.
    """

    def __init__(
        self,
        host: str,
        port: int,
        timeout: float,
        retries: int = 1,
        oid: Optional[str] = None,
    ) -> None:
        """Initialize the timeout error.

        Args:
            host: Target host address.
            port: Target UDP port.
            timeout: The timeout value that was exceeded (seconds).
            retries: Number of retries attempted.
            oid: The OID that was being queried (if applicable).
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.oid = oid
        msg = f"SNMP request timed out"
        ctx = f"host={host}:{port} timeout={timeout}s retries={retries}"
        if oid:
            ctx += f" oid={oid}"
        super().__init__(msg, context=ctx)


class SNMPCommunityError(SNMPError):
    """Exception raised for bad community string errors.

    This is an SNMPv1/v2c-specific error indicating the community string
    was rejected by the SNMP agent. It may mean:
    - The community string is incorrect
    - The agent uses a different community for this host
    - Access control (VACM) denies access

    Attributes:
        community: The community string that was rejected.
        host: Target host address.
    """

    def __init__(
        self,
        community: str,
        host: str,
        port: int = 161,
    ) -> None:
        """Initialize the community error.

        Args:
            community: The community string that was rejected.
            host: Target host address.
            port: Target UDP port.
        """
        self.community = community
        self.host = host
        self.port = port
        msg = f"Community '{community}' rejected"
        ctx = f"community={community} host={host}:{port}"
        super().__init__(msg, context=ctx)


class BERDecodeError(SNMPError):
    """Exception raised for BER encoding/decoding errors.

    This indicates the received data does not conform to ASN.1 BER format.
    Common causes:
    - Non-SNMP response from the target (e.g., HTTP, SSH banner)
    - Corrupted or truncated UDP datagram
    - Mismatched endianness or byte order

    Attributes:
        data: The raw bytes that caused the error.
        offset: Position in the data where parsing failed.
    """

    def __init__(
        self,
        message: str,
        data: Optional[bytes] = None,
        offset: Optional[int] = None,
    ) -> None:
        """Initialize the BER decode error.

        Args:
            message: Human-readable error message.
            data: The raw bytes that caused the error.
            offset: Position in the data where parsing failed.
        """
        self.data = data
        self.offset = offset
        ctx_parts = []
        if data:
            hex_preview = data[:32].hex(" ") if isinstance(data, bytes) else str(data)
            ctx_parts.append(f"data={hex_preview[:64]}")
        if offset is not None:
            ctx_parts.append(f"offset={offset}")
        ctx = " | ".join(ctx_parts) if ctx_parts else None
        super().__init__(message, context=ctx)


class SNMPErrorStatus(SNMPError):
    """Exception raised for SNMP error status responses.

    Covers both SNMPv1 error Status (NoSuchName, NoSuchObject, NoSuchValue,
    TooBig, NotWritable, GenError) and SNMPv2c/SmError status.

    Attributes:
        error_status: The SNMP error status integer (0 = noError).
        error_index: The SNMP error index.
        pdu_type: The PDU type that returned the error.
    """

    # SNMPv1 error status values
    NO_SUCH_NAME = 2
    BAD_VALUE = 3
    READ_ONLY = 4
    GEN_ERROR = 5
    TOO_BIG = 6

    # SNMPv2c/Sm error status values
    NO_ACCESS = 2
    WRONG_TYPE = 3
    WRONG_VALUE = 4
    WRONG_SIZE = 5
    NO_SUCH_INSTANCE = 6
    NO_SUCH_OBJECT = 7
    BAD_ROUCH = 8
    NOT_WRITABLE = 9
    NO_CREATION = 10
    INCONSISTENT_VALUE = 11
    RESOURCE_UNAVAILABLE = 12
    NOT_WRITABLE_ON_CONSITUTION = 13
    END_TO_M_END = 14
    NOT_IN_TIME_WINDOW = 15
    NOT_SYNCED = 16
    NOT_SYNCED_2 = 17

    def __init__(
        self,
        error_status: int,
        error_index: int,
        pdu_type: Optional[str] = None,
        host: Optional[str] = None,
    ) -> None:
        """Initialize the error status exception.

        Args:
            error_status: SNMP error status value.
            error_index: SNMP error index.
            pdu_type: The PDU type that returned the error.
            host: Host that returned the error (if known).
        """
        self.error_status = error_status
        self.error_index = error_index
        self.pdu_type = pdu_type

        # Map error status to human-readable names
        status_names = {
            0: "noError",
            1: "tooBig",
            2: "noSuchName",
            3: "badValue",
            4: "readOnly",
            5: "genErr",
            6: "genErr",  # SNMPv2c genErr
        }
        name = status_names.get(error_status, f"unknown({error_status})")
        msg = f"SNMP error: {name} (status={error_status}, index={error_index})"

        ctx_parts = []
        if pdu_type:
            ctx_parts.append(f"pdu={pdu_type}")
        if host:
            ctx_parts.append(f"host={host}")
        ctx = " | ".join(ctx_parts) if ctx_parts else None
        super().__init__(msg, context=ctx, code=error_status)


class SNMPProtocolError(SNMPError):
    """Exception raised for protocol-level violations.

    Covers:
    - Invalid SNMP version in response
    - Mismatched request/response IDs
    - Invalid PDU type in response
    - Unexpected or malformed SNMP messages

    Attributes:
        expected: The expected value.
        received: The actual value received.
        operation: The operation being performed when the error occurred.
    """

    def __init__(
        self,
        message: str,
        expected: Optional[Any] = None,
        received: Optional[Any] = None,
        operation: Optional[str] = None,
    ) -> None:
        """Initialize the protocol error.

        Args:
            message: Human-readable error message.
            expected: The expected value.
            received: The actual value received.
            operation: The operation being performed.
        """
        self.expected = expected
        self.received = received
        self.operation = operation
        ctx_parts = []
        if expected is not None:
            ctx_parts.append(f"expected={expected}")
        if received is not None:
            ctx_parts.append(f"received={received}")
        if operation:
            ctx_parts.append(f"operation={operation}")
        ctx = " | ".join(ctx_parts) if ctx_parts else None
        super().__init__(message, context=ctx)


class SNMPNoSuchObject(SNMPErrorStatus):
    """Exception for SNMP NoSuchObject error status."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(error_status=self.NO_SUCH_NAME, *args, **kwargs)


class SNMPNoSuchInstance(SNMPErrorStatus):
    """Exception for SNMP NoSuchInstance error status."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(error_status=self.NO_SUCH_INSTANCE, *args, **kwargs)


class SNMPTooBig(SNMPErrorStatus):
    """Exception for SNMP TooBig error status."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(error_status=self.TOO_BIG, *args, **kwargs)


class SNMPGeneralError(SNMPErrorStatus):
    """Exception for SNMP GenError status."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(error_status=self.GEN_ERROR, *args, **kwargs)


# ===========================================================================
# Helper functions
# ===========================================================================

def log_exception(exc: BaseException, level: str = "debug", msg: Optional[str] = None) -> None:
    """Log an exception with context information.

    This is a convenience function for use in except blocks where you want
    to log the exception but not re-raise it. It provides more context
    than a simple ``logger.debug()`` call.

    Args:
        exc: The exception to log.
        level: Logging level ("debug", "warning", "error", "critical").
        msg: Optional custom message to prepend.
    """
    fn = getattr(logger, level, logger.debug)
    if msg:
        fn(f"{msg}: {type(exc).__name__}: {exc}")
    else:
        fn(f"{type(exc).__name__}: {exc}")


def error_status_for_exception(exc: BaseException) -> int:
    """Convert a generic exception to an SNMP error status code.

    This maps Python exceptions to SNMP error status integers that can
    be used in response PDUs.

    Args:
        exc: The exception to convert.

    Returns:
        SNMP error status integer (0 = no error, 5 = genErr).
    """
    if isinstance(exc, (SNMPNoSuchObject, SNMPNoSuchInstance)):
        return 2  # noSuchName
    if isinstance(exc, SNMPTooBig):
        return 6  # tooBig
    if isinstance(exc, BERDecodeError):
        return 4  # badValue
    return 5  # genErr


# ===========================================================================
# Exports
# ===========================================================================

__all__ = [
    # Base
    "SNMPError",
    # Specific errors
    "SNMPTimeoutError",
    "SNMPCommunityError",
    "BERDecodeError",
    "SNMPErrorStatus",
    "SNMPProtocolError",
    # Error status aliases
    "SNMPNoSuchObject",
    "SNMPNoSuchInstance",
    "SNMPTooBig",
    "SNMPGeneralError",
    # Helpers
    "log_exception",
    "error_status_for_exception",
]