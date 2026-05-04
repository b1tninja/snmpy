"""Masscan binary scan file reader (stdlib only; masscan --readscan / -oB format)."""

from __future__ import annotations

import ctypes
import logging
import mmap
import struct
from collections.abc import Iterator
from datetime import datetime
from ipaddress import IPv4Address
from pathlib import Path
from typing import BinaryIO, ClassVar

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Enums / bitsets
# ------------------------------------------------------------------

class CustomIntEnum(int):
    """Custom int enum with string representation."""

    @property
    def name(self) -> str:
        cls = type(self)
        for key, val in cls.__dict__.items():
            if key.startswith("_"):
                continue
            if isinstance(val, int) and val == int(self):
                return key
        return hex(int(self))

    def __str__(self) -> str:
        return self.name


class RecordStatus(CustomIntEnum):
    """Masscan record status codes."""

    Open = 1
    Closed = 2
    Banner1 = 5
    Open2 = 6
    Closed2 = 7
    Arp2 = 8
    Banner9 = 9


class InternetProtocol(CustomIntEnum):
    """Internet protocol numbers."""

    ARP = 0
    ICMP = 1
    TCP = 6
    UDP = 17
    SCTP = 132


class ApplicationProtocol(CustomIntEnum):
    """Application layer protocols."""

    PROTO_NONE = 0
    PROTO_HEUR = 1
    PROTO_SSH1 = 2
    PROTO_SSH2 = 3
    PROTO_HTTP = 4
    PROTO_FTP = 5
    PROTO_DNS_VERSIONBIND = 6
    PROTO_SNMP = 7
    PROTO_NBTSTAT = 8
    PROTO_SSL3 = 9
    PROTO_SMTP = 10
    PROTO_POP3 = 11
    PROTO_IMAP4 = 12
    PROTO_UDP_ZEROACCESS = 13
    PROTO_X509_CERT = 14
    PROTO_HTML_TITLE = 15
    PROTO_HTML_FULL = 16
    PROTO_NTP = 17
    PROTO_VULN = 18
    PROTO_HEARTBLEED = 19
    PROTO_VNC_RFB = 20
    PROTO_SAFE = 21


class Bitset(list):
    """Bitset with labeled bit positions."""

    labels: ClassVar[list[str]] = []

    def __init__(self, value: int) -> None:
        assert isinstance(value, int)
        self.value = value
        super().__init__(list(self))

    def __int__(self) -> int:
        return self.value

    def __iter__(self) -> Iterator[str]:
        n = 1
        i = 0
        while n <= self.value:
            if self.value & n:
                yield (self.labels[i] if i < len(self.labels) and self.labels[i] else hex(n))
            i += 1
            n = 1 << i


class ReasonFlags(Bitset):
    """TCP flag bitset."""

    labels: ClassVar[list[str]] = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]


# ------------------------------------------------------------------
# Timestamp
# ------------------------------------------------------------------

class Timestamp(int):
    """Custom timestamp type."""

    def __repr__(self) -> str:
        return datetime.fromtimestamp(self).isoformat()


# ------------------------------------------------------------------
# Data classes
# ------------------------------------------------------------------

class MassscanStatus:
    """Masscan scan result status."""

    def __init__(
        self,
        status: RecordStatus,
        timestamp: Timestamp,
        ip: IPv4Address,
        ip_proto: InternetProtocol,
        port: int,
        ttl: int,
    ) -> None:
        self.status = status
        self.timestamp = timestamp
        self.ip = ip
        self.ip_proto = ip_proto
        self.port = port
        self.ttl = ttl

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}: {self.__dict__}"


class ReasonStatus(MassscanStatus):
    """Masscan status with reason flags."""

    def __init__(
        self,
        status: RecordStatus,
        timestamp: Timestamp,
        ip: IPv4Address,
        ip_proto: InternetProtocol,
        port: int,
        reason: ReasonFlags,
        ttl: int,
    ) -> None:
        super().__init__(status, timestamp, ip, ip_proto, port, ttl)
        self.reason = reason


class BannerStatus(MassscanStatus):
    """Masscan status with banner data."""

    def __init__(
        self,
        status: RecordStatus,
        timestamp: Timestamp,
        ip: IPv4Address,
        ip_proto: InternetProtocol,
        port: int,
        app_proto: ApplicationProtocol,
        ttl: int,
        banner: str,
    ) -> None:
        super().__init__(status, timestamp, ip, ip_proto, port, ttl)
        self.app_proto = app_proto
        self.banner = banner


# ------------------------------------------------------------------
# Reader
# ------------------------------------------------------------------

class MasscanReader:
    """Reader for masscan output files."""

    compat_version = b"masscan/1.1"

    def __init__(self, path: str | Path) -> None:
        self.path = path
        self.fh: Path | None = None
        self.fh_file: BinaryIO | None = None
        self.buffer: mmap.mmap | None = None
        self.start_time: datetime | None = None
        self.version = self.compat_version
        self.footers: list[bytes] = []

        try:
            path_obj = Path(path)
            self.fh = path_obj
            fh_file = path_obj.open("rb")
            buffer = mmap.mmap(fh_file.fileno(), 0, access=mmap.ACCESS_READ)
        except Exception as e:
            logger.critical("Failed to open %s: %s", path, e)
        else:
            self.fh_file = fh_file
            self.buffer = buffer
            self._parse_headers()

    # -- public helpers --------------------------------------------------

    def __len__(self) -> int:
        """Return the number of records in the file."""
        return sum(1 for _ in self)

    # -- internal --------------------------------------------------------

    def _parse_headers(self) -> None:
        """Parse file headers and assess compatibility."""
        if self.buffer is None:
            return
        headers = self.buffer[0:100].rstrip(b"\x00").split()
        assert headers[0].startswith(self.compat_version)
        self.version = headers[0]

        for header in headers[1:]:
            header_str = ctypes.create_string_buffer(header).value.decode()
            if ":" in header_str:
                header_type, value = header_str.split(":", 1)
                if header_type == "s":
                    self.start_time = datetime.fromtimestamp(int(value))
            elif header_str:
                logger.warning("%s: has unknown header: %s", self, header_str)

        if self.buffer is not None:
            footers = self.buffer[self.buffer.size() - 99 :].rstrip(b"\x00").split(b"\n")
            if footers[0] == self.compat_version:
                self.footers = footers
            else:
                logger.warning("%s: has an invalid footer, incomplete file?", self)

    def __del__(self) -> None:
        if self.buffer is not None:
            self.buffer.close()
        if self.fh_file is not None:
            self.fh_file.close()

    def __repr__(self) -> str:
        timestamp = getattr(self, "start_time", None)
        return f"{self.__class__.__name__}: {self.path}, timestamp: {timestamp}"

    # -- iteration -------------------------------------------------------

    def __iter__(self) -> Iterator[MassscanStatus]:
        """Iterate over records in the binary file."""
        logger.debug("Parsing results from: %s", self.path)
        if self.buffer is None:
            return
        yield from self._iter_records()

    def _iter_records(self) -> Iterator[MassscanStatus]:
        """Internal record iteration logic."""
        assert self.buffer is not None
        offset = 99
        try:
            size = self.buffer.size()
            while offset < size - 99:
                rec_type = RecordStatus(self.buffer[offset])
                length_width = 2
                length = self.buffer[offset + 1]
                rec: MassscanStatus
                if rec_type in (RecordStatus.Open2, RecordStatus.Closed2, RecordStatus.Arp2):
                    assert length == 13
                    (timestamp, ip, ip_proto, port, reason, ttl) = struct.unpack_from(
                        ">LLBHBB", self.buffer, offset + 2
                    )
                    rec = ReasonStatus(
                        rec_type,
                        Timestamp(timestamp),
                        IPv4Address(ip),
                        InternetProtocol(ip_proto),
                        port,
                        ReasonFlags(reason),
                        ttl,
                    )
                elif rec_type == RecordStatus.Banner9:
                    if length >= 128:
                        length_width = 3
                        if self.buffer[offset + 2] > 0b01111111:
                            logger.warning("its happening")
                        length = ((self.buffer[offset + 1] & 0b01111111) << 7) | (self.buffer[offset + 2] & 0b01111111)

                    (timestamp, ip, ip_proto, port, app_proto, ttl) = struct.unpack_from(
                        ">LLBHHB",
                        self.buffer,
                        offset + length_width,
                    )
                    banner = (
                        self.buffer[offset + length_width + 14 : offset + length + length_width]
                        .decode("latin-1")
                        .rstrip("\x00")
                    )
                    rec = BannerStatus(
                        rec_type,
                        Timestamp(timestamp),
                        IPv4Address(ip),
                        InternetProtocol(ip_proto),
                        port,
                        ApplicationProtocol(app_proto),
                        ttl,
                        banner,
                    )
                else:
                    break

                offset += length + length_width
                yield rec
        except Exception as e:
            logger.warning("%s: %s @ %d", self, e, offset)

    @classmethod
    def iter_results_glob(cls, pattern: str) -> Iterator[MasscanReader]:
        """Iterate over masscan files matching a glob pattern.

        Args:
            pattern: Glob pattern for file paths.

        Yields:
            MasscanReader instances.
        """
        from glob import glob

        scan_files = glob(pattern)
        for n, scan_file in enumerate(reversed(sorted(scan_files))):
            logger.debug("%d of %d: %s", n, len(scan_files), scan_file)
            yield cls(scan_file)


# ------------------------------------------------------------------
# Module-level utility helpers
# ------------------------------------------------------------------

def filter_scan(
    scan_file: str | Path,
    port: int = 161,
    status: RecordStatus = RecordStatus(int(RecordStatus.Open2)),
) -> Iterator[MassscanStatus]:
    """Filter scan results for open hosts matching a port and status.

    Args:
        scan_file: Path to the masscan output file.
        port: Port number to filter on. Defaults to 161 (SNMP).
        status: Record status to filter on. Defaults to Open2.

    Yields:
        MassscanStatus objects for open hosts matching the criteria.
    """
    yield from filter(
        lambda obj: obj.status == status and obj.port == port,
        MasscanReader(scan_file),
    )