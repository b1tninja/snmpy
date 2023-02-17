import ctypes
import itertools
import logging
import mmap
import struct
from argparse import ArgumentParser
from datetime import datetime
from enum import IntEnum
from glob import glob
from ipaddress import IPv4Address

import snmp.mib

logging.basicConfig(level=logging.INFO)


class Timestamp(int):
    def __repr__(self):
        return datetime.fromtimestamp(self).isoformat()


class CustomIntEnum(IntEnum):
    def __str__(self):
        return self.name


class RecordStatus(CustomIntEnum):
    Open = 1
    Closed = 2
    Banner1 = 5
    Open2 = 6
    Closed2 = 7
    Arp2 = 8
    Banner9 = 9,


class InternetProtocol(CustomIntEnum):
    ARP = 0
    ICMP = 1
    TCP = 6
    UDP = 17
    SCTP = 132


class ApplicationProtocol(CustomIntEnum):
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
    labels = []

    def __init__(self, value):
        assert isinstance(value, int)
        # TODO: support list of labels -> int
        self.value = value
        super().__init__(list(self))

    def __int__(self):
        return self.value

    def __iter__(self):
        n = 1
        i = 0
        while n <= self.value:
            if self.value & n:
                yield self.labels[i] if len(self.labels) > i and self.labels[i] else hex(n)
            i += 1
            n = 1 << i


class ReasonFlags(Bitset):
    labels = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR']


class MassscanStatus(object):
    status: RecordStatus
    timesamp: Timestamp
    ip: IPv4Address
    ip_proto: InternetProtocol
    port: int
    ttl: int

    def __init__(self, status, timestamp, ip, ip_proto, port, ttl):
        self.status = status  # TODO: make more consistent with other args
        self.timestamp = Timestamp(timestamp)
        self.ip = IPv4Address(ip)
        self.ip_proto = InternetProtocol(ip_proto)
        self.port = port
        self.ttl = ttl

    def __repr__(self):
        return '%s: %s' % (self.__class__.__name__, self.__dict__)


class ReasonStatus(MassscanStatus):
    reason: ReasonFlags

    def __init__(self, status, timestamp, ip, ip_proto, port, reason, ttl):
        super(ReasonStatus, self).__init__(status, timestamp, ip, ip_proto, port, ttl)
        self.reason = ReasonFlags(reason)


class BannerStatus(MassscanStatus):
    def __init__(self, status, timestamp, ip, ip_proto, port, app_proto, ttl, banner):
        super(BannerStatus, self).__init__(status, timestamp, ip, ip_proto, port, ttl)
        self.app_proto = ApplicationProtocol(app_proto)
        self.banner = banner


class MasscanReader:
    compat_version = b'masscan/1.1'

    def __init__(self, path):
        self.path = path
        self.fh = None
        self.buffer = None
        try:
            fh = open(path, 'rb')
            buffer = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        except Exception as e:
            logging.critical(e)
        else:
            self.fh = fh
            self.buffer = buffer
            # Read the header of the file and asses compatability
            headers = buffer[0:100].rstrip(b"\x00").split()

            assert headers[0].startswith(self.compat_version)
            self.version = headers[0]

            for header in headers[1:]:
                header = ctypes.create_string_buffer(header).value.decode()
                if ':' in header:
                    (header_type, value) = tuple(header.split(':', 1))
                    if header_type == 's':
                        # Not sure if this is intended to be a generic string or indication of start time
                        self.start_time = datetime.fromtimestamp(int(value))
                elif header:
                    logging.warning("%s: has unknown header: %s", self, header)
                    # TODO: parse other headers?

            footers = buffer[buffer.size() - 99:].rstrip(b"\x00").split(b"\n")
            if footers[0] == self.compat_version:
                self.footers = footers
            else:
                logging.warning("%s: has an invalid footer, incomplete file?", self)

    def __del__(self):
        if self.buffer:
            self.buffer.close()
        if self.fh:
            self.fh.close()

    def __repr__(self):
        return "%s: %s, timestamp: %s" % (self.__class__.__name__, self.path, self.start_time)

    def __iter__(self):
        logging.debug("Parsing results from: %s", self.path)
        offset = 99
        try:
            size = self.buffer.size()
            while offset < size - 99:
                status = RecordStatus(self.buffer[offset])
                length_width = 2
                length = self.buffer[offset + 1]
                if status in [RecordStatus.Open2, RecordStatus.Closed2, RecordStatus.Arp2]:
                    assert length == 13
                    (timestamp, ip, ip_proto, port, reason, ttl) = struct.unpack_from('>LLBHBB', self.buffer,
                                                                                      offset + 2)
                    status = ReasonStatus(status, timestamp, ip, ip_proto, port, reason, ttl)
                elif status == RecordStatus.Banner9:
                    if length >= 128:
                        length_width = 3
                        if self.buffer[offset + 2] > 0b01111111:
                            logging.warning("its happening")  # TODO: test this
                        length = ((self.buffer[offset + 1] & 0b01111111) << 7) | \
                                 (self.buffer[offset + 2] & 0b01111111)

                    (timestamp, ip, ip_proto, port, app_proto, ttl) = struct.unpack_from('>LLBHHB',
                                                                                         self.buffer,
                                                                                         offset + length_width)
                    banner = self.buffer[offset + length_width + 14:offset + length + length_width].decode('latin-1')
                    status = BannerStatus(status, timestamp, ip, ip_proto, port, app_proto, ttl, banner)
                else:
                    break

                offset += length + length_width
                yield status
        except Exception as e:
            logging.warning('%s: %s @ ', self, e, offset)

    @classmethod
    def iter_results_glob(cls, pattern):
        scan_files = glob(pattern)
        for n, scan_file in enumerate(reversed(sorted(scan_files))):
            logging.debug("%d of %d: %s", n, len(scan_files), scan_file)
            yield cls(scan_file)


def get_open_ips(scan_file):
    logging.debug("Iterating over open ips found in: %s", scan_file)
    # yield from map(lambda r: r.ip.exploded, filter(lambda obj: obj.status == RecordStatus.Open2 and obj.port == 161, MasscanReader(scan_file)))
    for result in filter(lambda obj: obj.status == RecordStatus.Open2 and obj.port == 161, MasscanReader(scan_file)):
        result: MassscanStatus
        yield result.ip.exploded


def chunks(iterable, size):
    it = iter(iterable)
    chunk = tuple(itertools.islice(it, size))
    while chunk:
        yield chunk
        chunk = tuple(itertools.islice(it, size))


import asyncio
import logging

from snmp import DEFAULT_PORT
from snmp.protocol import SNMPProtocol


def get(host='127.0.0.1', oid=snmp.mib.sysDescr, port=DEFAULT_PORT):
    loop = asyncio.get_event_loop()
    snmp_protocol_startup_task = loop.create_datagram_endpoint(SNMPProtocol, local_addr=('0.0.0.0', 0))
    transport, protocol = loop.run_until_complete(snmp_protocol_startup_task)
    assert isinstance(protocol, SNMPProtocol)
    try:
        task = asyncio.wait_for(protocol.get_next(host, oid=oid), timeout=5)
        result = loop.run_until_complete(task)
        return result
    except asyncio.TimeoutError:
        print("Task timed out...")
    else:
        print("Done, result: ", result)

async def get_oid_from_scan(oid, scan_file):
    # for ips in chunks(get_open_ips(scan_file), 25):
    tasks = []
    n = 100
    # TODO: figure out a proper semaphore, this could run away...
    # TODO: timeouts
    for ips in chunks(get_open_ips(scan_file), n):
        tasks.extend(map(lambda ip: protocol.get_next(ip, oid=snmp.mib.sysDescr), ips))

        finished, unfinished = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

        for task in finished:
            pdu = task.result()
            if pdu:
                pdu: snmp.protocol.SNMPDatagram
                response = pdu.value[2]
                response: snmp.protocol.GetResponse
                print(response)

        tasks = list(unfinished)

if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('path', help='Masscan files')
    args = parser.parse_args()
    scan_files = glob(args.path)
    # ips = set(itertools.chain(*map(get_open_ips, glob(args.path))))

    loop = asyncio.get_event_loop()
    snmp_protocol_startup_task = loop.create_datagram_endpoint(SNMPProtocol, local_addr=('0.0.0.0', 0))
    transport, protocol = loop.run_until_complete(snmp_protocol_startup_task)

    for scan_file in glob(args.path):
        loop.run_until_complete(get_oid_from_scan(snmp.mib.sysDescr, scan_file))
