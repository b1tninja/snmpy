"""Integration tests for snmp.session.Session.

Runs against ``FakeSNMPAgent`` — a minimal v2c agent (one UDP socket on
127.0.0.1 + worker thread) that answers GET / GETNEXT / SET from a dict.
Exception values follow RFC 3416 §4.1.6 (noSuchInstance / endOfMibView).
"""

from __future__ import annotations

import socket
import threading
import unittest

from ber.enums import TagClassEnum
from ber.object import Integer, Object, ObjectTag, OctetString
from snmp.datagram import SNMPDatagram
from snmp.enums import SNMPVersion
from snmp.exceptions import SNMPTimeoutError
from snmp.factories import make_var_binds
from snmp.pdus import GetNextRequest, GetRequest, GetResponse, SetRequest
from snmp.session import Session
from snmp.values import exception_name

NO_SUCH_INSTANCE = Object(ObjectTag(TagClassEnum.context_specific, False, 1), b"")
END_OF_MIB_VIEW = Object(ObjectTag(TagClassEnum.context_specific, False, 2), b"")


def _key(oid: str) -> tuple[int, ...]:
    return tuple(int(p) for p in oid.split("."))


def make_mib() -> dict[str, Object]:
    """Static system-group MIB served by the fake agent."""
    return {
        "1.3.6.1.2.1.1.1.0": OctetString(b"FakeSNMP agent").get_object(),
        "1.3.6.1.2.1.1.3.0": Integer.from_int(123456).get_object(),
        "1.3.6.1.2.1.1.4.0": OctetString(b"ops@example.com").get_object(),
        "1.3.6.1.2.1.1.5.0": OctetString(b"fakebox").get_object(),
        "1.3.6.1.2.1.1.7.0": Integer.from_int(78).get_object(),
    }


class FakeSNMPAgent:
    """Threaded blocking-UDP mini agent serving one OID dict."""

    def __init__(self, mib: dict[str, Object]) -> None:
        self.mib = dict(mib)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
        self.port: int = self._sock.getsockname()[1]
        self._running = False
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> FakeSNMPAgent:
        self._running = True
        self._thread.start()
        return self

    def stop(self) -> None:
        self._running = False
        self._sock.close()
        self._thread.join(timeout=2)

    def __enter__(self) -> FakeSNMPAgent:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def _serve(self) -> None:
        while self._running:
            try:
                data, addr = self._sock.recvfrom(65535)
            except OSError:
                return
            reply = self._handle(data)
            if reply is not None:
                try:
                    self._sock.sendto(reply, addr)
                except OSError:
                    return

    def _handle(self, data: bytes) -> bytes | None:
        req = SNMPDatagram.decode(data)
        pdu = req.pdu
        pairs: list[tuple[str, Object]] = []
        if isinstance(pdu, GetRequest):
            for oid, _ in pdu.items():
                oid_s = str(oid)
                pairs.append((oid_s, self.mib.get(oid_s, NO_SUCH_INSTANCE)))
        elif isinstance(pdu, GetNextRequest):
            for oid, _ in pdu.items():
                oid_s = str(oid)
                nxt = min(
                    (k for k in self.mib if _key(k) > _key(oid_s)),
                    key=_key, default=None,
                )
                pairs.append((nxt or oid_s, self.mib[nxt] if nxt else END_OF_MIB_VIEW))
        elif isinstance(pdu, SetRequest):
            for oid, value in pdu.items():
                oid_s = str(oid)
                self.mib[oid_s] = value
                pairs.append((oid_s, value))
        else:
            return None
        if not pairs:
            return None
        resp = GetResponse(request_id=pdu.request_id,
                           variable_bindings=make_var_binds(pairs))
        datagram = SNMPDatagram(
            version=Integer.from_int(int(SNMPVersion.v2c)),
            community=OctetString(bytes(req.community.value)).get_object(),
            pdu=resp,
        )
        return bytes(datagram)


def _closed_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class TestSession(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.agent = FakeSNMPAgent(make_mib()).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.agent.stop()

    def setUp(self) -> None:
        self.session = Session(
            "127.0.0.1", port=self.agent.port,
            community="public", timeout=1.0, retries=2,
        ).open()
        self.addCleanup(self.session.close)

    def test_get_str_int_bytes(self) -> None:
        self.assertEqual(self.session.get_str("1.3.6.1.2.1.1.1.0"),
                         "FakeSNMP agent")
        self.assertEqual(self.session.get_int("1.3.6.1.2.1.1.7.0"), 78)
        self.assertEqual(self.session.get_bytes("1.3.6.1.2.1.1.5.0"),
                         b"fakebox")

    def test_get_accepts_pack_shorthand(self) -> None:
        self.assertEqual(self.session.get_int("mib2-system:sysServices"), 78)

    def test_get_missing_returns_exception_value(self) -> None:
        value = self.session.get("1.3.6.1.2.1.1.99.0")
        self.assertIsNotNone(value)
        self.assertEqual(exception_name(value), "noSuchInstance")
        with self.assertRaises(LookupError):
            self.session.get_str("1.3.6.1.2.1.1.99.0")

    def test_get_next(self) -> None:
        result = self.session.get_next("1.3.6.1.2.1.1.1.0")
        self.assertIsNotNone(result)
        oid_s, value = result  # type: ignore[misc]
        self.assertEqual(oid_s, "1.3.6.1.2.1.1.3.0")
        self.assertEqual(int.from_bytes(bytes(value.value), "big"), 123456)

    def test_walk_subtree(self) -> None:
        rows = self.session.walk("1.3.6.1.2.1.1")
        self.assertEqual([oid for oid, _ in rows], [
            "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0",
            "1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.5.0",
            "1.3.6.1.2.1.1.7.0",
        ])

    def test_walk_stop_oid(self) -> None:
        rows = self.session.walk("1.3.6.1.2.1.1", stop_oid="1.3.6.1.2.1.1.4.0")
        self.assertEqual([oid for oid, _ in rows],
                         ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0"])

    def test_walk_past_last_is_empty(self) -> None:
        self.assertEqual(self.session.walk("1.3.6.1.2.1.1.7.0"), [])

    def test_set_roundtrip(self) -> None:
        oid = "1.3.6.1.2.1.1.4.0"
        self.assertTrue(self.session.set(oid, "new@example.com"))
        self.assertEqual(self.session.get_str(oid), "new@example.com")
        status, index = self.session.set_result(oid, "ops@example.com")
        self.assertEqual((status, index), (0, 0))

    def test_get_many(self) -> None:
        rows = self.session.get_many(
            ["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.99.0"])
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][0], "1.3.6.1.2.1.1.5.0")
        self.assertEqual(exception_name(rows[1][1]), "noSuchInstance")

    def test_v1_session_works(self) -> None:
        with Session("127.0.0.1", port=self.agent.port,
                     version=SNMPVersion.v1, timeout=1.0, retries=2) as s:
            self.assertEqual(s.get_str("1.3.6.1.2.1.1.1.0"), "FakeSNMP agent")

    def test_timeout_raises(self) -> None:
        dead = Session("127.0.0.1", port=_closed_port(),
                       timeout=0.05, retries=1)
        with self.assertRaises(SNMPTimeoutError):
            dead.get("1.3.6.1.2.1.1.1.0")

    def test_context_manager_closes_socket(self) -> None:
        with Session("127.0.0.1", port=self.agent.port, timeout=1.0) as s:
            self.assertIsNotNone(s._sock)
        self.assertIsNone(s._sock)


if __name__ == "__main__":
    unittest.main()


