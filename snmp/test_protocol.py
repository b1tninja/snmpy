"""Tests for SNMPProtocol's SNMPv3 receive path (RFC 3414 §3.2 wiring).

SNMPProtocol previously fed every datagram through SNMPDatagram.decode, which
understands only the v1/v2c [version, community, pdu] framing — every v3
message was therefore logged as malformed and dropped, and the USM machinery
in MPv3 was unreachable from the transport.  These tests drive datagram_
received/_process_incoming with real encoded messages.
"""

from __future__ import annotations

import unittest

from snmp.mpm import (
    AUTH_FLAG,
    USM_STATS_UNKNOWN_USER_NAMES,
    USM_STATS_WRONG_DIGESTS,
    MPv3,
    SNMPv3Message,
    USMError,
)
from snmp.pdus import GetRequest
from snmp.protocol import SNMPProtocol
from snmp.scoped_pdu import ScopedPDU
from snmp.usm import (
    AuthProtocol,
    SecurityParameters,
    USMUser,
    USMUserDatabase,
    localize_passphrase,
)

ENGINE = bytes.fromhex("800000000042424242")
SYS_DESCR = "1.3.6.1.2.1.1.1.0"


def make_user_db(*usernames: str) -> USMUserDatabase:
    """A USM table of SHA-authNoPriv users sharing one passphrase."""
    db = USMUserDatabase()
    for name in usernames:
        db.add_user(
            USMUser(username=name, auth_protocol=AuthProtocol.SHA, auth_passphrase=name)
        )
    return db


def make_request_message(
    engine_id: bytes,
    username: str,
    passphrase: str,
    boots_time: tuple[int, int],
) -> SNMPv3Message:
    """An authNoPriv GetRequest for sysDescr.0 naming engine_id."""
    boots, engine_time = boots_time
    message = SNMPv3Message(msg_id=99, msg_flags=AUTH_FLAG)
    message.security_parameters = SecurityParameters(
        engine_id=engine_id,
        username=username,
        authentication_key=localize_passphrase(
            passphrase, engine_id, AuthProtocol.SHA
        ),
        auth_protocol="SHA",
    )
    message.security_parameters.engine_boots = boots
    message.security_parameters.engine_time = engine_time
    message.scoped_pdu = ScopedPDU(
        context_engine_id=b"", context_name="", pdu=GetRequest.from_oid(SYS_DESCR)
    )
    return message


def make_discovery_message() -> SNMPv3Message:
    """An engineID discovery request (RFC 3414 §2.6.1, §4)."""
    message = SNMPv3Message(msg_id=1)
    message.security_parameters = SecurityParameters(engine_id=b"", username="")
    message.scoped_pdu = ScopedPDU(
        context_engine_id=b"", context_name="", pdu=GetRequest.from_oid(SYS_DESCR)
    )
    return message


class TestV3Receive(unittest.TestCase):
    def setUp(self) -> None:
        self.protocol = SNMPProtocol(
            engine_id=ENGINE, user_db=make_user_db("maplesyrup")
        )
        self.mpv3 = self.protocol.message_processor.mpv3

    def encode_with(self, message: SNMPv3Message, engine_id: bytes = ENGINE) -> bytes:
        """Encode with a client-side MPv3 sharing the engine ID."""
        return MPv3(engine_id).encode(message)

    def test_discovery_is_not_dropped(self) -> None:
        """A noAuthNoPriv discovery request reaches USM and passes (§3.2 3a)."""
        raw = self.encode_with(make_discovery_message())
        datagram = self.protocol._process_incoming(raw, ("127.0.0.1", 161))
        self.assertIsInstance(datagram.pdu, GetRequest)

    def test_authenticated_request_is_delivered(self) -> None:
        """A correctly signed request for a known user is accepted (§3.2 4-7)."""
        boots_time = self.mpv3.engine_time_source()
        raw = self.encode_with(
            make_request_message(ENGINE, "maplesyrup", "maplesyrup", boots_time)
        )
        datagram = self.protocol._process_incoming(raw, ("127.0.0.1", 161))
        self.assertIsInstance(datagram.pdu, GetRequest)

    def test_unknown_user_raises_usm_error(self) -> None:
        """A valid message naming no user fails with the unknownUsers stat."""
        boots_time = self.mpv3.engine_time_source()
        raw = self.encode_with(
            make_request_message(ENGINE, "nobody", "nobody", boots_time)
        )
        with self.assertRaises(USMError) as caught:
            self.protocol._process_incoming(raw, ("127.0.0.1", 161))
        self.assertEqual(caught.exception.stat, USM_STATS_UNKNOWN_USER_NAMES)

    def test_forged_mac_raises_usm_error(self) -> None:
        """A message signed with the wrong key fails with wrongDigests (§3.2 6)."""
        boots_time = self.mpv3.engine_time_source()
        raw = self.encode_with(
            make_request_message(ENGINE, "maplesyrup", "wrongpass", boots_time)
        )
        with self.assertRaises(USMError) as caught:
            self.protocol._process_incoming(raw, ("127.0.0.1", 161))
        self.assertEqual(caught.exception.stat, USM_STATS_WRONG_DIGESTS)

    def test_engine_time_window_rejects_stale_time(self) -> None:
        """A far-past engineTime fails with the notInTimeWindows stat (§3.2 7a)."""
        # Pin the local clock: the default one starts near 0, so a clamped
        # "stale" value would still land inside the window of a fresh engine.
        self.mpv3.engine_time_source = lambda: (7, 5000)
        raw = self.encode_with(
            make_request_message(ENGINE, "maplesyrup", "maplesyrup", (7, 3500))
        )
        with self.assertRaises(USMError) as caught:
            self.protocol._process_incoming(raw, ("127.0.0.1", 161))
        self.assertIn("time window", str(caught.exception))


class TestDatagramReceivedV3(unittest.TestCase):
    """datagram_received must route v3 by USM outcome, not crash (§2.5.2)."""

    def setUp(self) -> None:
        self.protocol = SNMPProtocol(
            engine_id=ENGINE, user_db=make_user_db("maplesyrup")
        )
        self.mpv3 = self.protocol.message_processor.mpv3

    def test_security_failure_is_discarded_quietly(self) -> None:
        """A forged message on port 161 is dropped without raising."""
        boots_time = self.mpv3.engine_time_source()
        forged = MPv3(ENGINE).encode(
            make_request_message(ENGINE, "maplesyrup", "wrongpass", boots_time)
        )
        before = self.mpv3.stats[USM_STATS_WRONG_DIGESTS]
        self.protocol.datagram_received(forged, ("127.0.0.1", 161))
        self.assertEqual(self.mpv3.stats[USM_STATS_WRONG_DIGESTS], before + 1)

    def test_valid_v3_is_not_reported_malformed(self) -> None:
        """A good discovery message survives datagram_received intact."""
        raw = MPv3(ENGINE).encode(make_discovery_message())
        self.protocol.datagram_received(raw, ("127.0.0.1", 161))
        self.assertEqual(sum(self.mpv3.stats.values()), 0)


if __name__ == "__main__":
    unittest.main()

