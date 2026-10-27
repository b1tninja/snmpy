"""Unit tests for the SNMPv3 Message Processing Model (snmp.mpm).

RFC 3412 §7.1 fixes the SNMPv3Message frame, RFC 3414 §2.4 and §A.4 fix the
USM contents of msgSecurityParameters, and RFC 3414 §6.3.1/§7.3.1 (read with
Errata 278) plus RFC 7860 §4 define the MAC: a digest over the complete
message with msgAuthenticationParameters replaced by zero octets.

Every expectation below is either a published sample value or a structural
fact stated by those documents — no third-party encoder is trusted.
"""

from __future__ import annotations

import unittest
from importlib.util import find_spec

from ber.object import Object
from snmp.auth import calculate_mic
from snmp.enums import SNMPVersion
from snmp.exceptions import SNMPProtocolError
from snmp.mpm import (
    AUTH_FLAG,
    DEFAULT_TIME_WINDOW,
    PRIV_FLAG,
    REPORTABLE_FLAG,
    USM_STATS_NOT_IN_TIME_WINDOWS,
    USM_STATS_UNKNOWN_ENGINE_IDS,
    USM_STATS_UNKNOWN_USER_NAMES,
    USM_STATS_WRONG_DIGESTS,
    MessageProcessor,
    MPv3,
    SNMPv3Message,
    USMError,
    split_message_mic,
)
from snmp.pdus import PDU, GetRequest
from snmp.privacy import (
    PrivacyContext,
    PrivacyError,
    localize_privacy_key,
    resolve_auth_protocol,
)
from snmp.scoped_pdu import ScopedPDU
from snmp.usm import (
    AuthProtocol,
    SecurityParameters,
    USMUser,
    USMUserDatabase,
    localize_passphrase,
)

requires_crypto = unittest.skipUnless(
    find_spec("cryptography") is not None, "requires the cryptography package"
)

# RFC 3414 §A.3 sample credentials.  The key derivation itself is pinned by
# test_usm.py, so these tests may build on localize_passphrase().
ENGINE = bytes.fromhex("000000000000000000000002")
PASSPHRASE = "maplesyrup"
SYS_DESCR = "1.3.6.1.2.1.1.1.0"

# RFC 3414 §A.4 sample msgSecurityParameters.  The RFC's own length octets
# are self-inconsistent: it prints 04 0c for the 9 octets of engine ID it
# shows, and 30 37 / 04 39 for a SEQUENCE that those values only fill with 48
# octets.  What is asserted here is therefore the normative part -- the §2.4
# field list, in order, carrying the documented values: the IBM engine ID for
# 9.132.3.1, boots 1, time 257, user "bert", a 12-octet MAC, an 8-octet salt.
A4_ENGINE_ID = bytes.fromhex("800000020109840301")
A4_MAC = bytes.fromhex("0123456789abcdeffedcba98")
A4_PRIV = bytes.fromhex("0123456789abcdef")
A4_SEQUENCE = (
    "3030"  # SEQUENCE, 48 octets of content
    + "0409" + A4_ENGINE_ID.hex()  # msgAuthoritativeEngineID
    + "020101"  # msgAuthoritativeEngineBoots = 1
    + "02020101"  # msgAuthoritativeEngineTime = 257
    + "040462657274"  # msgUserName = "bert"
    + "040c" + A4_MAC.hex()  # msgAuthenticationParameters
    + "0408" + A4_PRIV.hex()  # msgPrivacyParameters
)


def children(obj: Object) -> list[Object]:
    """Return the sub-objects of a constructed BER object."""
    assert isinstance(obj.value, list)
    return obj.value


def value_bytes(obj: Object) -> bytes:
    """Return the value octets of a primitive BER object."""
    assert isinstance(obj.value, bytes)
    return obj.value


def make_scoped(context_engine_id: bytes = b"") -> ScopedPDU:
    """A GetRequest for sysDescr.0 wrapped in a ScopedPDU (RFC 3411 §3.3.4)."""
    return ScopedPDU(
        context_engine_id=context_engine_id,
        context_name="",
        pdu=GetRequest.from_oid(SYS_DESCR),
    )


def requested_oids(pdu: object) -> list[str]:
    """The OIDs a request PDU asks for, as dotted strings.

    A PDU exposes its variable bindings as a dict keyed by ObjectIdentifier,
    and that hash is the OID's integer tuple — so membership has to be tested
    on the string form of the keys, not with a plain str key.
    """
    if isinstance(pdu, PDU):
        return [str(oid) for oid in pdu.keys()]
    return [str(oid) for oid in GetRequest.from_object(pdu).keys()]


class TestSecurityParametersWireFormat(unittest.TestCase):
    """RFC 3414 §2.4: six USM fields, in order, with their BER types."""

    def setUp(self) -> None:
        self.params = SecurityParameters(
            engine_id=A4_ENGINE_ID,
            engine_boots=1,
            engine_time=257,
            username="bert",
            mac=A4_MAC,
            priv_parameters=A4_PRIV,
        )

    def test_encoding_matches_the_rfc_a4_sample(self) -> None:
        self.assertEqual(bytes(self.params.encode()).hex(), A4_SEQUENCE)

    def test_decoding_the_rfc_a4_sample(self) -> None:
        decoded = SecurityParameters.decode(bytes.fromhex(A4_SEQUENCE))
        self.assertEqual(decoded.engine_id, A4_ENGINE_ID)
        self.assertEqual(decoded.engine_boots, 1)
        self.assertEqual(decoded.engine_time, 257)
        self.assertEqual(decoded.username, "bert")
        self.assertEqual(decoded.mac, A4_MAC)
        self.assertEqual(decoded.priv_parameters, A4_PRIV)

    def test_empty_fields_round_trip(self) -> None:
        # Engine-ID discovery uses an empty engine ID, user name, MAC and
        # privacy parameter (RFC 3414 §2.4, §4).
        decoded = SecurityParameters.decode(SecurityParameters().encode())
        self.assertEqual(decoded.engine_id, b"")
        self.assertEqual(decoded.username, "")
        self.assertEqual(decoded.mac, b"")
        self.assertEqual(decoded.priv_parameters, b"")


class TestMPv3Encode(unittest.TestCase):
    """RFC 3412 §7.1 framing plus the RFC 3414 §2.5.1 generation steps."""

    def setUp(self) -> None:
        self.mpm = MPv3(ENGINE)
        self.auth_key = localize_passphrase(PASSPHRASE, ENGINE, AuthProtocol.SHA)

    def auth_message(self, protocol: str = "SHA") -> SNMPv3Message:
        message = SNMPv3Message(msg_id=42, msg_flags=AUTH_FLAG)
        message.security_parameters = SecurityParameters(
            engine_id=ENGINE,
            engine_boots=0,
            engine_time=0,
            username=PASSPHRASE,
            authentication_key=localize_passphrase(
                PASSPHRASE, ENGINE, resolve_auth_protocol(protocol)
            ),
            auth_protocol=protocol,
        )
        message.scoped_pdu = make_scoped(ENGINE)
        return message

    def test_discovery_message_frame(self) -> None:
        # A noAuthNoPriv message with an empty user name is the engine-ID
        # discovery request of RFC 3414 §4.
        message = SNMPv3Message(msg_id=1, msg_max_size=1024)
        message.security_parameters = SecurityParameters()
        message.scoped_pdu = make_scoped()

        raw = self.mpm.encode(message)
        outer, end = Object.decode(raw, 0)
        self.assertEqual(end, len(raw))

        fields = children(outer)
        self.assertEqual(len(fields), 4)
        # msgVersion takes the SNMPv1/v2c slot so a parser can branch (RFC 3412 §5.1).
        self.assertEqual(int(fields[0]), 3)
        global_data = children(fields[1])
        self.assertEqual(int(global_data[0]), 1)  # msgID
        self.assertEqual(int(global_data[1]), 1024)  # msgMaxSize
        self.assertEqual(value_bytes(global_data[2]), bytes([REPORTABLE_FLAG]))
        self.assertEqual(int(global_data[3]), 3)  # msgSecurityModel = USM
        # msgSecurityParameters is an opaque OCTET STRING holding the SEQUENCE.
        self.assertEqual(SecurityParameters.decode(value_bytes(fields[2])).username, "")
        # Unencrypted msgData is the ScopedPDU itself, not an OCTET STRING.
        self.assertTrue(fields[3].tag.is_constructed)
        scoped = children(fields[3])
        self.assertEqual(scoped[2].tag.tag_id, 0)  # GetRequest
        self.assertIn(SYS_DESCR, requested_oids(scoped[2]))

    def test_auth_no_priv_message_authenticates(self) -> None:
        message = self.auth_message()
        raw = self.mpm.encode(message)

        mac, zeroed = split_message_mic(raw)
        self.assertEqual(len(mac), 12)  # RFC 3414 §7.3.1
        self.assertEqual(mac, message.security_parameters.mac)
        self.assertEqual(len(zeroed), len(raw))
        differing = sum(1 for a, b in zip(raw, zeroed, strict=True) if a != b)
        self.assertLessEqual(differing, len(mac))
        # The placeholder must already carry the MAC's length while hashing.
        self.assertIn(bytes([0x04, len(mac)]) + mac, raw)
        self.assertIn(bytes([0x04, len(mac)]) + bytes(len(mac)), zeroed)
        self.assertEqual(mac, calculate_mic(zeroed, self.auth_key, "CBC-SHA-96"))
        self.assertTrue(self.mpm.verify_message_mic(raw, self.auth_key, "SHA"))

    def test_authentication_rejects_forgery(self) -> None:
        raw = self.mpm.encode(self.auth_message())
        self.assertFalse(self.mpm.verify_message_mic(raw, bytes(20), "SHA"))
        tampered = bytearray(raw)
        tampered[-1] ^= 0x01
        self.assertFalse(self.mpm.verify_message_mic(bytes(tampered), self.auth_key, "SHA"))

    def test_mac_length_follows_the_protocol(self) -> None:
        # RFC 3414 §6.3.1/§7.3.1 truncate to 12 octets, RFC 7860 §4 to 16/24/32/48.
        expected = {"MD5": 12, "SHA": 12, "SHA224": 16, "SHA256": 24, "SHA384": 32, "SHA512": 48}
        for protocol, length in expected.items():
            with self.subTest(protocol=protocol):
                raw = self.mpm.encode(self.auth_message(protocol))
                mac, _ = split_message_mic(raw)
                self.assertEqual(len(mac), length)

    @requires_crypto
    def test_auth_priv_message(self) -> None:
        priv_key = localize_privacy_key(PASSPHRASE, ENGINE, "AES128", AuthProtocol.SHA)
        message = SNMPv3Message(msg_id=7, msg_flags=AUTH_FLAG | PRIV_FLAG)
        message.security_parameters = SecurityParameters(
            engine_id=ENGINE,
            engine_boots=1,
            engine_time=257,
            username=PASSPHRASE,
            authentication_key=self.auth_key,
            auth_protocol="SHA",
            privacy_key=priv_key,
            priv_protocol="AES128",
        )
        message.scoped_pdu = make_scoped(ENGINE)
        plaintext = message.scoped_pdu.encode()

        raw = self.mpm.encode(message)
        decoded = self.mpm.decode(raw)

        self.assertEqual(decoded.msg_flags, AUTH_FLAG | PRIV_FLAG | REPORTABLE_FLAG)
        self.assertTrue(decoded.is_encrypted)
        self.assertIsNone(decoded.scoped_pdu)
        self.assertEqual(decoded.security_parameters.engine_boots, 1)
        self.assertEqual(decoded.security_parameters.engine_time, 257)
        self.assertEqual(len(decoded.security_parameters.priv_parameters), 8)  # AES salt
        self.assertNotIn(plaintext[:16], raw)
        # The AES IV embeds the authoritative boots/time plus the transmitted
        # salt (RFC 3826 §3.3.1), so decrypting proves both travelled correctly.
        recovered = PrivacyContext("AES128", priv_key, engine_boots=1, engine_time=257).decrypt(
            decoded.encrypted_data, decoded.security_parameters.priv_parameters
        )
        self.assertEqual(recovered, plaintext)
        self.assertTrue(self.mpm.verify_message_mic(raw, self.auth_key, "SHA"))

    def test_missing_keys_are_rejected(self) -> None:
        unauthenticated = SNMPv3Message(msg_id=1, msg_flags=AUTH_FLAG)
        unauthenticated.security_parameters = SecurityParameters(username="bert", auth_protocol="SHA")
        unauthenticated.scoped_pdu = make_scoped()
        with self.assertRaises(ValueError):
            self.mpm.encode(unauthenticated)

        unencrypted = SNMPv3Message(msg_id=1, msg_flags=AUTH_FLAG | PRIV_FLAG)
        unencrypted.security_parameters = SecurityParameters(
            username="bert",
            authentication_key=self.auth_key,
            auth_protocol="SHA",
            priv_protocol="AES128",
        )
        unencrypted.scoped_pdu = make_scoped()
        with self.assertRaises(ValueError):
            self.mpm.encode(unencrypted)

    def test_unknown_auth_protocol_is_rejected(self) -> None:
        message = self.auth_message("SHA")
        assert message.security_parameters is not None
        message.security_parameters.auth_protocol = "RC4"
        with self.assertRaises(PrivacyError):
            self.mpm.encode(message)


class TestMPv3Decode(unittest.TestCase):
    """RFC 3414 §2.5.2: reading an incoming message back."""

    def setUp(self) -> None:
        self.mpm = MPv3(ENGINE)

    def test_reads_flags_and_counters(self) -> None:
        # msgFlags is an OCTET STRING — the old int(b"\x01") raised TypeError.
        message = SNMPv3Message(msg_id=4242, msg_max_size=2048, msg_flags=AUTH_FLAG)
        message.security_parameters = SecurityParameters(
            engine_id=A4_ENGINE_ID,
            engine_boots=1,
            engine_time=257,
            username="bert",
            authentication_key=bytes(20),
            auth_protocol="SHA",
        )
        message.scoped_pdu = make_scoped()

        decoded = self.mpm.decode(self.mpm.encode(message))

        self.assertEqual(decoded.msg_version, 3)
        self.assertEqual(decoded.msg_id, 4242)
        self.assertEqual(decoded.msg_max_size, 2048)
        self.assertEqual(decoded.msg_flags, AUTH_FLAG | REPORTABLE_FLAG)
        self.assertEqual(decoded.security_level, 1)
        self.assertTrue(decoded.reportable)
        self.assertTrue(decoded.is_authentication_enabled)
        self.assertFalse(decoded.is_privacy_enabled)
        self.assertEqual(decoded.msg_security_model, 3)
        params = decoded.security_parameters
        assert params is not None
        self.assertEqual(params.engine_id, A4_ENGINE_ID)
        self.assertEqual(params.engine_boots, 1)
        self.assertEqual(params.engine_time, 257)
        self.assertEqual(params.username, "bert")
        self.assertEqual(len(params.mac), 12)
        assert decoded.scoped_pdu is not None and decoded.scoped_pdu.pdu is not None
        self.assertIn(SYS_DESCR, requested_oids(decoded.scoped_pdu.pdu))

    def test_decode_promotes_scoped_pdu_to_typed_pdu(self) -> None:
        """msgData must decode to a PDU, not a raw BER Object.

        ``SNMPDatagram.decode`` promotes v1/v2c PDUs to typed classes that
        iterate as variable bindings; ScopedPDU decoding used to leave the raw
        Object, so the same varbind loop silently walked the PDU's four BER
        fields over v3 instead.
        """
        message = SNMPv3Message(msg_id=5150, msg_flags=AUTH_FLAG)
        message.security_parameters = SecurityParameters(
            engine_id=A4_ENGINE_ID,
            username="bert",
            authentication_key=localize_passphrase(
                PASSPHRASE, A4_ENGINE_ID, resolve_auth_protocol("SHA")
            ),
            auth_protocol="SHA",
        )
        message.scoped_pdu = make_scoped(A4_ENGINE_ID)

        decoded = self.mpm.decode(self.mpm.encode(message))
        assert decoded.scoped_pdu is not None
        pdu = decoded.scoped_pdu.pdu

        self.assertIsInstance(pdu, PDU)
        pairs = list(pdu)
        self.assertEqual([str(oid) for oid, _value in pairs], [SYS_DESCR])
        self.assertIn(SYS_DESCR, requested_oids(pdu))

    def test_message_processor_routes_v3(self) -> None:
        """A v3 datagram reaches MPv3 and comes back fully authenticated."""
        message = SNMPv3Message(msg_id=99, msg_flags=AUTH_FLAG)
        message.security_parameters = SecurityParameters(
            engine_id=ENGINE,
            username="bert",
            authentication_key=bytes(20),
            auth_protocol="MD5",
        )
        message.scoped_pdu = make_scoped()
        raw = self.mpm.encode(message)

        users = USMUserDatabase()
        users.add_user(
            USMUser("bert", auth_protocol=AuthProtocol.MD5, auth_key=bytes(20))
        )
        processed = MessageProcessor(ENGINE, users).process_incoming(
            raw, SNMPVersion.v3
        )
        assert isinstance(processed, SNMPv3Message)
        self.assertEqual(processed.msg_id, 99)
        self.assertTrue(processed.is_authentication_enabled)

    def test_rejects_truncated_messages(self) -> None:
        for bad in (b"", b"\x30\x00", bytes.fromhex("3005020103"), bytes.fromhex("3003020100")):
            with self.subTest(raw=bad.hex()):
                with self.assertRaises(SNMPProtocolError):
                    self.mpm.decode(bad)

    def test_split_mic_rejects_truncated_messages(self) -> None:
        with self.assertRaises(SNMPProtocolError):
            split_message_mic(bytes.fromhex("3003020100"))


class TestUSMIncomingProcessing(unittest.TestCase):
    """RFC 3414 §3.2: the checks an engine must make before acting on a message.

    These pin the security properties rather than the encoding: a message must
    name this engine, name a known user, carry a MAC that verifies, and fall
    inside the time window — and each failure must raise with the usmStats
    counter a Report PDU would name.
    """

    USER = "maplesyrup"

    def setUp(self) -> None:
        self.auth_key = localize_passphrase(PASSPHRASE, ENGINE, AuthProtocol.SHA)
        users = USMUserDatabase()
        users.add_user(
            USMUser(self.USER, auth_protocol=AuthProtocol.SHA, auth_key=self.auth_key)
        )
        self.mpm = MPv3(ENGINE, users)

    def request(
        self,
        *,
        username: str | None = None,
        engine_id: bytes = ENGINE,
        boots: int = 0,
        engine_time: int = 0,
        key: bytes | None = None,
    ) -> bytes:
        """An authenticated GetRequest for sysDescr.0, as it would be on the wire."""
        message = SNMPv3Message(msg_id=7, msg_flags=AUTH_FLAG)
        message.security_parameters = SecurityParameters(
            engine_id=engine_id,
            username=self.USER if username is None else username,
            authentication_key=self.auth_key if key is None else key,
            auth_protocol="SHA",
            engine_boots=boots,
            engine_time=engine_time,
        )
        message.scoped_pdu = make_scoped(engine_id)
        return self.mpm.encode(message)

    def test_accepts_and_authenticates_request(self) -> None:
        message = self.mpm.process_incoming(self.request())
        assert message.scoped_pdu is not None
        self.assertEqual(requested_oids(message.scoped_pdu.pdu), [SYS_DESCR])
        assert message.security_parameters is not None
        self.assertEqual(message.security_parameters.username, self.USER)

    def test_engine_id_discovery_is_accepted_unauthenticated(self) -> None:
        """§3.2 step 3: an empty engine ID and user name must reach the caller.

        This is the only noAuthNoPriv request that may proceed, and it is what
        lets a client learn our engine ID.
        """
        message = SNMPv3Message(msg_id=8)
        message.security_parameters = SecurityParameters()
        message.scoped_pdu = make_scoped()
        processed = self.mpm.process_incoming(self.mpm.encode(message))
        assert processed.security_parameters is not None
        self.assertEqual(processed.security_parameters.engine_id, b"")

    def _assert_fails(self, raw: bytes, stat: str) -> None:
        """The message must be rejected and the matching usmStats counted."""
        before = self.mpm.stats[stat]
        with self.assertRaises(USMError) as caught:
            self.mpm.process_incoming(raw)
        self.assertEqual(caught.exception.stat, stat)
        self.assertEqual(self.mpm.stats[stat], before + 1)

    def test_rejects_unknown_user(self) -> None:
        self._assert_fails(self.request(username="nobody"), USM_STATS_UNKNOWN_USER_NAMES)

    def test_rejects_forged_mac(self) -> None:
        """A message carrying a valid user but a MAC nobody computed is refused."""
        self._assert_fails(
            self.request(key=bytes(20)), USM_STATS_WRONG_DIGESTS
        )

    def test_rejects_request_for_another_engine(self) -> None:
        other = bytes.fromhex("800000020109840301")
        self._assert_fails(
            self.request(engine_id=other), USM_STATS_UNKNOWN_ENGINE_IDS
        )

    def test_rejects_stale_engine_time(self) -> None:
        """§3.2 step 7a: boots must match and time be within the window."""
        self._assert_fails(self.request(engine_time=10_000), USM_STATS_NOT_IN_TIME_WINDOWS)

    def test_authoritative_window_accepts_current_time(self) -> None:
        mpm = MPv3(ENGINE, engine_time_source=lambda: (3, 50_000))
        params = SecurityParameters(
            engine_id=ENGINE, engine_boots=3, engine_time=50_000 + DEFAULT_TIME_WINDOW
        )
        mpm._check_time_window(params, authoritative=True)
        params.engine_time += 1
        with self.assertRaises(USMError):
            mpm._check_time_window(params, authoritative=True)

    def test_peer_clock_rejects_replay(self) -> None:
        """§3.2 step 7b: as a client, an older message from a peer is refused.

        Note the limit of what step 7 can do: it compares against the newest
        (boots, time) pair seen, with no per-message cache, so an exact replay
        of the most recent message is indistinguishable from the original here.
        Discarding such a duplicate is the job of the request-id matching in the
        PDU layer (RFC 3412 §7).  Anything that the peer's clock has since
        moved past — an older boot, or a stale time within the current boot —
        is caught.
        """
        peer = bytes.fromhex("800000020109840301")
        mpm = MPv3(ENGINE)

        def params(boots: int, engine_time: int) -> SecurityParameters:
            return SecurityParameters(
                engine_id=peer, engine_boots=boots, engine_time=engine_time
            )

        mpm._check_time_window(params(1, 500), authoritative=False)
        mpm._check_time_window(params(1, 900), authoritative=False)
        mpm._check_time_window(params(2, 40), authoritative=False)

        # A message from the superseded boot, even with a larger engineTime.
        with self.assertRaises(USMError):
            mpm._check_time_window(params(1, 900), authoritative=False)
        # Same boot, but 200 seconds behind the newest value seen.
        with self.assertRaises(USMError):
            mpm._check_time_window(params(2, 40 - 200), authoritative=False)
        # The newest pair itself is accepted: not this layer's decision.
        mpm._check_time_window(params(2, 40), authoritative=False)
