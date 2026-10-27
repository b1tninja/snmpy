"""Unit tests for snmp.privacy (RFC 3414 §8, RFC 3826, RFC 7860 §2.2)."""

from __future__ import annotations

import unittest
from importlib.util import find_spec

from snmp.privacy import (
    AES_BLOCK_SIZE,
    DES_BLOCK_SIZE,
    PrivacyContext,
    PrivacyError,
    decrypt,
    encrypt,
    generate_salt,
    localize_privacy_key,
    priv_block_size,
    priv_key_length,
    priv_param_length,
    resolve_protocol,
)
from snmp.usm import AuthProtocol, PrivProtocol

requires_crypto = unittest.skipUnless(find_spec("cryptography") is not None, "requires the cryptography package")

# RFC 3414 Appendix A.3 sample credentials.
ENGINE = bytes.fromhex("000000000000000000000002")
PASSPHRASE = "maplesyrup"
MD5_KEY = bytes.fromhex("526f5eed9fcce26f8964c2930787d82b")
SHA_KEY = bytes.fromhex("6695febc9288e36282235fc7151f1284")


def _triple_des_ecb(key: bytes, block: bytes) -> bytes:
    """Encrypt one 8-octet block with single DES (2TDEA with equal halves)."""
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    from cryptography.hazmat.primitives.ciphers import Cipher, modes

    encryptor = Cipher(TripleDES(key + key + key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def _aes_ecb(key: bytes, block: bytes) -> bytes:
    """Encrypt one 16-octet block with AES in ECB mode."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def _des_cbc_reference(key: bytes, iv: bytes, data: bytes) -> bytes:
    """DES-CBC (RFC 3414 §8.1.1.2) built independently of snmp.privacy."""
    out = bytearray()
    previous = iv
    for offset in range(0, len(data), DES_BLOCK_SIZE):
        block = data[offset : offset + DES_BLOCK_SIZE]
        xored = bytes(a ^ b for a, b in zip(block, previous, strict=True))
        previous = _triple_des_ecb(key, xored)
        out += previous
    return bytes(out)


def _aes_cfb128_reference(key: bytes, iv: bytes, data: bytes) -> bytes:
    """CFB128-AES (RFC 3826 §3.1.3) built independently of snmp.privacy."""
    out = bytearray()
    feedback = iv
    for offset in range(0, len(data), AES_BLOCK_SIZE):
        block = data[offset : offset + AES_BLOCK_SIZE]
        keystream = _aes_ecb(key, feedback)
        cipher_block = bytes(a ^ b for a, b in zip(block, keystream, strict=False))
        out += cipher_block
        feedback = cipher_block
    return bytes(out)


class TestLocalizePrivacyKey(unittest.TestCase):
    def test_md5_vector(self) -> None:
        key = localize_privacy_key(PASSPHRASE, ENGINE, PrivProtocol.DES, AuthProtocol.MD5)
        self.assertEqual(key, MD5_KEY)

    def test_sha_vector(self) -> None:
        key = localize_privacy_key(PASSPHRASE, ENGINE, "AES128", "SHA")
        self.assertEqual(key, SHA_KEY)

    def test_key_sized_for_protocol(self) -> None:
        # SHA-1 yields only 20 octets, so AES-256 needs a SHA-2 digest to
        # localize enough key material (RFC 7860 §4.1).
        key = localize_privacy_key(PASSPHRASE, ENGINE, "AES256", "SHA512")
        self.assertEqual(len(key), 32)

    def test_requires_auth_digest(self) -> None:
        with self.assertRaises(PrivacyError):
            localize_privacy_key(PASSPHRASE, ENGINE, "AES128", AuthProtocol.NONE)

    def test_rejects_empty_passphrase(self) -> None:
        with self.assertRaises(ValueError):
            localize_privacy_key("", ENGINE, "AES128", "SHA")


class TestResolveProtocol(unittest.TestCase):
    def test_wire_names_and_oids(self) -> None:
        cases = {
            "privAES128": PrivProtocol.AES128,
            "1.3.6.1.6.3.10.1.2.4": PrivProtocol.AES128,  # usmAesCfb128Protocol
            "privAES256": PrivProtocol.AES256,
            "1.3.6.1.6.3.10.1.2.6": PrivProtocol.AES256,
            "privDES": PrivProtocol.DES,
            "1.3.6.1.6.3.10.1.2.2": PrivProtocol.DES,  # usmDESPrivProtocol
            "privNone": PrivProtocol.NONE,
            "1.3.6.1.6.3.10.1.2.1": PrivProtocol.NONE,  # usmNoPrivProtocol
        }
        for name, expected in cases.items():
            with self.subTest(name=name):
                self.assertIs(resolve_protocol(name), expected)

    def test_configuration_spellings(self) -> None:
        for name in ("aes128", "AES-128", "AES_128", "aes-128"):
            with self.subTest(name=name):
                self.assertIs(resolve_protocol(name), PrivProtocol.AES128)

    def test_legacy_aes_is_aes128(self) -> None:
        self.assertIs(resolve_protocol("AES"), PrivProtocol.AES128)
        self.assertIs(resolve_protocol(PrivProtocol.AES), PrivProtocol.AES128)

    def test_missing_protocol(self) -> None:
        for value in (None, "", "none", "privNone"):
            with self.subTest(value=value):
                self.assertIs(resolve_protocol(value), PrivProtocol.NONE)

    def test_unknown_protocol(self) -> None:
        for value in ("rc4", "aes512", "priv-aes-512"):
            with self.subTest(value=value):
                with self.assertRaises(PrivacyError):
                    resolve_protocol(value)

    def test_rejects_non_protocol_type(self) -> None:
        with self.assertRaises(PrivacyError):
            resolve_protocol(PrivProtocol)  # type: ignore[arg-type]


class TestSizing(unittest.TestCase):
    def test_key_and_param_lengths(self) -> None:
        self.assertEqual(priv_key_length("AES128"), 16)
        self.assertEqual(priv_key_length("AES192"), 24)
        self.assertEqual(priv_key_length("AES256"), 32)
        self.assertEqual(priv_key_length("DES"), 16)
        self.assertEqual(priv_key_length("none"), 0)
        self.assertEqual(priv_param_length("AES256"), 8)
        self.assertEqual(priv_param_length("none"), 0)

    def test_block_sizes(self) -> None:
        self.assertEqual(priv_block_size("DES"), DES_BLOCK_SIZE)
        self.assertEqual(priv_block_size("AES128"), AES_BLOCK_SIZE)


class TestNoPrivacy(unittest.TestCase):
    def test_passthrough(self) -> None:
        self.assertEqual(encrypt("none", b"", b"abc"), (b"abc", b""))
        self.assertEqual(decrypt("none", b"", b"abc", b""), b"abc")

    def test_generate_salt(self) -> None:
        self.assertEqual(generate_salt("none"), b"")
        self.assertEqual(len(generate_salt("AES128")), 8)
        self.assertEqual(len(generate_salt("DES")), 8)


@requires_crypto
class TestAES(unittest.TestCase):
    def test_round_trip_all_key_sizes(self) -> None:
        plaintext = b"0!\x02\x01\x01\x04\x00\xa0\x16"
        for protocol, key in (("AES128", SHA_KEY), ("AES192", bytes(range(24))), ("AES256", bytes(range(32)))):
            with self.subTest(protocol=protocol):
                cipher, salt = encrypt(protocol, key, plaintext, engine_boots=3, engine_time=99)
                self.assertEqual(len(cipher), len(plaintext))
                self.assertEqual(len(salt), 8)
                restored = decrypt(protocol, key, cipher, salt, engine_boots=3, engine_time=99)
                self.assertEqual(restored, plaintext)

    def test_matches_reference_cfb128(self) -> None:
        plaintext = b"a scoped-pdu shaped payload of 29 oct"
        salt = bytes.fromhex("0102030405060708")
        boots, when = 7, 300
        cipher, echoed = encrypt("AES128", SHA_KEY, plaintext, engine_boots=boots, engine_time=when, salt=salt)
        self.assertEqual(echoed, salt)
        iv = boots.to_bytes(4, "big") + when.to_bytes(4, "big") + salt
        self.assertEqual(cipher, _aes_cfb128_reference(SHA_KEY, iv, plaintext))

    def test_iv_uses_boots_and_time(self) -> None:
        cipher, salt = encrypt("AES128", SHA_KEY, b"payload", engine_boots=1, engine_time=2)
        self.assertNotEqual(decrypt("AES128", SHA_KEY, cipher, salt, engine_boots=2, engine_time=2), b"payload")

    def test_rejects_bad_parameters(self) -> None:
        with self.assertRaises(PrivacyError):
            encrypt("AES128", b"\x00" * 8, b"x")
        with self.assertRaises(PrivacyError):
            decrypt("AES128", SHA_KEY, b"xx", b"\x00" * 7)
        with self.assertRaises(PrivacyError):
            encrypt("rc4", b"\x00" * 16, b"x")


@requires_crypto
class TestDES(unittest.TestCase):
    SALT = bytes.fromhex("0807060504030201")

    def test_matches_reference_cbc(self) -> None:
        plaintext = b"a scoped-pdu shaped payload of 29 oct"
        cipher, _ = encrypt("DES", MD5_KEY, plaintext, salt=self.SALT)
        pre_iv = MD5_KEY[DES_BLOCK_SIZE : 2 * DES_BLOCK_SIZE]
        iv = bytes(a ^ b for a, b in zip(self.SALT, pre_iv, strict=True))
        padded = plaintext + bytes((-len(plaintext)) % DES_BLOCK_SIZE)
        self.assertEqual(cipher, _des_cbc_reference(MD5_KEY[:DES_BLOCK_SIZE], iv, padded))

    def test_round_trip_pads_to_block(self) -> None:
        plaintext = b"0!\x02\x01\x01\x04\x00\xa0\x01\x02"
        cipher, salt = encrypt("DES", MD5_KEY, plaintext)
        self.assertEqual(len(cipher) % DES_BLOCK_SIZE, 0)
        self.assertGreaterEqual(len(cipher), len(plaintext))
        restored = decrypt("DES", MD5_KEY, cipher, salt)
        self.assertEqual(restored[: len(plaintext)], plaintext)

    def test_rejects_unaligned_ciphertext(self) -> None:
        with self.assertRaises(PrivacyError):
            decrypt("DES", MD5_KEY, b"\x00" * 7, b"\x00" * 8)


@requires_crypto
class TestPrivacyContext(unittest.TestCase):
    def test_round_trip_and_parameters(self) -> None:
        context = PrivacyContext("AES128", SHA_KEY, engine_boots=5, engine_time=4242)
        cipher = context.encrypt(b"scoped pdu bytes")
        self.assertEqual(len(context.priv_parameters), 8)
        self.assertEqual(context.decrypt(cipher), b"scoped pdu bytes")

    def test_explicit_salt_is_deterministic(self) -> None:
        context = PrivacyContext(PrivProtocol.AES128, SHA_KEY, engine_boots=1, engine_time=1)
        salt = bytes(range(8))
        self.assertEqual(context.encrypt(b"x", salt=salt), context.encrypt(b"x", salt=salt))
        self.assertEqual(context.priv_parameters, salt)

    def test_repr(self) -> None:
        self.assertIn("DES", repr(PrivacyContext("DES", MD5_KEY)))


if __name__ == "__main__":
    unittest.main()
