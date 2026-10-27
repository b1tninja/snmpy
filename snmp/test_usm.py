"""Unit tests for the snmp.usm protocol enums and key localization."""

from __future__ import annotations

import unittest

from snmp.usm import (
    AuthProtocol,
    PrivProtocol,
    SecurityLevel,
    localize_passphrase,
    password_to_key,
)

# RFC 3414 Appendix A.3 sample credentials.
ENGINE = bytes.fromhex("000000000000000000000002")
PASSPHRASE = "maplesyrup"


class TestAuthProtocol(unittest.TestCase):
    def test_members_are_protocols_only(self) -> None:
        # Regression: the sizing tables used to sit in the enum class body,
        # where a single-underscore name becomes an enum member rather than a
        # class attribute, which broke every table lookup.
        self.assertEqual(
            set(AuthProtocol.__members__),
            {"NONE", "MD5", "SHA", "SHA96", "SHA224", "SHA256", "SHA384", "SHA512"},
        )

    def test_mac_lengths(self) -> None:
        # RFC 3414 §6.3.1/§7.3.1 truncate to 12 octets, RFC 7860 §4 keeps
        # 16/24/32/48 octets of the SHA-2 MAC.
        expected = {
            AuthProtocol.NONE: 0,
            AuthProtocol.MD5: 12,
            AuthProtocol.SHA: 12,
            AuthProtocol.SHA96: 12,
            AuthProtocol.SHA224: 16,
            AuthProtocol.SHA256: 24,
            AuthProtocol.SHA384: 32,
            AuthProtocol.SHA512: 48,
        }
        for protocol, length in expected.items():
            with self.subTest(protocol=protocol):
                self.assertEqual(protocol.get_mac_length(), length)
                self.assertEqual(protocol.get_digest_length(), length)

    def test_key_lengths(self) -> None:
        # Localized key == digest size of the hash (RFC 3414 §2.6).
        expected = {
            AuthProtocol.NONE: 0,
            AuthProtocol.MD5: 16,
            AuthProtocol.SHA: 20,
            AuthProtocol.SHA96: 20,
            AuthProtocol.SHA224: 28,
            AuthProtocol.SHA256: 32,
            AuthProtocol.SHA384: 48,
            AuthProtocol.SHA512: 64,
        }
        for protocol, length in expected.items():
            with self.subTest(protocol=protocol):
                self.assertEqual(protocol.get_key_length(), length)

    def test_hash_names(self) -> None:
        self.assertEqual(AuthProtocol.MD5.hash_name, "md5")
        self.assertEqual(AuthProtocol.SHA.hash_name, "sha1")
        self.assertEqual(AuthProtocol.SHA96.hash_name, "sha1")
        self.assertEqual(AuthProtocol.SHA256.hash_name, "sha256")
        self.assertEqual(AuthProtocol.NONE.hash_name, "")


class TestPrivProtocol(unittest.TestCase):
    def test_members_are_protocols_only(self) -> None:
        self.assertEqual(
            set(PrivProtocol.__members__),
            {"NONE", "DES", "AES", "AES128", "AES192", "AES256"},
        )

    def test_key_lengths(self) -> None:
        # DES takes 16 octets: 8 for the key and 8 for the pre-IV
        # (RFC 3414 §8.1.1.1); AES takes the cipher key itself (RFC 3826 §3.1.2.1).
        expected = {
            PrivProtocol.NONE: 0,
            PrivProtocol.DES: 16,
            PrivProtocol.AES: 16,
            PrivProtocol.AES128: 16,
            PrivProtocol.AES192: 24,
            PrivProtocol.AES256: 32,
        }
        for protocol, length in expected.items():
            with self.subTest(protocol=protocol):
                self.assertEqual(protocol.get_key_length(), length)

    def test_priv_param_lengths(self) -> None:
        for protocol in (PrivProtocol.DES, PrivProtocol.AES128, PrivProtocol.AES256):
            with self.subTest(protocol=protocol):
                self.assertEqual(protocol.get_priv_param_length(), 8)
        self.assertEqual(PrivProtocol.NONE.get_priv_param_length(), 0)


class TestLocalizePassphrase(unittest.TestCase):
    def test_md5_vector(self) -> None:
        key = localize_passphrase(PASSPHRASE, ENGINE, AuthProtocol.MD5)
        self.assertEqual(key.hex(), "526f5eed9fcce26f8964c2930787d82b")

    def test_sha_vector(self) -> None:
        key = localize_passphrase(PASSPHRASE, ENGINE, AuthProtocol.SHA)
        self.assertEqual(key.hex(), "6695febc9288e36282235fc7151f128497b38f3f")

    def test_sha_privacy_key_is_truncated(self) -> None:
        # RFC 3826 §3.1.2.1 uses the first 16 octets of the localized key.
        key = localize_passphrase(PASSPHRASE, ENGINE, AuthProtocol.SHA, key_length=16)
        self.assertEqual(key.hex(), "6695febc9288e36282235fc7151f1284")

    def test_password_to_key_vectors(self) -> None:
        # RFC 3414 §A.3.1/§A.3.2 intermediate keys (Ku) before localization.
        self.assertEqual(password_to_key(b"maplesyrup", "md5").hex(), "9faf3283884e92834ebc9847d8edd963")
        self.assertEqual(
            password_to_key(b"maplesyrup", "sha1").hex(),
            "9fb5cc0381497b3793528939ff788d5d79145211",
        )

    def test_sha256_length(self) -> None:
        key = localize_passphrase(PASSPHRASE, ENGINE, AuthProtocol.SHA256)
        self.assertEqual(len(key), AuthProtocol.SHA256.get_key_length())


class TestSecurityLevel(unittest.TestCase):
    def test_values(self) -> None:
        self.assertEqual(SecurityLevel.NO_AUTH_NO_PRIV.value, 0)
        self.assertEqual(SecurityLevel.AUTH_NO_PRIV.value, 1)
        self.assertEqual(SecurityLevel.AUTH_PRIV.value, 2)

    def test_from_int(self) -> None:
        self.assertEqual(SecurityLevel.from_int(2), SecurityLevel.AUTH_PRIV)
        self.assertEqual(SecurityLevel.from_int(1), SecurityLevel.AUTH_NO_PRIV)
        self.assertEqual(SecurityLevel.from_int(0), SecurityLevel.NO_AUTH_NO_PRIV)


if __name__ == "__main__":
    unittest.main()
