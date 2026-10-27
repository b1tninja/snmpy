"""Async tests for SNMPClientImpl against the FakeSNMPAgent (loopback UDP)."""

from __future__ import annotations

import unittest

from snmp.client import SNMPClientImpl
from snmp.test_session import FakeSNMPAgent, _closed_port, make_mib
from snmp.values import as_bytes, as_int, as_str, exception_name


class TestSNMPClientImpl(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.agent = FakeSNMPAgent(make_mib()).start()
        self.addCleanup(self.agent.stop)
        self.client = SNMPClientImpl(community="public", timeout=1.0, retries=2)

    async def test_get_returns_value(self) -> None:
        value = await self.client.get("127.0.0.1", "1.3.6.1.2.1.1.1.0",
                                      port=self.agent.port)
        self.assertIsNotNone(value)
        self.assertEqual(as_bytes(value), b"FakeSNMP agent")  # type: ignore[arg-type]

    async def test_get_missing_returns_exception_value(self) -> None:
        value = await self.client.get("127.0.0.1", "1.3.6.1.2.1.1.99.0",
                                      port=self.agent.port)
        self.assertIsNotNone(value)
        self.assertEqual(exception_name(value), "noSuchInstance")

    async def test_get_next(self) -> None:
        value = await self.client.get_next("127.0.0.1", "1.3.6.1.2.1.1.1.0",
                                           port=self.agent.port)
        self.assertIsNotNone(value)
        self.assertEqual(as_int(value), 123456)

    async def test_walk(self) -> None:
        rows = await self.client.walk("127.0.0.1", "1.3.6.1.2.1.1",
                                      port=self.agent.port)
        self.assertEqual([oid for oid, _ in rows], [
            "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0",
            "1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.5.0",
            "1.3.6.1.2.1.1.7.0",
        ])
        self.assertEqual(as_str(rows[0][1]), "FakeSNMP agent")

    async def test_set_roundtrip(self) -> None:
        ok = await self.client.set("127.0.0.1", "1.3.6.1.2.1.1.4.0",
                                   "new@example.com", port=self.agent.port)
        self.assertTrue(ok)
        value = await self.client.get("127.0.0.1", "1.3.6.1.2.1.1.4.0",
                                      port=self.agent.port)
        self.assertEqual(as_str(value), "new@example.com")

    async def test_get_timeout_returns_none(self) -> None:
        client = SNMPClientImpl(timeout=0.05, retries=1)
        self.assertIsNone(
            await client.get("127.0.0.1", "1.3.6.1.2.1.1.1.0",
                             port=_closed_port())
        )

    async def test_community_override(self) -> None:
        client = SNMPClientImpl(community="private")
        value = await client.get("127.0.0.1", "1.3.6.1.2.1.1.1.0",
                                 port=self.agent.port)
        self.assertEqual(as_bytes(value), b"FakeSNMP agent")


if __name__ == "__main__":
    unittest.main()


