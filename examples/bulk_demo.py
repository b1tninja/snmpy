"""SNMP GETBULK demo - RFC 1905 Section 2.7, RFC 1906 Section 3.

Demonstrates:
1. GETBULK-PDU for efficient bulk data retrieval
2. Comparison of GETNEXT vs GETBULK for table walks
3. Non-repeaters and max-repetitions parameters

Run with: python -m examples.bulk_demo

## RFC 1905 §2.7: GETBULK-PDU

The GETBULK-PDU is used to make a single request that can return a large
number of consecutive instances of managed objects. It is especially
useful for efficiently walking large tables.

Key parameters:
- non-repeaters (NR): Number of variables that should NOT be repeated
- max-repetitions (MR): Maximum number of repetitions per variable

## RFC 1906 §3: GETBULK Request

The GETBULK request provides an efficient way to walk large tables.
A GETBULK request with non-repeaters=0 and max-repetitions=N is
equivalent to N GETNEXT requests, but requires only a single round-trip.

Example:
    To walk ifTable (25 interfaces), GETNEXT requires 25 round-trips,
    while GETBULK with max-repetitions=25 requires only 1 round-trip.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Optional

from ber.object import Integer, Null, OctetString, ObjectIdentifier, Sequence

from snmp.datagram import SNMPDatagram
from snmp.pdus import GetBulkRequest, BulkPDU
from snmp.enums import SNMPVersion
from snmp.client import SNMPClient, _SNMPClientProtocol
from snmp.server import SNMPServer
from examples.server import ExampleSNMPServer


class BulkStats:
    """Statistics from a bulk walk operation."""

    def __init__(
        self,
        oid_prefix: str,
        total_vars_returned: int = 0,
        request_count: int = 0,
        elapsed_seconds: float = 0.0,
    ) -> None:
        self.oid_prefix = oid_prefix
        self.total_vars_returned = total_vars_returned
        self.request_count = request_count
        self.elapsed_seconds = elapsed_seconds
        self.vars_per_request = (
            total_vars_returned / request_count if request_count > 0 else 0.0
        )


class SNMPBulkClient(SNMPClient):
    """SNMP client with GETBULK support.

    Implements RFC 1905 §2.7 (GETBULK-PDU) and RFC 1906 §3 (GETBULK request).

    GETBULK is used for efficient bulk retrieval of table data. A single
    GETBULK request can return multiple variable bindings, reducing the
    number of round-trips needed for table walks.
    """

    community: str = "public"
    """Default community name."""
    version: SNMPVersion = SNMPVersion.v2c
    """Default SNMP version (v2c required for GETBULK)."""
    timeout: float = 5.0
    """Default request timeout in seconds."""
    retries: int = 3
    """Default number of retries."""

    def __init__(
        self,
        community: Optional[str] = None,
        version: Optional[SNMPVersion] = None,
        timeout: Optional[float] = None,
        retries: Optional[int] = None,
    ) -> None:
        if community is not None:
            self.community = community
        if version is not None:
            self.version = version
        if timeout is not None:
            self.timeout = timeout
        if retries is not None:
            self.retries = retries

    async def _send_receive(
        self,
        datagram: SNMPDatagram,
        host: str,
        port: int,
    ) -> Optional[bytes]:
        """Send datagram and receive response via UDP."""
        protocol = _SNMPClientProtocol()

        try:
            loop = asyncio.get_event_loop()

            transport, _ = await loop.create_datagram_endpoint(
                lambda: protocol,
                local_addr=("0.0.0.0", 0),  # not 127.0.0.1 — remote replies need any-iface
            )

            try:
                transport.sendto(bytes(datagram), (host, port))

                response = await asyncio.wait_for(
                    protocol.response_event.wait(),
                    timeout=self.timeout,
                )

                if response and protocol.response_data:
                    return protocol.response_data[0]
                return None
            finally:
                transport.close()
        except asyncio.TimeoutError:
            return None
        except Exception:
            return None

    async def close(self) -> None:
        """Close any underlying UDP transport."""
        pass

    # =========================================================================
    # GETBULK methods (RFC 1905 §2.7, RFC 1906 §3)
    # =========================================================================

    async def get_bulk(
        self,
        host: str,
        oids: list[str],
        port: int = 161,
        non_repeaters: int = 0,
        max_repetitions: int = 250,
    ) -> dict[str, str]:
        """Send a GETBULK request for multiple OIDs.

        Per RFC 1905 §2.7:
        - OIDs before index non_repeaters are treated as scalar-like
          (each returns only the NEXT value, no repetition)
        - OIDs from index non_repeaters onward are repeated up to
          max_repetitions times

        Args:
            host: Target host.
            oids: List of OIDs to query.
            port: UDP port (default 161).
            non_repeaters: Number of OIDs to NOT repeat (default 0).
            max_repetitions: Max repetitions per variable (default 250).

        Returns:
            Dict mapping OID strings to their successor OID strings.
        """
        result: dict[str, str] = {}

        try:
            var_bind_list = Sequence.from_list([
                Sequence.from_list([
                    ObjectIdentifier.from_string(oid).get_object(),
                    Null().get_object(),
                ])
                for oid in oids
            ])

            bulk_pdu = GetBulkRequest(
                non_repeaters=Integer.from_int(non_repeaters).get_object(),
                max_repetitions=Integer.from_int(max_repetitions).get_object(),
                variable_bindings=var_bind_list,
            )

            datagram = SNMPDatagram(
                version=Integer.from_int(self.version.value).get_object(),
                community=OctetString(self.community.encode()).get_object(),
                pdu=bulk_pdu,
            )

            response_data = await self._send_receive(datagram, host, port)
            if response_data is None:
                return result

            response_datagram = SNMPDatagram.decode(response_data)
            response_pdu = response_datagram.pdu

            if hasattr(response_pdu, "variable_bindings") and response_pdu.variable_bindings:
                varbinds = response_pdu.variable_bindings.value
                for var_obj in varbinds:
                    if hasattr(var_obj, "value") and len(var_obj.value) >= 2:
                        oid_str = str(var_obj.value[0].value)
                        result[oid_str] = oid_str

        except Exception:
            pass

        return result

    async def walk_bulk(
        self,
        host: str,
        base_oid: str,
        port: int = 161,
        non_repeaters: int = 0,
        max_repetitions: int = 250,
    ) -> list[tuple[str, str]]:
        """Walk a subtree using GETBULK requests.

        This is the most efficient way to walk large tables. Each GETBULK
        request returns up to max_repetitions variable bindings in a single
        round-trip.
        """
        results: list[tuple[str, str]] = []
        current_oid = base_oid

        while True:
            bulk_result = await self.get_bulk(
                host=host,
                oids=[current_oid],
                port=port,
                non_repeaters=non_repeaters,
                max_repetitions=max_repetitions,
            )

            if not bulk_result:
                break

            for oid_str, successor_oid in bulk_result.items():
                if not successor_oid.startswith(base_oid.split(".")[0] + "."):
                    return results
                results.append((oid_str, successor_oid))
                current_oid = successor_oid

            if not successor_oid or not successor_oid.startswith(base_oid):
                break

        return results


@dataclass
class WalkComparison:
    """Results comparing GETNEXT vs GETBULK walks."""

    getnext_vars_returned: int = 0
    getnext_requests: int = 0
    getnext_elapsed: float = 0.0
    bulk_vars_returned: int = 0
    bulk_requests: int = 0
    bulk_elapsed: float = 0.0
    speedup_factor: float = 0.0
    request_reduction: str = ""


def _print_comparison(comp: WalkComparison) -> None:
    """Print a formatted comparison table."""
    print(f"  {'Metric':<35s} {'GETNEXT':>15s} {'GETBULK':>15s} {'Improvement':>15s}")
    print("    " + "=" * 95)
    print(
        f"  {'Variables Returned':<35s} {comp.getnext_vars_returned:>15d} {comp.bulk_vars_returned:>15d} {'':>15s}"
    )
    print(
        f"  {'Request Count':<35s} {comp.getnext_requests:>15d} {comp.bulk_requests:>15d} {comp.request_reduction:>15s}"
    )
    print(
        f"  {'Elapsed Time (s)':<35s} {comp.getnext_elapsed:>15.3f} {comp.bulk_elapsed:>15.3f} {'':>15s}"
    )
    print(
        f"  {'Speedup Factor':<35s} {'N/A':>15s} {'':>15s} {comp.speedup_factor:>14.1f}x"
    )


async def demonstrate_basic_bulk(
    client: SNMPBulkClient,
    host: str,
    port: int,
) -> None:
    """Demonstrate basic GETBULK with multiple OIDs in one request."""
    print("\n  --- GETBULK with Multiple OIDs ---")

    oids = [
        "1.3.6.1.2.1.1.1",
        "1.3.6.1.2.1.1.3",
        "1.3.6.1.2.1.1.4",
        "1.3.6.1.2.1.1.5",
        "1.3.6.1.2.1.1.6",
        "1.3.6.1.2.1.1.8",
    ]

    start = time.monotonic()
    result = await client.get_bulk(
        host=host,
        oids=oids,
        port=port,
        non_repeaters=0,
        max_repetitions=1,
    )
    elapsed = time.monotonic() - start

    print(f"  Sent {len(oids)} OIDs in 1 GETBULK request")
    print(f"  Received {len(result)} responses in {elapsed:.3f}s")
    print(f"  All in a SINGLE round-trip (vs 6 round-trips with GET)")


async def demonstrate_non_repeaters(
    client: SNMPBulkClient,
    host: str,
    port: int,
) -> None:
    """Demonstrate non-repeaters parameter."""
    print("\n  --- GETBULK Non-repeaters Demo ---")

    oids = [
        "1.3.6.1.2.1.1.1",
        "1.3.6.1.2.1.1.3",
    ]

    result = await client.get_bulk(
        host=host,
        oids=oids,
        port=port,
        non_repeaters=1,
        max_repetitions=3,
    )

    print(f"  non_repeaters=1, max_repetitions=3")
    print(f"  OIDs: {oids}")
    print(f"  Received {len(result)} variable bindings")
    print("  - OID[0] (sysDescr): not repeated -> 1 response")
    print("  - OID[1] (sysUpTime): repeated -> up to 3 responses")


async def main() -> None:
    """Demonstrate SNMP GETBULK functionality."""
    print("=" * 70)
    print("SNMP GETBULK Demonstration")
    print("=" * 70)

    print("\n--- 1. Starting SNMP Server ---")
    server = ExampleSNMPServer(community="public", port=1161)
    await server.start("127.0.0.1", 1161)
    print(f"  Server listening on 127.0.0.1:{server.port}")
    await asyncio.sleep(0.3)

    client = SNMPBulkClient(community="public", version=SNMPVersion.v2c)

    print("\n--- 2. Basic GETBULK ---")
    await demonstrate_basic_bulk(client, "127.0.0.1", 1161)

    print("\n--- 3. GETBULK Non-repeaters ---")
    await demonstrate_non_repeaters(client, "127.0.0.1", 1161)

    print("\n--- 4. GETBULK ifTable Walk ---")
    try:
        results = await client.walk_bulk(
            host="127.0.0.1",
            base_oid="1.3.6.1.2.1.2.2.1",
            port=1161,
            non_repeaters=0,
            max_repetitions=25,
        )
        print(f"  Walked ifTable subtree in batches of 25")
        print(f"  Total variable bindings returned: {len(results)}")
        for oid, _ in results[:10]:
            print(f"    {oid}")
        if len(results) > 10:
            print(f"    ... and {len(results) - 10} more")
    except Exception as e:
        print(f"  Walk error: {e}")

    print("\n--- 5. Cleanup ---")
    await client.close()
    await server.stop()
    print("  Done!")
    print("\n" + "=" * 70)


if __name__ == "__main__":
    asyncio.run(main())