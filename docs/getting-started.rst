Getting Started with snmpy
=========================

This guide provides an overview of how to use snmpy for SNMP operations.


Installation
------------

Install snmpy with pip:

.. code-block:: bash

   pip install snmpy


Basic Usage
-----------

SNMP Client
~~~~~~~~~~~

The ``SNMPClient`` class provides methods for querying SNMP agents:

.. code-block:: python

   from snmp.client import SNMPClient

   # Create a client instance (override _send_receive for your transport)
   class MyClient(SNMPClient):
       async def _send_receive(self, datagram, host, port):
           # Your UDP transport implementation
           pass

   client = MyClient()

   # Get a single OID value
   value = await client.get("192.168.1.1", "1.3.6.1.2.1.1.1.0")

   # Get the next OID in the MIB tree
   value = await client.get_next("192.168.1.1", "1.3.6.1.2.1.1.1.0")

   # Walk an entire subtree
   results = await client.walk("192.168.1.1", "1.3.6.1.2.1.2.2.1")

   # Bulk retrieve multiple OIDs efficiently
   results = await client.bulk_get("192.168.1.1", ["1.3.6.1.2.1.1.1", "1.3.6.1.2.1.1.2"])

   # Set a MIB value (if the agent allows it)
   success = await client.set("192.168.1.1", "1.3.6.1.2.1.1.5.0", "myDevice")

   # Send a trap to a management station
   await client.send_trap("192.168.1.100", trap_type=Trap.COLD_START)


SNMP Server
~~~~~~~~~~~

The ``SNMPServer`` class provides an abstract base for implementing SNMP agents:

.. code-block:: python

   from snmp.server import MockSNMPServer

   # Create a mock SNMP server with real system information
   server = MockSNMPServer(
       community="public",
       community_rw="private",
       port=1161,
   )

   # Start listening for SNMP requests
   await server.start(host="0.0.0.0", port=1161)

   # Register custom OID handlers
   server.register_static("1.3.6.1.4.1.99999.1.1", "My Custom Value")

   # Stop the server
   await server.stop()


SNMP Traps
----------

Send and receive SNMP traps for network event monitoring:

.. code-block:: python

   from snmp.pdus import Trap, SNMPv2Trap

   # Send a cold start trap (SNMPv1)
   await client.send_trap(
       host="192.168.1.100",
       trap_type=Trap.COLD_START,
       variables=[
           ("1.3.6.1.2.1.1.1", "Device rebooted".encode()),
       ],
       port=162,
   )

   # Send an SNMPv2 trap with variables
   await client.send_inform(
       host="192.168.1.100",
       trap_type=4,
       variables=[
           ("1.3.6.1.2.1.1.3", 12345),  # sysUpTime
           ("1.3.6.1.6.3.1.1.4.1.0.1", "linkDown"),
       ],
   )


MIB Module
----------

The ``snmp.mib`` module provides pre-defined OID constants for MIB-2 objects:

.. code-block:: python

   from snmp import mib

   # System Group OIDs
   print(mib.sysDescr)     # 1.3.6.1.2.1.1.1
   print(mib.sysObjectID)  # 1.3.6.1.2.1.1.2
   print(mib.sysUpTime)    # 1.3.6.1.2.1.1.3

   # Interface Group OIDs
   print(mib.ifTable)      # 1.3.6.1.2.1.2.2
   print(mib.ifNumber)     # 1.3.6.1.2.1.2.1

   # OID concatenation
   oid = mib.sysDescr + (0,)
   print(oid)  # 1.3.6.1.2.1.1.1.0


OID Handling
------------

The ``ber.object.ObjectIdentifier`` class provides tuple-like operations for OIDs:

.. code-block:: python

   from ber.object import ObjectIdentifier

   # Create from dotted-decimal string
   oid = ObjectIdentifier.from_string("1.3.6.1.2.1.1.1")

   # Tuple operations
   print(len(oid))         # 8 components
   print(oid[0])           # 1
   print(oid[0:4])         # 1.3.6.1
   print(list(oid))        # [1, 3, 6, 1, 2, 1, 1, 1]

   # OID concatenation
   full_oid = oid + (0,)
   print(full_oid)         # 1.3.6.1.2.1.1.1.0

   # String representation
   print(str(oid))         # "1.3.6.1.2.1.1.1"

   # Membership testing
   print(1 in oid)         # True


Error Handling
--------------

snmpy provides a comprehensive exception hierarchy:

.. code-block:: python

   from snmp.exceptions import (
       SNMPError,
       SNMPTimeoutError,
       SNMPCommunityError,
       BERDecodeError,
       SNMPErrorStatus,
       SNMPProtocolError,
   )

   try:
       result = await client.get(host, oid, port)
   except SNMPTimeoutError:
       print("Request timed out - check host and network connectivity")
   except SNMPCommunityError:
       print("Bad community string")
   except BERDecodeError:
       print("Received non-SNMP data")
   except SNMPErrorStatus:
       print(f"SNMP error: {exc.error_status}")
   except SNMPError:
       print(f"SNMP error: {exc}")


Configuration
-------------

Key configuration parameters:

+-----------------+----------------+--------------------------------------------------+
| Parameter       | Default        | Description                                      |
+=================+================+==================================================+
| ``community``   | "public"       | SNMP community string for authentication         |
+-----------------+----------------+--------------------------------------------------+
| ``version``     | SNMPVersion.v1 | SNMP protocol version (v1, v2c, v3)              |
+-----------------+----------------+--------------------------------------------------+
| ``timeout``     | 5.0            | Request timeout in seconds                       |
+-----------------+----------------+--------------------------------------------------+
| ``retries``     | 3              | Number of retries on timeout                     |
+-----------------+----------------+--------------------------------------------------+


Building the Documentation
--------------------------

To build the HTML documentation:

.. code-block:: bash

   cd docs
   pip install -e "..[dev]"
   sphinx-build -b html . _build/html

The generated documentation will be in ``docs/_build/html/index.html``.