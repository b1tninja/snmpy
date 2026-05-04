"""MIB (Management Information Base) OIDs.

Implements RFC 1156: Management Information Base for Network Management
of TCP/IP-based internets.

Defines OIDs for:
    - System Group (§5.1) - 7 objects
    - Interfaces Group (§5.2) - 24 objects
    - Address Translation Group (§5.3) - 5 objects
    - IP Group (§5.4) - 18+ objects
    - ICMP Group (§5.5) - 25 objects
    - TCP Group (§5.6) - 12+ objects
    - UDP Group (§5.7) - 4 objects
    - EGP Group (§5.8) - 5+ objects

OID Naming Convention (RFC 1157 §3.2.6.3):
    - Single-instance objects: x.0 (e.g., sysDescr.0 = 1.3.6.1.2.1.1.1.0)
    - Indexed objects: x.index (e.g., ifDescr.1 = 1.3.6.1.2.1.2.2.1.2.1)
"""

from __future__ import annotations

from typing import Optional

from ber.object import ObjectIdentifier

# 1 - ISO assigned OIDs
# 1.3 - ISO Identified Organization
# 1.3.6 - US Department of Defense
# 1.3.6.1 - OID assignments from 1.3.6.1 - Internet
# 1.3.6.1.2 - IETF Management
# 1.3.6.1.2.1 - SNMP MIB-2

# =============================================================================
# Root OIDs
# =============================================================================

mib2 = ObjectIdentifier.from_string("1.3.6.1.2.1")          # { mib 1 }
interfaces = ObjectIdentifier.from_string("1.3.6.1.2.1.2")  # { mib 2 }
at = ObjectIdentifier.from_string("1.3.6.1.2.1.3")          # { mib 3 }
ip = ObjectIdentifier.from_string("1.3.6.1.2.1.4")          # { mib 4 }
icmp = ObjectIdentifier.from_string("1.3.6.1.2.1.5")        # { mib 5 }
tcp = ObjectIdentifier.from_string("1.3.6.1.2.1.6")         # { mib 6 }
udp = ObjectIdentifier.from_string("1.3.6.1.2.1.7")         # { mib 7 }
egp = ObjectIdentifier.from_string("1.3.6.1.2.1.8")         # { mib 8 }

# =============================================================================
# System Group (§5.1) - Implementation mandatory for all systems
# =============================================================================

system = ObjectIdentifier.from_string("1.3.6.1.2.1.1")           # { mib 1 }
sysDescr = ObjectIdentifier.from_string("1.3.6.1.2.1.1.1")       # system.1 - OCTET STRING, read-only
sysObjectID = ObjectIdentifier.from_string("1.3.6.1.2.1.1.2")    # system.2 - OBJECT IDENTIFIER, read-only
sysUpTime = ObjectIdentifier.from_string("1.3.6.1.2.1.1.3")      # system.3 - TimeTicks, read-only
sysContact = ObjectIdentifier.from_string("1.3.6.1.2.1.1.4")     # system.4 - OCTET STRING, read-write
sysName = ObjectIdentifier.from_string("1.3.6.1.2.1.1.5")        # system.5 - OCTET STRING, read-write
sysLocation = ObjectIdentifier.from_string("1.3.6.1.2.1.1.6")    # system.6 - OCTET STRING, read-write
sysServices = ObjectIdentifier.from_string("1.3.6.1.2.1.1.7")    # system.7 - INTEGER, read-only

# =============================================================================
# System Group (RFC 1907) — SNMPv2 System Extensions
# =============================================================================

sysORLastChange = ObjectIdentifier.from_string("1.3.6.1.2.1.1.8")  # system.8 - TimeStamp, read-only
# sysORTable (system.9) defined below

# sysORTable: A list of supported MIB modules and their capabilities
sysORTable = ObjectIdentifier.from_string("1.3.6.1.2.1.1.9")  # system.9 - SEQUENCE OF SysOREntry

# sysOREntry fields (RFC 1907 §2.1.2)
sysORIndex = ObjectIdentifier.from_string("1.3.6.1.2.1.1.9.1.1")    # sysOREntry.1 - INTEGER (index)
sysORID = ObjectIdentifier.from_string("1.3.6.1.2.1.1.9.1.2")        # sysOREntry.2 - OBJECT IDENTIFIER
sysORDescr = ObjectIdentifier.from_string("1.3.6.1.2.1.1.9.1.3")     # sysOREntry.3 - DisplayString
sysORUpTime = ObjectIdentifier.from_string("1.3.6.1.2.1.1.9.1.4")    # sysOREntry.4 - TimeStamp

# =============================================================================
# Interfaces Group (§5.2) - Implementation mandatory for all systems
# =============================================================================

# ifNumber: The number of interfaces
ifNumber = ObjectIdentifier.from_string("1.3.6.1.2.1.2.1")

# ifTable: A list of interface entries
ifTable = ObjectIdentifier.from_string("1.3.6.1.2.1.2.2")

# ifEntry fields (ifEntry ::= SEQUENCE { ... })
ifIndex = ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.1")    # ifEntry.1 - INTEGER, read-only
ifDescr = ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.2")    # ifEntry.2 - OCTET STRING, read-only
ifType = ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.3")     # ifEntry.3 - INTEGER, read-only
ifMtu = ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.4")      # ifEntry.4 - INTEGER, read-only
ifSpeed = ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.5")    # ifEntry.5 - Gauge, read-only
ifPhysAddress = ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.6")  # ifEntry.6 - OCTET STRING, read-only
ifAdminStatus = ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.7")  # ifEntry.7 - INTEGER, read-write
ifOperStatus = ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.8")  # ifEntry.8 - INTEGER, read-only
ifLastChange = ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.9")  # ifEntry.9 - TimeTicks, read-only
ifInOctets = ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.10")   # ifEntry.10 - Counter, read-only
ifInUcastPkts = ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.11") # ifEntry.11 - Counter, read-only
ifInNUcastPkts = ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.12") # ifEntry.12 - Counter, read-only
ifInDiscards = ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.13")   # ifEntry.13 - Counter, read-only
ifInErrors = ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.14")     # ifEntry.14 - Counter, read-only
ifInUnknownProtos = ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.15") # ifEntry.15 - Counter, read-only
ifOutOctets = ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.16")    # ifEntry.16 - Counter, read-only
ifOutUcastPkts = ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.17") # ifEntry.17 - Counter, read-only
ifOutNUcastPkts = ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.18") # ifEntry.18 - Counter, read-only
ifOutDiscards = ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.19")   # ifEntry.19 - Counter, read-only
ifOutErrors = ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.20")     # ifEntry.20 - Counter, read-only
ifOutQLen = ObjectIdentifier.from_string("1.3.6.1.2.1.2.2.1.21")       # ifEntry.21 - Gauge, read-only

# ifType values (RFC 1156 §5.2)
IF_TYPE_OTHER = 1
IF_TYPE_ETHERNET = 6
IF_TYPE_ISO88023_CSMACD = 7
IF_TYPE_ISO88024_TOKENBUS = 8
IF_TYPE_ISO88025_TOKENRING = 9
IF_TYPE_FDDI = 15
IF_TYPE_T1 = 18
IF_TYPE_CEP = 19
IF_TYPE_BASIC_ISDN = 20
IF_TYPE_PRIMARY_ISDN = 21
IF_TYPE_PROP_POINTTOPOINT_SERIAL = 22

# ifAdminStatus / ifOperStatus values
IF_STATUS_UP = 1
IF_STATUS_DOWN = 2
IF_STATUS_TESTING = 3

# =============================================================================
# Address Translation Group (§5.3) - Maps network addresses to physical addresses
# =============================================================================

atTable = ObjectIdentifier.from_string("1.3.6.1.2.1.3.1")          # at.1 - SEQUENCE OF AtEntry
atEntry = ObjectIdentifier.from_string("1.3.6.1.2.1.3.1.1")        # atEntry.1
atIndex = ObjectIdentifier.from_string("1.3.6.1.2.1.3.1.1.1")      # atEntry.1.1 - INTEGER
atPhysAddress = ObjectIdentifier.from_string("1.3.6.1.2.1.3.1.1.2")  # atEntry.1.2 - OCTET STRING
atNetAddress = ObjectIdentifier.from_string("1.3.6.1.2.1.3.1.1.3")  # atEntry.1.3 - IpAddress

# =============================================================================
# IP Group (§5.4) - IP layer management
# =============================================================================

# IP General
ipForwarding = ObjectIdentifier.from_string("1.3.6.1.2.1.4.1")         # ip.1 - INTEGER, read-write
ipInReasmMaxSize = ObjectIdentifier.from_string("1.3.6.1.2.1.4.2")     # ip.2 - INTEGER, read-only
ipReasmReqd = ObjectIdentifier.from_string("1.3.6.1.2.1.4.3")          # ip.3 - Counter
ipReasmTimeout = ObjectIdentifier.from_string("1.3.6.1.2.1.4.4")       # ip.4 - INTEGER, read-only
ipReasmOKs = ObjectIdentifier.from_string("1.3.6.1.2.1.4.5")           # ip.5 - Counter
ipReasmFails = ObjectIdentifier.from_string("1.3.6.1.2.1.4.6")         # ip.6 - Counter
ipFragOKs = ObjectIdentifier.from_string("1.3.6.1.2.1.4.7")            # ip.7 - Counter
ipFragFails = ObjectIdentifier.from_string("1.3.6.1.2.1.4.8")          # ip.8 - Counter
ipFragCreates = ObjectIdentifier.from_string("1.3.6.1.2.1.4.9")        # ip.9 - Counter
ipInDiscards = ObjectIdentifier.from_string("1.3.6.1.2.1.4.10")        # ip.10 - Counter
ipInErrors = ObjectIdentifier.from_string("1.3.6.1.2.1.4.11")          # ip.11 - Counter
ipInHdrErrors = ObjectIdentifier.from_string("1.3.6.1.2.1.4.12")       # ip.12 - Counter
ipInAddrErrors = ObjectIdentifier.from_string("1.3.6.1.2.1.4.13")      # ip.13 - Counter
ipInUnknownProtos = ObjectIdentifier.from_string("1.3.6.1.2.1.4.14")   # ip.14 - Counter
ipOutRequests = ObjectIdentifier.from_string("1.3.6.1.2.1.4.15")       # ip.15 - Counter
ipOutNoRoutes = ObjectIdentifier.from_string("1.3.6.1.2.1.4.16")       # ip.16 - Counter
ipRoutingDiscards = ObjectIdentifier.from_string("1.3.6.1.2.1.4.17")   # ip.17 - Counter

# ipAddrTable: Table of IP addresses and their associated data
ipAddrTable = ObjectIdentifier.from_string("1.3.6.1.2.1.4.19")
ipAddrEntry = ObjectIdentifier.from_string("1.3.6.1.2.1.4.19.1")
ipAdEntAddr = ObjectIdentifier.from_string("1.3.6.1.2.1.4.19.1.1")        # ipAddrEntry.1 - IpAddress
ipAdEntIfIndex = ObjectIdentifier.from_string("1.3.6.1.2.1.4.19.1.2")      # ipAddrEntry.2 - INTEGER
ipAdEntNetMask = ObjectIdentifier.from_string("1.3.6.1.2.1.4.19.1.3")      # ipAddrEntry.3 - IpAddress
ipAdEntBcastAddr = ObjectIdentifier.from_string("1.3.6.1.2.1.4.19.1.4")    # ipAddrEntry.4 - INTEGER
ipAdEntReasmMaxSize = ObjectIdentifier.from_string("1.3.6.1.2.1.4.19.1.5") # ipAddrEntry.5 - INTEGER

# ipRouteTable: Routing table
ipRouteTable = ObjectIdentifier.from_string("1.3.6.1.2.1.4.20")
ipRouteEntry = ObjectIdentifier.from_string("1.3.6.1.2.1.4.20.1")
ipRouteDest = ObjectIdentifier.from_string("1.3.6.1.2.1.4.20.1.1")         # ipRouteEntry.1 - IpAddress
ipRouteIfIndex = ObjectIdentifier.from_string("1.3.6.1.2.1.4.20.1.2")      # ipRouteEntry.2 - INTEGER
ipRouteMetric1 = ObjectIdentifier.from_string("1.3.6.1.2.1.4.20.1.3")      # ipRouteEntry.3 - INTEGER
ipRouteMetric2 = ObjectIdentifier.from_string("1.3.6.1.2.1.4.20.1.4")      # ipRouteEntry.4 - INTEGER
ipRouteMetric3 = ObjectIdentifier.from_string("1.3.6.1.2.1.4.20.1.5")      # ipRouteEntry.5 - INTEGER
ipRouteMetric4 = ObjectIdentifier.from_string("1.3.6.1.2.1.4.20.1.6")      # ipRouteEntry.6 - INTEGER
ipRouteNextHop = ObjectIdentifier.from_string("1.3.6.1.2.1.4.20.1.7")      # ipRouteEntry.7 - IpAddress
ipRouteType = ObjectIdentifier.from_string("1.3.6.1.2.1.4.20.1.8")         # ipRouteEntry.8 - INTEGER
ipRouteProto = ObjectIdentifier.from_string("1.3.6.1.2.1.4.20.1.9")        # ipRouteEntry.9 - INTEGER
ipRouteMetric5 = ObjectIdentifier.from_string("1.3.6.1.2.1.4.20.1.10")     # ipRouteEntry.10 - INTEGER

# =============================================================================
# ICMP Group (§5.5) - ICMP protocol statistics
# =============================================================================

# ICMP input counters
icmpInMsgs = ObjectIdentifier.from_string("1.3.6.1.2.1.5.1")           # icmp.1 - Counter
icmpInErrors = ObjectIdentifier.from_string("1.3.6.1.2.1.5.2")         # icmp.2 - Counter
icmpInDestUnreachs = ObjectIdentifier.from_string("1.3.6.1.2.1.5.3")   # icmp.3 - Counter
icmpInTimeExcds = ObjectIdentifier.from_string("1.3.6.1.2.1.5.4")      # icmp.4 - Counter
icmpInParamProbs = ObjectIdentifier.from_string("1.3.6.1.2.1.5.5")     # icmp.5 - Counter
icmpInSrcQuenchs = ObjectIdentifier.from_string("1.3.6.1.2.1.5.6")     # icmp.6 - Counter
icmpInRedirects = ObjectIdentifier.from_string("1.3.6.1.2.1.5.7")      # icmp.7 - Counter
icmpInEchos = ObjectIdentifier.from_string("1.3.6.1.2.1.5.8")          # icmp.8 - Counter
icmpInEchoReps = ObjectIdentifier.from_string("1.3.6.1.2.1.5.9")       # icmp.9 - Counter
icmpInTimestamps = ObjectIdentifier.from_string("1.3.6.1.2.1.5.10")    # icmp.10 - Counter
icmpInTimestampReps = ObjectIdentifier.from_string("1.3.6.1.2.1.5.11") # icmp.11 - Counter
icmpInAddrMasks = ObjectIdentifier.from_string("1.3.6.1.2.1.5.12")     # icmp.12 - Counter
icmpInAddrMaskReps = ObjectIdentifier.from_string("1.3.6.1.2.1.5.13")  # icmp.13 - Counter

# ICMP output counters
icmpOutMsgs = ObjectIdentifier.from_string("1.3.6.1.2.1.5.14")          # icmp.14 - Counter
icmpOutErrors = ObjectIdentifier.from_string("1.3.6.1.2.1.5.15")       # icmp.15 - Counter
icmpOutDestUnreachs = ObjectIdentifier.from_string("1.3.6.1.2.1.5.16") # icmp.16 - Counter
icmpOutTimeExcds = ObjectIdentifier.from_string("1.3.6.1.2.1.5.17")    # icmp.17 - Counter
icmpOutParamProbs = ObjectIdentifier.from_string("1.3.6.1.2.1.5.18")   # icmp.18 - Counter
icmpOutSrcQuenchs = ObjectIdentifier.from_string("1.3.6.1.2.1.5.19")   # icmp.19 - Counter
icmpOutRedirects = ObjectIdentifier.from_string("1.3.6.1.2.1.5.20")    # icmp.20 - Counter
icmpOutEchos = ObjectIdentifier.from_string("1.3.6.1.2.1.5.21")        # icmp.21 - Counter
icmpOutEchoReps = ObjectIdentifier.from_string("1.3.6.1.2.1.5.22")     # icmp.22 - Counter
icmpOutTimestamps = ObjectIdentifier.from_string("1.3.6.1.2.1.5.23")   # icmp.23 - Counter
icmpOutTimestampReps = ObjectIdentifier.from_string("1.3.6.1.2.1.5.24") # icmp.24 - Counter
icmpOutAddrMasks = ObjectIdentifier.from_string("1.3.6.1.2.1.5.25")    # icmp.25 - Counter
icmpOutAddrMaskReps = ObjectIdentifier.from_string("1.3.6.1.2.1.5.26") # icmp.26 - Counter

# =============================================================================
# TCP Group (§5.6) - TCP transport statistics
# =============================================================================

tcpInSegs = ObjectIdentifier.from_string("1.3.6.1.2.1.6.1")            # tcp.1 - Counter
tcpOutSegs = ObjectIdentifier.from_string("1.3.6.1.2.1.6.2")           # tcp.2 - Counter
tcpRetranSegs = ObjectIdentifier.from_string("1.3.6.1.2.1.6.3")        # tcp.3 - Counter
tcpInErrs = ObjectIdentifier.from_string("1.3.6.1.2.1.6.4")            # tcp.4 - Counter
tcpOutRsts = ObjectIdentifier.from_string("1.3.6.1.2.1.6.5")           # tcp.5 - Counter
tcpActiveOpens = ObjectIdentifier.from_string("1.3.6.1.2.1.6.6")       # tcp.6 - Counter
tcpPassiveOpens = ObjectIdentifier.from_string("1.3.6.1.2.1.6.7")      # tcp.7 - Counter
tcpAttemptFails = ObjectIdentifier.from_string("1.3.6.1.2.1.6.8")      # tcp.8 - Counter
tcpEstabResets = ObjectIdentifier.from_string("1.3.6.1.2.1.6.9")       # tcp.9 - Counter
tcpCurrEstab = ObjectIdentifier.from_string("1.3.6.1.2.1.6.10")        # tcp.10 - Gauge

# TCP connection table
tcpConnTable = ObjectIdentifier.from_string("1.3.6.1.2.1.6.13")
tcpConnEntry = ObjectIdentifier.from_string("1.3.6.1.2.1.6.13.1")
tcpConnState = ObjectIdentifier.from_string("1.3.6.1.2.1.6.13.1.1")    # tcpConnEntry.1 - INTEGER
tcpConnLocalAddr = ObjectIdentifier.from_string("1.3.6.1.2.1.6.13.1.2") # tcpConnEntry.2 - IpAddress
tcpConnLocalPort = ObjectIdentifier.from_string("1.3.6.1.2.1.6.13.1.3") # tcpConnEntry.3 - INTEGER
tcpConnRemoteAddr = ObjectIdentifier.from_string("1.3.6.1.2.1.6.13.1.4") # tcpConnEntry.4 - IpAddress
tcpConnRemotePort = ObjectIdentifier.from_string("1.3.6.1.2.1.6.13.1.5") # tcpConnEntry.5 - INTEGER

# TCP connection state values
TCP_CLOSED = 1
TCP_SYN_SENT = 2
TCP_SYN_RECEIVED = 3
TCP_ESTABLISHED = 4
TCP_FIN_WAIT_1 = 5
TCP_FIN_WAIT_2 = 6
TCP_CLOSE_WAIT = 7
TCP_LAST_ACK = 8
TCP_CLOSING = 9
TCP_TIME_WAIT = 10
TCP_CLOSE = 11
TCP_LISTEN = 12
TCP_HALF_CLOSE = 13

# =============================================================================
# SNMP Group (§2.2, RFC 1907) - SNMP entity instrumentation and control
# =============================================================================
# OID prefix: 1.3.6.1.2.1.11

snmp = ObjectIdentifier.from_string("1.3.6.1.2.1.11")          # snmp - SNMP group root

# snmpIn* counters
snmpInPkts = ObjectIdentifier.from_string("1.3.6.1.2.1.11.1")         # snmp.1 - Counter32, in PDUs
snmpInBadVersions = ObjectIdentifier.from_string("1.3.6.1.2.1.11.3")   # snmp.3 - Counter32, bad SNMP versions
snmpInBadCommunityNames = ObjectIdentifier.from_string("1.3.6.1.2.1.11.4")  # snmp.4 - Counter32, bad community names
snmpInBadCommunityUses = ObjectIdentifier.from_string("1.3.6.1.2.1.11.5")   # snmp.5 - Counter32, bad community uses
snmpInASNParseErrs = ObjectIdentifier.from_string("1.3.6.1.2.1.11.6")    # snmp.6 - Counter32, ASN.1/BER parse errors

# snmpEnableAuthenTraps — RFC 1157 §4.1.6.5, RFC 3418 §6.7
snmpEnableAuthenTraps = ObjectIdentifier.from_string("1.3.6.1.2.1.11.30")  # snmpEnableAuthenTraps — INTEGER (1=enabled, 2=disabled)

# snmpSet* objects (RFC 1907 §2.5)
snmpSet = ObjectIdentifier.from_string("1.3.6.1.2.1.11.100")  # snmpSet - set group root
snmpSetSerialNo = ObjectIdentifier.from_string("1.3.6.1.2.1.11.100.1")  # snmpSetSerialNo — TestAndIncr

# =============================================================================
# SNMP Trap/Notification OIDs (§2.4, RFC 1907)
# =============================================================================
# OID prefix: 1.3.6.1.6.3.18 (snmpTrapOID)

snmpTrap = ObjectIdentifier.from_string("1.3.6.1.6.3.18")          # snmpTrapOID —_trap-OID
snmpTrapOID = ObjectIdentifier.from_string("1.3.6.1.6.3.18.1")     # snmpTrapOID.1 — the trap OID

# Well-known notification OIDs (RFC 1907 §2.4.1)
snmpTraps = ObjectIdentifier.from_string("1.3.6.1.6.3.1.1")         # snmpTraps — well-known traps root
coldStart = ObjectIdentifier.from_string("1.3.6.1.6.3.1.1.4.1.0.1")  # coldStart(1)
warmStart = ObjectIdentifier.from_string("1.3.6.1.6.3.1.1.4.1.0.2")  # warmStart(2)
# linkDown/linkUp defined in RFC 1213 (2.3.5.1.1 / 2.3.5.1.2)
linkDown = ObjectIdentifier.from_string("1.3.6.1.6.3.1.1.4.1.0.3")  # linkDown(3)
linkUp = ObjectIdentifier.from_string("1.3.6.1.6.3.1.1.4.1.0.4")    # linkUp(4)
authenticationFailure = ObjectIdentifier.from_string("1.3.6.1.6.3.1.1.4.1.0.5")  # authenticationFailure(5)
egpNeighborLoss = ObjectIdentifier.from_string("1.3.6.1.6.3.1.1.4.1.0.6")  # egpNeighborLoss(6)

# =============================================================================
# UDP Group (§5.7) - UDP transport statistics
# =============================================================================

udpInDatagrams = ObjectIdentifier.from_string("1.3.6.1.2.1.7.1")       # udp.1 - Counter
udpNoPorts = ObjectIdentifier.from_string("1.3.6.1.2.1.7.2")           # udp.2 - Counter
udpInErrors = ObjectIdentifier.from_string("1.3.6.1.2.1.7.3")          # udp.3 - Counter
udpOutDatagrams = ObjectIdentifier.from_string("1.3.6.1.2.1.7.4")      # udp.4 - Counter

# UDP table
udpTable = ObjectIdentifier.from_string("1.3.6.1.2.1.7.5")
udpEntry = ObjectIdentifier.from_string("1.3.6.1.2.1.7.5.1")
udpLocalAddr = ObjectIdentifier.from_string("1.3.6.1.2.1.7.5.1.1")     # udpEntry.1 - IpAddress
udpLocalPort = ObjectIdentifier.from_string("1.3.6.1.2.1.7.5.1.2")     # udpEntry.2 - INTEGER

# =============================================================================
# EGP Group (§5.8) - Exterior Gateway Protocol (obsolete, replaced by BGP)
# =============================================================================

# EGP input counters
egpInMsgs = ObjectIdentifier.from_string("1.3.6.1.2.1.8.1")            # egp.1 - Counter
egpInErrors = ObjectIdentifier.from_string("1.3.6.1.2.1.8.2")          # egp.2 - Counter

# EGP output counters
egpOutMsgs = ObjectIdentifier.from_string("1.3.6.1.2.1.8.3")           # egp.3 - Counter
egpOutErrors = ObjectIdentifier.from_string("1.3.6.1.2.1.8.4")         # egp.4 - Counter
egpInSegs = ObjectIdentifier.from_string("1.3.6.1.2.1.8.5")            # egp.5 - Counter

# EGP neighbor table
egpNeighTable = ObjectIdentifier.from_string("1.3.6.1.2.1.8.6")
egpNeighEntry = ObjectIdentifier.from_string("1.3.6.1.2.1.8.6.1")
egpNeighAddr = ObjectIdentifier.from_string("1.3.6.1.2.1.8.6.1.1")     # egpNeighEntry.1 - IpAddress
egpNeighState = ObjectIdentifier.from_string("1.3.6.1.2.1.8.6.1.2")    # egpNeighEntry.2 - INTEGER
egpNeighDSInMsgs = ObjectIdentifier.from_string("1.3.6.1.2.1.8.6.1.3")  # egpNeighEntry.3 - Counter
egpNeighDSInErrs = ObjectIdentifier.from_string("1.3.6.1.2.1.8.6.1.4")  # egpNeighEntry.4 - Counter
egpNeighDSOutMsgs = ObjectIdentifier.from_string("1.3.6.1.2.1.8.6.1.5") # egpNeighEntry.5 - Counter
egpNeighDSOutErrs = ObjectIdentifier.from_string("1.3.6.1.2.1.8.6.1.6") # egpNeighEntry.6 - Counter
egpNeighInMsgs = ObjectIdentifier.from_string("1.3.6.1.2.1.8.6.1.7")    # egpNeighEntry.7 - Counter
egpNeighInErrs = ObjectIdentifier.from_string("1.3.6.1.2.1.8.6.1.8")    # egpNeighEntry.8 - Counter
egpNeighOutMsgs = ObjectIdentifier.from_string("1.3.6.1.2.1.8.6.1.9")   # egpNeighEntry.9 - Counter
egpNeighOutErrs = ObjectIdentifier.from_string("1.3.6.1.2.1.8.6.1.10")  # egpNeighEntry.10 - Counter
egpNeighISIS = ObjectIdentifier.from_string("1.3.6.1.2.1.8.6.1.11")     # egpNeighEntry.11 - INTEGER
egpNeighLastChange = ObjectIdentifier.from_string("1.3.6.1.2.1.8.6.1.12") # egpNeighEntry.12 - TimeTicks

# EGP neighbor state values
EGP_UP_AND_OPERATIONAL = 1
EGP_DOWN = 2
EGP_PEER_UNSTABLE = 3
EGP_COLD_START = 4
EGP_WARM_START = 5

# =============================================================================
# Exported names
# =============================================================================

__all__ = [
    # Root
    "mib2", "interfaces", "at", "ip", "icmp", "tcp", "udp", "egp",
    # System Group (RFC 1156 + RFC 1907)
    "system", "sysDescr", "sysObjectID", "sysUpTime",
    "sysContact", "sysName", "sysLocation", "sysServices",
    "sysORLastChange", "sysORTable",
    "sysORIndex", "sysORID", "sysORDescr", "sysORUpTime",
    # Interfaces Group
    "ifNumber", "ifTable",
    "ifIndex", "ifDescr", "ifType", "ifMtu", "ifSpeed", "ifPhysAddress",
    "ifAdminStatus", "ifOperStatus", "ifLastChange",
    "ifInOctets", "ifInUcastPkts", "ifInNUcastPkts",
    "ifInDiscards", "ifInErrors", "ifInUnknownProtos",
    "ifOutOctets", "ifOutUcastPkts", "ifOutNUcastPkts",
    "ifOutDiscards", "ifOutErrors", "ifOutQLen",
    # Address Translation Group
    "atTable", "atEntry", "atIndex", "atPhysAddress", "atNetAddress",
    # IP Group
    "ipForwarding", "ipInReasmMaxSize",
    "ipReasmReqd", "ipReasmOKs", "ipReasmFails",
    "ipFragOKs", "ipFragFails", "ipFragCreates",
    "ipInDiscards", "ipInErrors", "ipInHdrErrors",
    "ipInAddrErrors", "ipInUnknownProtos", "ipOutRequests",
    "ipOutNoRoutes", "ipRoutingDiscards",
    "ipAddrTable", "ipAddrEntry",
    "ipAdEntAddr", "ipAdEntIfIndex", "ipAdEntNetMask",
    "ipAdEntBcastAddr", "ipAdEntReasmMaxSize",
    "ipRouteTable", "ipRouteEntry",
    "ipRouteDest", "ipRouteIfIndex", "ipRouteMetric1", "ipRouteMetric2",
    "ipRouteMetric3", "ipRouteMetric4", "ipRouteNextHop", "ipRouteType",
    "ipRouteProto", "ipRouteMetric5",
    # ICMP Group
    "icmpInMsgs", "icmpInErrors", "icmpInDestUnreachs",
    "icmpInTimeExcds", "icmpInParamProbs", "icmpInSrcQuenchs",
    "icmpInRedirects", "icmpInEchos", "icmpInEchoReps",
    "icmpInTimestamps", "icmpInTimestampReps",
    "icmpInAddrMasks", "icmpInAddrMaskReps",
    "icmpOutMsgs", "icmpOutErrors", "icmpOutDestUnreachs",
    "icmpOutTimeExcds", "icmpOutParamProbs", "icmpOutSrcQuenchs",
    "icmpOutRedirects", "icmpOutEchos", "icmpOutEchoReps",
    "icmpOutTimestamps", "icmpOutTimestampReps",
    "icmpOutAddrMasks", "icmpOutAddrMaskReps",
    # TCP Group
    "tcpInSegs", "tcpOutSegs", "tcpRetranSegs",
    "tcpInErrs", "tcpOutRsts", "tcpActiveOpens", "tcpPassiveOpens",
    "tcpAttemptFails", "tcpEstabResets", "tcpCurrEstab",
    "tcpConnTable", "tcpConnEntry", "tcpConnState",
    "tcpConnLocalAddr", "tcpConnLocalPort",
    "tcpConnRemoteAddr", "tcpConnRemotePort",
    # UDP Group
    "udpInDatagrams", "udpNoPorts", "udpInErrors", "udpOutDatagrams",
    "udpTable", "udpEntry", "udpLocalAddr", "udpLocalPort",
    # EGP Group
    "egpInMsgs", "egpInErrors", "egpOutMsgs", "egpOutErrors", "egpInSegs",
    "egpNeighTable", "egpNeighEntry", "egpNeighAddr", "egpNeighState",
    "egpNeighDSInMsgs", "egpNeighDSInErrs", "egpNeighDSOutMsgs",
    "egpNeighDSOutErrs", "egpNeighInMsgs", "egpNeighInErrs",
    "egpNeighOutMsgs", "egpNeighOutErrs", "egpNeighISIS", "egpNeighLastChange",
    # SNMP Group (RFC 1907 §2.2)
    "snmp", "snmpInPkts", "snmpInBadVersions", "snmpInBadCommunityNames",
    "snmpInBadCommunityUses", "snmpInASNParseErrs",
    "snmpSet", "snmpSetSerialNo",
    "snmpEnableAuthenTraps",
    # Trap/Notification OIDs (RFC 1907 §2.4)
    "snmpTrap", "snmpTrapOID", "snmpTraps",
    "coldStart", "warmStart", "linkDown", "linkUp",
    "authenticationFailure", "egpNeighborLoss",
    # Constants
    "IF_TYPE_OTHER", "IF_TYPE_ETHERNET", "IF_TYPE_FDDI",
    "IF_TYPE_T1", "IF_TYPE_BASIC_ISDN", "IF_TYPE_PRIMARY_ISDN",
    "IF_STATUS_UP", "IF_STATUS_DOWN", "IF_STATUS_TESTING",
    "TCP_CLOSED", "TCP_SYN_SENT", "TCP_SYN_RECEIVED", "TCP_ESTABLISHED",
    "TCP_FIN_WAIT_1", "TCP_FIN_WAIT_2", "TCP_CLOSE_WAIT", "TCP_LAST_ACK",
    "TCP_CLOSING", "TCP_TIME_WAIT", "TCP_CLOSE", "TCP_LISTEN",
    "TCP_HALF_CLOSE",
    "EGP_UP_AND_OPERATIONAL", "EGP_DOWN", "EGP_PEER_UNSTABLE",
    "EGP_COLD_START", "EGP_WARM_START",
]