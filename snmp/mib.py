from ber.object import ObjectIdentifier

# TODO: RFC1155 (MIB) parser https://www.ietf.org/rfc/rfc1155.txt

# 1 - ISO assigned OIDs
# 1.3 - ISO Identified Organization
# 1.3.6 - US Department of Defense
# 1.3.6.1 - OID assignments from 1.3.6.1 - Internet
# 1.3.6.1.2 - IETF Management
# 1.3.6.1.2.1 - SNMP MIB-2
# 1.3.6.1.2.1.1 - system

mib2 = ObjectIdentifier.from_string('1.3.6.1.2.1')
system = ObjectIdentifier.from_string('1.3.6.1.2.1.1')
sysDescr = ObjectIdentifier.from_string('1.3.6.1.2.1.1.1')
sysObjectID = ObjectIdentifier.from_string('1.3.6.1.2.1.1.2')
sysUpTime = ObjectIdentifier.from_string('1.3.6.1.2.1.1.1.3')
sysContact = ObjectIdentifier.from_string('1.3.6.1.2.1.1.1.4')
sysName = ObjectIdentifier.from_string('1.3.6.1.2.1.1.5')
sysLocation = ObjectIdentifier.from_string('1.3.6.1.2.1.1.1.6')
sysServices = ObjectIdentifier.from_string('1.3.6.1.2.1.1.1.7')

