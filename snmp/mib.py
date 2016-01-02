from ber.object import ObjectIdentifier

# 1 - ISO assigned OIDs
# 1.3 - ISO Identified Organization
# 1.3.6 - US Department of Defense
# 1.3.6.1 - OID assignments from 1.3.6.1 - Internet
# 1.3.6.1.2 - IETF Management
# 1.3.6.1.2.1 - SNMP MIB-2

system = ObjectIdentifier.from_string('1.3.6.1.2.1')
