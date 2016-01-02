from ber.enums import TagClassEnum, UniversalClassTags
from ber.object import Object, ObjectTag, OctetString, Integer
from snmp.enums import SNMPVersion
from snmp.pdus import PDU


class SNMPDatagram(Object):
    snmp_version = SNMPVersion.v1
    pdus = dict([(pdu.tag_id, pdu) for pdu in PDU.__subclasses__()])

    def __init__(self, version=None, community=None, pdu=None):
        if version is None:
            version = Integer.from_int(self.snmp_version).get_object()
        if community is None:
            community = OctetString(b'public').get_object()
        if pdu is None:
            pass

        Object.__init__(self, ObjectTag(TagClassEnum.universal, True, UniversalClassTags.sequence_of),
                        [version, community, pdu])

        self.version = version
        self.community = community
        self.pdu = pdu

    @classmethod
    def decode(cls, buffer, offset=0):
        """Decodes SNMP packet
        :param buffer:
        :param offset:
        """
        (obj, offset) = Object.decode(buffer, offset)
        assert len(buffer) == offset
        (version, community, pdu) = obj.value
        assert pdu.tag.tag_class == TagClassEnum.context_specific
        assert isinstance(community.value, OctetString)
        if pdu.tag.tag_id in cls.pdus:
            pdu = cls.pdus[pdu.tag.tag_id].from_object(pdu)
        return cls(version, community, pdu)

    def __repr__(self):
        return "%s={version: %s, community: %s, pdu: %s}" % (
            self.__class__.__name__, self.version, self.community, self.pdu)
