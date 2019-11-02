from snmpy.asn1.enums import TagClassEnum, UniversalClassTags
from .asn1.ber import BERObject, BERObjectTag
from snmpy.asn1 import OctetString, Integer
from .enums import SNMPVersion
from .pdus import PDU

from typing import Optional

class SNMPDatagram(BERObject):
    snmp_version: SNMPVersion

    pdus = dict([(pdu.tag_id, pdu) for pdu in PDU.__subclasses__()])

    def __init__(self, payload: PDU, community: Optional[str] = 'public'):
            community = OctetString(community).get_object()
        if pdu is None:
            pass


        BERObject.__init__(self, BERObjectTag(TagClassEnum.universal, True, UniversalClassTags.sequence_of),
                           [Integer.from_int(self.snmp_version).get_object(), community, pdu])

        self.version = version
        self.community = community
        self.pdu = pdu

    @classmethod
    def decode(cls, buffer, offset=0):
        """Decodes SNMP packet
        :param buffer:
        :param offset:
        """
        (obj, offset) = BERObject.decode(buffer, offset)
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

class SNMPv1Datagram(SNMPDatagram):
    snmp_version = SNMPVersion.v1
