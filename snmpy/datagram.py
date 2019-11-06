from .asn1 import TagClassEnum, UniversalClassTags
from .asn1.ber import ASN1BERASN1Object, BERObjectTag
from .asn1.types import OctetString, Integer
from . import SNMPVersion
from .pdus import PDU

from typing import Optional, Union

class SNMPDatagram(ASN1BERASN1Object):
    snmp_version: SNMPVersion = None
    _tag_constructed_ = True
    _tag_id_ = UniversalClassTags.sequence_of
    community = 'public'

    # def __new__(cls, payload: Union[PDU, ASN1BERObject, bytes], community: Optional[str]):
    #     if not isinstance(payload, PDU):
    #         payload = PDU(payload)
    #
    #     # TODO: Determine version
    #
    #     return cls([Integer(cls.snmp_version), OctetString(community), payload])

    @classmethod
    def decode(cls, buffer: bytes, offset: int = 0):
        assert len(buffer) > offset
        (obj, offset) = ASN1BERASN1Object.decode(buffer, offset)
        (version, community, pdu) = obj
        assert pdu.tag_class == TagClassEnum.context_specific
        assert isinstance(community, OctetString)
        return cls(pdu, community)

    def __repr__(self):
        return "%s={version: %s, community: %s, pdu: %s}" % (
            self.__class__.__name__, self.version, self.community, self.pdu)

class SNMPv1Datagram(SNMPDatagram):
    snmp_version = SNMPVersion.v1
