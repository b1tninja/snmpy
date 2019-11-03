from random import randint

from snmpy.asn1 import TagClassEnum, UniversalClassTags
from .asn1.ber import ASN1BERObject, BERObjectTag
from .asn1.types import Null, ObjectIdentifier, Integer, Sequence
from . import ErrorStatus

#    IMPORTS
#           ObjectName, ObjectSyntax, NetworkAddress, IpAddress, TimeTicks
#                   FROM RFC1155-SMI;
#
#
#      -- top-level message
#
#              Message ::=
#                      SEQUENCE {
#                           version        -- version-1 for this RFC
#                              INTEGER {
#                                  version-1(0)
#                              },
#
#                          community      -- community name
#                              OCTET STRING,
#
#                          data           -- e.g., PDUs if trivial
#                              ANY        -- authentication is being used
#                      }
#
#
#              PDUs ::=
#                      CHOICE {
#                          get-request
#                              GetRequest-PDU,
#
#                          get-next-request
#                              GetNextRequest-PDU,
#
#                          get-response
#                              GetResponse-PDU,
#
#                          set-request
#                              SetRequest-PDU,
#
#                          trap
#                              Trap-PDU
#                           }

# TODO: PDU.get_object()
class PDU(ASN1BERObject):
    tag_class = TagClassEnum.context_specific
    is_constructed = True

    @classmethod
    def get_object_tag(cls):
        return BERObjectTag(cls.tag_class, cls.is_constructed, cls.tag_id)

    def get_object(self):
        assert self.tag_id is not None
        return ASN1BERObject(self.get_object_tag(), self)

    def __init__(self, tag=None, request_id=None, error_status=None, error_index=None, variable_bindings=None):
        if request_id is None:
            # TODO: when Integer() is fixed, use wider range of values
            request_id = Integer.from_int(randint(1 << 24, 1 << 31)).get_object()
        assert isinstance(request_id.value, Integer)
        self.request_id = request_id

        if error_status is None:
            error_status = Integer.from_int(ErrorStatus.no_error).get_object()
        assert isinstance(error_status.value, Integer)
        self.error_status = error_status

        if error_index is None:
            error_index = Integer.from_int(0).get_object()
        assert isinstance(error_index.value, Integer)
        self.error_index = error_index

        assert variable_bindings is not None
        self.variable_bindings = variable_bindings

        ASN1BERObject.__init__(self, self.get_object_tag() if tag is None else tag,
                               [self.request_id, self.error_status, self.error_index, self.variable_bindings])

    @classmethod
    def from_object(cls, obj):
        assert isinstance(obj, ASN1BERObject)
        assert len(obj.value) == 4
        (request_id, error_status, error_index, variable_bindings) = obj.value
        return cls(obj.tag, request_id, error_status, error_index, variable_bindings)

    def __repr__(self):
        return "%s={request_id: %s, error_status: %s, error_index: %s, variables_bindings: %s}" % (
            self.__class__.__name__, self.request_id, self.error_status, self.error_index, self.variable_bindings)


class GetNextRequest(PDU):
    tag_id = 1

    def __new__(cls, oid: str, *args, **kwargs):
        return cls(
            Sequence(
                [
                    Sequence(
                        [
                            ObjectIdentifier(oid), Null()
                        ],
                    )
                ]
            ))

    def __repr__(self):
        return "%s={request_id: %s, oid: %s]" % (self.__class__.__name__, self.request_id, self.oid)


class GetResponse(PDU):
    tag_id = 2

    def __init__(self, *args, **kwargs):
        PDU.__init__(self, *args, **kwargs)
        oid = self.variable_bindings.value[0].value[0].value
        assert isinstance(oid, ObjectIdentifier)
        self.oid = oid

        response = self.variable_bindings.value[0].value[1]
        self.response = response

    def __repr__(self):
        return "%s={request_id: %s, oid: %s, response: %s}" % (
            self.__class__.__name__, self.request_id, self.oid, self.response)
