from os import urandom

import snmp.mib
from ber.enums import TagClassEnum
from ber.object import Object, ObjectTag, Null, ObjectIdentifier, Integer, Sequence
from snmp.enums import ErrorStatus


class PDU(Object):
    tag_class = TagClassEnum.context_specific
    is_constructed = True
    tag_id = None

    @classmethod
    def get_object_tag(cls):
        return ObjectTag(cls.tag_class, cls.is_constructed, cls.tag_id)

    def __init__(self, tag=None, request_id=None, error_status=None, error_index=None, variable_bindings=None):
        if request_id is None:
            request_id = Integer(urandom(4)).get_object()
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

        Object.__init__(self, self.get_object_tag() if tag is None else tag,
                        [self.request_id, self.error_status, self.error_index, self.variable_bindings])

    @classmethod
    def from_object(cls, obj):
        assert isinstance(obj, Object)
        assert len(obj.value) == 4
        (request_id, error_status, error_index, variable_bindings) = obj.value
        return cls(obj.tag, request_id, error_status, error_index, variable_bindings)

    def __repr__(self):
        return "%s={request_id: %s, error_status: %s, error_index: %s, variables_bindings: %s}" % (
            self.__class__.__name__, self.request_id, self.error_status, self.error_index, self.variable_bindings)


class GetNextRequest(PDU):
    tag_id = 1

    def __init__(self, *args, **kwargs):
        PDU.__init__(self, *args, **kwargs)
        oid = self.variable_bindings.value[0].value[0].value
        assert isinstance(oid, ObjectIdentifier)
        self.oid = oid

    @classmethod
    def from_oid(cls, oid=None):
        if oid is None:
            oid = snmp.mib.system
        if isinstance(oid, str):
            oid = ObjectIdentifier.from_string(oid)
        assert isinstance(oid, ObjectIdentifier)
        variable_bindings = Sequence.from_list([Sequence.from_list([oid.get_object(), Null().get_object()])])
        return cls(variable_bindings=variable_bindings)

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
