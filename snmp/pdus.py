from os import urandom

from ber.enums import TagClassEnum, UniversalClassTags
from ber.object import Object, ObjectTag, Null, ObjectIdentifier, Integer
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
        self.request_id = request_id
        if error_status is None:
            error_status = Integer.from_int(ErrorStatus.no_error).get_object()
        assert isinstance(error_status, Object)
        self.error_status = error_status

        if error_index is None:
            error_index = Integer.from_int(0).get_object()
        assert isinstance(error_index, Object)
        self.error_index = error_index

        # TODO: if variables_bindings is not None
        assert variable_bindings is not None
        self.variable_bindings = variable_bindings

        Object.__init__(self, self.get_object_tag() if tag is None else tag,
                        [self.request_id, self.error_status, self.error_index, self.variable_bindings])

    @classmethod
    def from_object(cls, obj):
        assert isinstance(obj, Object)
        assert len(obj.value) == 4
        (request_id, error_status, error_index, variable_bindings) = obj.value
        assert variable_bindings.tag.tag_class == TagClassEnum.universal
        assert variable_bindings.tag.tag_id == UniversalClassTags.sequence_of
        assert variable_bindings.tag.is_constructed
        assert isinstance(variable_bindings.value, list)
        # assert len(variable_bindings.value) == 1
        # TODO: not sure if following applies, get bulk?
        assert isinstance(variable_bindings.value[0].value, list) and len(variable_bindings.value[0].value) == 2
        return cls(obj.tag, request_id, error_status, error_index, variable_bindings)

    def __repr__(self):
        return "<%s request_id=%s, error_status=%s, error_index=%s, variables_bindings=%s>" % (
            self.__class__.__name__, self.request_id, self.error_status, self.error_index, self.variable_bindings)


class GetNextRequest(PDU):
    tag_id = 1

    def __init__(self, oid=None):
        if oid is None:
            oid = '1.3.6.1.2.1'  # MIB system
        # TODO: clean this up, variable_bindings to/from dict?
        variable_bindings = Object(ObjectTag(TagClassEnum.universal, True, UniversalClassTags.sequence_of),
                                   [Object(ObjectTag(TagClassEnum.universal, True, UniversalClassTags.sequence_of),
                                           [ObjectIdentifier.from_string(oid).get_object(),
                                            Null().get_object()])])

        PDU.__init__(self, variable_bindings=variable_bindings)


class GetResponse(PDU):
    tag_id = 2
