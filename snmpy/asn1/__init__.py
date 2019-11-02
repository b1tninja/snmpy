from enum import IntEnum
from typing import Union, SupportsBytes

from .ber import ASN1BERObject, BERObjectTag


class TagClassEnum(IntEnum):
    universal = 0
    application = 1
    context_specific = 2
    private = 3


class UniversalClassTags(IntEnum):
    eoc = 0
    boolean = 1
    integer = 2
    bit_string = 3
    octet_string = 4
    null = 5
    object_identifier = 6
    object_descriptor = 7
    external = 8
    real = 9
    enumerated = 10
    embedded_pdv = 11
    utf8_string = 12
    realative_oid = 13
    reserved_14 = 14
    reserved_15 = 15
    sequence_of = 16
    set_of = 17
    numeric_string = 18
    printable_string = 19
    t61_string = 20
    videotex_string = 21
    ia5string = 22
    utc_time = 23
    generalized_time = 24
    graphic_string = 25
    visible_string = 26
    general_string = 27
    universal_string = 28
    character_string = 29
    bmp_string = 30

class ObjectTag:
    def __init__(self, tag_class: TagClassEnum, is_constructed: bool, tag_id: Union[UniversalClassTags, int]):
        self.tag_class = tag_class
        self.is_constructed = is_constructed
        self.tag_id = tag_id

    def __bytes__(self):
        raise NotImplementedError()

    def __repr__(self):
        return "(%s,%s,%s)" % (self.tag_class.name,
                               "constructed" if self.is_constructed else "simple",
                               self.tag_id.name if hasattr(self.tag_id, 'name') else self.tag_id)


class Object:
    _tag_class_: TagClassEnum = TagClassEnum.universal
    _tag_constructed_: bool = False
    _tag_id_: UniversalClassTags
    _content_: SupportsBytes = None

    def __init__(self, tag: ObjectTag, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tag = tag

    def __new__(cls, *args, **kwargs):
        return cls(ObjectTag(cls._tag_class_, cls._tag_constructed_, cls._tag_id_), *args, **kwargs)

    def __repr__(self):
        return "%s{%s: %s}" % (self.__class__.__name__, self._tag_id_, self.value)

    def __bytes__(self):
        raise NotImplementedError()
