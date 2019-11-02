from binascii import b2a_hex
from math import ceil, log2
from string import printable
from typing import Union

from snmpy.asn1.ber import TagClassEnum, UniversalClassTags, BERObject, BERObjectTag


class ObjectTag:
    def __init__(self, tag_class: TagClassEnum, is_constructed: bool, tag_id: Union[UniversalClassTags, int]):
        if tag_class == TagClassEnum.universal and isinstance(tag_id, int):
            tag_id = UniversalClassTags(tag_id)

        self.tag_class = tag_class
        self.is_constructed = is_constructed
        self.tag_id = tag_id

    def __bytes__(self):
        raise NotImplementedError()

    def __repr__(self):
        return "(%s,%s,%s)" % (self.tag_class.name,
                               "constructed" if self.is_constructed else "primitive",
                               self.tag_id.name if isinstance(self.tag_id, UniversalClassTags) else self.tag_id)


class ObjectValue:
    tag_class: TagClassEnum = TagClassEnum.universal
    is_constructed: bool = False
    tag_id: UniversalClassTags

    def get_object(self):
        return BERObject(self.get_object_tag(), self)

    @classmethod
    def get_object_tag(cls):
        # TODO: support other TagClasses, tag_id in UniversalClassTags._members_.values()?
        # TODO: support constructed values
        return BERObjectTag(TagClassEnum.universal, False, cls.tag_id)


class Null(ObjectValue):
    tag_id = UniversalClassTags.null


class ObjectIdentifier(ObjectValue):
    tag_id = UniversalClassTags.object_identifier

    @classmethod
    def from_string(cls, oid: str):
        ids = list(map(int, oid.split('.')))
        assert 0 <= ids[0] <= 2
        if ids[0] < 2:
            assert ids[1] < 40
        else:
            assert ids[1] < 256 - 80
        buffer = bytearray([ids[0] * 40 + ids[1]])
        for n in range(2, len(ids)):
            i = ids[n]
            sub_buffer = bytearray([i & 0b01111111])
            while i >= 0b10000000:
                i >>= 7
                sub_buffer.insert(0, 0b10000000 | i & 0xff)
            buffer.extend(sub_buffer)
        return cls(bytes(buffer))

    def __str__(self):
        x = min(2, self[0] // 40)
        y = self[0] - x * 40
        oid = [x, y]
        i = 0
        for n in range(1, len(self)):
            i |= self[n] & 0b01111111
            if self[n] & 0b10000000:
                i <<= 7
            else:
                oid.append(i)
                i = 0
        return '.'.join(map(str, oid))

    @classmethod
    def as_object(cls, oid):
        return cls(oid).get_object()


class OctetString(ObjectValue):
    is_constructed = False
    tag_id = 4

    def __str__(self):
        if set(self).issubset(set(map(ord, printable))):
            return self.decode('ascii')
        else:
            return b2a_hex(self).decode('ascii')

    @classmethod
    def encode(cls, value):
        assert isinstance(value, str)
        return cls(value.encode('ascii'))


class Integer(ObjectValue):
    # TODO: should be twos complement representation
    tag_id = 2

    def __int__(self):
        return int.from_bytes(self, byteorder='big')

    def __str__(self):
        return "%d" % int(self)

    @classmethod
    def from_int(cls, value):
        assert isinstance(value, int)
        assert value >= 0
        return cls(value.to_bytes(1 if value == 0 else ceil(log2(value) / 8), byteorder='big'))


class Sequence(BERObject):
    tag_id = 16
    is_constructed = True

    @classmethod
    def from_list(cls, value):
        return cls(BERObjectTag(TagClassEnum.universal, True, UniversalClassTags.sequence_of), value)


class Object:
    """Basic Encoding Rules"""
    universal_tags = dict([(tag.tag_id, tag) for tag in ObjectValue.__subclasses__()])

    def __init__(self, tag, value):
        assert isinstance(tag, BERObjectTag)
        self.tag = tag
        self.value = value

    def __repr__(self):
        return "%s={%s: %s}" % (self.__class__.__name__, self.tag, self.value)