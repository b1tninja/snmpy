from math import ceil, log2

from ber.enums import TagClassEnum, UniversalClassTags


class ObjectTag(object):
    def __init__(self, tag_class, is_constructed, tag_id):
        if isinstance(tag_class, int):
            tag_class = TagClassEnum(tag_class)
        else:
            assert isinstance(tag_class, TagClassEnum)
        self.tag_class = tag_class

        assert isinstance(is_constructed, bool)
        self.is_constructed = is_constructed

        if tag_class == TagClassEnum.universal and isinstance(tag_id, int):
            try:
                tag_id = UniversalClassTags(tag_id)
            except ValueError:
                pass
        else:
            assert isinstance(tag_id, int)
        self.tag_id = tag_id

    def __bytes__(self):
        buffer = bytearray()
        buffer.append(self.tag_class << 6 | self.is_constructed * 0b00100000 | min(0b00011111, self.tag_id))
        if self.tag_id >= 0b00011111:
            n = self.tag_id
            buffer.append(n & 0b01111111)
            while n >= 0b10000000:
                n >>= 7
                buffer.insert(1, 0b10000000 | n & 0b011111111)
        return bytes(buffer)

    def __repr__(self):
        return "(%s,%s,%s)" % (self.tag_class,
                               "constructed" if self.is_constructed else "primitive",
                               self.tag_id)

    @classmethod
    def decode(cls, buffer, offset=0):
        tag_class = TagClassEnum(buffer[offset] >> 6)
        is_constructed = bool(buffer[offset] & 0b00100000)
        tag_id = buffer[offset] & 0b00011111
        if tag_id == 0b00011111:
            # long-form identifier
            tag_id = 0
            while buffer[offset] & 0b10000000:
                tag_id |= buffer[offset] & 0b01111111
                tag_id <<= 7
                offset += 1
            else:
                tag_id |= buffer[offset]  # & 0b01111111
        offset += 1
        return cls(tag_class, is_constructed, tag_id), offset


class ObjectValue(bytes):
    tag_id = None

    def get_object(self):
        return Object(self.get_object_tag(), self)

    @classmethod
    def get_object_tag(cls):
        assert cls.tag_id is not None
        return ObjectTag(TagClassEnum.universal, False, cls.tag_id)


class ObjectLength:
    @staticmethod
    def encode(length):
        # TODO: indefinite form
        assert not (length >> 128)  # maximum length of 2**(2**7)
        if length < 0b10000000:
            # short-form
            return bytes([length])
        else:
            # long-form
            octets = ceil(log2(length) / 8)
            return bytes([0b10000000 | octets]) + length.to_bytes(octets, byteorder='big')

    @staticmethod
    def decode(buffer, offset=0):
        if buffer[offset] == 0b10000000:
            try:
                offset += 1
                octet_length = buffer.index(b'\0' * 2, offset) - offset
            except ValueError:
                raise Exception("Malformed packet: Indefinite form has no end-of-content terminator.")
        elif buffer[offset] < 0b10000000:
            octet_length = buffer[offset]
            offset += 1
        else:  # buffer[offset] > 128
            length_octets = buffer[offset] & 0b01111111
            offset += 1
            octet_length = int.from_bytes(buffer[offset:offset + length_octets], 'big')
            offset += length_octets
        return octet_length, offset


class Null(ObjectValue):
    tag_id = 5


class ObjectIdentifier(ObjectValue):
    tag_id = 6

    @classmethod
    def from_string(cls, oid):
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


class OctetString(ObjectValue):
    is_constructed = False
    tag_id = 4

    def __str__(self):
        return self.decode('ascii')

    @classmethod
    def encode(cls, value):
        assert isinstance(value, str)
        return cls(value.encode('ascii'))


class Integer(ObjectValue):
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


# TODO: reorganize module a bit, perhaps extract the universal primitives into own file
class Object(object):
    """Basic Encoding Rules"""
    universal_tags = dict([(tag.tag_id, tag) for tag in ObjectValue.__subclasses__()])

    def __init__(self, tag, value):
        assert isinstance(tag, ObjectTag)
        self.tag = tag
        self.value = value

    def __bytes__(self):
        encoded_value = b''.join(map(bytes, self.value)) if isinstance(self.value, list) else bytes(self.value)
        return bytes(self.tag) + ObjectLength.encode(len(encoded_value)) + encoded_value

    def __repr__(self):
        return "<%s tag=%s value=%s>" % (self.__class__.__name__, self.tag, self.value)

    @classmethod
    def decode(cls, buffer, offset=0):
        (tag, offset) = ObjectTag.decode(buffer, offset)
        (octet_length, offset) = ObjectLength.decode(buffer, offset)
        stop_octet = offset + octet_length

        if tag.is_constructed:
            value = []
            while offset < stop_octet:
                (sub_object, offset) = cls.decode(buffer, offset)
                value.append(sub_object)
        else:
            value = buffer[offset:stop_octet]

        if tag.tag_class == TagClassEnum.universal:
            if tag.tag_id in cls.universal_tags:
                value = cls.universal_tags[tag.tag_id](value)

        return cls(tag, value), stop_octet
