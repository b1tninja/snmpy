import string
from math import ceil, log2

from . import ASN1Object,  ObjectTag
from .enums import TagClassEnum, UniversalClassTags


class Null(ASN1Object):
    tag_id = UniversalClassTags.null


from typing import Union, SupportsBytes, Sized, Iterable, ByteString


class ASN1ObjectIdentifier(ASN1Object):
    tag_id = UniversalClassTags.object_identifier

    def __new__(cls, oid: str, *args, **kwargs):
        assert oid.isdecimal()
        if isinstance(oid, str):
            assert set(string.digits+'.')
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


class OctetString(ASN1Object):
    tag = UniversalClassTags.octet_string

    def __str__(self):
        if self.isascii():
            return self.decode('ascii')
        else:
            return bytes(self).hex()

    def __bytes__(self):
        pass

    @classmethod
    def encode(cls, value):
        assert isinstance(value, str)
        return cls(value.encode('ascii'))


class Integer(ASN1Object):
    tag_id = UniversalClassTags.integer

    def __int__(self):
        return int.from_bytes(self, byteorder='big')

    def __str__(self):
        return "%d" % int(self)

    @classmethod
    def from_int(cls, value):
        assert isinstance(value, int)
        assert value >= 0
        return cls(value.to_bytes(1 if value == 0 else ceil(log2(value) / 8), byteorder='big'))


class Sequence(ASN1Object):

    tag_id = UniversalClassTags.sequence_of
    is_constructed = True


