from math import ceil, log2

from .. import ObjectTag, ASN1Object
from ..enums import TagClassEnum

from typing import Iterable

class byte(bytes):
    def __new__(cls, *args, **kwargs):
        return bytes(args)

class BERObjectTag(ObjectTag):
    def __bytes__(self):
        if self.tag_id < 31:
            # Low-tag-number form.
            # One octet.
            # Bits 8 and 7 specify the class
            # bit 6 has value "0," indicating that the encoding is primitive,
            # and bits 5-1 give the tag number.
            return byte(self.tag_class << 6 | 1 << 5 * self.is_constructed | self.tag_id)


        elif self.tag_id >= 31:
            n = self.tag_id
            buffer.append(n & 0b01111111)
            while n >= 0b10000000:
                n >>= 7
                buffer.insert(1, 0b10000000 | n & 0b011111111)
        return bytes(buffer)

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

        # TODO: return metaclass for Object type
        return cls(tag_class, is_constructed, tag_id), offset


class ASN1BERASN1Object(ASN1Object):
    def __bytes__(self):
        encoded_value = bytes(self.value)
        return bytes(self.tag) + ObjectLength.encode(len(encoded_value)) + encoded_value


    @classmethod
    def decode(cls, buffer, offset=0):
        (tag, offset) = BERObjectTag.decode(buffer, offset)
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



class ObjectLength:
    @staticmethod
    def encode(length: int):
        # TODO: indefinite form
        assert length < 2**(2**7)  # maximum length of 2**(2**7)
        if length < 0b10000000:
            # short-form
            return bytes([length])
            length.to_bytes()
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
