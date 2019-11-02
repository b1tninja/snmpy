from unittest import TestCase

from ber.enums import TagClassEnum, UniversalClassTags
from ber.object import ObjectTag


class TestObjectTag(TestCase):
    # known_tags = [((0,False,5) bytes([5]),
    #               b'\xa1\x19'ObjectTag.decode()[0])]
    # def test_decode(self):
    #     TODO: self.assertEquals(ObjectTag.decode(),?)
    #     self.assertEqual(, )

    def test_encode(self):
        self.assertEqual(bytes(ObjectTag(TagClassEnum.universal, False, UniversalClassTags.null)), bytes([5]))
        self.assertEqual(bytes(ObjectTag(TagClassEnum.universal, True, UniversalClassTags.sequence_of)),
                         bytes([0b00110000]))
