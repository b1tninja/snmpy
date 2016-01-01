from unittest import TestCase

from ber.object import ObjectLength


class TestObjectLength(TestCase):
    def test_encode(self):
        self.assertEqual(ObjectLength.encode(0b01111111), bytes([127]))
        self.assertEqual(ObjectLength.encode(0b10000000), bytes([0b10000001, 128]))
        self.assertEqual(ObjectLength.encode(0b0000000100000001), bytes([0b10000010, 1, 1]))

    def test_decode(self):
        self.assertEqual(ObjectLength.decode(bytes([127])), (0b01111111, 1))
        self.assertEqual(ObjectLength.decode(bytes([0b10000001, 128])), (0b10000000, 2))
        self.assertEqual(ObjectLength.decode(bytes([0b10000010, 1, 1])), (0b0000000100000001, 3))
