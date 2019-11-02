from unittest import TestCase

from ber.object import ObjectLength


class TestObjectLength(TestCase):
    test_cases = [(0b01111111, bytes([127])),
                  (0b10000000, bytes([0b10000001, 128])),
                  (0b0000000100000001, bytes([0b10000010, 1, 1]))]

    def test_encode(self):
        for (length, encoded_bytes) in self.test_cases:
            self.assertEqual(ObjectLength.encode(length), encoded_bytes)

    def test_decode(self):
        for (length, encoded_bytes) in self.test_cases:
            self.assertEqual(ObjectLength.decode(encoded_bytes)[0], length)
