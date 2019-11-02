import binascii
from unittest import TestCase

from ber.object import ObjectIdentifier


class TestObjectIdentifier(TestCase):
    examples = [('1.3.0', bytes([43, 0])),
                ('1.3.127', bytes([43, 127])),
                ('1.3.128', bytes([43, 129, 0])),
                ('1.3.8571.3.2', binascii.a2b_hex('2BC27B0302')),
                ('2.100.3', bytes([180, 3])),
                ]

    def test_from_string(self):
        for known_string, known_encoding in self.examples:
            print(known_string, binascii.hexlify(known_encoding))
            obj = ObjectIdentifier.from_string(known_string)
            encoding = bytes(obj)
            self.assertEqual(known_encoding, encoding)

    def test_to_string(self):
        for known_string, known_encoding in self.examples:
            obj = ObjectIdentifier(known_encoding)
            string = str(obj)
            print(known_string, binascii.hexlify(known_encoding), string)
            self.assertEqual(known_string, string)
        with self.assertRaises(AssertionError):
            ObjectIdentifier.from_string('3.0')
        with self.assertRaises(AssertionError):
            ObjectIdentifier.from_string('1.41')
