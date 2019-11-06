from unittest import TestCase

from ...types import ASN1ObjectIdentifier


class TestObjectIdentifier(TestCase):
    examples = [('1.3.0', bytes([43, 0])),
                ('1.3.127', bytes([43, 127])),
                ('1.3.128', bytes([43, 129, 0])),
                ('1.3.8571.3.2', bytes.fromhex('2BC27B0302')),
                ('2.100.3', bytes([180, 3]))]

    def encode(self):
        for known_string, known_encoding in self.examples:
            obj = ObjectIdentifier(known_string)
            self.assertEqual(known_string, str(obj))
            self.assertEqual(known_encoding, bytes(obj))

    def decode(self):
        for known_string, known_encoding in self.examples:
            obj = ObjectIdentifier(known_encoding)
            self.assertEqual(known_string, str(obj))

    def invalid(self):
        with self.assertRaises(AssertionError):
            ObjectIdentifier('3.0')
        with self.assertRaises(AssertionError):
            ObjectIdentifier('1.41')
