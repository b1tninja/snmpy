from unittest import TestCase

from ..datagram import SNMPDatagram


class TestSNMPDatagram(TestCase):
    def test_decode(self):
        examples = map(bytes.fromhex,
                       ['302602010004067075626c6963a119020452447053020100020100300b300906052b060102010500',
                        '307902010004067075626c6963a26c020452447053020100020100305e305c06082b0601020101010004504c696e7578206e696e6a616c6170707920342e322e352d312d4152434820233120534d5020505245454d505420547565204f63742032372030383a31333a3238204345542032303135207838365f3634',
                        '302902010004067075626c6963a11c020452447054020100020100300e300c06082b060102010101000500',
                        '303302010004067075626c6963a2260204524470540201000201003018301606082b06010201010200060a2b06010401bf0803020a'])

        for buffer in examples:
            datagram = SNMPDatagram(buffer)
            print(datagram)
            # encoded = bytes(decoded)
            # TODO: __cmp__ or __hash__ perhaps
            # Not always true for BER
            #  DER uses a canonical form, eg: representation of booleans, and ambiguous length encodings
            assert encoded == datagram
