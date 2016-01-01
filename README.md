## SNMPy

A python3 SNMP built with asyncio.

## Example

    $ python3 snmp.py
    <SNMPDatagram version=<Object tag=(TagClassEnum.universal,primitive,UniversalClassTags.integer) value=0>, community=<Object tag=(TagClassEnum.universal,primitive,UniversalClassTags.octet_string) value=public>, pdu=<GetNextRequest request_id=<Object tag=(TagClassEnum.universal,primitive,UniversalClassTags.integer) value=1901134645>, error_status=<Object tag=(TagClassEnum.universal,primitive,UniversalClassTags.integer) value=0>, error_index=<Object tag=(TagClassEnum.universal,primitive,UniversalClassTags.integer) value=0>, variables_bindings=<Object tag=(TagClassEnum.universal,constructed,UniversalClassTags.sequence_of) value=[<Object tag=(TagClassEnum.universal,constructed,UniversalClassTags.sequence_of) value=[<Object tag=(TagClassEnum.universal,primitive,UniversalClassTags.object_identifier) value=1.3.6.1.2.1>, <Object tag=(TagClassEnum.universal,primitive,UniversalClassTags.null) value=b''>]>]>>>
    Sending: b'302602010004067075626c6963a119020471510335020100020100300b300906052b060102010500'
    Received from: ('127.0.0.1', 161) b'307902010004067075626c6963a26c020471510335020100020100305e305c06082b0601020101010004504c696e7578206e696e6a616c6170707920342e322e352d312d4152434820233120534d5020505245454d505420547565204f63742032372030383a31333a3238204345542032303135207838365f3634'
    <SNMPDatagram version=<Object tag=(TagClassEnum.universal,primitive,UniversalClassTags.integer) value=0>, community=<Object tag=(TagClassEnum.universal,primitive,UniversalClassTags.octet_string) value=public>, pdu=<GetResponse request_id=<Object tag=(TagClassEnum.universal,primitive,UniversalClassTags.integer) value=1901134645>, error_status=<Object tag=(TagClassEnum.universal,primitive,UniversalClassTags.integer) value=0>, error_index=<Object tag=(TagClassEnum.universal,primitive,UniversalClassTags.integer) value=0>, variables_bindings=<Object tag=(TagClassEnum.universal,constructed,UniversalClassTags.sequence_of) value=[<Object tag=(TagClassEnum.universal,constructed,UniversalClassTags.sequence_of) value=[<Object tag=(TagClassEnum.universal,primitive,UniversalClassTags.object_identifier) value=1.3.6.1.2.1.1.1.0>, <Object tag=(TagClassEnum.universal,primitive,UniversalClassTags.octet_string) value=Linux ninjalappy 4.2.5-1-ARCH #1 SMP PREEMPT Tue Oct 27 08:13:28 CET 2015 x86_64>]>]>>>

