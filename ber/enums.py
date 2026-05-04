"""BER tag class and universal class enums."""

from __future__ import annotations

from enum import IntEnum


class TagClassEnum(IntEnum):
    """ASN.1 BER tag classes."""

    universal = 0
    application = 1
    context_specific = 2
    private = 3


class UniversalClassTags(IntEnum):
    """ASN.1 Universal class tags."""

    eoc = 0
    boolean = 1
    integer = 2
    bit_string = 3
    octet_string = 4
    null = 5
    object_identifier = 6
    object_descriptor = 7
    external = 8
    real = 9
    enumerated = 10
    embedded_pdv = 11
    utf8_string = 12
    realative_oid = 13
    # reserved = 14
    # reserved = 15
    sequence_of = 16
    set_of = 17
    numeric_string = 18
    printable_string = 19
    t61_string = 20
    videotex_string = 21
    ia5string = 22
    utc_time = 23
    generalized_time = 24
    graphic_string = 25
    visible_string = 26
    general_string = 27
    universal_string = 28
    character_string = 29
    bmp_string = 30


class ApplicationTags(IntEnum):
    """SNMP SMIv2 Application type tags (RFC 1902).

    These are APPLICATION class tag values used by SNMPv2 management types.
    """

    ip_address = 0
    counter32 = 1
    gauge32 = 2
    time_ticks = 3
    opaque = 4
    # reserved = 5
    counter64 = 6
