from enum import IntEnum


class ErrorStatus(IntEnum):
    no_error = 0
    too_big = 1
    no_such_name = 2
    bad_value = 3
    read_only = 4
    generic_error = 5


class SNMPVersion(IntEnum):
    v1 = 0
    v2c = 1
    v3 = 2
