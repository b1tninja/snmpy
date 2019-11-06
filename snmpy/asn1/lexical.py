import string

_NONBREAKINGHYPHEN = u"\u2011"
_NOBREAKSPACE = u"\u00A0"

CharacterSet = string.ascii_letters + string.digits + r"""!"&'()*,-./:;<=>@[]^_{|}_""" + _NONBREAKINGHYPHEN
Newline = string.whitespace[2:]
Whitespace = string.whitespace + _NOBREAKSPACE

import re
import typing

ReservedWords = ['ABSENT',
                 'ENCODED',
                 'INTERSECTION',
                 'SEQUENCE',
                 'ABSTRACT-SYNTAX',
                 'ENCODING-CONTROL',
                 'ISO646String',
                 'SET',
                 'ALL',
                 'END',
                 'MAX',
                 'SETTINGS',
                 'APPLICATION',
                 'ENUMERATED',
                 'MIN',
                 'SIZE',
                 'AUTOMATIC',
                 'EXCEPT',
                 'MINUS-INFINITY',
                 'STRING',
                 'BEGIN',
                 'EXPLICIT',
                 'NOT-A-NUMBER',
                 'SYNTAX',
                 'BIT',
                 'EXPORTS',
                 'NULL',
                 'T61String',
                 'BMPString',
                 'EXTENSIBILITY',
                 'NumericString',
                 'TAGS',
                 'BOOLEAN',
                 'EXTERNAL',
                 'OBJECT',
                 'TeletexString',
                 'BY',
                 'FALSE',
                 'ObjectDescriptor',
                 'TIME',
                 'CHARACTER',
                 'FROM',
                 'OCTET',
                 'TIME-OF-DAY',
                 'CHOICE',
                 'GeneralizedTime',
                 'OF',
                 'TRUE',
                 'CLASS',
                 'GeneralString',
                 'OID-IRI',
                 'TYPE-IDENTIFIER',
                 'COMPONENT',
                 'GraphicString',
                 'OPTIONAL',
                 'UNION',
                 'COMPONENTS',
                 'IA5String',
                 'PATTERN',
                 'UNIQUE',
                 'CONSTRAINED',
                 'IDENTIFIER',
                 'PDV',
                 'UNIVERSAL',
                 'CONTAINING',
                 'IMPLICIT',
                 'PLUS-INFINITY',
                 'UniversalString',
                 'DATE',
                 'IMPLIED',
                 'PRESENT',
                 'UTCTime',
                 'DATE-TIME',
                 'IMPORTS',
                 'PrintableString',
                 'UTF8String',
                 'DEFAULT',
                 'INCLUDES',
                 'PRIVATE',
                 'VideotexString',
                 'DEFINITIONS',
                 'INSTANCE',
                 'REAL',
                 'VisibleString',
                 'DURATION',
                 'INSTRUCTIONS',
                 'RELATIVE-OID',
                 'WITH',
                 'EMBEDDED',
                 'INTEGER',
                 'RELATIVE-OID-IRI']


class LexicalItem(type):
    name: str
    regex: typing.Union[re.Pattern, str]


class TypeReference(LexicalItem):
    name = "typereference"
    regex = "[A-Z](?:[A-Za-z0-9]|-)*"