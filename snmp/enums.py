"""SNMP-specific enums."""

from __future__ import annotations

from enum import IntEnum


class ErrorStatus(IntEnum):
    """SNMP error status codes.
    
    SNMPv1 (RFC 1157 §4.1.1): noError, tooBig, noSuchName, badValue, readOnly, genErr
    SNMPv2 (RFC 1905 §4.1): adds noAccess, wrongType, wrongLength, wrongEncoding,
            wrongValue, noCreation, inconsistentValue, resourceUnavailable,
            commitFailed, undoFailed, authorizationError, notWritable, inconsistentName
    """

    # SNMPv1 error codes
    no_error = 0
    too_big = 1
    no_such_name = 2
    bad_value = 3
    read_only = 4
    generic_error = 5

    # SNMPv2 additional error codes (RFC 1905 §4.1)
    no_access = 6
    wrong_type = 7
    wrong_length = 8
    wrong_encoding = 9
    wrong_value = 10
    no_creation = 11
    inconsistent_value = 12
    resource_unavailable = 13
    commit_failed = 14
    undo_failed = 15
    authorization_error = 16
    not_writable = 17
    inconsistent_name = 18

    # SNMPv3 exception types (RFC 3416 §4.2.5, RFC 3584 §4.2.2.2)
    no_such_object = 200
    no_such_instance = 201
    end_of_mib_view = 202

    @classmethod
    def from_error_code(cls, code: int) -> "ErrorStatus":
        """Create ErrorStatus from SNMPv1 error code (0-5)."""
        try:
            return cls(code)
        except ValueError:
            return cls.no_error

    @classmethod
    def from_snmpv2_code(cls, code: int) -> "ErrorStatus":
        """Create ErrorStatus from SNMPv2 error code (0-18)."""
        if 0 <= code <= 18:
            return cls(code)
        return cls.no_error

    @classmethod
    def from_exception_code(cls, code: int) -> "ErrorStatus":
        """Create ErrorStatus from SNMPv3 exception code (200-202)."""
        mapping = {
            200: cls.no_such_object,
            201: cls.no_such_instance,
            202: cls.end_of_mib_view,
        }
        return mapping.get(code, cls.no_error)

    def to_snmpv1_error(self) -> "ErrorStatus":
        """Map SNMPv2/SNMPv3 error to SNMPv1 error code.
        
        RFC 3584 §4.4 (Error Status Mappings):
        - noError → noError
        - tooBig → tooBig
        - noAccess → noSuchName
        - wrongType → noSuchName
        - wrongLength → noSuchName
        - wrongEncoding → noSuchName
        - wrongValue → noSuchName
        - noCreation → noSuchName
        - inconsistentValue → noSuchName
        - resourceUnavailable → genErr
        - noSuchObject → noSuchName
        - noSuchInstance → noSuchName
        - endOfMibView → noSuchName
        - commitFailed → genErr
        - undoFailed → genErr
        - authorizationError → noSuchName
        - notWritable → genErr
        - inconsistentName → genErr
        """
        mapping = {
            self.no_error: self.no_error,
            self.too_big: self.too_big,
            self.no_access: self.no_such_name,
            self.wrong_type: self.no_such_name,
            self.wrong_length: self.no_such_name,
            self.wrong_encoding: self.no_such_name,
            self.wrong_value: self.no_such_name,
            self.no_creation: self.no_such_name,
            self.inconsistent_value: self.no_such_name,
            self.resource_unavailable: self.generic_error,
            self.no_such_object: self.no_such_name,
            self.no_such_instance: self.no_such_name,
            self.end_of_mib_view: self.no_such_name,
            self.commit_failed: self.generic_error,
            self.undo_failed: self.generic_error,
            self.authorization_error: self.no_such_name,
            self.not_writable: self.generic_error,
            self.inconsistent_name: self.generic_error,
        }
        return mapping.get(self, self.no_error)


class SNMPException(IntEnum):
    """SNMPv3 exception codes for SNMPv1 response mapping.
    
    RFC 3584 §4.2.2.2 (Mapping SNMPv2 Exceptions):
    - noSuchObject (200) → noSuchName for SNMPv1 responses
    - noSuchInstance (201) → noSuchName for SNMPv1 responses
    - endOfMibView (202) → noSuchName for SNMPv1 responses
    """
    
    no_such_object = 200
    no_such_instance = 201
    end_of_mib_view = 202

    @staticmethod
    def is_exception(error_status: int) -> bool:
        """Check if an error code is an SNMPv3 exception."""
        return error_status in (200, 201, 202)

    @staticmethod
    def map_to_snmpv1(exception_code: int) -> int:
        """Map SNMPv3 exception code to SNMPv1 error code.
        
        RFC 3584 §4.2.2.2: All SNMPv2 exceptions map to noSuchName (2).
        """
        if exception_code in (200, 201, 202):
            return 2  # noSuchName
        return exception_code  # Not an exception, return as-is


class SNMPVersion(IntEnum):
    """SNMP protocol versions."""

    v1 = 0
    v2c = 1
    v3 = 2