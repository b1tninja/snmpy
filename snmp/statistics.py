"""SNMP Statistics — Thread-safe counter tracking for RFC 1907 & RFC 3418.

Implements the snmpGroup (RFC 1907 §2.2) and snmpStatisticsObjects (RFC 3418 §6.6.3).

All counters are atomic and thread-safe. Usage:

    >>> stats = SNMPStatistics()
    >>> stats.increment_incoming()
    >>> stats.increment_bad_community_names()
    >>> stats.snmp_in_pkts  # Get current value
    1
    >>> stats.get_all()  # Get all counters as a dict
    {"snmpInPkts": 1, "snmpInBadCommunityNames": 1, ...}
"""

from __future__ import annotations

import threading
from typing import Dict, Optional


class _AtomicCounter:
    """Thread-safe counter with increment, decrement, get, and reset operations."""

    def __init__(self, initial: int = 0) -> None:
        self._value: int = initial
        self._lock = threading.Lock()

    def increment(self, by: int = 1) -> int:
        """Increment by the given amount (default 1). Returns new value."""
        with self._lock:
            self._value = max(0, self._value + by)
            return self._value

    def decrement(self, by: int = 1) -> int:
        """Decrement by the given amount (default 1). Returns new value."""
        with self._lock:
            self._value = max(0, self._value - by)
            return self._value

    def get(self) -> int:
        """Get the current value."""
        with self._lock:
            return self._value

    def set(self, value: int) -> int:
        """Set the value explicitly. Returns new value."""
        with self._lock:
            self._value = max(0, value)
            return self._value

    def reset(self) -> int:
        """Reset to zero. Returns previous value."""
        with self._lock:
            old = self._value
            self._value = 0
            return old

    def __repr__(self) -> str:
        with self._lock:
            return f"Counter({self._value})"


class SNMPStatistics:
    """SNMP protocol statistics tracker (RFC 1907 §2.2, RFC 3418 §6.6.3).

    Tracks all counter values defined in the snmpGroup and statistics objects.
    All operations are thread-safe via internal locking.

    Attributes:
        snmp_in_pkts: Total SNMP messages delivered to the entity
        snmp_out_pkts: Total SNMP messages sent from the entity
        snmp_in_bad_versions: Unsupported SNMP versions
        snmp_in_bad_community_names: Unknown community names
        snmp_in_bad_community_uses: Disallowed SNMP operations
        snmp_in_asn_parse_errs: ASN.1/BER parsing errors
        snmp_enable_authen_traps: Whether authentication traps are enabled
    """

    def __init__(self) -> None:
        """Initialize all counters to zero."""
        # ------------------------------------------------------------------
        # RFC 1907 snmpGroup — snmpIn* counters
        # ------------------------------------------------------------------
        self.snmp_in_pkts = _AtomicCounter()

        # NOTE: snmpOutPkts (RFC 1213, made obsolete by RFC 1907) is intentionally
        # not tracked here. Use snmp_out_* counters below instead.
        # snmp_out_pkts = { snmp 2 }  — obsolete per RFC 1907

        self.snmp_in_bad_versions = _AtomicCounter()
        self.snmp_in_bad_community_names = _AtomicCounter()
        self.snmp_in_bad_community_uses = _AtomicCounter()
        self.snmp_in_asn_parse_errs = _AtomicCounter()

        # RFC 1213 counters (made obsolete by RFC 1907, kept for compatibility)
        self.snmp_in_too_bigs = _AtomicCounter()        # { snmp 8 }
        self.snmp_in_no_such_names = _AtomicCounter()   # { snmp 9 }
        self.snmp_in_bad_values = _AtomicCounter()      # { snmp 10 }
        self.snmp_in_read_onlys = _AtomicCounter()      # { snmp 11 }
        self.snmp_in_gen_errs = _AtomicCounter()        # { snmp 12 }
        self.snmp_in_total_req_vars = _AtomicCounter()  # { snmp 13 }
        self.snmp_in_total_set_vars = _AtomicCounter()  # { snmp 14 }
        self.snmp_in_get_requests = _AtomicCounter()    # { snmp 15 }
        self.snmp_in_get_nexts = _AtomicCounter()       # { snmp 16 }
        self.snmp_in_set_requests = _AtomicCounter()    # { snmp 17 }
        self.snmp_in_get_responses = _AtomicCounter()   # { snmp 18 }
        self.snmp_in_traps = _AtomicCounter()           # { snmp 19 }

        # ------------------------------------------------------------------
        # RFC 1907 snmpGroup — snmpOut* counters (non-obsolete)
        # ------------------------------------------------------------------
        self.snmp_out_too_bigs = _AtomicCounter()
        self.snmp_out_no_such_names = _AtomicCounter()
        self.snmp_out_bad_values = _AtomicCounter()
        self.snmp_out_gen_errs = _AtomicCounter()
        self.snmp_out_get_requests = _AtomicCounter()
        self.snmp_out_get_nexts = _AtomicCounter()
        self.snmp_out_set_requests = _AtomicCounter()
        self.snmp_out_get_responses = _AtomicCounter()
        self.snmp_out_traps = _AtomicCounter()

        # ------------------------------------------------------------------
        # RFC 3418 framework statistics (SNMPv3)
        # ------------------------------------------------------------------
        self.snmp_unknown_security_levels = _AtomicCounter()
        self.snmp_invalid_msgs = _AtomicCounter()
        self.snmp_sec_failed_snmp_entities = _AtomicCounter()

        # ------------------------------------------------------------------
        # Control counters
        # ------------------------------------------------------------------
        self._snmp_enable_authen_traps = _AtomicCounter(initial=1)  # enabled(1) by default
        self.snmp_silent_drops = _AtomicCounter()
        self.snmp_proxy_drops = _AtomicCounter()

    # ======================================================================
    # SNMPv1/v2c message counters
    # ======================================================================

    def increment_incoming(self) -> int:
        """Called when a valid SNMP message is received. Returns new value."""
        return self.snmp_in_pkts.increment()

    def increment_outgoing(self) -> int:
        """Called when an SNMP message is sent. Returns new value."""
        return self.snmp_out_get_responses.increment()

    def record_bad_version(self) -> int:
        """Record an unsupported SNMP version."""
        return self.snmp_in_bad_versions.increment()

    def record_bad_community_name(self) -> int:
        """Record an unknown community name."""
        return self.snmp_in_bad_community_names.increment()

    def record_bad_community_use(self) -> int:
        """Record a disallowed SNMP operation."""
        return self.snmp_in_bad_community_uses.increment()

    def record_asn_parse_error(self) -> int:
        """Record an ASN.1/BER parsing error."""
        return self.snmp_in_asn_parse_errs.increment()

    def record_bad_value(self) -> int:
        """Record a badValue error status in a response."""
        self.snmp_in_bad_values.increment()
        self.snmp_out_bad_values.increment()
        return self.snmp_out_bad_values.get()

    def record_too_big(self) -> int:
        """Record a tooBig error status in a response."""
        self.snmp_in_too_bigs.increment()
        self.snmp_out_too_bigs.increment()
        return self.snmp_out_too_bigs.get()

    def record_no_such_name(self) -> int:
        """Record a noSuchName error status in a response."""
        self.snmp_in_no_such_names.increment()
        self.snmp_out_no_such_names.increment()
        return self.snmp_out_no_such_names.get()

    def record_generic_error(self) -> int:
        """Record a genErr error status in a response."""
        self.snmp_in_gen_errs.increment()
        self.snmp_out_gen_errs.increment()
        return self.snmp_out_gen_errs.get()

    def record_read_only(self) -> int:
        """Record a readOnly error status in a response."""
        self.snmp_in_read_onlys.increment()
        return self.snmp_in_read_onlys.get()

    # ======================================================================
    # Operation counters
    # ======================================================================

    def record_get_request(self) -> int:
        """Record a processed GetRequest PDU."""
        self.snmp_in_get_requests.increment()
        return self.snmp_in_get_requests.get()

    def record_get_next_request(self) -> int:
        """Record a processed GetNextRequest PDU."""
        self.snmp_in_get_nexts.increment()
        return self.snmp_in_get_nexts.get()

    def record_set_request(self) -> int:
        """Record a processed SetRequest PDU."""
        self.snmp_in_set_requests.increment()
        return self.snmp_in_set_requests.get()

    def record_get_response_sent(self) -> int:
        """Record a sent GetResponse PDU."""
        self.snmp_out_get_responses.increment()
        return self.snmp_out_get_responses.get()

    def record_trap_sent(self) -> int:
        """Record a sent Trap-PDU."""
        self.snmp_in_traps.increment()
        self.snmp_out_traps.increment()
        return self.snmp_out_traps.get()

    # ======================================================================
    # SNMPv3 framework counters
    # ======================================================================

    def record_unknown_security_level(self) -> int:
        """Record an unknown security level (SNMPv3)."""
        return self.snmp_unknown_security_levels.increment()

    def record_invalid_message(self) -> int:
        """Record an invalid SNMP message (SNMPv3)."""
        return self.snmp_invalid_msgs.increment()

    def record_sec_failed_entity(self) -> int:
        """Record a failed security operation on an SNMP entity (SNMPv3)."""
        return self.snmp_sec_failed_snmp_entities.increment()

    def record_silent_drop(self) -> int:
        """Record a silent drop (response too large)."""
        return self.snmp_silent_drops.increment()

    def record_proxy_drop(self) -> int:
        """Record a proxy agent transmission failure."""
        return self.snmp_proxy_drops.increment()

    # ======================================================================
    # Trap control
    # ======================================================================

    def set_authen_traps_enabled(self, enabled: bool) -> int:
        """Enable or disable authenticationFailure traps.

        Args:
            enabled: True to enable traps, False to disable.

        Returns:
            New value (1=enabled, 2=disabled).
        """
        value = 1 if enabled else 2
        return self._snmp_enable_authen_traps.set(value)

    def is_authen_traps_enabled(self) -> bool:
        """Check if authenticationFailure traps are enabled."""
        return self._snmp_enable_authen_traps.get() == 1

    # ======================================================================
    # Bulk operations
    # ======================================================================

    def get_all(self) -> Dict[str, int]:
        """Get all counter values as a dictionary.

        Returns:
            Mapping of counter names to current values.
        """
        return {
            # RFC 1907 snmpGroup — inbound
            "snmpInPkts": self.snmp_in_pkts.get(),
            "snmpInBadVersions": self.snmp_in_bad_versions.get(),
            "snmpInBadCommunityNames": self.snmp_in_bad_community_names.get(),
            "snmpInBadCommunityUses": self.snmp_in_bad_community_uses.get(),
            "snmpInASNParseErrs": self.snmp_in_asn_parse_errs.get(),
            # RFC 1907 snmpGroup — outbound
            "snmpOutTooBigs": self.snmp_out_too_bigs.get(),
            "snmpOutNoSuchNames": self.snmp_out_no_such_names.get(),
            "snmpOutBadValues": self.snmp_out_bad_values.get(),
            "snmpOutGenErrs": self.snmp_out_gen_errs.get(),
            "snmpOutGetRequests": self.snmp_out_get_requests.get(),
            "snmpOutGetNexts": self.snmp_out_get_nexts.get(),
            "snmpOutSetRequests": self.snmp_out_set_requests.get(),
            "snmpOutGetResponses": self.snmp_out_get_responses.get(),
            "snmpOutTraps": self.snmp_out_traps.get(),
            # RFC 3418 framework statistics
            "snmpUnknownSecurityLevels": self.snmp_unknown_security_levels.get(),
            "snmpInvalidMsgs": self.snmp_invalid_msgs.get(),
            "snmpSecFailedSnmpEntities": self.snmp_sec_failed_snmp_entities.get(),
            "snmpSilentDrops": self.snmp_silent_drops.get(),
            "snmpProxyDrops": self.snmp_proxy_drops.get(),
            # Control
            "snmpEnableAuthenTraps": self._snmp_enable_authen_traps.get(),
        }

    def reset_all(self) -> Dict[str, int]:
        """Reset all counters to zero. Returns previous values.

        Returns:
            Snapshot of all counter values before reset.
        """
        snapshot = self.get_all()
        for counter in [
            self.snmp_in_pkts,
            self.snmp_in_bad_versions,
            self.snmp_in_bad_community_names,
            self.snmp_in_bad_community_uses,
            self.snmp_in_asn_parse_errs,
            self.snmp_out_too_bigs,
            self.snmp_out_no_such_names,
            self.snmp_out_bad_values,
            self.snmp_out_gen_errs,
            self.snmp_out_get_requests,
            self.snmp_out_get_nexts,
            self.snmp_out_set_requests,
            self.snmp_out_get_responses,
            self.snmp_out_traps,
            self.snmp_unknown_security_levels,
            self.snmp_invalid_msgs,
            self.snmp_sec_failed_snmp_entities,
            self.snmp_silent_drops,
            self.snmp_proxy_drops,
        ]:
            counter.reset()
        self._snmp_enable_authen_traps.set(1)
        return snapshot

    def get_snmp_group_snapshot(self) -> Dict[str, int]:
        """Get only the snmpGroup (RFC 1907) counters.

        Returns:
            Mapping of snmpGroup counter names to values.
        """
        return {
            "snmpInPkts": self.snmp_in_pkts.get(),
            "snmpInBadVersions": self.snmp_in_bad_versions.get(),
            "snmpInBadCommunityNames": self.snmp_in_bad_community_names.get(),
            "snmpInBadCommunityUses": self.snmp_in_bad_community_uses.get(),
            "snmpInASNParseErrs": self.snmp_in_asn_parse_errs.get(),
            "snmpEnableAuthenTraps": self._snmp_enable_authen_traps.get(),
        }


# =============================================================================
# Global singleton
# =============================================================================

_statistics: Optional[SNMPStatistics] = None
_statistics_lock = threading.Lock()


def get_statistics() -> SNMPStatistics:
    """Get the global SNMPStatistics singleton."""
    global _statistics
    with _statistics_lock:
        if _statistics is None:
            _statistics = SNMPStatistics()
        return _statistics


def reset_statistics() -> None:
    """Reset the global statistics singleton."""
    global _statistics
    with _statistics_lock:
        if _statistics is not None:
            _statistics.reset_all()
            _statistics = None