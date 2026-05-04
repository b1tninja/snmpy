"""OID handler base classes and concrete implementations.

Provides:
- OIDHandler ABC — Base class for OID value handlers
- StaticValueHandler — For static MIB values
- DynamicValueHandler — For dynamically computed values
- TableHandler — For table-style MIB data
- CounterHandler — For SNMP counter-style values

RFC 1157 §4.1 (Protocol Operations), RFC 1902 (SMIv2)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional, Callable, Sequence, Union
from collections.abc import Iterator

from snmp.enums import ErrorStatus
from ber.object import ObjectIdentifier, Object, Integer, OctetString, Null, Sequence as BERSequence

# ---------------------------------------------------------------------------
# Type aliases for SNMP handler operations
# ---------------------------------------------------------------------------

GetterFn = Callable[[str], object]
"""A getter function: takes an OID string, returns a value."""

SetterFn = Callable[[str, object], bool]
"""A setter function: takes an OID string and value, returns success status."""

OIDHandlerFn = Callable[[str], Optional[object]]
"""A generic OID handler function: takes an OID, returns an optional value."""


class OIDHandler(ABC):
    """Abstract base class for OID value handlers.

    Subclasses implement get(), get_next(), and optionally set() to
    handle SNMP protocol operations for specific OIDs.

    RFC 1157 §4.1 (Protocol Operations), RFC 3416 §4.2 (PDU Operations)
    """

    def __init__(self, oid: str, access: str = "read") -> None:
        """Initialize the handler.

        Args:
            oid: The OID this handler is responsible for.
            access: "read", "write", or "readwrite".
        """
        self.oid = oid
        self.access = access

    @abstractmethod
    def get(self, oid: str) -> Optional[object]:
        """Handle GetRequest for this OID.

        Args:
            oid: The full instance OID being requested.

        Returns:
            The value Object, or None if not found/accessible.
        """
        ...

    @abstractmethod
    def get_next(self, oid: str) -> Optional[str]:
        """Handle GetNextRequest — return successor OID.

        Args:
            oid: The OID to find successor for.

        Returns:
            The next OID in the MIB, or None.
        """
        ...

    def set(self, oid: str, value: object) -> ErrorStatus:
        """Handle SetRequest. Default: read-only."""
        return ErrorStatus.readOnly

    def is_readable(self, community: str = "", oid: str = "") -> bool:
        """Check if community can read this OID."""
        return self.access in ("read", "readwrite")

    def is_writable(self, community: str = "", oid: str = "") -> bool:
        """Check if community can write to this OID."""
        return self.access == "readwrite"

    @property
    def is_leaf(self) -> bool:
        """Whether this handler represents a leaf node (not a table)."""
        return True

    def _to_snmp_object(self, value: object) -> Object:
        """Convert a Python value to an SNMP-compatible BER Object.

        Type mapping (per RFC 1902 SMIV2):
          - int → Integer Object (Counter32, Gauge32, TimeTicks, Unsigned32)
          - bool → Integer Object (0/1)
          - str/bytes → OctetString Object
          - Object → returned as-is
          - anything else → Null Object

        Each BER type (Integer, OctetString, etc.) is a subclass of
        ObjectValue which inherits from bytes. The ``.get_object()``
        method wraps the value in an Object tag for BER encoding.

        Args:
            value: Python value to convert.

        Returns:
            BER Object with appropriate tag.
        """
        if isinstance(value, Object):
            return value
        if isinstance(value, bytes):
            return OctetString(value).get_object()
        if isinstance(value, int) and not isinstance(value, bool):
            try:
                return Integer.from_int(value).get_object()
            except (OverflowError, ValueError):
                # Large integers that don't fit in Integer — fall back to OctetString
                return OctetString(str(value).encode()).get_object()
        if isinstance(value, bool):
            return Integer.from_int(1 if value else 0).get_object()
        if isinstance(value, str):
            return OctetString(value.encode()).get_object()
        from ber.object import Null
        return Null().get_object()


class StaticValueHandler(OIDHandler):
    """Handler for static MIB values that never change.

    Typical use: sysDescr, sysObjectID, or other invariant MIB objects.
    """

    def __init__(self, oid: str, value: object, access: str = "read") -> None:
        """Initialize static value handler.

        Args:
            oid: The OID this handler is responsible for.
            value: The constant value.
            access: "read" (only) since values are static.
        """
        super().__init__(oid, access="read")
        self._value = value

    def get(self, oid: str) -> Optional[object]:
        """Return the static value if OID matches."""
        if oid == self.oid or oid.startswith(self.oid):
            return self._to_snmp_object(self._value)
        return None

    def get_next(self, oid: str) -> Optional[str]:
        """Return this OID as successor."""
        if self.oid > oid:
            return self.oid
        return None


class DynamicValueHandler(OIDHandler):
    """Handler for dynamically computed values.

    Typical use: sysUpTime, interface counters, or other values
    computed at request time from system state.
    """

    def __init__(
        self,
        oid: str,
        getter: GetterFn,
        setter: Optional[SetterFn] = None,
        access: str = "read",
    ) -> None:
        """Initialize dynamic value handler.

        Args:
            oid: The OID this handler is responsible for.
            getter: Function(oid) -> value called on each GetRequest.
            setter: Optional function(oid, value) -> bool called on SetRequest.
            access: "read" or "readwrite".
        """
        super().__init__(oid, access)
        self._getter = getter
        self._setter = setter

    def get(self, oid: str) -> Optional[object]:
        """Compute and return the current value."""
        if oid == self.oid or oid.startswith(self.oid):
            value = self._getter(oid)
            return self._to_snmp_object(value)
        return None

    def get_next(self, oid: str) -> Optional[str]:
        """Return this OID as successor."""
        if self.oid > oid:
            return self.oid
        return None

    def set(self, oid: str, value: object) -> ErrorStatus:
        """Call the setter function if available."""
        if self._setter is None:
            return ErrorStatus.readOnly
        try:
            if self._setter(oid, value):
                return ErrorStatus.noError
            return ErrorStatus.genErr
        except Exception:
            return ErrorStatus.genErr

    def is_writable(self, community: str = "", oid: str = "") -> bool:
        """Check write access (requires setter and readwrite access)."""
        return self._setter is not None and self.access == "readwrite"


class TableHandler(OIDHandler):
    """Handler for table-style MIB data (e.g., ifTable, ipTable).

    Tables are indexed sequences of related OID instances.
    """

    def __init__(
        self,
        base_oid: str,
        rows: Optional[Sequence[dict[str, object]]] = None,
        columns: Optional[Sequence[str]] = None,
        access: str = "read",
    ) -> None:
        """Initialize table handler.

        Args:
            base_oid: The base OID for the table (e.g., "1.3.6.1.2.1.2.2.1").
            rows: List of row dictionaries. Each dict maps column names to values.
            columns: Column names in order.
            access: "read" or "readwrite".
        """
        super().__init__(base_oid, access)
        self._rows: list[dict[str, object]] = rows or []
        self._columns: list[str] = columns or []
        if rows and not columns:
            self._columns = list(rows[0].keys()) if rows else []

    def get(self, oid: str) -> Optional[object]:
        """Get a specific cell or column from the table."""
        for idx, row in enumerate(self._rows, start=1):
            # Match column.N pattern (e.g., ifDescr.1, ifType.1)
            for col_name, col_value in row.items():
                cell_oid = f"{self.oid}.{col_name}.{idx}" if not str(col_name).isdigit() else f"{self.oid}.{col_name}.{idx}"
                if oid == f"{self.oid}.{idx}" or (
                    str(col_name).isdigit() or
                    (isinstance(col_name, str) and oid.startswith(f"{self.oid}." + str(col_name) + "."))
                ):
                    return self._to_snmp_object(col_value)
        return None

    def get_next(self, oid: str) -> Optional[str]:
        """Find the next cell in the table."""
        candidates: list[str] = []
        for idx, row in enumerate(self._rows, start=1):
            for col_name, col_value in row.items():
                cell_oid = f"{self.oid}.{col_name}.{idx}" if isinstance(col_name, str) else f"{self.oid}.{col_name}.{idx}"
                if cell_oid > oid:
                    candidates.append(cell_oid)
        return min(candidates) if candidates else None

    @property
    def is_leaf(self) -> bool:
        """Tables are not leaf nodes."""
        return False

    def add_row(self, row: dict[str, object]) -> None:
        """Add a row to the table."""
        self._rows.append(row)

    def remove_row(self, index: int) -> bool:
        """Remove a row by index."""
        if 0 <= index < len(self._rows):
            self._rows.pop(index)
            return True
        return False

    def get_all_cells(self) -> list[tuple[str, object]]:
        """Get all cells in the table as (oid, value) pairs."""
        cells: list[tuple[str, object]] = []
        for idx, row in enumerate(self._rows, start=1):
            for col_name, col_value in row.items():
                cell_oid = f"{self.oid}.{col_name}.{idx}" if isinstance(col_name, str) else f"{self.oid}.{col_name}.{idx}"
                cells.append((cell_oid, self._to_snmp_object(col_value)))
        return cells


class CounterHandler(OIDHandler):
    """Handler for SNMP counter values (RFC 1212 Counter32/Counter64).

    Counters monotonically increase from 0 and never wrap in application.
    """

    def __init__(
        self,
        oid: str,
        initial_value: int = 0,
        max_value: int = 0xFFFFFFFF,  # Counter32 max
        access: str = "read",
    ) -> None:
        """Initialize counter handler.

        Args:
            oid: The OID for this counter.
            initial_value: Starting counter value.
            max_value: Maximum value before wrapping.
            access: "read" (counters are typically read-only).
        """
        super().__init__(oid, access)
        self._value = initial_value
        self._max_value = max_value

    def get(self, oid: str) -> Optional[object]:
        """Return current counter value."""
        if oid == self.oid or oid.startswith(self.oid):
            return self._to_snmp_object(self._value)
        return None

    def get_next(self, oid: str) -> Optional[str]:
        """Return this OID as successor."""
        if self.oid > oid:
            return self.oid
        return None

    def increment(self, delta: int = 1) -> int:
        """Increment the counter."""
        self._value = (self._value + delta) % (self._max_value + 1)
        return self._value

    def reset(self) -> int:
        """Reset the counter to 0."""
        self._value = 0
        return 0

    def set(self, oid: str, value: object) -> ErrorStatus:
        """Counters cannot be set directly."""
        return ErrorStatus.readOnly


class EnumerableHandler(OIDHandler):
    """Handler for list-based MIB data with lazy iteration via get_next().

    The underlying data is a list of items. Each item maps to multiple
    OID columns (e.g., ifDescr.N, ifType.N, ifAdminStatus.N).

    Supports:
    - get(oid) — Look up by exact OID index
    - get_next(oid) — Lexicographic successor for iteration

    RFC 1156 — MIB-2: ifTable (RFC 2233)
    """

    def __init__(
        self,
        base_oid: str,
        items: Sequence[dict[str, object]],
        columns: dict[str, str],  # Column name -> sub-OID suffix mapping
        access: str = "read",
    ) -> None:
        """Initialize enumerable handler.

        Args:
            base_oid: The base OID for the table (e.g., "1.3.6.1.2.1.2.2.1").
            items: List of row dictionaries. Each dict maps column names to values.
            columns: Mapping of {column_name: sub_oid_suffix} (e.g., {"ifDescr": ".2"}).
            access: "read" or "readwrite".
        """
        super().__init__(base_oid, access)
        self._items: list[dict[str, object]] = list(items)
        self._columns = columns

    @property
    def is_leaf(self) -> bool:
        """Enumerables are not leaf nodes."""
        return False

    def get(self, oid: str) -> Optional[object]:
        """Get a specific cell from the table.

        Looks up the value by matching the OID pattern:
        base_oid.column_name.index

        Args:
            oid: The full instance OID being requested.

        Returns:
            The value, or None if not found.
        """
        for col_name, sub_oid in self._columns.items():
            cell_oid = f"{self.oid}{sub_oid}"
            if oid.startswith(cell_oid + "."):
                suffix = oid[len(cell_oid):].lstrip('.')
                try:
                    idx = int(suffix)
                    if 1 <= idx <= len(self._items):
                        item = self._items[idx - 1]
                        if col_name in item:
                            return self._to_snmp_object(item[col_name])
                except (ValueError, TypeError):
                    continue
        return None

    def get_next(self, oid: str) -> Optional[str]:
        """Find the lexicographic successor of an OID.

        Iterates through all columns and indices to find the next OID
        that is greater than the requested OID. Only returns full cell OIDs
        with indices (e.g., base_oid.column.index), not bare column OIDs.

        Uses proper numeric OID comparison (RFC 2578 §7.1) — components are
        compared as integers, not strings. This ensures 1.3.6.1.2.1.2.2.1.2.1
        (column .2) comes before 1.3.6.1.2.1.2.2.1.10.1 (column .10).

        Args:
            oid: The OID to find successor for.

        Returns:
            The next OID in the table, or None.
        """
        candidates: list[str] = []
        for col_name, sub_oid in self._columns.items():
            cell_oid = f"{self.oid}{sub_oid}"
            for idx, item in enumerate(self._items, start=1):
                cell_with_idx = f"{cell_oid}.{idx}"
                if self._oid_is_greater(cell_with_idx, oid):
                    candidates.append(cell_with_idx)

        return min(candidates, key=self._oid_key) if candidates else None

    @staticmethod
    def _oid_key(oid: str) -> tuple[int, ...]:
        """Convert OID string to tuple of integers for proper numeric comparison."""
        return tuple(int(x) for x in oid.split('.'))

    @staticmethod
    def _oid_is_greater(oid_a: str, oid_b: str) -> bool:
        """Compare OIDs numerically: return True if oid_a > oid_b."""
        parts_a = tuple(int(x) for x in oid_a.split('.'))
        parts_b = tuple(int(x) for x in oid_b.split('.'))
        return parts_a > parts_b

    def get_all_cells(self) -> list[tuple[str, object]]:
        """Get all cells in the table as (oid, value) pairs."""
        cells: list[tuple[str, object]] = []
        for col_name, sub_oid in self._columns.items():
            cell_oid = f"{self.oid}{sub_oid}"
            for idx, item in enumerate(self._items, start=1):
                if col_name in item:
                    cells.append((f"{cell_oid}.{idx}", self._to_snmp_object(item[col_name])))
        return cells

    def add_row(self, row: dict[str, object]) -> None:
        """Add a row to the table."""
        self._items.append(row)

    def remove_row(self, index: int) -> bool:
        """Remove a row by index."""
        if 0 <= index < len(self._items):
            self._items.pop(index)
            return True
        return False


class GeneratorHandler(OIDHandler):
    """Handler for lazy iteration over generators/iterables via get_next() only.

    No get() is supported — only GetNextRequest is valid.
    Useful for streaming data, large datasets, or when you want to
    enumerate items one at a time without loading everything into memory.

    RFC 1156 — MIB-2: Routing table, ARP table (large tables)
    """

    def __init__(
        self,
        base_oid: str,
        generator: Callable[[], Iterator[dict[str, object]]],
        columns: dict[str, str],  # Column name -> sub-OID suffix mapping
        access: str = "read",
    ) -> None:
        """Initialize generator handler.

        Args:
            base_oid: The base OID for the table.
            generator: A callable() -> iterator that yields items on demand.
            columns: Mapping of {column_name: sub_oid_suffix}.
            access: "read" only.
        """
        super().__init__(base_oid, access)
        self._generator = generator
        self._columns = columns
        self._cache: Optional[list[dict[str, object]]] = None
        self._cache_dirty = True

    @property
    def is_leaf(self) -> bool:
        """Generators are not leaf nodes."""
        return False

    def _ensure_cache(self) -> None:
        """Ensure the cache is populated from the generator."""
        if self._cache_dirty:
            self._cache = list(self._generator())
            self._cache_dirty = False

    def get(self, oid: str) -> Optional[object]:
        """Not supported for generators — returns None.

        Generator handlers only support GetNextRequest.
        """
        return None

    def get_next(self, oid: str) -> Optional[str]:
        """Find the lexicographic successor of an OID.

        Iterates through the generator and returns the first OID that
        is greater than the requested OID.

        Args:
            oid: The OID to find successor for.

        Returns:
            The next OID, or None if no more items.
        """
        self._ensure_cache()
        if self._cache is None:
            return None

        candidates: list[str] = []
        for item in self._cache:
            for col_name, sub_oid in self._columns.items():
                cell_oid = f"{self.oid}{sub_oid}"
                if cell_oid > oid:
                    candidates.append(cell_oid)
                    continue
                idx = self._cache.index(item) + 1 if item in self._cache else 0
                cell_with_idx = f"{cell_oid}.{idx}"
                if cell_with_idx > oid:
                    candidates.append(cell_with_idx)

        return min(candidates) if candidates else None


class CompoundHandler(OIDHandler):
    """Handler that combines multiple sub-handlers under a common OID prefix.

    Useful for MIB subtrees where different OIDs are handled by different
    specialized handlers but grouped under one parent.
    """

    def __init__(self, prefix: str) -> None:
        """Initialize compound handler.

        Args:
            prefix: The common OID prefix for all sub-handlers.
        """
        super().__init__(prefix, access="read")
        self._handlers: dict[str, OIDHandler] = {}

    def register(self, oid: str, handler: OIDHandler) -> None:
        """Register a sub-handler for a specific OID."""
        self._handlers[oid] = handler

    def unregister(self, oid: str) -> bool:
        """Remove a sub-handler."""
        if oid in self._handlers:
            del self._handlers[oid]
            return True
        return False

    def get(self, oid: str) -> Optional[object]:
        """Forward to the appropriate sub-handler."""
        for handler_oid, handler in self._handlers.items():
            if oid == handler_oid or oid.startswith(handler_oid + "."):
                result = handler.get(oid)
                if result is not None:
                    return result
        return None

    def get_next(self, oid: str) -> Optional[str]:
        """Find the earliest successor across all sub-handlers."""
        candidates: list[str] = []
        for handler in self._handlers.values():
            next_oid = handler.get_next(oid)
            if next_oid is not None:
                candidates.append(next_oid)
        return min(candidates) if candidates else None

    def list_suboids(self) -> list[str]:
        """List all registered sub-OIDs."""
        return sorted(self._handlers.keys())

    @property
    def is_leaf(self) -> bool:
        """Compound handlers are not leaf nodes."""
        return False