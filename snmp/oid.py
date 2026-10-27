"""OID leaves and packs — lean named OID registries for RE / tooling.

Not a full SMIv2 compiler. Metadata (syntax / access / scalar) is optional
hints for docs, CLI listing, and unwrap helpers — SET values are not validated
against ``syntax``.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Iterable, Iterator, Mapping, Optional, Union

from ber.object import ObjectIdentifier

OidLike = Union[str, ObjectIdentifier, "Oid"]

# Global registry of named packs (populated via register_pack).
PACKS: dict[str, "OidPack"] = {}


@dataclass(frozen=True, slots=True)
class Oid:
    """A named OID leaf or tree root with light metadata."""

    name: str
    oid: str
    syntax: Optional[str] = None
    access: Optional[str] = None  # "ro" | "rw" | "wo"
    scalar: bool = False
    doc: str = ""

    def as_object_identifier(self) -> ObjectIdentifier:
        """Return a BER ``ObjectIdentifier`` for this leaf."""
        return ObjectIdentifier.from_string(self.oid)

    def instance(self, *index: int) -> Oid:
        """Append table indices (e.g. supply column + hrDevice + supplyIndex)."""
        if not index:
            return self
        suffix = ".".join(str(i) for i in index)
        return replace(
            self,
            name=f"{self.name}.{suffix}" if self.name else suffix,
            oid=f"{self.oid}.{suffix}",
            scalar=True,
        )

    def __str__(self) -> str:
        return self.oid

    def __repr__(self) -> str:
        return f"Oid({self.name!r}, {self.oid!r})"


class OidPack:
    """Named collection of ``Oid`` leaves (vendor or MIB slice)."""

    def __init__(
        self,
        name: str,
        oids: Iterable[Oid],
        *,
        pen: Optional[int] = None,
        doc: str = "",
    ) -> None:
        self.name = name
        self.pen = pen
        self.doc = doc
        self._by_name: dict[str, Oid] = {}
        self._by_oid: dict[str, Oid] = {}
        for leaf in oids:
            if leaf.name in self._by_name:
                raise ValueError(f"duplicate Oid name {leaf.name!r} in pack {name!r}")
            self._by_name[leaf.name] = leaf
            self._by_oid[leaf.oid] = leaf

    def __getitem__(self, name: str) -> Oid:
        return self._by_name[name]

    def get(self, name: str, default: Optional[Oid] = None) -> Optional[Oid]:
        return self._by_name.get(name, default)

    def by_oid(self, dotted: str) -> Optional[Oid]:
        return self._by_oid.get(dotted)

    def __contains__(self, name: str) -> bool:
        return name in self._by_name

    def __iter__(self) -> Iterator[Oid]:
        return iter(self._by_name.values())

    def __len__(self) -> int:
        return len(self._by_name)

    def names(self) -> Iterable[str]:
        return self._by_name.keys()

    def scalars(self) -> list[Oid]:
        return [o for o in self if o.scalar]

    def trees(self) -> list[Oid]:
        return [o for o in self if not o.scalar]

    def as_mapping(self) -> Mapping[str, Oid]:
        return self._by_name

    def __repr__(self) -> str:
        pen = f", pen={self.pen}" if self.pen is not None else ""
        return f"OidPack({self.name!r}, {len(self)} oids{pen})"


def register_pack(pack: OidPack, *, replace: bool = False) -> OidPack:
    """Register *pack* in the global ``PACKS`` map (by ``pack.name``)."""
    if pack.name in PACKS and not replace:
        raise ValueError(f"OidPack {pack.name!r} already registered")
    PACKS[pack.name] = pack
    return pack


def get_pack(name: str) -> OidPack:
    """Return a registered pack or raise ``KeyError``."""
    return PACKS[name]


def resolve_oid(oid: OidLike) -> str:
    """Normalize ``str`` / ``ObjectIdentifier`` / ``Oid`` to a dotted string."""
    if isinstance(oid, Oid):
        return oid.oid
    if isinstance(oid, ObjectIdentifier):
        return str(oid)
    if isinstance(oid, str):
        text = oid.strip()
        if not text:
            raise ValueError("empty OID")
        # Allow pack:name shorthand when pack is registered
        if ":" in text and not text[0].isdigit():
            pack_name, leaf = text.split(":", 1)
            pack = PACKS.get(pack_name)
            if pack is None:
                raise KeyError(f"unknown OID pack {pack_name!r}")
            if leaf not in pack:
                raise KeyError(f"unknown OID {leaf!r} in pack {pack_name!r}")
            return pack[leaf].oid
        return text.lstrip(".")
    raise TypeError(f"resolve_oid: unsupported type {type(oid).__name__}")


def resolve_symbolic(pack_name: str, leaf: str) -> Oid:
    """Look up ``PACKS[pack_name][leaf]``."""
    pack = get_pack(pack_name)
    if leaf not in pack:
        raise KeyError(f"unknown OID {leaf!r} in pack {pack_name!r}")
    return pack[leaf]


__all__ = [
    "Oid",
    "OidLike",
    "OidPack",
    "PACKS",
    "get_pack",
    "register_pack",
    "resolve_oid",
    "resolve_symbolic",
]
