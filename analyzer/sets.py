from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_network, IPv4Network, IPv6Network
from typing import Iterable, List, Optional, Sequence, Set, Union


Net = Union[IPv4Network, IPv6Network]


def _collapse(nets: Iterable[Net]) -> List[Net]:
    # ipaddress.collapse_addresses returns an iterator
    import ipaddress
    return list(ipaddress.collapse_addresses(list(nets)))


@dataclass(frozen=True)
class AddressSet:
    _any: bool
    nets: tuple[Net, ...]

    @staticmethod
    def any() -> "AddressSet":
        return AddressSet(True, ())

    @staticmethod
    def empty() -> "AddressSet":
        return AddressSet(False, ())

    @staticmethod
    def from_cidrs(cidrs: Sequence[str]) -> "AddressSet":
        nets: List[Net] = []
        for c in cidrs:
            nets.append(ip_network(str(c), strict=False))
        nets = _collapse(nets)
        return AddressSet(False, tuple(nets))

    def is_any(self) -> bool:
        return self._any

    def is_empty(self) -> bool:
        return (not self._any) and len(self.nets) == 0

    def intersects(self, other: "AddressSet") -> bool:
        if self._any and not other.is_empty():
            return True
        if other._any and not self.is_empty():
            return True
        if self.is_empty() or other.is_empty():
            return False
        for a in self.nets:
            for b in other.nets:
                if a.overlaps(b):
                    return True
        return False

    def is_subset_of(self, other: "AddressSet") -> bool:
        if other._any:
            return not self.is_empty()
        if self._any:
            return other._any  # only subset of ANY
        if self.is_empty():
            return True
        if other.is_empty():
            return False
        # every net in self must be covered by some net in other
        for a in self.nets:
            covered = any(a.subnet_of(b) for b in other.nets)
            if not covered:
                return False
        return True

    def is_superset_of(self, other: "AddressSet") -> bool:
        return other.is_subset_of(self)

    def union(self, other: "AddressSet") -> "AddressSet":
        if self._any or other._any:
            # ANY ∪ X = ANY, but keep empties sane
            return AddressSet.any()
        nets = _collapse(list(self.nets) + list(other.nets))
        return AddressSet(False, tuple(nets))

    def contains_ip(self, ip: str) -> bool:
        if self._any:
            return True
        if self.is_empty():
            return False
        import ipaddress
        addr = ipaddress.ip_address(ip)
        return any(addr in n for n in self.nets)


@dataclass(frozen=True)
class PortSet:
    _any: bool
    ports: frozenset[int]

    @staticmethod
    def any() -> "PortSet":
        return PortSet(True, frozenset())

    @staticmethod
    def empty() -> "PortSet":
        return PortSet(False, frozenset())

    @staticmethod
    def from_values(values: Optional[Sequence[int]]) -> "PortSet":
        if values is None:
            return PortSet.empty()
        s: Set[int] = set()
        for v in values:
            if v is None:
                continue
            iv = int(v)
            if 0 <= iv <= 65535:
                s.add(iv)
        return PortSet(False, frozenset(s))

    def is_any(self) -> bool:
        return self._any

    def is_empty(self) -> bool:
        return (not self._any) and len(self.ports) == 0

    def intersects(self, other: "PortSet") -> bool:
        if self._any and not other.is_empty():
            return True
        if other._any and not self.is_empty():
            return True
        if self.is_empty() or other.is_empty():
            return False
        return len(self.ports.intersection(other.ports)) > 0

    def is_subset_of(self, other: "PortSet") -> bool:
        if other._any:
            return not self.is_empty()
        if self._any:
            return other._any
        if self.is_empty():
            return True
        if other.is_empty():
            return False
        return self.ports.issubset(other.ports)

    def is_superset_of(self, other: "PortSet") -> bool:
        return other.is_subset_of(self)


@dataclass(frozen=True)
class ProtocolSet:
    _any: bool
    protos: frozenset[str]

    @staticmethod
    def any() -> "ProtocolSet":
        return ProtocolSet(True, frozenset())

    @staticmethod
    def empty() -> "ProtocolSet":
        return ProtocolSet(False, frozenset())

    @staticmethod
    def from_values(values: Optional[Sequence[str]]) -> "ProtocolSet":
        if values is None:
            return ProtocolSet.empty()
        s: Set[str] = set()
        for v in values:
            if not v:
                continue
            s.add(str(v).lower())
        return ProtocolSet(False, frozenset(s))

    def is_any(self) -> bool:
        return self._any

    def is_empty(self) -> bool:
        return (not self._any) and len(self.protos) == 0

    def intersects(self, other: "ProtocolSet") -> bool:
        if self._any and not other.is_empty():
            return True
        if other._any and not self.is_empty():
            return True
        if self.is_empty() or other.is_empty():
            return False
        return len(self.protos.intersection(other.protos)) > 0

    def is_subset_of(self, other: "ProtocolSet") -> bool:
        if other._any:
            return not self.is_empty()
        if self._any:
            return other._any
        if self.is_empty():
            return True
        if other.is_empty():
            return False
        return self.protos.issubset(other.protos)

    def is_superset_of(self, other: "ProtocolSet") -> bool:
        return other.is_subset_of(self)
