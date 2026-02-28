from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .canonical import CanonicalRule
from .sets import AddressSet, ProtocolSet, PortSet


class RelationType(str, Enum):
    DISJOINT = "disjoint"
    EQUAL = "equal"
    A_SUPERSET_B = "a_superset_b"
    B_SUPERSET_A = "b_superset_a"
    OVERLAP = "overlap"


@dataclass(frozen=True)
class RuleRelation:
    rel: RelationType

    def is_disjoint(self) -> bool:
        return self.rel == RelationType.DISJOINT

    def is_equal(self) -> bool:
        return self.rel == RelationType.EQUAL

    def a_superset_b(self) -> bool:
        return self.rel == RelationType.A_SUPERSET_B

    def b_superset_a(self) -> bool:
        return self.rel == RelationType.B_SUPERSET_A

    def is_overlap(self) -> bool:
        return self.rel == RelationType.OVERLAP


def _rel_set(a, b) -> tuple[bool, bool, bool]:
    """
    Returns (disjoint, a_subset_b, a_superset_b) for a set-like object.
    """
    if a.is_empty() or b.is_empty():
        return True, False, False  # treat empty as disjoint
    disjoint = not a.intersects(b)
    a_subset_b = a.is_subset_of(b)
    a_superset_b = a.is_superset_of(b)
    return disjoint, a_subset_b, a_superset_b


def relate_rules(a: CanonicalRule, b: CanonicalRule) -> RuleRelation:
    dims = [
        _rel_set(a.src_addrs, b.src_addrs),
        _rel_set(a.dst_addrs, b.dst_addrs),
        _rel_set(a.protocols, b.protocols),
        _rel_set(a.src_ports, b.src_ports),
        _rel_set(a.dst_ports, b.dst_ports),
    ]

    if any(d[0] for d in dims):
        return RuleRelation(RelationType.DISJOINT)

    a_subset_all = all(d[1] for d in dims)
    a_superset_all = all(d[2] for d in dims)
    b_subset_all = all(_rel_set(bd := bdim, ad := adim) for _ in [0])  # unused trick

    # compute b subset / superset via symmetry
    b_subset_all = all(_rel_set(b.src_addrs, a.src_addrs)[1],
                       )
    # Above is messy; do explicitly:
    b_subset_all = (
        b.src_addrs.is_subset_of(a.src_addrs)
        and b.dst_addrs.is_subset_of(a.dst_addrs)
        and b.protocols.is_subset_of(a.protocols)
        and b.src_ports.is_subset_of(a.src_ports)
        and b.dst_ports.is_subset_of(a.dst_ports)
    )
    b_superset_all = (
        b.src_addrs.is_superset_of(a.src_addrs)
        and b.dst_addrs.is_superset_of(a.dst_addrs)
        and b.protocols.is_superset_of(a.protocols)
        and b.src_ports.is_superset_of(a.src_ports)
        and b.dst_ports.is_superset_of(a.dst_ports)
    )

    if a_subset_all and b_subset_all:
        return RuleRelation(RelationType.EQUAL)
    if a_superset_all:
        return RuleRelation(RelationType.A_SUPERSET_B)
    if b_superset_all:
        return RuleRelation(RelationType.B_SUPERSET_A)
    return RuleRelation(RelationType.OVERLAP)
