from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .sets import AddressSet, PortSet, ProtocolSet


# ----------------------------
# Address / Service Objects
# ----------------------------

@dataclass
class AddressObject:
    """
    Canonical address object.

    kind:
      - any
      - network
      - host
      - group

    value: CIDR for network/host
    members: list of names (for group)
    """
    name: str
    kind: str
    value: Optional[str] = None
    members: List[str] = field(default_factory=list)


@dataclass
class ServiceObject:
    """
    Canonical service object.

    kind:
      - any
      - service
      - group

    proto: tcp/udp/icmp/any (for kind=service)
    dst_ports/src_ports: list of ranges (start,end) inclusive (for kind=service)
    members: list of service names (for kind=group)
    """
    name: str
    kind: str
    proto: str = "any"
    dst_ports: List[Tuple[int, int]] = field(default_factory=list)
    src_ports: List[Tuple[int, int]] = field(default_factory=list)
    members: List[str] = field(default_factory=list)


# ----------------------------
# Policy Rules
# ----------------------------

@dataclass
class CanonicalRule:
    rule_id: str
    order: int
    action: str  # allow|deny
    enabled: bool = True
    log: bool = True
    comment: str = ""

    # raw references (for unused detection / reporting)
    src_refs: List[str] = field(default_factory=list)
    dst_refs: List[str] = field(default_factory=list)
    service_refs: List[str] = field(default_factory=list)

    # resolved sets (for analysis)
    src_addrs: AddressSet = field(default_factory=AddressSet.empty)
    dst_addrs: AddressSet = field(default_factory=AddressSet.empty)
    protocols: ProtocolSet = field(default_factory=ProtocolSet.empty)
    dst_ports: PortSet = field(default_factory=PortSet.empty)

    # warnings bound to this rule
    unresolved: List[str] = field(default_factory=list)

    def is_any_any_any_allow(self) -> bool:
        return (
            self.enabled
            and self.action == "allow"
            and self.src_addrs.is_any()
            and self.dst_addrs.is_any()
            and self.protocols.is_any()
            and self.dst_ports.is_any()
        )


# ----------------------------
# NAT
# ----------------------------

@dataclass
class CanonicalNatRule:
    rule_id: str
    order: int
    enabled: bool = True
    comment: str = ""

    # raw refs (important for unused/broken groups detection)
    in_refs: List[str] = field(default_factory=list)
    out_refs: List[str] = field(default_factory=list)

    # resolved sets (minimal canonicalization)
    in_addrs: AddressSet = field(default_factory=AddressSet.empty)
    out_addrs: AddressSet = field(default_factory=AddressSet.empty)

    unresolved: List[str] = field(default_factory=list)


# ----------------------------
# Routing
# ----------------------------

@dataclass
class CanonicalRoute:
    route_id: str
    order: int
    enabled: bool = True
    prefix_raw: str = ""           # as it was in JSON
    prefix: AddressSet = field(default_factory=AddressSet.empty)
    next_hop: str = ""
    metric: int = 0
    comment: str = ""
    zone: str = "unknown"          # internal|external|unknown
    unresolved: List[str] = field(default_factory=list)


# ----------------------------
# IAM
# ----------------------------

@dataclass(frozen=True)
class Privilege:
    obj: str
    action: str


@dataclass
class CanonicalIamRole:
    name: str
    parents: List[str] = field(default_factory=list)
    privileges: Set[Privilege] = field(default_factory=set)


@dataclass
class CanonicalIamRule:
    rule_id: str
    order: int
    effect: str = "deny"   # allow|deny
    enabled: bool = True
    comment: str = ""

    subjects: Set[str] = field(default_factory=set)
    objects: Set[str] = field(default_factory=set)
    actions: Set[str] = field(default_factory=set)


# ----------------------------
# Whole Config
# ----------------------------

@dataclass
class CanonicalConfig:
    vendor: str = "kontinent"
    version: str = "unknown"

    objects: Dict[str, AddressObject] = field(default_factory=dict)
    services: Dict[str, ServiceObject] = field(default_factory=dict)

    rules: List[CanonicalRule] = field(default_factory=list)

    nat_rules: List[CanonicalNatRule] = field(default_factory=list)
    routes: List[CanonicalRoute] = field(default_factory=list)

    iam_roles: Dict[str, CanonicalIamRole] = field(default_factory=dict)
    iam_rules: List[CanonicalIamRule] = field(default_factory=list)
    iam_checklist: List[Privilege] = field(default_factory=list)

    internal_networks: AddressSet = field(default_factory=AddressSet.empty)
    external_networks: AddressSet = field(default_factory=AddressSet.empty)

    parse_messages: List[str] = field(default_factory=list)

    def rules_sorted(self) -> List[CanonicalRule]:
        return sorted(self.rules, key=lambda r: r.order)

    def nat_sorted(self) -> List[CanonicalNatRule]:
        return sorted(self.nat_rules, key=lambda r: r.order)

    def routes_sorted(self) -> List[CanonicalRoute]:
        return sorted(self.routes, key=lambda r: r.order)

    def iam_rules_sorted(self) -> List[CanonicalIamRule]:
        return sorted(self.iam_rules, key=lambda r: r.order)
