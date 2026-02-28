from __future__ import annotations

from ipaddress import ip_address
from typing import Any, Dict, List, Optional, Tuple

from ..canonical import CanonicalConfig, CanonicalRoute
from ..sets import AddressSet


def _anomaly(a_type: str, level: str, description: str, related: List[str], risk: int, evidence: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "type": a_type,
        "level": level,
        "description": description,
        "related_rules": related,
        "risk_score": risk,
        "evidence": evidence,
    }


def _best_route_for_ip(ip: str, routes: List[CanonicalRoute]) -> Optional[CanonicalRoute]:
    addr = ip_address(ip)
    candidates = [r for r in routes if r.enabled and addr in r.prefix]
    if not candidates:
        return None
    # longest prefix first, then metric, then order
    candidates.sort(key=lambda r: (-r.prefix.prefixlen, r.metric, r.order, r.route_id))
    return candidates[0]


def detect_routing_anomalies(cfg: CanonicalConfig) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    routes = [r for r in cfg.routes if r.enabled]

    # Conflict: same prefix, different next-hop
    for i in range(len(routes)):
        for j in range(i + 1, len(routes)):
            a, b = routes[i], routes[j]
            if a.prefix == b.prefix and a.next_hop != b.next_hop:
                out.append(_anomaly(
                    "Routing: Conflict",
                    "warning",
                    f"Конфликт маршрутов {a.route_id} и {b.route_id}: одинаковый prefix, разный next-hop.",
                    [a.route_id, b.route_id],
                    65,
                    {"prefix": str(a.prefix), "a_nh": a.next_hop, "b_nh": b.next_hop},
                ))

    # Overlap / Shadowing / PriorityError
    for i in range(len(routes)):
        for j in range(i + 1, len(routes)):
            a, b = routes[i], routes[j]

            # for CIDR networks, overlap implies subnet_of relation or equality
            if not a.prefix.overlaps(b.prefix):
                continue

            # pick specific vs general
            if a.prefix == b.prefix:
                continue

            if a.prefix.subnet_of(b.prefix):
                specific, general = a, b
            elif b.prefix.subnet_of(a.prefix):
                specific, general = b, a
            else:
                # should not happen for proper CIDR, but keep as overlap
                out.append(_anomaly(
                    "Routing: Overlap",
                    "info",
                    f"Маршруты {a.route_id} и {b.route_id} пересекаются по адресному пространству.",
                    [a.route_id, b.route_id],
                    20,
                    {},
                ))
                continue

            if specific.next_hop != general.next_hop:
                out.append(_anomaly(
                    "Routing: Overlap",
                    "info",
                    f"Маршруты {specific.route_id} и {general.route_id} перекрываются (subnet/supernet) и имеют разные next-hop.",
                    [specific.route_id, general.route_id],
                    20,
                    {"specific": str(specific.prefix), "general": str(general.prefix)},
                ))

            # Shadowing / PriorityError when general has better or equal metric than specific
            if general.metric < specific.metric and general.next_hop != specific.next_hop:
                out.append(_anomaly(
                    "Routing: Shadowing",
                    "warning",
                    f"Маршрут {specific.route_id} затенён: суперсеть {general.route_id} имеет лучший metric.",
                    [general.route_id, specific.route_id],
                    60,
                    {"general_metric": general.metric, "specific_metric": specific.metric},
                ))

            if general.metric <= specific.metric and general.next_hop != specific.next_hop:
                out.append(_anomaly(
                    "Routing: PriorityError",
                    "warning",
                    f"Ошибочный приоритет: суперсеть {general.route_id} не хуже по metric, чем подсеть {specific.route_id}.",
                    [general.route_id, specific.route_id],
                    55,
                    {"general_metric": general.metric, "specific_metric": specific.metric},
                ))

    # Blackhole / HangingRoute (zone-based heuristics)
    known_nets = AddressSet.empty()
    if not cfg.internal_networks.is_empty():
        known_nets = known_nets.union(cfg.internal_networks)
    if not cfg.external_networks.is_empty():
        known_nets = known_nets.union(cfg.external_networks)
    # also consider routed prefixes as "known"
    for r in routes:
        known_nets = known_nets.union(AddressSet.from_cidrs([str(r.prefix)]))

    for r in routes:
        nh = r.next_hop.strip()
        try:
            # validate ip
            ip_address(nh)
        except Exception:
            out.append(_anomaly(
                "Routing: Blackhole",
                "warning",
                f"Маршрут {r.route_id}: некорректный next-hop (не IP).",
                [r.route_id],
                60,
                {"next_hop": nh},
            ))
            continue

        if not known_nets.contains_ip(nh):
            out.append(_anomaly(
                "Routing: Blackhole",
                "warning",
                f"Маршрут {r.route_id}: next-hop {nh} не попадает ни в одну известную сеть (возможная 'черная дыра').",
                [r.route_id],
                60,
                {"next_hop": nh},
            ))

        # HangingRoute: internal prefix but gateway outside internal
        if not cfg.internal_networks.is_empty():
            if AddressSet.from_cidrs([str(r.prefix)]).is_subset_of(cfg.internal_networks) and not cfg.internal_networks.contains_ip(nh):
                out.append(_anomaly(
                    "Routing: HangingRoute",
                    "warning",
                    f"Маршрут {r.route_id}: внутренняя сеть, но next-hop вне internal-зоны.",
                    [r.route_id],
                    55,
                    {"prefix": str(r.prefix), "next_hop": nh},
                ))

    # Loop: build recursion graph via best route for next-hop
    next_map: Dict[str, str] = {}
    for r in routes:
        br = _best_route_for_ip(r.next_hop, routes)
        if br and br.route_id != r.route_id:
            next_map[r.route_id] = br.route_id

    # detect cycles
    seen = set()
    in_stack = set()

    def dfs(u: str, path: List[str]) -> None:
        seen.add(u)
        in_stack.add(u)
        v = next_map.get(u)
        if v:
            if v not in seen:
                dfs(v, path + [v])
            elif v in in_stack:
                if v in path:
                    idx = path.index(v)
                    cycle = path[idx:] + [v]
                    out.append(_anomaly(
                        "Routing: Loop",
                        "warning",
                        "Обнаружено потенциальное зацикливание маршрутизации (рекурсивные next-hop).",
                        cycle,
                        70,
                        {"cycle": cycle},
                    ))
        in_stack.discard(u)

    for node in list(next_map.keys()):
        if node not in seen:
            dfs(node, [node])

    return out
