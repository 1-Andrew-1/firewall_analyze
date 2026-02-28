from __future__ import annotations

from typing import Any, Dict, List

from ..canonical import CanonicalConfig, CanonicalNatRule


def _translation_equal(a: CanonicalNatRule, b: CanonicalNatRule) -> bool:
    return a.out_addrs.equals(b.out_addrs) and a.out_ports.equals(b.out_ports)


def detect_nat_anomalies(cfg: CanonicalConfig) -> List[Dict[str, Any]]:
    """
    NAT anomalies (локально, внутри устройства):
      1) Overlap: пересекающиеся домены при разных трансляциях
      2) ConflictTranslation: одинаковый домен, разные трансляции (неоднозначность)
      3) UncoveredInternal: внутренние сети не покрыты NAT (если internal_networks заданы)
      4) Cycle / DoubleNAT: цепочки и циклы по NAT
    """
    findings: List[Dict[str, Any]] = []
    nat = [r for r in cfg.nat_sorted() if r.enabled]
    n = len(nat)

    # 1-2) overlap / conflict
    for i in range(n):
        a = nat[i]
        for j in range(i + 1, n):
            b = nat[j]

            domain_intersects = a.in_addrs.intersects(b.in_addrs) and a.in_ports.intersects(b.in_ports)
            if not domain_intersects:
                continue

            domain_equal = a.in_addrs.equals(b.in_addrs) and a.in_ports.equals(b.in_ports)
            if domain_equal and not _translation_equal(a, b):
                findings.append(
                    {
                        "type": "NAT: ConflictTranslation",
                        "description": "Конфликтные переводы: одинаковый домен, разные трансляции (неоднозначность).",
                        "related_rules": f"{a.nat_id} ↔ {b.nat_id}",
                        "level": "critical",
                    }
                )
                continue

            if (not domain_equal) and (not _translation_equal(a, b)):
                findings.append(
                    {
                        "type": "NAT: Overlap",
                        "description": "Перекрывающиеся NAT-правила: домены пересекаются при разных трансляциях.",
                        "related_rules": f"{a.nat_id} ↔ {b.nat_id}",
                        "level": "warning",
                    }
                )

    # 3) uncovered internal networks (если заданы зоны)
    if (not cfg.internal_networks.is_empty()) and (not cfg.internal_networks.is_any()) and nat:
        # быстрый консервативный критерий
        if not any(r.in_addrs.is_any() for r in nat):
            if not any(cfg.internal_networks.is_subset_of(r.in_addrs) for r in nat):
                findings.append(
                    {
                        "type": "NAT: UncoveredInternal",
                        "description": "Непокрытые сети: часть внутренних адресов не охвачена NAT (трафик наружу может не выйти).",
                        "related_rules": ", ".join(r.nat_id for r in nat[:10]) + (" ..." if len(nat) > 10 else ""),
                        "level": "warning",
                    }
                )

    # 4) double NAT / cycles
    edges: Dict[str, List[str]] = {r.nat_id: [] for r in nat}
    for a in nat:
        for b in nat:
            if a.nat_id == b.nat_id:
                continue
            if a.out_addrs.intersects(b.in_addrs) and a.out_ports.intersects(b.in_ports):
                edges[a.nat_id].append(b.nat_id)

    visited: Dict[str, int] = {}  # 0/1/2
    stack: List[str] = []
    cycles: List[List[str]] = []

    def dfs(u: str) -> None:
        visited[u] = 1
        stack.append(u)
        for v in edges.get(u, []):
            if visited.get(v, 0) == 0:
                dfs(v)
            elif visited.get(v) == 1:
                if v in stack:
                    idx = stack.index(v)
                    cycles.append(stack[idx:] + [v])
        stack.pop()
        visited[u] = 2

    for r in nat:
        if visited.get(r.nat_id, 0) == 0:
            dfs(r.nat_id)

    if cycles:
        for c in cycles[:5]:
            findings.append(
                {
                    "type": "NAT: Cycle",
                    "description": "Цикл/каскад трансляции (Double NAT): результат одного правила попадает в домен другого, возможны цепочки и зацикливание.",
                    "related_rules": " → ".join(c),
                    "level": "critical",
                }
            )
    else:
        # double NAT без цикла: путь длиной >= 2
        for u, vs in edges.items():
            for v in vs:
                if edges.get(v):
                    findings.append(
                        {
                            "type": "NAT: DoubleNAT",
                            "description": "Двойная трансляция: результат NAT попадает под действие следующего NAT-правила.",
                            "related_rules": f"{u} → {v}",
                            "level": "warning",
                        }
                    )
                    return findings  # не спамим

    return findings
