# analyzer/anomaly_detectors.py
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Iterable

# -----------------------------
# Нормализованные сущности
# -----------------------------

@dataclass(frozen=True)
class NetSpec:
    nets: tuple[ipaddress._BaseNetwork, ...]  # набор префиксов
    any: bool = False                         # "любой адрес"

@dataclass(frozen=True)
class PortRange:
    start: int
    end: int

@dataclass(frozen=True)
class SvcSpec:
    # proto: 6 TCP, 17 UDP, 1 ICMP и т.п.
    # ports: None = любой порт (для TCP/UDP), либо список диапазонов
    proto: int | None
    ports: tuple[PortRange, ...] | None  # None -> any
    any: bool = False

@dataclass(frozen=True)
class RuleSpec:
    idx: int
    name: str
    enabled: bool
    action: str  # "pass"/"drop" и т.п.
    src: NetSpec
    dst: NetSpec
    svc: SvcSpec
    logging: bool
    inverse_src: bool
    inverse_dst: bool

@dataclass(frozen=True)
class NatSpec:
    idx: int
    name: str
    enabled: bool
    nat_type: str  # dnat/static/dynamic/masquerade
    src: NetSpec
    dst: NetSpec
    svc: SvcSpec
    value: NetSpec  # адрес трансляции (упрощенно)
    port_value: SvcSpec  # трансляция порта (если есть)


# -----------------------------
# Парсинг / flatten NetEntity, ServiceEntity
# -----------------------------

def _to_network(ip: str) -> ipaddress._BaseNetwork | None:
    ip = (ip or "").strip()
    if not ip:
        return None
    try:
        # ipaddress принимает и "10.0.0.1" (как /32)
        return ipaddress.ip_network(ip, strict=False)
    except Exception:
        return None

def _flatten_net_entities(items: list[Any] | None) -> list[dict]:
    if not items:
        return []
    out: list[dict] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        t = (it.get("type") or "").lower()
        if t == "netobject":
            out.append(it)
        elif t == "group" and (it.get("subtype") or "").lower() == "netobject":
            members = it.get("members") or []
            if isinstance(members, list):
                for m in members:
                    if isinstance(m, dict):
                        out.append(m)
    return out

def _flatten_service_entities(items: list[Any] | None) -> list[dict]:
    if not items:
        return []
    out: list[dict] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        t = (it.get("type") or "").lower()
        if t == "service":
            out.append(it)
        elif t == "group" and (it.get("subtype") or "").lower() == "service":
            members = it.get("members") or []
            if isinstance(members, list):
                for m in members:
                    if isinstance(m, dict):
                        out.append(m)
    return out

def normalize_nets(entities: list[Any] | None) -> NetSpec:
    flat = _flatten_net_entities(entities)
    nets: list[ipaddress._BaseNetwork] = []

    # эвристика any: пусто => any (как и в большинстве FW)
    if not flat:
        return NetSpec(nets=tuple(), any=True)

    for e in flat:
        ip = e.get("ip")
        net = _to_network(ip)
        if net is None:
            continue
        if str(net) in ("0.0.0.0/0", "::/0"):
            return NetSpec(nets=tuple(), any=True)
        nets.append(net)

    if not nets:
        # если не смогли распарсить — считаем any, но ниже дадим отдельную аномалию "INVALID_NET"
        return NetSpec(nets=tuple(), any=True)

    # объединять префиксы строго не обязательно; достаточно нормальной формы
    return NetSpec(nets=tuple(nets), any=False)

def _parse_ports(s: str) -> tuple[PortRange, ...] | None:
    """
    "80" -> 80-80
    "80,443" -> два диапазона
    "1000-2000" -> диапазон
    "" -> None (any)
    """
    s = (s or "").strip()
    if s == "":
        return None

    ranges: list[PortRange] = []
    parts = [p.strip() for p in s.split(",") if p.strip()]
    for p in parts:
        if "-" in p:
            a, b = p.split("-", 1)
            try:
                start = int(a.strip())
                end = int(b.strip())
                if 0 <= start <= end <= 65535:
                    ranges.append(PortRange(start, end))
            except Exception:
                continue
        else:
            try:
                v = int(p)
                if 0 <= v <= 65535:
                    ranges.append(PortRange(v, v))
            except Exception:
                continue

    if not ranges:
        return None
    return tuple(ranges)

def normalize_service(services: list[Any] | None) -> SvcSpec:
    flat = _flatten_service_entities(services)

    # пусто => any service
    if not flat:
        return SvcSpec(proto=None, ports=None, any=True)

    # В КОНТИНЕНТ service массивом: правило может содержать несколько сервисов.
    # Для формальной логики (вложение/пересечение) удобнее трактовать как объединение.
    # Здесь упрощаем до:
    # - если есть TCP/UDP с пустым dst => any
    # - иначе берём "самое широкое" объединение (proto None/any если разные протоколы)
    protos: set[int] = set()
    port_ranges: list[PortRange] = []
    any_ports = False

    for s in flat:
        proto = s.get("proto")
        if isinstance(proto, int):
            protos.add(proto)

        # dst = порт назначения
        dst = (s.get("dst") or "").strip()
        pr = _parse_ports(dst)

        # если TCP/UDP и порт пустой => any ports
        if proto in (6, 17) and pr is None:
            any_ports = True
        elif pr is not None:
            port_ranges.extend(list(pr))

        # ICMP (proto 1/58) портов нет -> считаем "any" по портам
        if proto in (1, 58):
            any_ports = True

    if not protos:
        return SvcSpec(proto=None, ports=None, any=True)

    if len(protos) > 1:
        # разные протоколы => считаем any-proto (иначе логика вложений резко усложняется)
        return SvcSpec(proto=None, ports=None, any=True)

    proto = next(iter(protos))
    if any_ports:
        return SvcSpec(proto=proto, ports=None, any=True)

    if not port_ranges:
        return SvcSpec(proto=proto, ports=None, any=True)

    return SvcSpec(proto=proto, ports=tuple(port_ranges), any=False)


def normalize_fw_rule(idx: int, r: dict) -> RuleSpec:
    return RuleSpec(
        idx=idx,
        name=str(r.get("name") or ""),
        enabled=bool(r.get("is_enabled", True)),
        action=str(r.get("rule_action") or "").lower(),
        src=normalize_nets(r.get("src") or []),
        dst=normalize_nets(r.get("dst") or []),
        svc=normalize_service(r.get("service") or []),
        logging=bool(r.get("logging", True)),
        inverse_src=bool(r.get("is_inverse_src", False)),
        inverse_dst=bool(r.get("is_inverse_dst", False)),
    )

def normalize_nat_rule(idx: int, r: dict) -> NatSpec:
    return NatSpec(
        idx=idx,
        name=str(r.get("name") or ""),
        enabled=bool(r.get("is_enabled", True)),
        nat_type=str(r.get("nat_type") or "").lower(),
        src=normalize_nets(r.get("src") or []),
        dst=normalize_nets(r.get("dst") or []),
        svc=normalize_service(r.get("service") or []),
        value=normalize_nets(r.get("value") or []),
        port_value=normalize_service(r.get("port_value") or []),
    )


# -----------------------------
# Множества пакетов: сравнение/пересечение/вложение
# -----------------------------

def _net_overlaps(a: NetSpec, b: NetSpec) -> bool:
    if a.any or b.any:
        return True
    for x in a.nets:
        for y in b.nets:
            if x.overlaps(y):
                return True
    return False

def _net_covers(a: NetSpec, b: NetSpec) -> bool:
    """
    a ⊇ b (a покрывает b)
    """
    if a.any:
        return True
    if b.any:
        return False
    # каждую сеть b должен покрывать какой-то префикс из a
    for bn in b.nets:
        ok = False
        for an in a.nets:
            # bn подсеть an?
            if bn.subnet_of(an):
                ok = True
                break
        if not ok:
            return False
    return True

def _ports_overlap(a: tuple[PortRange, ...] | None, b: tuple[PortRange, ...] | None) -> bool:
    if a is None or b is None:
        return True
    for x in a:
        for y in b:
            if not (x.end < y.start or y.end < x.start):
                return True
    return False

def _ports_cover(a: tuple[PortRange, ...] | None, b: tuple[PortRange, ...] | None) -> bool:
    if a is None:
        return True
    if b is None:
        return False
    # каждый диапазон b должен быть полностью покрыт хотя бы одним диапазоном a
    for br in b:
        ok = False
        for ar in a:
            if ar.start <= br.start and ar.end >= br.end:
                ok = True
                break
        if not ok:
            return False
    return True

def _svc_overlaps(a: SvcSpec, b: SvcSpec) -> bool:
    if a.any or b.any:
        return True
    if a.proto is None or b.proto is None:
        return True
    if a.proto != b.proto:
        return False
    return _ports_overlap(a.ports, b.ports)

def _svc_covers(a: SvcSpec, b: SvcSpec) -> bool:
    if a.any:
        return True
    if b.any:
        return False
    # протокол
    if a.proto is None:
        return True
    if b.proto is None:
        return False
    if a.proto != b.proto:
        return False
    # порты
    return _ports_cover(a.ports, b.ports)

def rule_overlaps(a: RuleSpec, b: RuleSpec) -> bool:
    return _net_overlaps(a.src, b.src) and _net_overlaps(a.dst, b.dst) and _svc_overlaps(a.svc, b.svc)

def rule_covers(a: RuleSpec, b: RuleSpec) -> bool:
    # inverse_* сейчас не разворачиваем в полноценную булеву алгебру — фиксируем как ограничение модели.
    # Можно добавить отдельную аномалию "INVERSE_FIELDS_UNSUPPORTED_FOR_FORMAL_CHECK".
    if a.inverse_src or a.inverse_dst or b.inverse_src or b.inverse_dst:
        return False
    return _net_covers(a.src, b.src) and _net_covers(a.dst, b.dst) and _svc_covers(a.svc, b.svc)


# NAT домен/образ (упрощенная модель из PDF)
@dataclass(frozen=True)
class NatDomain:
    src: NetSpec
    dst: NetSpec
    svc: SvcSpec

def nat_domain(n: NatSpec) -> NatDomain:
    # Унифицированно: домен = (src,dst,svc) ровно как в твоём JSON-формате
    return NatDomain(src=n.src, dst=n.dst, svc=n.svc)

def nat_domain_overlaps(a: NatDomain, b: NatDomain) -> bool:
    return _net_overlaps(a.src, b.src) and _net_overlaps(a.dst, b.dst) and _svc_overlaps(a.svc, b.svc)

def nat_domain_covers(a: NatDomain, b: NatDomain) -> bool:
    return _net_covers(a.src, b.src) and _net_covers(a.dst, b.dst) and _svc_covers(a.svc, b.svc)


# -----------------------------
# Детекторы аномалий (по PDF)
# -----------------------------

def detect_filterrule_anomalies(fw_rules: list[dict]) -> list[dict]:
    rules: list[RuleSpec] = []
    anomalies: list[dict] = []

    for i, r in enumerate(fw_rules or []):
        if isinstance(r, dict):
            rules.append(normalize_fw_rule(i, r))

    # 0) базовые (технические) — но не “вместо”, а “в дополнение”
    for a in rules:
        if not a.enabled:
            anomalies.append(_anom_fw(a, "FW_DISABLED_RULE", "Отключенное правило фильтрации", "low",
                                     "Правило присутствует, но выключено."))
        if a.action == "pass" and not a.logging:
            anomalies.append(_anom_fw(a, "FW_ALLOW_NO_LOG", "Разрешающее правило без логирования", "medium",
                                     "Разрешающее правило не пишет события."))

    # 1) затенение (shadowing): i покрывает j, действия разные, i выше по порядку
    # 2) избыточность (redundancy): i покрывает j, действия одинаковые
    # 3) обобщение (generalization): j покрывает i, действия разные, j ниже
    # 4) корреляция (correlation): пересечение есть, но ни одно не покрывает другое, действия разные

    n = len(rules)
    for j in range(n):
        Rj = rules[j]
        for i in range(j):
            Ri = rules[i]

            # если модель не может корректно сравнить из-за inverse — можно сигнализировать отдельной аномалией
            if Ri.inverse_src or Ri.inverse_dst or Rj.inverse_src or Rj.inverse_dst:
                # не спамим для каждой пары — только как факт у правила
                continue

            if not rule_overlaps(Ri, Rj):
                continue

            Ri_covers_Rj = rule_covers(Ri, Rj)
            Rj_covers_Ri = rule_covers(Rj, Ri)

            if Ri_covers_Rj and Ri.action != Rj.action:
                anomalies.append(_anom_fw(
                    Rj, "FW_SHADOWING", "Затенение (shadowing)", "high",
                    "Правило полностью покрывается предыдущим правилом с другим действием и фактически не влияет на политику.",
                    details={"shadowed_by_index": Ri.idx, "shadowed_by_name": Ri.name, "prev_action": Ri.action, "this_action": Rj.action}
                ))
                continue

            if Ri_covers_Rj and Ri.action == Rj.action:
                anomalies.append(_anom_fw(
                    Rj, "FW_REDUNDANCY", "Избыточность (redundancy)", "low",
                    "Правило покрывается предыдущим правилом с тем же действием; удаление обычно не меняет политику.",
                    details={"covered_by_index": Ri.idx, "covered_by_name": Ri.name}
                ))
                continue

            # обобщение: ниже стоит более общее правило с другим действием
            if Rj_covers_Ri and Ri.action != Rj.action:
                anomalies.append(_anom_fw(
                    Rj, "FW_GENERALIZATION", "Обобщение (generalization)", "medium",
                    "Ниже расположено более общее правило с другим действием; порядок критичен, при перестановке получится затенение.",
                    details={"more_specific_index": Ri.idx, "more_specific_name": Ri.name, "specific_action": Ri.action, "general_action": Rj.action}
                ))
                # не continue: обобщение может сосуществовать с корреляциями в других парах

            # корреляция: пересечение есть, но нет полного покрытия
            if (not Ri_covers_Rj) and (not Rj_covers_Ri) and (Ri.action != Rj.action):
                anomalies.append(_anom_fw(
                    Rj, "FW_CORRELATION", "Корреляция (correlation)", "medium",
                    "Правила пересекаются по области действия и имеют разные действия; порядок влияет на итоговую политику.",
                    details={"correlates_with_index": Ri.idx, "correlates_with_name": Ri.name, "other_action": Ri.action, "this_action": Rj.action}
                ))

    return anomalies


def detect_natrule_anomalies(nat_rules: list[dict], fw_rules: list[dict] | None = None) -> list[dict]:
    nats: list[NatSpec] = []
    anomalies: list[dict] = []

    for i, r in enumerate(nat_rules or []):
        if isinstance(r, dict):
            nats.append(normalize_nat_rule(i, r))

    # базовое
    for a in nats:
        if not a.enabled:
            anomalies.append(_anom_nat(a, "NAT_DISABLED_RULE", "Отключенное NAT-правило", "low",
                                      "NAT-правило выключено (возможный мусор/устаревшая запись)."))

    # домены и “значения трансляции”
    doms = [nat_domain(x) for x in nats]

    # 1) перекрывающиеся NAT-правила с разной трансляцией
    # 2) конфликтные переводы (полный совпадающий домен, разные трансляции)
    for j in range(len(nats)):
        Rj = nats[j]
        Dj = doms[j]
        for i in range(j):
            Ri = nats[i]
            Di = doms[i]

            if not nat_domain_overlaps(Di, Dj):
                continue

            # сравнение “значения” трансляции: (value, port_value) как образ f(x)
            same_value = _same_net(Ri.value, Rj.value) and _same_svc(Ri.port_value, Rj.port_value)

            # домены совпадают полностью?
            dom_equal = nat_domain_covers(Di, Dj) and nat_domain_covers(Dj, Di)

            if dom_equal and not same_value:
                anomalies.append(_anom_nat(
                    Rj, "NAT_CONFLICT_TRANSLATION", "Конфликтные переводы", "high",
                    "Два правила имеют одинаковый домен (область действия), но задают разные значения трансляции.",
                    details={"conflicts_with_index": Ri.idx, "conflicts_with_name": Ri.name}
                ))
                continue

            if (not dom_equal) and (not same_value):
                anomalies.append(_anom_nat(
                    Rj, "NAT_OVERLAP_DIFFERENT_TRANSLATION", "Перекрывающиеся NAT-правила", "medium",
                    "Домены NAT-правил пересекаются, но трансляции различаются; результат зависит от порядка/приоритета.",
                    details={"overlaps_with_index": Ri.idx, "overlaps_with_name": Ri.name}
                ))

    # 3) непокрытые сети (неохваченные) — практичная реализация:
    # Internal берём как объединение источников из FilterRules (если дали) + src из NAT.
    internal = _collect_internal_space(nats, fw_rules or [])
    covered = _collect_nat_domain_space(nats)
    if internal and covered:
        gaps = _subtract_internal(internal, covered)
        if gaps:
            anomalies.append({
                "scope": "nat",
                "code": "NAT_UNCOVERED_INTERNAL",
                "title": "Непокрытые сети (неохваченные)",
                "severity": "medium",
                "rule_index": None,
                "rule_name": "",
                "description": "Часть внутреннего адресного пространства не попадает ни под один домен NAT-правил.",
                "details": {"uncovered_prefixes": [str(x) for x in gaps[:50]], "uncovered_count": len(gaps)}
            })

    # 4) Double NAT / циклы: если value одного правила попадает в домен другого (цепочка)
    # Граф: i -> j, если value(i) пересекается с domain(j).src (упрощённо).
    graph = _nat_graph(nats)
    cycles = _find_cycles(graph)
    for cyc in cycles:
        anomalies.append({
            "scope": "nat",
            "code": "NAT_DOUBLE_NAT_OR_CYCLE",
            "title": "Двойная трансляция (Double NAT) / цикл",
            "severity": "high",
            "rule_index": cyc[0],
            "rule_name": nats[cyc[0]].name if 0 <= cyc[0] < len(nats) else "",
            "description": "Результат трансляции одного правила попадает в домен другого; возможны каскады преобразований или циклическая трансляция.",
            "details": {"cycle_rule_indexes": cyc, "cycle_rule_names": [nats[i].name for i in cyc if 0 <= i < len(nats)]}
        })

    return anomalies


def detect_all(fw_rules: list[dict], nat_rules: list[dict]) -> list[dict]:
    fw = detect_filterrule_anomalies(fw_rules or [])
    nat = detect_natrule_anomalies(nat_rules or [], fw_rules=fw_rules or [])
    return fw + nat


# -----------------------------
# Helpers: anomaly dict builders
# -----------------------------

def _anom_fw(r: RuleSpec, code: str, title: str, severity: str, description: str, details: dict | None = None) -> dict:
    return {
        "scope": "fw",
        "code": code,
        "title": title,
        "severity": severity,
        "rule_index": r.idx,
        "rule_name": r.name,
        "description": description,
        "details": details or {},
    }

def _anom_nat(r: NatSpec, code: str, title: str, severity: str, description: str, details: dict | None = None) -> dict:
    return {
        "scope": "nat",
        "code": code,
        "title": title,
        "severity": severity,
        "rule_index": r.idx,
        "rule_name": r.name,
        "description": description,
        "details": details or {},
    }


def _same_net(a: NetSpec, b: NetSpec) -> bool:
    if a.any != b.any:
        return False
    if a.any:
        return True
    return set(map(str, a.nets)) == set(map(str, b.nets))

def _same_svc(a: SvcSpec, b: SvcSpec) -> bool:
    if a.any != b.any:
        return False
    if a.any:
        return True
    if a.proto != b.proto:
        return False
    if a.ports is None and b.ports is None:
        return True
    if (a.ports is None) != (b.ports is None):
        return False
    return set((p.start, p.end) for p in (a.ports or ())) == set((p.start, p.end) for p in (b.ports or ()))


# -----------------------------
# NAT: Internal/Covered/Cycles helpers
# -----------------------------

def _collect_internal_space(nats: list[NatSpec], fw_rules: list[dict]) -> list[ipaddress._BaseNetwork]:
    nets: list[ipaddress._BaseNetwork] = []

    # из NAT src
    for n in nats:
        if not n.src.any:
            nets.extend(list(n.src.nets))

    # из FW src (как “внутреннее пространство”)
    for i, r in enumerate(fw_rules or []):
        if not isinstance(r, dict):
            continue
        src = normalize_nets(r.get("src") or [])
        if not src.any:
            nets.extend(list(src.nets))

    # уникализируем строково
    uniq = {}
    for x in nets:
        uniq[str(x)] = x
    return list(uniq.values())

def _collect_nat_domain_space(nats: list[NatSpec]) -> list[ipaddress._BaseNetwork]:
    nets: list[ipaddress._BaseNetwork] = []
    for n in nats:
        # домен по src (для твоего универсального формата это наиболее практично)
        if not n.src.any:
            nets.extend(list(n.src.nets))
    uniq = {}
    for x in nets:
        uniq[str(x)] = x
    return list(uniq.values())

def _subtract_internal(internal: list[ipaddress._BaseNetwork], covered: list[ipaddress._BaseNetwork]) -> list[ipaddress._BaseNetwork]:
    """
    Упрощение: считаем непокрытым префикс internal[i], если ни один covered не покрывает его полностью.
    """
    gaps: list[ipaddress._BaseNetwork] = []
    for inn in internal:
        ok = False
        for cov in covered:
            if inn.subnet_of(cov):
                ok = True
                break
        if not ok:
            gaps.append(inn)
    return gaps

def _nat_graph(nats: list[NatSpec]) -> dict[int, set[int]]:
    graph: dict[int, set[int]] = {i: set() for i in range(len(nats))}
    doms = [nat_domain(x) for x in nats]

    for i, ni in enumerate(nats):
        # value(i) как результат трансляции
        if ni.value.any:
            continue
        for j, dj in enumerate(doms):
            if i == j:
                continue
            # если translated-address пересекается с src домена другого правила => возможна каскадность
            if _net_overlaps(NetSpec(ni.value.nets, any=False), dj.src):
                graph[i].add(j)

    return graph

def _find_cycles(graph: dict[int, set[int]]) -> list[list[int]]:
    """
    Простая DFS-детекция циклов. Возвращает циклы как список индексов правил.
    """
    cycles: list[list[int]] = []
    color: dict[int, int] = {v: 0 for v in graph}  # 0 white, 1 gray, 2 black
    stack: list[int] = []
    pos: dict[int, int] = {}

    def dfs(v: int):
        color[v] = 1
        pos[v] = len(stack)
        stack.append(v)

        for to in graph.get(v, ()):
            if color[to] == 0:
                dfs(to)
            elif color[to] == 1:
                # цикл: часть стека
                start = pos.get(to, 0)
                cyc = stack[start:] + [to]
                # нормализуем (чтобы не дублировать одинаковые)
                cycles.append(cyc)

        stack.pop()
        color[v] = 2

    for v in graph:
        if color[v] == 0:
            dfs(v)

    # дедуп по строке
    uniq = []
    seen = set()
    for c in cycles:
        key = "->".join(map(str, c))
        if key not in seen:
            seen.add(key)
            uniq.append(c)
    return uniq
