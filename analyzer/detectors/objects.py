from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Set

from ..canonical import CanonicalConfig


def _looks_like_cidr(s: str) -> bool:
    s = (s or "").strip()
    if "/" not in s:
        return False
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except Exception:
        return False


def detect_objects_anomalies(cfg: CanonicalConfig) -> List[Dict[str, Any]]:
    """
    Object/Service level anomalies (beyond pure rule relations):
      - UnusedObject / UnusedService
      - BrokenObjectGroup / BrokenServiceGroup
      - InvalidAddressObject
    """
    anomalies: List[Dict[str, Any]] = []
    anomalies.extend(_detect_broken_groups(cfg))
    anomalies.extend(_detect_invalid_address_objects(cfg))
    anomalies.extend(_detect_unused(cfg))
    return anomalies


def _detect_broken_groups(cfg: CanonicalConfig) -> List[Dict[str, Any]]:
    res: List[Dict[str, Any]] = []

    # Address groups
    for name, obj in cfg.objects.items():
        if obj.kind != "group":
            continue
        missing = []
        for m in obj.members:
            if not m:
                continue
            ms = str(m).strip()
            if not ms or ms.lower() == "any":
                continue
            if _looks_like_cidr(ms):
                continue
            if ms not in cfg.objects:
                missing.append(ms)

        if missing:
            res.append(
                {
                    "type": "BrokenObjectGroup",
                    "description": f"Группа адресов '{name}' содержит ссылки на несуществующие объекты: {', '.join(sorted(set(missing)))}.",
                    "related_rules": name,
                    "level": "warning",
                }
            )

    # Service groups
    for name, svc in cfg.services.items():
        if svc.kind != "group":
            continue
        missing = []
        for m in svc.members:
            if not m:
                continue
            ms = str(m).strip()
            if not ms or ms.lower() == "any":
                continue
            # inline tcp/80 also allowed in policy, но в группе обычно так не делают — не считаем ошибкой
            if ms not in cfg.services:
                missing.append(ms)

        if missing:
            res.append(
                {
                    "type": "BrokenServiceGroup",
                    "description": f"Группа сервисов '{name}' содержит ссылки на несуществующие сервисы: {', '.join(sorted(set(missing)))}.",
                    "related_rules": name,
                    "level": "warning",
                }
            )

    return res


def _detect_invalid_address_objects(cfg: CanonicalConfig) -> List[Dict[str, Any]]:
    res: List[Dict[str, Any]] = []

    for name, obj in cfg.objects.items():
        if obj.kind not in ("network", "host"):
            continue
        if not obj.value or not str(obj.value).strip():
            res.append(
                {
                    "type": "InvalidAddressObject",
                    "description": f"Адресный объект '{name}' имеет пустое значение (ожидался CIDR).",
                    "related_rules": name,
                    "level": "warning",
                }
            )
            continue
        val = str(obj.value).strip()
        try:
            ipaddress.ip_network(val, strict=False)
        except Exception:
            res.append(
                {
                    "type": "InvalidAddressObject",
                    "description": f"Адресный объект '{name}' содержит невалидный CIDR: '{val}'.",
                    "related_rules": name,
                    "level": "warning",
                }
            )

    return res


def _detect_unused(cfg: CanonicalConfig) -> List[Dict[str, Any]]:
    """
    Unused items detection with group expansion.

    Important:
    - if group is used, its members are considered used transitively.
    - inline CIDRs are ignored (they are not objects).
    """
    used_objects: Set[str] = set()
    used_services: Set[str] = set()

    def use_object(ref: str, depth: int = 0) -> None:
        if depth > 20:
            return
        r = (ref or "").strip()
        if not r or r.lower() == "any":
            return
        if _looks_like_cidr(r):
            return
        if r in used_objects:
            return
        used_objects.add(r)
        obj = cfg.objects.get(r)
        if obj and obj.kind == "group":
            for m in obj.members:
                use_object(str(m), depth + 1)

    def use_service(ref: str, depth: int = 0) -> None:
        if depth > 20:
            return
        r = (ref or "").strip()
        if not r or r.lower() == "any":
            return
        # allow inline like tcp/80 -> not a named service
        if "/" in r:
            return
        if r in used_services:
            return
        used_services.add(r)
        svc = cfg.services.get(r)
        if svc and svc.kind == "group":
            for m in svc.members:
                use_service(str(m), depth + 1)

    # Policy references
    for rule in cfg.rules:
        for rr in rule.src_refs:
            use_object(rr)
        for rr in rule.dst_refs:
            use_object(rr)
        for sr in rule.service_refs:
            use_service(sr)

    # NAT references (raw, so we catch unused groups too)
    for nr in cfg.nat_rules:
        for rr in nr.in_refs:
            use_object(rr)
        for rr in nr.out_refs:
            use_object(rr)

    # Compute unused
    unused_objects = sorted(
        [name for name in cfg.objects.keys() if name.lower() != "any" and name not in used_objects]
    )
    unused_services = sorted(
        [name for name in cfg.services.keys() if name.lower() != "any" and name not in used_services]
    )

    anomalies: List[Dict[str, Any]] = []

    for name in unused_objects:
        anomalies.append(
            {
                "type": "UnusedObject",
                "description": f"Адресный объект '{name}' нигде не используется (policy/NAT) и может быть удалён или пересмотрен.",
                "related_rules": name,
                "level": "info",
            }
        )

    for name in unused_services:
        anomalies.append(
            {
                "type": "UnusedService",
                "description": f"Сервис '{name}' нигде не используется (policy) и может быть удалён или пересмотрен.",
                "related_rules": name,
                "level": "info",
            }
        )

    return anomalies
