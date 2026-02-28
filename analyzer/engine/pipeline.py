from __future__ import annotations

from typing import Any, Dict, List

from .parsers.kontinent_c4b import parse_config_text
from .detectors.policy import detect_policy_anomalies
from .detectors.nat import detect_nat_anomalies
from .detectors.routing import detect_routing_anomalies
from .detectors.iam import detect_iam_anomalies
from .detectors.objects import detect_objects_anomalies


def analyze_config_text(text: str) -> Dict[str, Any]:
    """
    Main entrypoint used by Django views.

    Returns:
      {
        "anomalies": [ {type, description, related_rules, level, ...}, ... ],
        "parse_messages": [...],
        "stats": {...}
      }
    """
    cfg = parse_config_text(text)

    anomalies: List[Dict[str, Any]] = []

    # Core detectors (per PDF logic)
    anomalies.extend(detect_policy_anomalies(cfg))
    anomalies.extend(detect_nat_anomalies(cfg))
    anomalies.extend(detect_routing_anomalies(cfg))
    anomalies.extend(detect_iam_anomalies(cfg))

    # Object/model level detectors (unused/broken/invalid)
    anomalies.extend(detect_objects_anomalies(cfg))

    # Surface unresolved references explicitly (important for debugging configs)
    for r in cfg.rules:
        if r.unresolved:
            anomalies.append(
                {
                    "type": "UnresolvedReference",
                    "description": f"Policy-правило '{r.rule_id}' содержит неразрешённые ссылки: {', '.join(r.unresolved)}.",
                    "related_rules": r.rule_id,
                    "level": "warning",
                }
            )

    for nr in cfg.nat_rules:
        if getattr(nr, "unresolved", None):
            anomalies.append(
                {
                    "type": "UnresolvedReference",
                    "description": f"NAT-правило '{nr.rule_id}' содержит неразрешённые ссылки: {', '.join(nr.unresolved)}.",
                    "related_rules": nr.rule_id,
                    "level": "warning",
                }
            )

    for rt in cfg.routes:
        if getattr(rt, "unresolved", None):
            anomalies.append(
                {
                    "type": "UnresolvedReference",
                    "description": f"Маршрут '{rt.route_id}' содержит неразрешённые поля/ссылки: {', '.join(rt.unresolved)}.",
                    "related_rules": rt.route_id,
                    "level": "info",
                }
            )

    # Parse warnings (low-level)
    for msg in cfg.parse_messages:
        anomalies.append(
            {
                "type": "ParseWarning",
                "description": msg,
                "related_rules": "",
                "level": "info",
            }
        )

    stats = {
        "rules": len(cfg.rules),
        "nat_rules": len(cfg.nat_rules),
        "routes": len(cfg.routes),
        "iam_rules": len(cfg.iam_rules),
        "iam_roles": len(cfg.iam_roles),
        "objects": len(cfg.objects),
        "services": len(cfg.services),
    }

    return {"anomalies": anomalies, "parse_messages": cfg.parse_messages, "stats": stats}
