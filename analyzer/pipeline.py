# analyzer/engine/pipeline.py
from __future__ import annotations

from typing import Any, Dict, List


def analyze_filter_nat(filter_rules: List[dict], nat_rules: List[dict]) -> Dict[str, Any]:
    """
    Единая точка анализа: сюда потом подключишь реальные детекторы.
    Сейчас: минимально рабочая реализация, чтобы UI/отчёты жили.
    """

    anomalies: List[Dict[str, Any]] = []

    # Примеры простых детектов (не "топорно", но и не перегружено):
    # 1) отключённое правило
    for idx, r in enumerate(filter_rules):
        if not r.get("is_enabled", True):
            anomalies.append({
                "type": "FW_DISABLED_RULE",
                "level": "low",
                "risk_score": 2.0,
                "description": f"Отключено правило фильтрации: '{r.get('name','')}'",
                "related_rules": f"fw[{idx}]",
            })

        if r.get("rule_action") in ("pass", "allow") and r.get("logging") is False:
            anomalies.append({
                "type": "FW_ALLOW_NO_LOGGING",
                "level": "medium",
                "risk_score": 5.0,
                "description": f"Разрешающее правило без логирования: '{r.get('name','')}'",
                "related_rules": f"fw[{idx}]",
            })

        # any-any эвристика (очень грубо, но полезно)
        if not r.get("src") and not r.get("dst") and r.get("rule_action") in ("pass", "allow"):
            anomalies.append({
                "type": "FW_ANY_ANY_ALLOW",
                "level": "high",
                "risk_score": 20.0,
                "description": f"Похоже на any-any allow (пустые src/dst): '{r.get('name','')}'",
                "related_rules": f"fw[{idx}]",
            })

    for idx, n in enumerate(nat_rules or []):
        if not n.get("is_enabled", True):
            anomalies.append({
                "type": "NAT_DISABLED_RULE",
                "level": "low",
                "risk_score": 2.0,
                "description": f"Отключено NAT-правило: '{n.get('name','')}'",
                "related_rules": f"nat[{idx}]",
            })

    total_risk = sum(float(a.get("risk_score", 0) or 0) for a in anomalies)
    security_score = max(0.0, 100.0 - total_risk)

    if security_score >= 85:
        risk_level = "low"
    elif security_score >= 60:
        risk_level = "medium"
    else:
        risk_level = "high"

    return {
        "anomalies": anomalies,
        "security_metrics": {
            "security_score": round(security_score, 1),
            "risk_level": risk_level,
            "notes": [],
        },
    }
