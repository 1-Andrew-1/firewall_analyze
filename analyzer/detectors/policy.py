from __future__ import annotations

from typing import Any, Dict, List

from ..canonical import CanonicalConfig, CanonicalRule
from ..relations import relate_rules


def _anomaly(a_type: str, level: str, description: str, related: List[str], risk: int, evidence: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "type": a_type,
        "level": level,
        "description": description,
        "related_rules": related,
        "risk_score": risk,
        "evidence": evidence,
    }


def detect_policy_anomalies(cfg: CanonicalConfig) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    rules = [r for r in cfg.rules if r.enabled]

    # per-rule checks
    for r in rules:
        if r.unresolved_refs:
            out.append(_anomaly(
                "Parser: UnresolvedReference",
                "warning",
                f"Правило {r.rule_id} содержит неразрешимые ссылки (объекты/сервисы).",
                [r.rule_id],
                60,
                {"unresolved": r.unresolved_refs},
            ))

        if r.domain_is_empty():
            out.append(_anomaly(
                "Policy: Irrelevant",
                "warning",
                f"Правило {r.rule_id} не применимо: домен правила пуст (после резолва объектов/сервисов).",
                [r.rule_id],
                55,
                {"comment": r.comment},
            ))
            continue

        if r.is_any_any_any_allow():
            out.append(_anomaly(
                "Policy: AnyAnyAnyAllow",
                "critical",
                f"Опасное правило {r.rule_id}: allow для ANY-ANY-ANY.",
                [r.rule_id],
                95,
                {"comment": r.comment},
            ))

        if r.action == "allow" and not r.log:
            out.append(_anomaly(
                "Policy: NoLogging",
                "info",
                f"Разрешающее правило {r.rule_id} без логирования.",
                [r.rule_id],
                20,
                {"comment": r.comment},
            ))

    # pairwise checks (order-sensitive)
    n = len(rules)
    for i in range(n):
        a = rules[i]
        if a.domain_is_empty():
            continue
        for j in range(i + 1, n):
            b = rules[j]
            if b.domain_is_empty():
                continue

            rel = relate_rules(a, b)

            # Shadowing / Redundancy: earlier rule covers later one
            if rel.a_superset_b():
                if a.action != b.action:
                    out.append(_anomaly(
                        "Policy: Shadowing",
                        "warning",
                        f"Правило {b.rule_id} затенено правилом {a.rule_id} (полное покрытие, разные действия).",
                        [a.rule_id, b.rule_id],
                        65,
                        {"a_action": a.action, "b_action": b.action},
                    ))
                else:
                    out.append(_anomaly(
                        "Policy: Redundancy",
                        "info",
                        f"Правило {b.rule_id} избыточно относительно {a.rule_id} (полное покрытие, одинаковое действие).",
                        [a.rule_id, b.rule_id],
                        25,
                        {"action": a.action},
                    ))

            # Generalization: later rule expands earlier with same action
            elif rel.b_superset_a():
                if a.action == b.action:
                    out.append(_anomaly(
                        "Policy: Generalization",
                        "warning",
                        f"Правило {b.rule_id} обобщает {a.rule_id} (расширение домена, одинаковое действие).",
                        [a.rule_id, b.rule_id],
                        50,
                        {"action": a.action},
                    ))
                else:
                    # different action + overlap will be caught by correlation below
                    pass

            # Correlation: overlap + different actions
            elif rel.is_overlap() and a.action != b.action:
                out.append(_anomaly(
                    "Policy: Correlation",
                    "warning",
                    f"Правила {a.rule_id} и {b.rule_id} частично пересекаются и имеют разные действия.",
                    [a.rule_id, b.rule_id],
                    60,
                    {"a_action": a.action, "b_action": b.action},
                ))

    return out
