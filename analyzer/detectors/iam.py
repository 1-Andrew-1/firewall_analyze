from __future__ import annotations

from typing import Any, Dict, List, Set

from ..canonical import CanonicalConfig, CanonicalIamRole, CanonicalIamRule, Privilege


def _set_rel(a: Set[str], b: Set[str]) -> str:
    if a == b:
        return "eq"
    if a.issubset(b):
        return "sub"
    if b.issubset(a):
        return "sup"
    if a.isdisjoint(b):
        return "disjoint"
    return "overlap"


def detect_iam_anomalies(cfg: CanonicalConfig) -> List[Dict[str, Any]]:
    """
    IAM (локально, внутри устройства):
      - Irrelevant (пустой домен правила)
      - Shadowing (затенение)
      - Redundancy (избыточность)
      - Conflict (конфликт allow/deny при пересечении доменов)
      - RoleCycle (циклы наследования ролей)
      - ElevatedPrivileges (у роли есть привилегии, не объясняемые наследованием)
      - UndefinedAccess (по checklist нет разрешающего правила)
    """
    findings: List[Dict[str, Any]] = []

    rules: List[CanonicalIamRule] = [r for r in cfg.iam_rules_sorted() if r.enabled]

    # 0) Irrelevant: пустой домен
    for r in rules:
        if r.is_empty_domain():
            findings.append(
                {
                    "type": "IAM: Irrelevant",
                    "description": "IAM-правило с пустыми наборами субъектов/объектов/действий (не может быть применено).",
                    "related_rules": f"{r.rule_id}",
                    "level": "info",
                }
            )

    # 1) Shadowing / Redundancy / Conflict (попарно)
    n = len(rules)
    for i in range(n):
        a = rules[i]
        for j in range(i + 1, n):
            b = rules[j]

            rs = _set_rel(a.subjects, b.subjects)
            ro = _set_rel(a.objects, b.objects)
            ra = _set_rel(a.actions, b.actions)

            # если по хотя бы одному измерению множества не пересекаются — правила не конфликтуют и не затеняют
            if "disjoint" in (rs, ro, ra):
                continue

            # a ⊇ b: a более общее/равное по всем измерениям
            a_covers_b = all(x in ("eq", "sup") for x in (rs, ro, ra))

            if a_covers_b:
                if a.effect != b.effect:
                    findings.append(
                        {
                            "type": "IAM: Shadowing",
                            "description": "Затенение: выше стоит более общее правило с противоположным эффектом, нижнее не сработает.",
                            "related_rules": f"{b.rule_id} ← {a.rule_id}",
                            "level": "warning",
                        }
                    )
                else:
                    findings.append(
                        {
                            "type": "IAM: Redundancy",
                            "description": "Избыточность: нижнее правило полностью покрывается верхним с тем же эффектом.",
                            "related_rules": f"{b.rule_id} ⊆ {a.rule_id}",
                            "level": "info",
                        }
                    )
                continue

            # иначе домены пересекаются, но никто никого полностью не покрывает
            if a.effect != b.effect:
                findings.append(
                    {
                        "type": "IAM: Conflict",
                        "description": "Конфликт разрешений: два применимых правила дают разные эффекты (allow/deny) на пересечении доменов.",
                        "related_rules": f"{a.rule_id} ↔ {b.rule_id}",
                        "level": "warning",
                    }
                )

    # 2) RoleCycle (граф наследования ролей)
    roles = cfg.iam_roles

    visited: dict[str, int] = {}
    stack: List[str] = []
    cycles: List[List[str]] = []

    def dfs(role: str) -> None:
        visited[role] = 1
        stack.append(role)

        for p in roles.get(role, CanonicalIamRole(name=role)).parents:
            if p not in roles:
                continue
            state = visited.get(p, 0)
            if state == 0:
                dfs(p)
            elif state == 1:
                if p in stack:
                    idx = stack.index(p)
                    cycles.append(stack[idx:] + [p])

        stack.pop()
        visited[role] = 2

    for rname in roles.keys():
        if visited.get(rname, 0) == 0:
            dfs(rname)

    for c in cycles[:5]:
        findings.append(
            {
                "type": "IAM: RoleCycle",
                "description": "Цикличность ролей: наследование образует цикл, корректное вычисление прав становится неоднозначным.",
                "related_rules": " → ".join(c),
                "level": "critical",
            }
        )

    # 3) ElevatedPrivileges
    def inherited_privs(role: str, depth: int = 0, seen: Set[str] | None = None) -> Set[Privilege]:
        if seen is None:
            seen = set()
        if depth > 20 or role in seen:
            return set()
        seen.add(role)

        acc: Set[Privilege] = set()
        rr = roles.get(role)
        if not rr:
            return acc

        for p in rr.parents:
            pr = roles.get(p)
            if not pr:
                continue
            acc |= pr.privileges
            acc |= inherited_privs(p, depth + 1, seen)

        return acc

    for name, role in roles.items():
        inh = inherited_privs(name)
        extra = role.privileges - inh
        if extra:
            findings.append(
                {
                    "type": "IAM: ElevatedPrivileges",
                    "description": "Повышенные привилегии: у роли есть разрешения, не объясняемые наследованием (проверь корректность выдачи прав).",
                    "related_rules": f"{name}: "
                    + ", ".join(f"{p.obj}:{p.action}" for p in list(extra)[:10])
                    + (" ..." if len(extra) > 10 else ""),
                    "level": "warning",
                }
            )

    # 4) UndefinedAccess (по checklist)
    if cfg.iam_checklist:
        for need in cfg.iam_checklist[:500]:
            ok = any(
                (r.enabled and r.effect == "allow" and (need.obj in r.objects) and (need.action in r.actions))
                for r in rules
            )
            if not ok:
                findings.append(
                    {
                        "type": "IAM: UndefinedAccess",
                        "description": "Неопределённый доступ: для требуемого действия над объектом нет ни одного разрешающего правила.",
                        "related_rules": f"{need.obj}:{need.action}",
                        "level": "warning",
                    }
                )

    return findings
