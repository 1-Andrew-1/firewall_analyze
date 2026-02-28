import json
from django.db import transaction
from django.http import JsonResponse, HttpResponseBadRequest
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_http_methods

from .models import Snapshot, Report, Anomaly
# analyzer/views.py (вверху)
from .engine.detectors import detect_all



def _stats_context() -> dict:
    last_snapshot = Snapshot.objects.filter(is_active=True).order_by("-created_at").first()
    last_report = Report.objects.order_by("-created_at").first()

    return {
        "snapshots_total": Snapshot.objects.filter(is_active=True).count(),
        "reports_total": Report.objects.count(),
        "last_snapshot_at": getattr(last_snapshot, "created_at", None),
        "last_report_at": getattr(last_report, "created_at", None),
        "last_snapshot_filename": getattr(last_snapshot, "filename", None),
    }


def _read_json_rules(uploaded_file):
    raw = uploaded_file.read()
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8-sig", errors="replace")
    data = json.loads(raw)
    if not isinstance(data, list):
        raise ValueError("Ожидается JSON-массив правил (список).")
    return data


def _infer_kind(rules: list) -> str | None:
    if not rules:
        return None
    first = rules[0]
    if not isinstance(first, dict):
        return None
    if "rule_action" in first:
        return "fw"
    if "nat_type" in first:
        return "nat"
    return None


def _is_any_net(entities: list) -> bool:
    if not entities:
        return True
    # примитивная эвристика: 0.0.0.0/0 или ::/0
    for e in entities:
        if isinstance(e, dict):
            ip = (e.get("ip") or "").strip()
            if ip in ("0.0.0.0/0", "::/0"):
                return True
    return False


def _is_any_service(services: list) -> bool:
    if not services:
        return True
    for s in services:
        if isinstance(s, dict):
            proto = s.get("proto")
            dst = (s.get("dst") or "").strip()
            # если TCP/UDP и порт пустой => “любой”
            if proto in (6, 17) and dst == "":
                return True
    return False


def _detect_fw(rules: list) -> list[dict]:
    anomalies = []
    seen = set()

    for idx, r in enumerate(rules):
        if not isinstance(r, dict):
            continue

        if not r.get("is_enabled", True):
            anomalies.append({
                "scope": "fw",
                "code": "FW_DISABLED_RULE",
                "title": "Отключенное правило фильтрации",
                "severity": "low",
                "rule_index": idx,
                "rule_name": r.get("name", ""),
                "description": "Правило присутствует, но выключено (возможный мусор/долг по настройке).",
                "details": {"name": r.get("name", ""), "action": r.get("rule_action")},
            })

        action = (r.get("rule_action") or "").lower()
        src = r.get("src") or []
        dst = r.get("dst") or []
        svc = r.get("service") or []

        # 1) слишком широкое allow any-any-any
        if action == "pass" and _is_any_net(src) and _is_any_net(dst) and _is_any_service(svc):
            anomalies.append({
                "scope": "fw",
                "code": "FW_ALLOW_ANY_ANY_ANY",
                "title": "Слишком широкое разрешающее правило (any→any, any service)",
                "severity": "critical",
                "rule_index": idx,
                "rule_name": r.get("name", ""),
                "description": "Разрешающее правило без ограничений по источнику/назначению/сервису.",
                "details": {"action": action},
            })

        # 2) allow без логирования
        if action == "pass" and not r.get("logging", True):
            anomalies.append({
                "scope": "fw",
                "code": "FW_ALLOW_NO_LOG",
                "title": "Разрешающее правило без логирования",
                "severity": "medium",
                "rule_index": idx,
                "rule_name": r.get("name", ""),
                "description": "Разрешающее правило не пишет события (сложнее расследование/контроль).",
                "details": {"logging": False},
            })

        # 3) дубликаты (грубый отпечаток)
        fp = json.dumps({
            "action": action,
            "src": src,
            "dst": dst,
            "svc": svc,
            "inv_s": r.get("is_inverse_src", False),
            "inv_d": r.get("is_inverse_dst", False),
        }, sort_keys=True, ensure_ascii=False)

        if fp in seen:
            anomalies.append({
                "scope": "fw",
                "code": "FW_DUPLICATE_RULE",
                "title": "Дублирующее правило фильтрации",
                "severity": "low",
                "rule_index": idx,
                "rule_name": r.get("name", ""),
                "description": "Правило полностью повторяет ранее встреченное (риск рассинхронизации при правках).",
                "details": {},
            })
        else:
            seen.add(fp)

    return anomalies


def _detect_nat(rules: list) -> list[dict]:
    anomalies = []
    seen = set()

    for idx, r in enumerate(rules):
        if not isinstance(r, dict):
            continue

        if not r.get("is_enabled", True):
            anomalies.append({
                "scope": "nat",
                "code": "NAT_DISABLED_RULE",
                "title": "Отключенное NAT-правило",
                "severity": "low",
                "rule_index": idx,
                "rule_name": r.get("name", ""),
                "description": "NAT-правило выключено (возможный мусор/устаревшая запись).",
                "details": {"nat_type": r.get("nat_type")},
            })

        nat_type = (r.get("nat_type") or "").lower()
        src = r.get("src") or []
        dst = r.get("dst") or []
        svc = r.get("service") or []
        val = r.get("value") or []

        # 1) DNAT на “всё подряд”
        if nat_type == "dnat" and _is_any_net(dst):
            anomalies.append({
                "scope": "nat",
                "code": "NAT_DNAT_DST_ANY",
                "title": "DNAT с неограниченным назначением (dst any)",
                "severity": "high",
                "rule_index": idx,
                "rule_name": r.get("name", ""),
                "description": "DNAT без ограничения по dst часто означает риск неожиданной трансляции.",
                "details": {},
            })

        # 2) masquerade на any-any-any
        if nat_type == "masquerade" and _is_any_net(src) and _is_any_net(dst) and _is_any_service(svc):
            anomalies.append({
                "scope": "nat",
                "code": "NAT_MASQ_TOO_WIDE",
                "title": "Masquerade без ограничений (any→any, any service)",
                "severity": "high",
                "rule_index": idx,
                "rule_name": r.get("name", ""),
                "description": "Слишком широкая маскарадинг-трансляция.",
                "details": {},
            })

        # 3) дубликаты NAT (грубый отпечаток)
        fp = json.dumps({
            "type": nat_type,
            "src": src,
            "dst": dst,
            "svc": svc,
            "val": val,
            "port_val": r.get("port_value") or [],
        }, sort_keys=True, ensure_ascii=False)

        if fp in seen:
            anomalies.append({
                "scope": "nat",
                "code": "NAT_DUPLICATE_RULE",
                "title": "Дублирующее NAT-правило",
                "severity": "low",
                "rule_index": idx,
                "rule_name": r.get("name", ""),
                "description": "Полный дубль NAT-правила.",
                "details": {},
            })
        else:
            seen.add(fp)

    return anomalies


def _build_report(snapshot: Snapshot) -> Report:
    # Формальные аномалии из PDF (FilterRules + NatRules)
    all_anoms = detect_all(snapshot.fw_rules or [], snapshot.nat_rules or [])

    rep = Report.objects.create(
        snapshot=snapshot,
        summary={
            "fw_rules": snapshot.policy_rules_count,
            "nat_rules": snapshot.nat_rules_count,
            "anomalies_total": len(all_anoms),
            "fw_anomalies": sum(1 for a in all_anoms if a.get("scope") == "fw"),
            "nat_anomalies": sum(1 for a in all_anoms if a.get("scope") == "nat"),
        },
    )

    objs = []
    for a in all_anoms:
        objs.append(Anomaly(
            report=rep,
            scope=a["scope"],
            code=a.get("code", ""),
            title=a.get("title", ""),
            description=a.get("description", ""),
            severity=a.get("severity", "medium"),
            rule_index=a.get("rule_index"),
            rule_name=a.get("rule_name", ""),
            details=a.get("details", {}),
        ))
    if objs:
        Anomaly.objects.bulk_create(objs)

    return rep



# analyzer/views.py
import json
from collections import Counter
from django.shortcuts import render
from django.views.decorators.http import require_http_methods

from .models import Report, Snapshot


def _stats_context():
    """
    Если у тебя уже есть такая функция — оставь свою.
    Главное: dashboard_page ниже делает ctx.update(...)
    """
    last_snapshot = Snapshot.objects.filter(is_active=True).order_by("-created_at").first()
    last_report = Report.objects.order_by("-created_at").first()

    return {
        "snapshots_total": Snapshot.objects.filter(is_active=True).count(),
        "reports_total": Report.objects.count(),
        "last_snapshot_at": getattr(last_snapshot, "created_at", None),
        "last_report_at": getattr(last_report, "created_at", None),
        "last_snapshot_filename": getattr(last_snapshot, "original_filename", "") if last_snapshot else "",
    }


def _iter_anomalies(anomalies_field):
    """
    Поддержка двух форматов:
    1) dict: {"fw":[...], "nat":[...]}  (как в sample_report_BIG_with_anomalies.json)
    2) list: [{...}, {...}]            (на всякий случай)
    """
    if not anomalies_field:
        return

    if isinstance(anomalies_field, dict):
        for bucket in ("fw", "nat"):
            items = anomalies_field.get(bucket) or []
            if isinstance(items, list):
                for a in items:
                    if isinstance(a, dict):
                        yield a
        return

    if isinstance(anomalies_field, list):
        for a in anomalies_field:
            if isinstance(a, dict):
                yield a


import json
from django.db.models import Count
from django.shortcuts import render
from django.views.decorators.http import require_http_methods

from .models import Snapshot, Report, Anomaly


@require_http_methods(["GET"])
def dashboard_page(request):
    # Топ-20 типов аномалий (берём title, если есть; иначе code)
    qs = (
        Anomaly.objects
        .values("code", "title")
        .annotate(cnt=Count("id"))
        .order_by("-cnt")
    )

    labels = []
    values = []
    total = 0

    for row in qs:
        label = (row.get("title") or row.get("code") or "UNKNOWN").strip() or "UNKNOWN"
        labels.append(label)
        values.append(int(row["cnt"]))
        total += int(row["cnt"])
        if len(labels) >= 20:
            break

    ctx = _stats_context()
    ctx.update({
        "labels_json": json.dumps(labels, ensure_ascii=False),
        "values_json": json.dumps(values),
        "has_chart_data": bool(labels),
        "anomalies_total": total,
    })
    return render(request, "dashboard.html", ctx)




@require_http_methods(["GET", "POST"])
def upload_page(request):
    ctx = _stats_context()

    if request.method == "GET":
        return render(request, "upload.html", ctx)

    # Поддержим разные имена инпутов (чтобы не ловить “Файл не выбран” из-за несовпадения name)
    fw_file = (
        request.FILES.get("fw_file")
        or request.FILES.get("filter_file")
        or request.FILES.get("filterrules_file")
        or request.FILES.get("config_file")
    )
    nat_file = (
        request.FILES.get("nat_file")
        or request.FILES.get("natrules_file")
    )

    if not fw_file and not nat_file:
        ctx["error"] = "Файл не выбран."
        return render(request, "upload.html", ctx)

    try:
        fw_rules = []
        nat_rules = []

        # Если дали только один файл — пробуем угадать тип
        if fw_file and not nat_file:
            rules = _read_json_rules(fw_file)
            kind = _infer_kind(rules)
            if kind == "fw":
                fw_rules = rules
            elif kind == "nat":
                nat_rules = rules
            else:
                raise ValueError("Не удалось определить тип правил (ожидается FilterRules или NatRules).")

            original_name = fw_file.name

        elif nat_file and not fw_file:
            rules = _read_json_rules(nat_file)
            kind = _infer_kind(rules)
            if kind == "nat":
                nat_rules = rules
            elif kind == "fw":
                fw_rules = rules
            else:
                raise ValueError("Не удалось определить тип правил (ожидается FilterRules или NatRules).")

            original_name = nat_file.name

        else:
            fw_rules = _read_json_rules(fw_file)
            nat_rules = _read_json_rules(nat_file)
            original_name = f"{fw_file.name} + {nat_file.name}"

        with transaction.atomic():
            snap = Snapshot.objects.create(
                original_filename=original_name,
                fw_rules=fw_rules,
                nat_rules=nat_rules,
                policy_rules_count=len(fw_rules),
                nat_rules_count=len(nat_rules),
                status=Snapshot.STATUS_READY,
            )
            rep = _build_report(snap)

        return redirect("report_detail", rep.id)

    except Exception as e:
        ctx["error"] = str(e)
        return render(request, "upload.html", ctx)


@require_http_methods(["GET"])
def snapshots_page(request):
    snaps = Snapshot.objects.filter(is_active=True).order_by("-created_at")
    return render(request, "snapshots.html", {**_stats_context(), "snapshots": snaps})


@require_http_methods(["GET"])
def snapshot_detail_page(request, id: int):
    # Чтобы не плодить новые шаблоны — просто открываем FilterRules как “детали”
    return redirect("snapshot_filter", id=id)


@require_http_methods(["GET"])
def snapshot_filter_page(request, id: int):
    s = get_object_or_404(Snapshot, pk=id)
    pretty = json.dumps(s.fw_rules or [], ensure_ascii=False, indent=2)
    return render(request, "snapshot_filter.html", {**_stats_context(), "snapshot": s, "rules_json": pretty, "rules": s.fw_rules or []})


@require_http_methods(["GET"])
def snapshot_nat_page(request, id: int):
    s = get_object_or_404(Snapshot, pk=id)
    pretty = json.dumps(s.nat_rules or [], ensure_ascii=False, indent=2)
    return render(request, "snapshot_nat.html", {**_stats_context(), "snapshot": s, "rules_json": pretty, "rules": s.nat_rules or []})


@require_http_methods(["GET"])
def snapshot_analyze(request, id: int):
    s = get_object_or_404(Snapshot, pk=id)
    rep = _build_report(s)
    return redirect("report_detail", rep.id)


@require_http_methods(["POST"])
def delete_snapshot(request, id: int):
    s = get_object_or_404(Snapshot, pk=id)
    s.delete()
    return redirect("snapshots")


@require_http_methods(["GET"])
def reports_page(request):
    reps = Report.objects.select_related("snapshot").order_by("-created_at")
    return render(request, "reports.html", {**_stats_context(), "reports": reps})


@require_http_methods(["GET"])
def report_detail_page(request, id: int):
    rep = get_object_or_404(Report.objects.select_related("snapshot"), pk=id)
    anoms = rep.anomalies.order_by("scope", "rule_index", "id")
    return render(request, "report_detail.html", {**_stats_context(), "r": rep, "anomalies": anoms})


@require_http_methods(["POST"])
def delete_report(request, id: int):
    rep = get_object_or_404(Report, pk=id)
    rep.delete()
    return redirect("reports")


@require_http_methods(["GET"])
def export_report_json(request, id: int):
    rep = get_object_or_404(Report.objects.select_related("snapshot"), pk=id)
    anomalies = []
    for a in rep.anomalies.all().order_by("id"):
        anomalies.append({
            "id": a.id,
            "created_at": a.created_at.isoformat(),
            "scope": a.scope,
            "code": a.code,
            "severity": a.severity,
            "title": a.title,
            "description": a.description,
            "rule_index": a.rule_index,
            "rule_name": a.rule_name,
            "details": a.details,
        })

    payload = {
        "report_id": rep.id,
        "created_at": rep.created_at.isoformat(),
        "snapshot_id": rep.snapshot_id,
        "snapshot_filename": rep.snapshot.filename if rep.snapshot_id else None,
        "summary": rep.summary,
        "anomalies": anomalies,
    }
    return JsonResponse(payload, json_dumps_params={"ensure_ascii": False, "indent": 2})
