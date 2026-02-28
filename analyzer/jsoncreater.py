#!/usr/bin/env python3
# make_suite.py
# Генератор большого набора тестовых конфигов под каноническую JSON-схему.

import argparse
import json
import os
import random
from copy import deepcopy

def mk_base(version: str):
    return {
        "vendor": "kontinent",
        "version": version,

        "objects": {
            "any": {"type": "any"},
            "LAN_NET": {"type": "network", "value": "10.0.0.0/24"},
            "LAN_HOST50": {"type": "host", "value": "10.0.0.50/32"},
            "DMZ_NET": {"type": "network", "value": "10.0.1.0/24"},
            "WEB_SRV": {"type": "host", "value": "10.0.1.10/32"},
            "DNS_SRV": {"type": "host", "value": "10.0.1.53/32"},
            "VPN_POOL": {"type": "network", "value": "10.8.0.0/24"},
            "PUB_NET1": {"type": "network", "value": "198.51.100.0/24"},
            "PUB_NET2": {"type": "network", "value": "203.0.113.0/24"},
            "INT_2": {"type": "network", "value": "10.0.2.0/24"},
        },

        "services": {
            "any": {"type": "any"},
            "HTTP": {"type": "service", "proto": "tcp", "dst_ports": [80]},
            "HTTPS": {"type": "service", "proto": "tcp", "dst_ports": [443]},
            "DNS": {"type": "service", "proto": "udp", "dst_ports": [53]},
            "WEB": {"type": "group", "members": ["HTTP", "HTTPS"]},
            "ANY_TCP": {"type": "service", "proto": "tcp"},
        },

        "rules": [],

        "zones": {
            "internal": ["10.0.0.0/24", "10.0.2.0/24", "10.8.0.0/24"],
            "external": ["198.51.100.0/24", "203.0.113.0/24"]
        },

        "nat_rules": [],
        "routes": [],

        "iam": {
            "roles": {},
            "rules": [],
            "checklist": []
        }
    }

def dump_json(path: str, obj: dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

def emit(out_dir: str, manifest: dict, filename: str, cfg: dict, expected: list[str]):
    path = os.path.join(out_dir, filename)
    dump_json(path, cfg)
    manifest[filename] = expected

def curated_cases(out_dir: str, manifest: dict):
    # ---------- POLICY ----------
    cfg = mk_base("curated-policy-01")
    cfg["rules"] = [
        {"id": "FW-1", "order": 1, "action": "allow", "enabled": True, "log": True,
         "comment": "ANY-ANY-ANY allow", "src": [], "dst": [], "service": []}
    ]
    emit(out_dir, manifest, "P01_any_any_any_allow.json", cfg, ["Policy:OverlyPermissive"])

    cfg = mk_base("curated-policy-02")
    cfg["rules"] = [
        {"id": "FW-1", "order": 1, "action": "allow", "enabled": True, "log": False,
         "comment": "ANY allow without log", "src": [], "dst": [], "service": []}
    ]
    emit(out_dir, manifest, "P02_any_allow_no_log.json", cfg, ["Policy:OverlyPermissive", "Policy:NoLog"])

    cfg = mk_base("curated-policy-03")
    cfg["rules"] = [
        {"id": "FW-1", "order": 1, "action": "allow", "enabled": True, "log": True,
         "comment": "Allow WEB", "src": ["LAN_NET"], "dst": ["WEB_SRV"], "service": ["WEB"]},
        {"id": "FW-2", "order": 2, "action": "deny", "enabled": True, "log": True,
         "comment": "Deny HTTP (shadowed)", "src": ["LAN_NET"], "dst": ["WEB_SRV"], "service": ["HTTP"]},
    ]
    emit(out_dir, manifest, "P03_shadowing_allow_over_deny.json", cfg, ["Policy:Shadowing"])

    cfg = mk_base("curated-policy-04")
    cfg["rules"] = [
        {"id": "FW-1", "order": 1, "action": "allow", "enabled": True, "log": True,
         "comment": "Allow WEB", "src": ["LAN_NET"], "dst": ["WEB_SRV"], "service": ["WEB"]},
        {"id": "FW-2", "order": 2, "action": "allow", "enabled": True, "log": True,
         "comment": "Duplicate Allow WEB", "src": ["LAN_NET"], "dst": ["WEB_SRV"], "service": ["WEB"]},
    ]
    emit(out_dir, manifest, "P04_redundant_duplicate.json", cfg, ["Policy:Redundant"])

    cfg = mk_base("curated-policy-05")
    cfg["rules"] = [
        {"id": "FW-1", "order": 1, "action": "allow", "enabled": True, "log": True,
         "comment": "Allow WEB", "src": ["LAN_NET"], "dst": ["WEB_SRV"], "service": ["WEB"]},
        {"id": "FW-2", "order": 2, "action": "allow", "enabled": True, "log": True,
         "comment": "Allow HTTPS redundant (subset of WEB)", "src": ["LAN_NET"], "dst": ["WEB_SRV"], "service": ["HTTPS"]},
    ]
    emit(out_dir, manifest, "P05_redundant_subset.json", cfg, ["Policy:Redundant"])

    cfg = mk_base("curated-policy-06")
    cfg["rules"] = [
        {"id": "FW-1", "order": 1, "action": "allow", "enabled": True, "log": True,
         "comment": "Allow LAN->WEB WEB", "src": ["LAN_NET"], "dst": ["WEB_SRV"], "service": ["WEB"]},
        {"id": "FW-2", "order": 2, "action": "deny", "enabled": True, "log": True,
         "comment": "Deny host50 any tcp (partial overlap)", "src": ["LAN_HOST50"], "dst": ["WEB_SRV"], "service": ["ANY_TCP"]},
    ]
    emit(out_dir, manifest, "P06_correlation_partial_overlap.json", cfg, ["Policy:Correlation"])

    cfg = mk_base("curated-policy-07")
    cfg["rules"] = [
        {"id": "FW-1", "order": 1, "action": "allow", "enabled": True, "log": True,
         "comment": "Allow DNS", "src": ["VPN_POOL"], "dst": ["DNS_SRV"], "service": ["DNS"]},
        {"id": "FW-2", "order": 2, "action": "deny", "enabled": True, "log": True,
         "comment": "Deny DNS conflict", "src": ["VPN_POOL"], "dst": ["DNS_SRV"], "service": ["DNS"]},
    ]
    emit(out_dir, manifest, "P07_conflict_exact.json", cfg, ["Policy:Conflict"])

    cfg = mk_base("curated-policy-08")
    cfg["objects"]["BROKEN_GRP"] = {"type": "group", "members": ["NO_SUCH_OBJECT", "ALSO_MISSING"]}
    cfg["rules"] = [
        {"id": "FW-1", "order": 1, "action": "allow", "enabled": True, "log": True,
         "comment": "Broken group => unresolved", "src": ["BROKEN_GRP"], "dst": ["DMZ_NET"], "service": ["WEB"]}
    ]
    emit(out_dir, manifest, "P08_unresolved_refs.json", cfg, ["Objects:UnresolvedRef", "Policy:IrrelevantOrEmptyDomain"])

    cfg = mk_base("curated-policy-09")
    cfg["rules"] = [
        {"id": "FW-1", "order": 1, "action": "allow", "enabled": True, "log": True,
         "comment": "Inline service", "src": ["LAN_NET"], "dst": ["WEB_SRV"], "service": ["tcp/80"]}
    ]
    emit(out_dir, manifest, "P09_inline_service_tcp_80.json", cfg, ["Services:InlineParsed"])

    cfg = mk_base("curated-policy-10")
    cfg["rules"] = [
        {"id": "FW-1", "order": 1, "action": "deny", "enabled": False, "log": True,
         "comment": "Disabled rule", "src": ["LAN_NET"], "dst": ["DMZ_NET"], "service": ["DNS"]},
        {"id": "FW-2", "order": 2, "action": "allow", "enabled": True, "log": True,
         "comment": "Allow WEB", "src": ["LAN_NET"], "dst": ["DMZ_NET"], "service": ["WEB"]},
    ]
    emit(out_dir, manifest, "P10_disabled_rule.json", cfg, ["Policy:DisabledRule"])

    # ---------- OBJECTS ----------
    cfg = mk_base("curated-objects-01")
    cfg["objects"]["UNUSED_NET"] = {"type": "network", "value": "10.0.9.0/24"}
    cfg["services"]["UNUSED_SVC"] = {"type": "service", "proto": "tcp", "dst_ports": [8080]}
    cfg["rules"] = [
        {"id": "FW-1", "order": 1, "action": "allow", "enabled": True, "log": True,
         "comment": "Does not use UNUSED_*", "src": ["LAN_NET"], "dst": ["WEB_SRV"], "service": ["HTTP"]}
    ]
    emit(out_dir, manifest, "O01_unused_object_service.json", cfg, ["Objects:Unused", "Services:Unused"])

    cfg = mk_base("curated-objects-02")
    cfg["objects"]["GRP_A"] = {"type": "group", "members": ["GRP_B"]}
    cfg["objects"]["GRP_B"] = {"type": "group", "members": ["GRP_A"]}
    cfg["rules"] = [
        {"id": "FW-1", "order": 1, "action": "allow", "enabled": True, "log": True,
         "comment": "Cycle group resolution", "src": ["GRP_A"], "dst": ["WEB_SRV"], "service": ["HTTP"]}
    ]
    emit(out_dir, manifest, "O02_object_group_cycle.json", cfg, ["Objects:GroupCycleOrDepthLimit"])

    # ---------- NAT ----------
    cfg = mk_base("curated-nat-01")
    cfg["nat_rules"] = [
        {"id": "NAT-1", "order": 1, "enabled": True, "comment": "LAN->PUB1", "in_addr": ["LAN_NET"], "out_addr": ["PUB_NET1"]},
        {"id": "NAT-2", "order": 2, "enabled": True, "comment": "LAN->PUB2 (conflict)", "in_addr": ["LAN_NET"], "out_addr": ["PUB_NET2"]},
    ]
    emit(out_dir, manifest, "N01_nat_conflict_translation.json", cfg, ["NAT:ConflictTranslation"])

    cfg = mk_base("curated-nat-02")
    cfg["nat_rules"] = [
        {"id": "NAT-1", "order": 1, "enabled": True, "comment": "LAN->PUB1", "in_addr": ["LAN_NET"], "out_addr": ["PUB_NET1"]},
        {"id": "NAT-2", "order": 2, "enabled": True, "comment": "HOST50->PUB1 (redundant)", "in_addr": ["LAN_HOST50"], "out_addr": ["PUB_NET1"]},
    ]
    emit(out_dir, manifest, "N02_nat_redundant_subset.json", cfg, ["NAT:Redundant"])

    cfg = mk_base("curated-nat-03")
    cfg["nat_rules"] = [
        {"id": "NAT-1", "order": 1, "enabled": True, "comment": "LAN->PUB1", "in_addr": ["LAN_NET"], "out_addr": ["PUB_NET1"]},
        {"id": "NAT-2", "order": 2, "enabled": True, "comment": "PUB1->PUB2 (chain)", "in_addr": ["PUB_NET1"], "out_addr": ["PUB_NET2"]},
        {"id": "NAT-3", "order": 3, "enabled": True, "comment": "PUB2->LAN (cycle)", "in_addr": ["PUB_NET2"], "out_addr": ["LAN_NET"]},
    ]
    emit(out_dir, manifest, "N03_nat_cycle.json", cfg, ["NAT:Cycle"])

    cfg = mk_base("curated-nat-04")
    cfg["nat_rules"] = [
        {"id": "NAT-1", "order": 1, "enabled": True, "comment": "only LAN->PUB1", "in_addr": ["LAN_NET"], "out_addr": ["PUB_NET1"]},
    ]
    emit(out_dir, manifest, "N04_nat_uncovered_internal.json", cfg, ["NAT:UncoveredInternalZone"])

    # ---------- ROUTING ----------
    cfg = mk_base("curated-route-01")
    cfg["routes"] = [
        {"id": "RT-1", "order": 1, "enabled": True, "prefix": "10.0.0.0/24", "next_hop": "10.0.0.1", "metric": 1},
        {"id": "RT-2", "order": 2, "enabled": True, "prefix": "10.0.0.0/24", "next_hop": "10.0.0.2", "metric": 1},
    ]
    emit(out_dir, manifest, "R01_route_conflict_same_prefix.json", cfg, ["Routing:ConflictSamePrefix"])

    cfg = mk_base("curated-route-02")
    cfg["routes"] = [
        {"id": "RT-1", "order": 1, "enabled": True, "prefix": "10.0.0.0/24", "next_hop": "192.0.2.1", "metric": 1},
        {"id": "RT-2", "order": 2, "enabled": True, "prefix": "192.0.2.0/24", "next_hop": "10.0.0.1", "metric": 1},
    ]
    emit(out_dir, manifest, "R02_route_loop.json", cfg, ["Routing:Loop"])

    cfg = mk_base("curated-route-03")
    cfg["routes"] = [
        {"id": "RT-1", "order": 1, "enabled": True, "prefix": "10.0.300.0/24", "next_hop": "10.0.0.1", "metric": 1},
    ]
    emit(out_dir, manifest, "R03_route_invalid_prefix.json", cfg, ["Routing:InvalidPrefix"])

    # ---------- IAM ----------
    cfg = mk_base("curated-iam-01")
    cfg["iam"]["roles"] = {
        "admin": {"parents": ["ops"], "privileges": [{"object": "firewall", "action": "write"}]},
        "ops": {"parents": ["admin"], "privileges": [{"object": "audit", "action": "read"}]},
    }
    emit(out_dir, manifest, "I01_iam_role_inheritance_cycle.json", cfg, ["IAM:RoleInheritanceCycle"])

    cfg = mk_base("curated-iam-02")
    cfg["iam"]["rules"] = [
        {"id": "IAM-1", "order": 1, "effect": "allow", "enabled": True, "comment": "allow viewer audit read",
         "subjects": ["viewer"], "objects": ["audit"], "actions": ["read"]},
        {"id": "IAM-2", "order": 2, "effect": "deny", "enabled": True, "comment": "deny viewer audit read (conflict)",
         "subjects": ["viewer"], "objects": ["audit"], "actions": ["read"]},
    ]
    emit(out_dir, manifest, "I02_iam_rule_conflict.json", cfg, ["IAM:Conflict"])

    cfg = mk_base("curated-iam-03")
    cfg["iam"]["rules"] = [
        {"id": "IAM-1", "order": 1, "effect": "allow", "enabled": True, "comment": "irrelevant empty subjects",
         "subjects": [], "objects": ["firewall"], "actions": ["read"]},
    ]
    emit(out_dir, manifest, "I03_iam_irrelevant_empty_subjects.json", cfg, ["IAM:Irrelevant"])

    # ---------- INTEGRATION ----------
    cfg = mk_base("curated-full-01")
    cfg["objects"]["BROKEN_GRP"] = {"type": "group", "members": ["NO_SUCH_OBJECT"]}
    cfg["rules"] = [
        {"id": "FW-1", "order": 1, "action": "allow", "enabled": True, "log": True,
         "comment": "LAN->DMZ WEB", "src": ["LAN_NET"], "dst": ["DMZ_NET"], "service": ["WEB"]},
        {"id": "FW-2", "order": 2, "action": "deny", "enabled": True, "log": True,
         "comment": "host50 deny any tcp", "src": ["LAN_HOST50"], "dst": ["WEB_SRV"], "service": ["ANY_TCP"]},
        {"id": "FW-3", "order": 3, "action": "allow", "enabled": True, "log": False,
         "comment": "ANY allow no log", "src": [], "dst": [], "service": []},
        {"id": "FW-4", "order": 4, "action": "allow", "enabled": True, "log": True,
         "comment": "Broken group", "src": ["BROKEN_GRP"], "dst": ["DMZ_NET"], "service": ["WEB"]},
    ]
    cfg["nat_rules"] = [
        {"id": "NAT-1", "order": 1, "enabled": True, "comment": "LAN->PUB1", "in_addr": ["LAN_NET"], "out_addr": ["PUB_NET1"]},
        {"id": "NAT-2", "order": 2, "enabled": True, "comment": "LAN->PUB2 (conflict)", "in_addr": ["LAN_NET"], "out_addr": ["PUB_NET2"]},
    ]
    cfg["routes"] = [
        {"id": "RT-1", "order": 1, "enabled": True, "prefix": "10.0.0.0/24", "next_hop": "10.0.0.1", "metric": 1},
        {"id": "RT-2", "order": 2, "enabled": True, "prefix": "10.0.0.0/24", "next_hop": "10.0.0.2", "metric": 1},
    ]
    cfg["iam"]["roles"] = {
        "admin": {"parents": ["ops"], "privileges": [{"object": "firewall", "action": "write"}]},
        "ops": {"parents": ["admin"], "privileges": [{"object": "audit", "action": "read"}]},
    }
    cfg["iam"]["rules"] = [
        {"id": "IAM-1", "order": 1, "effect": "allow", "enabled": True, "comment": "allow viewer audit read",
         "subjects": ["viewer"], "objects": ["audit"], "actions": ["read"]},
        {"id": "IAM-2", "order": 2, "effect": "deny", "enabled": True, "comment": "deny viewer audit read",
         "subjects": ["viewer"], "objects": ["audit"], "actions": ["read"]},
    ]
    emit(out_dir, manifest, "FULL_kitchen_sink.json", cfg, [
        "Policy:OverlyPermissive", "Policy:NoLog", "Policy:Correlation",
        "Objects:UnresolvedRef", "NAT:ConflictTranslation", "Routing:ConflictSamePrefix",
        "IAM:RoleInheritanceCycle", "IAM:Conflict"
    ])

def rand_cidr(rng: random.Random):
    # простая генерация приватных /24
    a = rng.choice([10, 172, 192])
    if a == 10:
        return f"10.{rng.randint(0,10)}.{rng.randint(0,255)}.0/24"
    if a == 172:
        return f"172.{rng.randint(16,31)}.{rng.randint(0,255)}.0/24"
    return f"192.168.{rng.randint(0,255)}.0/24"

def random_case(i: int, rng: random.Random):
    cfg = mk_base(f"random-{i:04d}")

    # нагенерим дополнительные сети
    for j in range(1, 9):
        cfg["objects"][f"NET_{j}"] = {"type": "network", "value": rand_cidr(rng)}

    cfg["services"]["TCP_22"] = {"type": "service", "proto": "tcp", "dst_ports": [22]}
    cfg["services"]["TCP_3389"] = {"type": "service", "proto": "tcp", "dst_ports": [3389]}
    cfg["services"]["RDP_SSH"] = {"type": "group", "members": ["TCP_22", "TCP_3389"]}

    # базовое правило
    cfg["rules"].append({
        "id": "FW-BASE", "order": 1, "action": "allow", "enabled": True, "log": True,
        "comment": "baseline allow", "src": ["NET_1"], "dst": ["NET_2"], "service": ["WEB"]
    })

    expected = []

    # инъекции (вероятностно)
    if rng.random() < 0.35:
        cfg["rules"].append({
            "id": "FW-ANY", "order": 2, "action": "allow", "enabled": True, "log": (rng.random() < 0.7),
            "comment": "any allow", "src": [], "dst": [], "service": []
        })
        expected += ["Policy:OverlyPermissive"]
        if cfg["rules"][-1]["log"] is False:
            expected += ["Policy:NoLog"]

    if rng.random() < 0.30:
        # конфликт allow/deny на одном домене
        cfg["rules"].append({
            "id": "FW-C1", "order": 3, "action": "allow", "enabled": True, "log": True,
            "comment": "conflict allow", "src": ["NET_1"], "dst": ["NET_2"], "service": ["TCP_22"]
        })
        cfg["rules"].append({
            "id": "FW-C2", "order": 4, "action": "deny", "enabled": True, "log": True,
            "comment": "conflict deny", "src": ["NET_1"], "dst": ["NET_2"], "service": ["TCP_22"]
        })
        expected += ["Policy:Conflict"]

    if rng.random() < 0.25:
        # broken group
        cfg["objects"]["BROKEN_GRP"] = {"type": "group", "members": ["MISSING_OBJ"]}
        cfg["rules"].append({
            "id": "FW-BROKEN", "order": 10, "action": "allow", "enabled": True, "log": True,
            "comment": "broken object ref", "src": ["BROKEN_GRP"], "dst": ["NET_2"], "service": ["WEB"]
        })
        expected += ["Objects:UnresolvedRef"]

    if rng.random() < 0.45:
        # NAT
        cfg["nat_rules"].append({
            "id": "NAT-1", "order": 1, "enabled": True, "comment": "nat",
            "in_addr": ["NET_1"], "out_addr": ["NET_8"]
        })
        if rng.random() < 0.20:
            cfg["nat_rules"].append({
                "id": "NAT-2", "order": 2, "enabled": True, "comment": "conflicting nat",
                "in_addr": ["NET_1"], "out_addr": ["NET_7"]
            })
            expected += ["NAT:ConflictTranslation"]

    if rng.random() < 0.35:
        # маршруты
        cfg["routes"] = [
            {"id": "RT-DEF", "order": 1, "enabled": True, "prefix": "0.0.0.0/0", "next_hop": "10.0.0.1", "metric": 10},
            {"id": "RT-1", "order": 2, "enabled": True, "prefix": cfg["objects"]["NET_1"]["value"], "next_hop": "10.0.0.2", "metric": 1},
        ]
        if rng.random() < 0.20:
            cfg["routes"].append(
                {"id": "RT-CONF", "order": 3, "enabled": True, "prefix": cfg["objects"]["NET_1"]["value"], "next_hop": "10.0.0.3", "metric": 1}
            )
            expected += ["Routing:ConflictSamePrefix"]

    if rng.random() < 0.20:
        # IAM cycle
        cfg["iam"]["roles"] = {
            "admin": {"parents": ["ops"], "privileges": [{"object": "firewall", "action": "write"}]},
            "ops": {"parents": ["admin"], "privileges": [{"object": "audit", "action": "read"}]},
        }
        expected += ["IAM:RoleInheritanceCycle"]

    return cfg, sorted(set(expected))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="testdata_suite", help="папка для JSON")
    ap.add_argument("--random", type=int, default=200, help="сколько случайных конфигов")
    ap.add_argument("--seed", type=int, default=42, help="seed для воспроизводимости")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    manifest = {}

    # курируемые
    curated_cases(args.out, manifest)

    # случайные
    rng = random.Random(args.seed)
    for i in range(1, args.random + 1):
        cfg, expected = random_case(i, rng)
        fname = f"ZZ_random_{i:04d}.json"
        emit(args.out, manifest, fname, cfg, expected)

    # манифест (для автотестов)
    dump_json(os.path.join(args.out, "manifest.json"), manifest)

    print(f"OK: {len(manifest)} файлов в {args.out}")
    print("manifest.json создан")

if __name__ == "__main__":
    main()
