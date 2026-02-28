import json
from typing import Any, Dict, List, Optional, Tuple


def _load_json_array(uploaded_file) -> List[Dict[str, Any]]:
    """
    uploaded_file: InMemoryUploadedFile / TemporaryUploadedFile (Django)
    """
    raw = uploaded_file.read()
    try:
        data = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError:
        data = json.loads(raw.decode("utf-8-sig"))
    finally:
        uploaded_file.seek(0)

    if not isinstance(data, list):
        raise ValueError("Ожидался JSON-массив правил (list).")

    # Все элементы должны быть объектами
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"Правило #{i} должно быть JSON-объектом (dict).")
    return data


def _guess_kind(rules: List[Dict[str, Any]]) -> str:
    """
    Пытаемся понять: это FW или NAT по ключам.
    """
    if not rules:
        return "unknown"
    sample = rules[0]
    if "rule_action" in sample or "logging" in sample or "is_inverse_src" in sample:
        return "fw"
    if "nat_type" in sample or "port_value" in sample or "address_type" in sample:
        return "nat"
    return "unknown"


def parse_rules_json_files(
    fw_file,
    nat_file,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], str]:
    """
    Возвращает: (fw_rules, nat_rules, display_filename)
    fw_file / nat_file могут быть None.
    Поддерживает кейс: загрузили только один файл, а второй пустой.
    """
    fw_rules: List[Dict[str, Any]] = []
    nat_rules: List[Dict[str, Any]] = []

    names = []

    if fw_file is not None:
        arr = _load_json_array(fw_file)
        kind = _guess_kind(arr)
        if kind == "nat":
            nat_rules = arr
        else:
            fw_rules = arr
        names.append(getattr(fw_file, "name", "fw.json"))

    if nat_file is not None:
        arr = _load_json_array(nat_file)
        kind = _guess_kind(arr)
        if kind == "fw":
            fw_rules = arr
        else:
            nat_rules = arr
        names.append(getattr(nat_file, "name", "nat.json"))

    display_name = " + ".join(names) if names else "rules.json"
    return fw_rules, nat_rules, display_name
