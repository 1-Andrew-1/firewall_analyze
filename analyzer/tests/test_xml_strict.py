import pytest
from analyzer.parsers.xml_strict import parse_xml_strict
from analyzer.parsers.logger import ParserLogger

SAMPLE = """<?xml version="1.0" encoding="utf-8"?>
<КонтинентКонфигурация>
  <Объекты>
    <Объект ID="obj_1" Тип="Адрес">
      <IP>10.0.0.1</IP>
    </Объект>
    <Объект ID="grp_1" Тип="ГруппаАдресов">
      <Элемент>obj_1</Элемент>
    </Объект>
  </Объекты>
  <ПравилаМЭ>
    <Правило ID="r1" Номер="1" Действие="Разрешить">
      <Источник>grp_1</Источник>
      <Назначение>any</Назначение>
      <Сервис>tcp_80</Сервис>
    </Правило>
  </ПравилаМЭ>
  <ПравилаNAT>
    <NAT ID="n1" Номер="1" Тип="SNAT">
      <Источник>10.0.0.1</Источник>
      <Преобразование>203.0.113.5</Преобразование>
    </NAT>
  </ПравилаNAT>
</КонтинентКонфигурация>
"""

def test_parse_basic():
    logger = ParserLogger()
    cfg, meta = parse_xml_strict(SAMPLE, xsd_path=None, logger=logger)
    assert isinstance(cfg.rules, list)
    assert len(cfg.rules) == 1
    assert cfg.rules[0].id == "r1"
    assert cfg.rules[0].action == "allow" or cfg.rules[0].action == "Разрешить".lower()
    assert len(cfg.nat) == 1
    assert "obj_1" in cfg.objects
