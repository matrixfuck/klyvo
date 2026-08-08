#!/usr/bin/env python3
"""Тесты настраиваемости правил и починки многострочного WHERE."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from klyvo.rules import scan  # noqa: E402

failures = 0


def check(desc, condition):
    global failures
    print(f"[{'OK' if condition else 'FAIL'}] {desc}")
    if not condition:
        failures += 1


def names(findings):
    return {n for n, _, _ in findings}


# 1. Баг-фикс: многострочный DELETE ... \n WHERE не должен помечаться
multiline = "psql -c \"DELETE FROM users\n  WHERE id = 5\""
check("многострочный DELETE ... WHERE не ложно-срабатывает",
      "sql_delete_no_where" not in names(scan(multiline)))

# и наоборот — многострочный DELETE без WHERE ловится
multiline_bad = "psql -c \"DELETE FROM users\n  RETURNING id\""
check("многострочный DELETE без WHERE ловится",
      "sql_delete_no_where" in names(scan(multiline_bad)))

# 2. disabled_rules выключает правило
cfg_disabled = {"disabled_rules": ["sql_drop_table"]}
check("disabled_rules выключает sql_drop_table",
      "sql_drop_table" not in names(scan("DROP TABLE x;", cfg_disabled)))
check("прочие правила при этом работают",
      "sql_truncate" in names(scan("TRUNCATE x;", cfg_disabled)))

# 3. можно выключить эвристику
cfg_no_heur = {"disabled_rules": ["sql_delete_no_where"]}
check("эвристику DELETE-без-WHERE можно выключить",
      "sql_delete_no_where" not in names(scan("DELETE FROM users;", cfg_no_heur)))

# 4. allowlist полностью пропускает команду
cfg_allow = {"allowlist": [r"^scripts/wipe_test_db\.sh"]}
check("allowlist пропускает команду целиком",
      scan("scripts/wipe_test_db.sh && DROP TABLE t;", cfg_allow) == [])
check("allowlist не влияет на другие команды",
      "sql_drop_table" in names(scan("DROP TABLE t;", cfg_allow)))

# 5. custom_rules добавляет проектное правило
cfg_custom = {"custom_rules": [
    {"name": "no_prod_seed", "severity": "critical",
     "pattern": r"seed\.py --env=prod", "description": "Сид прод-базы"}]}
found = scan("python seed.py --env=prod", cfg_custom)
check("custom_rules ловит проектную команду", "no_prod_seed" in names(found))

# битое custom-правило не роняет скан
cfg_broken = {"custom_rules": [{"name": "bad", "pattern": "([", "severity": "critical"}]}
try:
    scan("DROP TABLE x;", cfg_broken)
    check("битое custom-правило игнорируется без падения", True)
except Exception:
    check("битое custom-правило игнорируется без падения", False)

print(f"\n{'ВСЕ ТЕСТЫ ПРОШЛИ' if failures == 0 else f'{failures} ПРОВАЛЕННЫХ ТЕСТОВ'}")
sys.exit(1 if failures else 0)
