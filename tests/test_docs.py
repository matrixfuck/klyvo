#!/usr/bin/env python3
"""Обещания в документации и на сайте должны совпадать с кодом.

Появился после прогона живым пользователем: на лендинге в трёх местах стояло
«36 правил», в коде их было уже 53. Мелочь, но именно по конкретным числам
расхождение бьёт по доверию сильнее всего — человек проверяет то, что легко
проверить, и первым делом сверяет цифры.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from klyvo.rules import BASE_RULES  # noqa: E402

fail = 0


def check(desc, cond):
    global fail
    print(f"[{'OK' if cond else 'FAIL'}] {desc}")
    if not cond:
        fail += 1


N = len(BASE_RULES)
print(f"правил в ядре: {N}")

# ── лендинг ──────────────────────────────────────────────────────────────────
site = os.path.join(ROOT, "site", "index.html")
html = open(site, encoding="utf-8").read()

# Числа рядом со словом «правил» — в любой вёрстке: <b>53</b> правил, 53 из коробки.
claimed = set()
for m in re.finditer(r"<b>(\d+)</b>\s*(?:правил|из коробки)", html):
    claimed.add(int(m.group(1)))
for m in re.finditer(r"(\d+)\s*правил", re.sub(r"<[^>]+>", " ", html)):
    claimed.add(int(m.group(1)))

check(f"на лендинге вообще указано число правил (нашли: {sorted(claimed) or '—'})",
      bool(claimed))
check(f"на лендинге указано актуальное число правил ({N})",
      claimed <= {N})

# ── README ───────────────────────────────────────────────────────────────────
readme = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
rm = re.findall(r"\((\d+)\s+правил[а-я]*\s+и\s+2\s+эвристики\)", readme)
check("в README указано число правил", bool(rm))
check(f"в README актуальное число правил ({N})", all(int(x) == N for x in rm))

# ── честность про пределы ────────────────────────────────────────────────────
# Статья и README не должны расходиться: если мы публично признаём, что движок
# обходится, это должно быть и в документации продукта, а не только в посте.
check("в README сказано, что сигнатурный движок обходится",
      any(w in readme.lower() for w in ("обходится", "обход")) and "base64" in readme.lower())
check("в README названа честная область применения (спешка, не умысел)",
      "умысла" in readme or "умысел" in readme)

print("ВСЕ ТЕСТЫ ПРОШЛИ" if fail == 0 else f"{fail} ПРОВАЛЕННЫХ ТЕСТОВ")
sys.exit(1 if fail else 0)
