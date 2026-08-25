#!/usr/bin/env python3
"""Молчаливый отказ guard'а — худший сценарий, и он должен быть шумным.

Хук намеренно fail-open: собственная поломка не должна ломать работу агента.
Но если при этом ничего не сказать, человек продолжает считать себя защищённым.
Здесь проверяется, что сбой действительно фиксируется и виден в трёх местах:
код возврата остаётся нулевым, файл здоровья пишется, сводка предупреждает.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import klyvo_journal as kj  # noqa: E402

fail = 0


def check(desc, cond):
    global fail
    print(f"[{'OK' if cond else 'FAIL'}] {desc}")
    if not cond:
        fail += 1


work = tempfile.mkdtemp(prefix="klyvo-health-")
home = os.path.join(work, "home")
os.makedirs(home)

# ── 1. сломанный guard: ядро рядом не лежит, импорт обязан упасть ────────────
broken_dir = os.path.join(work, "broken", ".claude", "hooks")
os.makedirs(broken_dir)
shutil.copy(os.path.join(ROOT, ".claude", "hooks", "guard.py"),
            os.path.join(broken_dir, "guard.py"))

env = dict(os.environ, HOME=home)
env.pop("PYTHONPATH", None)  # иначе пакет найдётся и сбой не воспроизведётся
proc = subprocess.run(
    [sys.executable, os.path.join(broken_dir, "guard.py")],
    input=json.dumps({"tool_name": "Bash", "tool_input": {"command": "echo hi"}}),
    capture_output=True, text=True, env=env, timeout=30)

check("сломанный guard не роняет агента (код возврата 0)", proc.returncode == 0)
check("сломанный guard ничего не печатает в stdout (иначе испортит ответ хука)",
      proc.stdout.strip() == "")
check("сломанный guard предупреждает в stderr", "Klyvo" in proc.stderr)

hpath = os.path.join(home, ".klyvo", "health.jsonl")
check("сбой записан в файл здоровья", os.path.exists(hpath))
rows = kj.read_jsonl(hpath) if os.path.exists(hpath) else []
check("в записи о сбое указана стадия и ошибка",
      bool(rows) and rows[-1].get("stage") and rows[-1].get("error"))

# ── 2. сводка обязана предупреждать ──────────────────────────────────────────
out_bad = kj.render([], [], "s1", rows)
out_ok = kj.render([], [], "s1", [])
check("сводка предупреждает о сбоях guard'а",
      "БЕЗ проверки" in out_bad and "doctor" in out_bad)
check("предупреждение стоит раньше вывода о перехватах",
      out_bad.index("БЕЗ проверки") < out_bad.index("Опасных операций"))
check("без сбоев сводка не пугает зря", "БЕЗ проверки" not in out_ok)

# ── 3. doctor обязан отличать сломанное состояние от рабочего ────────────────
# HOME подменён, конфигов агентов там нет — значит хук никем не вызывается.
proc = subprocess.run(
    [sys.executable, os.path.join(ROOT, "klyvo_rules.py"), "doctor"],
    capture_output=True, text=True, env=env, timeout=60)
check("doctor завершается ненулевым кодом, когда есть проблемы", proc.returncode != 0)
check("doctor сообщает, что хук нигде не прописан",
      "ни в одном конфиге" in proc.stdout)
check("doctor показывает зафиксированные сбои", "давал сбой" in proc.stdout)
check("doctor всё равно подтверждает, что ядро и хук сами по себе живы",
      "ядро правил загружается" in proc.stdout and "отвечает deny" in proc.stdout)

shutil.rmtree(work, ignore_errors=True)
print("ВСЕ ТЕСТЫ ПРОШЛИ" if fail == 0 else f"{fail} ПРОВАЛЕННЫХ ТЕСТОВ")
sys.exit(1 if fail else 0)
