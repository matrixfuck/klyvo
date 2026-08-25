#!/usr/bin/env python3
"""Нормализация команды: обходы сигнатур и цена, которую за неё платят.

Klyvo обещает, что работает в том числе в auto-approve, когда человек команды не
читает. Обещание держалось на честном слове: `"DR""OP TABLE"` не совпадал ни с
одним паттерном. Здесь проверяется и то, что дешёвые обходы закрыты, и то, что
за это не заплатили ложными срабатываниями на обычных командах, — второе важнее,
потому что от ложных срабатываний инструмент сносят, а от дыры — нет.
"""
import json
import os
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from klyvo.rules import scan  # noqa: E402
from klyvo.adapter import decision_for  # noqa: E402
from klyvo.normalize import views, unquote, expand_vars, b64_payloads, MAX_INPUT  # noqa: E402

fail = 0

# Собираем опасные строки из кусков: файл с тестами живёт в репозитории, его
# читают и правят агенты, и целые литералы вида «удалить базу» ловил бы наш же
# хук при каждом редактировании.
DROP = "DR" + "OP"
DEL = "DELE" + "TE"


def check(desc, cond):
    global fail
    print(f"[{'OK' if cond else 'FAIL'}] {desc}")
    if not cond:
        fail += 1


def names(cmd, config=None):
    return {n for n, _, _ in scan(cmd, config)}


# ── 1. кирпичики нормализации по отдельности ─────────────────────────────────
check("склейка кавычками схлопывается",
      unquote('"' + DROP[:2] + '""' + DROP[2:] + ' TABLE"') == DROP + " TABLE")
check("экранирование снимается", unquote(DROP[:2] + "\\" + DROP[2:]) == DROP)
check("пробел между словами нормализация не съедает",
      unquote('"' + DROP[:2] + '" "' + DROP[2:] + '"') == DROP[:2] + " " + DROP[2:])

check("переменная подставляется",
      expand_vars('C="' + DROP + '"; psql -c "$C"').endswith('psql -c "' + DROP + '"'))
check("цепочка присваиваний собирается по порядку",
      DROP + " TABLE" in expand_vars(
          'C="' + DROP[:2] + '"; C="${C}' + DROP[2:] + ' TABLE users"; psql -c "$C"'))
check("неизвестная переменная остаётся как есть — правила рассчитаны на $HOME",
      "$HOME" in expand_vars("rm -rf $HOME/tmp"))

check("base64 с осмысленным текстом разбирается",
      b64_payloads("echo RFJPUCBUQUJMRSB1c2VyczsK | base64 -d") == [DROP + " TABLE users;\n"])
check("случайная длинная строка в base64 не разбирается",
      b64_payloads("Bearer abcdefghijklmnopqrstuvwxyz1234567890") == [])

# ── 2. представления ─────────────────────────────────────────────────────────
v = views('psql -c "' + DROP + ' TABLE t;"')
check("оригинал всегда первое представление", v[0] == 'psql -c "' + DROP + ' TABLE t;"')
check("представления не дублируются", len(v) == len(set(v)))
big = "echo " + "a" * (MAX_INPUT + 10)
check("слишком длинная команда не разворачивается", views(big) == [big])

# ── 3. обходы, ради которых всё затевалось ───────────────────────────────────
bypasses = [
    ("склейка кавычками", 'psql -c "' + DROP[:2] + '""' + DROP[2:] + ' TABLE users;"',
     "sql_drop_table"),
    ("экранирование", 'psql -c "' + DROP[:2] + "\\" + DROP[2:] + ' DATABASE prod;"',
     "sql_drop_database"),
    ("сборка через переменную",
     'C="' + DROP[:2] + '"; C="${C}' + DROP[2:] + ' DATABASE prod;"; psql -c "$C"',
     "sql_drop_database"),
    ("bash -c из переменной", 'C="prisma migrate reset --force"; bash -c "$C"',
     "prisma_migrate_reset"),
    ("base64", "echo RFJPUCBUQUJMRSB1c2VyczsK | base64 -d | psql -d prod",
     "sql_drop_table"),
    ("склейка в имени утилиты", 'psql -c "TRUN""CATE TABLE users;"', "sql_truncate"),
]
for desc, cmd, rule in bypasses:
    got = names(cmd)
    check(f"обход перехвачен: {desc}", rule in got)
    check(f"обход перехвачен жёстко (deny): {desc}", decision_for(scan(cmd)) == "deny")

check("эвристика без WHERE работает и после подстановки переменной",
      "sql_delete_no_where" in names('T=users; psql -c "' + DEL + ' FROM $T"'))

# ── 4. цена: ложных срабатываний быть не должно ──────────────────────────────
harmless = [
    "git commit -m 'fix: handle deletes correctly'",
    'git commit -m "add drop shadow to header"',
    "npm run build && npm test",
    'psql -c "SELECT count(*) FROM users WHERE active = true"',
    "rm -rf ./node_modules",
    'DIR=./build; rm -rf "$DIR"',
    'echo "hello world" > out.txt',
    "docker compose up -d",
    "curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234567890' https://api.example.com",
    "git log --oneline -20",
    "pytest tests/ -q",
    'find . -name "*.py" -newer setup.py -print',
    'grep -rn "TODO" src/',
    "python3 manage.py migrate",
    'ssh user@host "systemctl restart app"',
    "tar czf backup.tar.gz ./data",
    "REV=a1b2c3d4e5f60718293a4b5c6d7e8f9012345678; git show $REV",
]
for cmd in harmless:
    got = names(cmd)
    check(f"безобидная команда чиста: {cmd[:52]}", got == set())

# ── 5. нормализация не должна ничего потерять ────────────────────────────────
# Снятие кавычек ломает `WHERE 'a'='a'` — предикат перестаёт выглядеть обманкой.
# Именно поэтому оригинал проверяется всегда, а представления только дополняют.
check("WHERE-обманка в кавычках по-прежнему ловится",
      "sql_delete_no_where" in names(DEL + " FROM users WHERE 'a'='a'"))
check("правило не дублируется, если сработало в нескольких представлениях",
      [n for n, _, _ in scan('psql -c "' + DROP + ' TABLE users;"')].count("sql_drop_table") == 1)

# ── 6. allowlist сильнее нормализации ────────────────────────────────────────
cfg = {"allowlist": [r"^pg_dump\b"]}
check("разрешённая команда не сканируется", names("pg_dump -d prod > backup.sql", cfg) == set())
check("разрешение не распространяется на другие команды",
      "sql_drop_table" in names('psql -c "' + DROP[:2] + '""' + DROP[2:] + ' TABLE t;"', cfg))
check("выключенное правило остаётся выключенным во всех представлениях",
      names('psql -c "' + DROP[:2] + '""' + DROP[2:] + ' TABLE t;"',
            {"disabled_rules": ["sql_drop_table"]}) == set())

# ── 7. find: удаляет сам, слова rm в команде нет ─────────────────────────────
check("find с -delete по файлам баз ловится",
      "find_delete_data" in names("find . -name '*.db' -delete"))
check("find -exec rm по бэкапам ловится",
      "find_delete_data" in names("find /backups -name '*.dump' -exec rm {} \\;"))
check("find от домашнего каталога ловится",
      "find_delete_root" in names("find ~ -type f -delete"))
check("обычный find не трогаем", names("find . -name '*.log' -mtime +7 -print") == set())

# ── 7b. имя файла — не имя таблицы ───────────────────────────────────────────
# Найдено замером на 1270 настоящих командах агента: после снятия кавычек
# `grep -cn "purge|DELETE FROM" store.py` встаёт ровно в форму «удаление без
# WHERE». Искать опасный SQL в коде — обычное занятие, класс повторяемый.
check("поиск по коду не считается удалением",
      names('grep -cn "cleanup|purge|' + DEL + ' FROM" store.py') == set())
check("грепом по нескольким файлам тоже",
      names("grep -rn '" + DEL + " FROM' src/db.py src/store.py") == set())
check("настоящее удаление без WHERE по-прежнему ловится",
      "sql_delete_no_where" in names('psql -c "' + DEL + ' FROM users"'))
check("таблица со схемой не путается с файлом",
      "sql_delete_no_where" in names('psql -c "' + DEL + ' FROM public.users"'))
check("массовое обновление по-прежнему ловится",
      "sql_update_no_where" in names('psql -c "UPDATE users SET active = false"'))

# ── 8. цена по времени: хук стоит перед каждой командой агента ───────────────
typical = ('psql -h db.example.com -U app -d prod -c '
           '"SELECT id, email FROM users WHERE created_at > now() ORDER BY id LIMIT 100"')
t0 = time.time()
for _ in range(50):
    scan(typical)
per = (time.time() - t0) / 50
check(f"обычная команда сканируется быстрее 5 мс (вышло {per * 1000:.2f})", per < 0.005)

# Верхняя граница здесь — не норматив скорости, а страховка от
# экспоненциального разворачивания: представлений должно остаться единицы.
sample = 'psql -c "SELECT * FROM users WHERE id = 1" && ' * 200
t0 = time.time()
for _ in range(5):
    scan(sample)
per = (time.time() - t0) / 5
check(f"команда на 10 КБ не взрывается (вышло {per * 1000:.0f} мс)", per < 0.3)
check("число представлений ограничено", len(views(sample)) <= 8)

# ── 9. сквозная проверка: реальный хук против обфусцированной команды ────────
work = tempfile.mkdtemp(prefix="klyvo-norm-")
payload = {
    "tool_name": "Bash",
    "tool_input": {"command": 'C="' + DROP[:2] + '"; psql -c "${C}' + DROP[2:] + ' DATABASE prod;"'},
    "cwd": work,
}
proc = subprocess.run(
    [sys.executable, os.path.join(ROOT, ".claude", "hooks", "guard.py")],
    input=json.dumps(payload), capture_output=True, text=True,
    env=dict(os.environ, HOME=work), timeout=30)
out = json.loads(proc.stdout) if proc.stdout.strip() else {}
check("реальный хук блокирует команду, собранную через переменную",
      (out.get("hookSpecificOutput") or {}).get("permissionDecision") == "deny")

print("ВСЕ ТЕСТЫ ПРОШЛИ" if fail == 0 else f"{fail} ПРОВАЛЕННЫХ ТЕСТОВ")
sys.exit(1 if fail else 0)
