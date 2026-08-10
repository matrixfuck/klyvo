#!/usr/bin/env python3
"""Тесты сбора данных для веб-дашборда (klyvo_web.collect)."""
import json
import os
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
import klyvo_web  # noqa: E402

failures = 0


def check(desc, condition):
    global failures
    print(f"[{'OK' if condition else 'FAIL'}] {desc}")
    if not condition:
        failures += 1


with tempfile.TemporaryDirectory() as tmp:
    # пустой проект — без падений, всё по нулям
    d = klyvo_web.collect(tmp)
    check("пустой проект: 0 блокировок", d["stats"]["blocks_total"] == 0)
    check("пустой проект: пустой top_rules", d["top_rules"] == [])

    # наполняем журналы
    kdir = os.path.join(tmp, ".klyvo")
    os.makedirs(kdir)
    with open(os.path.join(kdir, "journal.jsonl"), "w", encoding="utf-8") as f:
        f.write(json.dumps({"ts": "2026-08-09T10:00:00", "command": "DROP TABLE x",
                            "rules_matched": ["sql_drop_table"], "severities": ["critical"],
                            "decision": "deny"}) + "\n")
        f.write(json.dumps({"ts": "2026-08-09T10:01:00", "command": "ALTER TABLE x DROP COLUMN y",
                            "rules_matched": ["sql_drop_column"], "severities": ["warning"],
                            "decision": "ask"}) + "\n")
    with open(os.path.join(kdir, "session_log.jsonl"), "w", encoding="utf-8") as f:
        f.write(json.dumps({"ts": "2026-08-09T10:00:00", "kind": "command", "detail": "npm test"}) + "\n")

    d = klyvo_web.collect(tmp)
    check("2 перехвата", d["stats"]["blocks_total"] == 2)
    check("1 критичный", d["stats"]["critical"] == 1)
    check("1 предупреждение", d["stats"]["warning"] == 1)
    check("2 разных правила", d["stats"]["rules_distinct"] == 2)
    check("1 действие сессии", d["stats"]["session_actions"] == 1)
    check("top_rules не пуст", len(d["top_rules"]) == 2)
    check("свежие блоки сверху", d["blocks"][0]["ts"] == "2026-08-09T10:01:00")
    check("rules_active > 0", d["stats"]["rules_active"] > 0)
    check("rules — непустой список с нужными полями",
          len(d["rules"]) > 0 and all({"name", "severity", "description", "count"} <= set(r) for r in d["rules"]))

    # битые строки в jsonl не роняют сбор
    with open(os.path.join(kdir, "journal.jsonl"), "a", encoding="utf-8") as f:
        f.write("{битый json\n")
    d = klyvo_web.collect(tmp)
    check("битая строка пропущена, не падаем", d["stats"]["blocks_total"] == 2)

# ── авторизация (пароль + сессии) ──
import hashlib
import hmac
import time as _time

with tempfile.TemporaryDirectory() as adir:
    os.environ["KLYVO_WEB_AUTH"] = os.path.join(adir, "auth.json")
    klyvo_web.set_password("admin", "correct horse battery")
    auth = klyvo_web.load_auth()
    check("auth-файл создан и читается", bool(auth) and auth["user"] == "admin")
    check("хэш пароля, а не сам пароль", "correct horse battery" not in json.dumps(auth))
    check("верный пароль проходит", klyvo_web.verify_password(auth, "correct horse battery"))
    check("неверный пароль не проходит", not klyvo_web.verify_password(auth, "wrong"))

    tok = klyvo_web.make_session(auth)
    check("своя сессия валидна", klyvo_web.valid_session(auth, tok))
    tampered = tok[:-1] + ("0" if tok[-1] != "0" else "1")
    check("подделанная подпись невалидна", not klyvo_web.valid_session(auth, tampered))
    check("пустая сессия невалидна", not klyvo_web.valid_session(auth, ""))

    exp = str(int(_time.time()) - 10)
    sig = hmac.new(bytes.fromhex(auth["secret"]), exp.encode(), hashlib.sha256).hexdigest()
    check("истёкшая сессия невалидна", not klyvo_web.valid_session(auth, f"{exp}.{sig}"))

    os.environ["KLYVO_WEB_AUTH"] = os.path.join(adir, "nonexistent.json")
    check("без файла — режим без входа (auth None)", klyvo_web.load_auth() is None)
    del os.environ["KLYVO_WEB_AUTH"]

print(f"\n{'ВСЕ ТЕСТЫ ПРОШЛИ' if failures == 0 else f'{failures} ПРОВАЛЕННЫХ ТЕСТОВ'}")
sys.exit(1 if failures else 0)
