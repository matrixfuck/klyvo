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

# ── мультипользовательский режим (регистрация, сессии, изоляция данных) ──
with tempfile.TemporaryDirectory() as mdir:
    os.environ["KLYVO_USERS_PATH"] = os.path.join(mdir, "users.json")
    os.environ["KLYVO_USER_DATA_DIR"] = os.path.join(mdir, "data")

    check("регистрация с валидными данными проходит", klyvo_web.register_user("alice", "correct-horse-1") is None)
    check("короткий пароль отклонён", klyvo_web.register_user("bob", "short") is not None)
    check("логин с недопустимыми символами отклонён", klyvo_web.register_user("bad user!", "correct-horse-1") is not None)
    err = klyvo_web.register_user("alice", "another-password-2")
    check("занятый логин отклонён", err is not None and "занят" in err)

    check("верный пароль проходит", klyvo_web.verify_user("alice", "correct-horse-1"))
    check("неверный пароль не проходит", not klyvo_web.verify_user("alice", "wrong-password"))
    check("несуществующий пользователь не проходит", not klyvo_web.verify_user("ghost", "whatever123"))

    users = klyvo_web.load_users()
    check("пароль не хранится в открытом виде", "correct-horse-1" not in json.dumps(users))

    tok = klyvo_web.make_user_session(users["secret"], "alice")
    check("сессия валидна и возвращает username", klyvo_web.valid_user_session(users["secret"], tok) == "alice")
    check("сессия с чужим секретом невалидна", klyvo_web.valid_user_session("00" * 32, tok) is None)
    tampered = tok[:-1] + ("0" if tok[-1] != "0" else "1")
    check("подделанная подпись сессии невалидна", klyvo_web.valid_user_session(users["secret"], tampered) is None)

    exp = str(int(_time.time()) - 10)
    payload = f"alice.{exp}"
    sig = hmac.new(bytes.fromhex(users["secret"]), payload.encode(), hashlib.sha256).hexdigest()
    expired_tok = f"alice.{exp}.{sig}"
    check("истёкшая сессия невалидна", klyvo_web.valid_user_session(users["secret"], expired_tok) is None)

    # изоляция данных между пользователями — каждый видит только своё
    bundle = {
        "blocked": [{"ts": "2026-08-13T10:00:00Z", "command": "DROP TABLE x", "decision": "deny",
                     "rules_matched": ["sql_drop_table"], "severities": ["critical"], "reasons": []}],
        "actions": [{"ts": "2026-08-13T10:00:00Z", "kind": "command", "detail": "npm test", "success": True}],
    }
    added_b, added_a = klyvo_web.merge_export("alice", bundle)
    check("экспорт добавил перехват и действие", added_b == 1 and added_a == 1)
    added_b2, added_a2 = klyvo_web.merge_export("alice", bundle)
    check("повторная загрузка того же экспорта не дублирует записи", added_b2 == 0 and added_a2 == 0)

    alice_data = klyvo_web.collect(klyvo_web._user_root("alice"))
    check("данные alice видны у неё", alice_data["stats"]["blocks_total"] == 1)
    klyvo_web.register_user("carl", "different-password-3")
    carl_data = klyvo_web.collect(klyvo_web._user_root("carl"))
    check("carl не видит данные alice (изоляция)", carl_data["stats"]["blocks_total"] == 0)

    try:
        klyvo_web.merge_export("alice", {"not": "a bundle"})
        check("битый bundle кидает ValueError", False)
    except ValueError:
        check("битый bundle кидает ValueError", True)

    del os.environ["KLYVO_USERS_PATH"]
    del os.environ["KLYVO_USER_DATA_DIR"]

# ── rate-limit ──
klyvo_web._rate_hits.clear()
ip = "203.0.113.5"
blocked_seen = False
for _ in range(20):
    if klyvo_web.rate_limited("login", ip):
        blocked_seen = True
        break
check("rate-limit срабатывает после серии попыток", blocked_seen)
klyvo_web._rate_hits.clear()

# ── _client_ip: должен доверять X-Real-IP от nginx, а не путать всех клиентов
# с адресом самого nginx (127.0.0.1) — иначе rate-limit становится общим
# бюджетом на всех пользователей сразу, что тривиально DoS-ится ──
class _FakeReq:
    def __init__(self, headers, peer):
        self.headers = headers
        self.client_address = (peer, 12345)


class _Headers(dict):
    def get(self, k, default=None):
        return super().get(k, default)


check("с X-Real-IP — берётся он, а не адрес nginx",
      klyvo_web.Handler._client_ip(_FakeReq(_Headers({"X-Real-IP": "203.0.113.9"}), "127.0.0.1"))
      == "203.0.113.9")
check("без X-Real-IP — берётся адрес сокета (локальный запуск без прокси)",
      klyvo_web.Handler._client_ip(_FakeReq(_Headers({}), "192.168.1.5")) == "192.168.1.5")

# ── central-auth: remote_verify против настоящего multiuser-сервера в треде ──
import threading
from http.server import HTTPServer

with tempfile.TemporaryDirectory() as cdir:
    os.environ["KLYVO_USERS_PATH"] = os.path.join(cdir, "users.json")
    os.environ["KLYVO_USER_DATA_DIR"] = os.path.join(cdir, "data")
    klyvo_web.register_user("dora", "central-auth-pass-1")
    klyvo_web._rate_hits.clear()

    class _MuHandler(klyvo_web.Handler):
        mode = "multiuser"

    srv = HTTPServer(("127.0.0.1", 0), _MuHandler)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        base = f"http://127.0.0.1:{port}"
        check("remote_verify: верные логин/пароль", klyvo_web.remote_verify(base, "dora", "central-auth-pass-1") is True)
        check("remote_verify: неверный пароль", klyvo_web.remote_verify(base, "dora", "wrong") is False)
        check("remote_verify: сервер недоступен → None",
              klyvo_web.remote_verify("http://127.0.0.1:1", "dora", "x") is None)
    finally:
        srv.shutdown()
        th.join(timeout=2)

    del os.environ["KLYVO_USERS_PATH"]
    del os.environ["KLYVO_USER_DATA_DIR"]

print(f"\n{'ВСЕ ТЕСТЫ ПРОШЛИ' if failures == 0 else f'{failures} ПРОВАЛЕННЫХ ТЕСТОВ'}")
sys.exit(1 if failures else 0)
