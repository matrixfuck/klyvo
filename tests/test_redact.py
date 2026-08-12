#!/usr/bin/env python3
"""Тесты маскировки секретов (klyvo/redact.py) + интеграция с журналом."""
import json
import os
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
from klyvo.redact import redact, MASK  # noqa: E402
from klyvo.adapter import log_finding  # noqa: E402
from klyvo.rules import scan  # noqa: E402

failures = 0


def check(desc, condition):
    global failures
    print(f"[{'OK' if condition else 'FAIL'}] {desc}")
    if not condition:
        failures += 1


# ── пароль в строке подключения: маскируется пароль, хост/юзер остаются ──
r = redact('psql "postgresql://admin:s3cretP@ss@db.host:5432/app"')
check("пароль в URL замаскирован", "s3cretP" not in r and MASK in r)
check("хост в URL сохранён", "db.host" in r)
check("имя пользователя сохранено", "admin" in r)

# ── присваивания секретных переменных ──
check("export TOKEN замаскирован", "abc123XYZ" not in redact("export TOKEN=abc123XYZ"))
check("API_KEY= замаскирован", MASK in redact("API_KEY=sk_live_0123456789"))
check("DB_PASSWORD в кавычках замаскирован", "hunter2" not in redact('DB_PASSWORD="hunter2"'))

# ── Authorization заголовок ──
check("Authorization Bearer замаскирован",
      "eyJhbGciOi" not in redact('curl -H "Authorization: Bearer eyJhbGciOiXXXX"'))

# ── известные форматы ключей ──
check("GitHub PAT замаскирован", MASK in redact("git remote set-url o https://ghp_ABCDEFGHIJKLMNOPQRSTUVWX@x"))
check("AWS access key замаскирован", MASK in redact("AKIAIOSFODNN7EXAMPLE"))
# Значения ниже собраны конкатенацией — фрагмент по формату похож на настоящий
# ключ (нужно для проверки regex), а секрет-сканеры GitHub/GitLab ищут точное
# совпадение подряд идущей строки, так что склейка не мешает тесту, но не триггерит их.
_fake_anthropic = "sk-ant-api03-" + "AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"
_fake_stripe_secret = "sk_live_" + "51AbCdEfGhIjKlMnOpQrStUvWxYz00112233"
_fake_stripe_pub = "pk_live_" + "51AbCdEfGhIjKlMnOpQrStUvWxYz00112233"
_fake_gitlab_pat = "glpat-" + "AbCdEfGhIjKlMnOpQrSt"
_fake_jwt = "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxIn0" + "." + "dQw4w9WgXcQ_signature123"

check("Anthropic-ключ (с дефисами внутри) замаскирован",
      "AbCdEfGhIjKlMnOpQrStUvWxYz1234567890" not in redact("echo " + _fake_anthropic))
check("Stripe secret key замаскирован",
      MASK in redact("echo " + _fake_stripe_secret))
check("Stripe publishable key НЕ маскируется (не секрет)",
      _fake_stripe_pub in redact("echo " + _fake_stripe_pub))
check("GitLab PAT замаскирован",
      MASK in redact("git clone https://oauth2:" + _fake_gitlab_pat + "@gitlab.com/x/y.git"))
check("JWT замаскирован целиком",
      "dQw4w9WgXcQ_signature123" not in redact("echo " + _fake_jwt))

# ── флаговый синтаксис (без = и без :) ──
check("curl -u user:pass замаскирован",
      "hunter2SuperSecret" not in redact("curl -u admin:hunter2SuperSecret https://api.example.com"))
check("--with-token X замаскирован",
      "abcDEF123TOKENVALUE" not in redact("gh auth login --with-token abcDEF123TOKENVALUE"))

# ── JSON-тело (ключ в кавычках перед :) ──
check("password в JSON-теле замаскирован",
      "hunter2Secret" not in redact('curl -d \'{"password":"hunter2Secret","token":"x"}\''))

# ── обычные флаги без секрета не должны портиться ──
check("--host/--port не трогаются",
      redact("mysqldump --host db --port 5432 mydb > out.sql")
      == "mysqldump --host db --port 5432 mydb > out.sql")

# ── обычные команды не трогаем (в т.ч. опасные — это не секреты) ──
check("обычная команда без изменений", redact("npm run build") == "npm run build")
check("DROP-команда не считается секретом",
      redact("psql -c 'DROP TABLE users'") == "psql -c 'DROP TABLE users'")
check("пустая строка/None не ломают", redact("") == "" and redact(None) is None)

# ── интеграция: секрет не попадает в journal.jsonl ──
with tempfile.TemporaryDirectory() as tmp:
    cmd = 'psql "postgresql://admin:TOPSECRET@h/db" -c "TRUNCATE users"'
    findings = scan(cmd)
    log_finding(tmp, cmd, findings, tool="test", decision="deny")
    raw = open(os.path.join(tmp, ".klyvo", "journal.jsonl"), encoding="utf-8").read()
    check("секрет не сохранён в журнал", "TOPSECRET" not in raw)
    check("команда всё же записана (в замаскированном виде)", "TRUNCATE users" in raw)

print(f"\n{'ВСЕ ТЕСТЫ ПРОШЛИ' if failures == 0 else f'{failures} ПРОВАЛЕННЫХ ТЕСТОВ'}")
sys.exit(1 if failures else 0)
