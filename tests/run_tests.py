#!/usr/bin/env python3
"""Симулирует PreToolUse-вызовы guard.py и проверяет решения."""
import json
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GUARD = os.path.join(REPO_ROOT, ".claude", "hooks", "guard.py")

sys.path.insert(0, REPO_ROOT)
from klyvo.rules import scan  # noqa: E402
from klyvo.adapter import decision_for  # noqa: E402

DANGEROUS = [
    "DROP TABLE users;",
    "psql -c \"DROP DATABASE prod;\"",
    "DELETE FROM users;",
    "DELETE FROM users WHERE 1=1;",              # обход WHERE
    "UPDATE accounts SET balance=0 WHERE true",  # обход WHERE
    "TRUNCATE orders;",
    "supabase db reset",
    "supabase projects delete abcd",
    "rm backup.sqlite3",
    "redis-cli FLUSHALL",
    "docker compose down -v",
    "docker system prune -a --volumes",
    "UPDATE users SET active=false;",
    "alembic downgrade base",
    "python manage.py flush --noinput",
    "npx prisma migrate reset",
    "dropdb production",
    "mongo --eval 'db.users.drop()'",
    "node -e \"db.sessions.deleteMany({})\"",
    "kubectl delete pvc data-postgres-0",
    "terraform destroy -auto-approve",
    "npx sequelize db:migrate:undo:all",
    "wrangler d1 execute mydb --command \"DROP TABLE logs\"",
    "npx typeorm schema:drop",
    "ALTER TABLE users DROP COLUMN email;",
]

SAFE = [
    "DELETE FROM users WHERE id = 5;",
    "UPDATE users SET active=true WHERE id=5;",
    "npm install",
    "git commit -m 'fix login bug'",
    "psql -c \"SELECT * FROM users;\"",
    "ls -la",
    "rm tmp_file.txt",
    "docker compose up -d",
    "pg_dump mydb > backup.sql",
    "SELECT count(*) FROM orders;",
    "git push origin main",
    "createdb myapp_dev",
    "cat schema.sql",
    "npm run build",
]


def run_case(command: str):
    payload = {
        "session_id": "test-session",
        "cwd": REPO_ROOT,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }
    env = dict(os.environ)
    env["CLAUDE_PROJECT_DIR"] = REPO_ROOT
    result = subprocess.run(
        ["python3", GUARD], input=json.dumps(payload),
        capture_output=True, text=True, env=env,
    )
    decision, reason = None, None
    if result.stdout.strip():
        try:
            out = json.loads(result.stdout)
            reason = out["hookSpecificOutput"]["permissionDecisionReason"]
            decision = out["hookSpecificOutput"]["permissionDecision"]
        except (json.JSONDecodeError, KeyError):
            pass
    return (decision in ("ask", "deny")), decision, reason, result.returncode


def main():
    journal = os.path.join(REPO_ROOT, ".klyvo", "journal.jsonl")
    if os.path.exists(journal):
        os.remove(journal)

    failures = 0

    print(f"-- Опасные команды ({len(DANGEROUS)}, должны быть помечены) --")
    for cmd in DANGEROUS:
        flagged, decision, _reason, code = run_case(cmd)
        ok = flagged and code == 0
        failures += 0 if ok else 1
        print(f"[{'OK' if ok else 'FAIL'}] ({decision}) {cmd!r}")

    print(f"\n-- Безопасные команды ({len(SAFE)}, не должны быть помечены) --")
    for cmd in SAFE:
        flagged, decision, reason, code = run_case(cmd)
        ok = (not flagged) and code == 0
        failures += 0 if ok else 1
        print(f"[{'OK' if ok else 'FAIL'}] {cmd!r}")
        if flagged:
            print(f"       -> ложное срабатывание: {reason}")

    print("\n-- Маппинг severity → decision (unit) --")
    mapping = [
        ("DROP TABLE users;", "deny", "critical"),
        ("ALTER TABLE users DROP COLUMN email;", "ask", "warning"),
        ("DROP INDEX idx_users;", "ask", "warning"),
    ]
    for cmd, expected, label in mapping:
        got = decision_for(scan(cmd))
        ok = got == expected
        failures += 0 if ok else 1
        print(f"[{'OK' if ok else 'FAIL'}] {label} → {expected} (got {got}): {cmd!r}")

    if os.path.exists(journal):
        n = len(open(journal, encoding="utf-8").readlines())
        ok = n == len(DANGEROUS)
        failures += 0 if ok else 1
        print(f"\nЗаписей в журнале: {n} (ожидалось {len(DANGEROUS)}) [{'OK' if ok else 'FAIL'}]")

    print(f"\n{'ВСЕ ТЕСТЫ ПРОШЛИ' if failures == 0 else f'{failures} ПРОВАЛЕННЫХ ТЕСТОВ'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
