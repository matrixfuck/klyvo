#!/usr/bin/env python3
"""Проверяет PostToolUse-хук журнала и рендер сводки."""
import json
import os
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JOURNAL_HOOK = os.path.join(REPO_ROOT, ".claude", "hooks", "journal.py")
RENDER = os.path.join(REPO_ROOT, "klyvo_journal.py")

POST_EVENTS = [
    {"tool_name": "Write", "tool_input": {"file_path": "app/main.py"}, "tool_response": {"ok": True}},
    {"tool_name": "Edit", "tool_input": {"file_path": "app/main.py"}, "tool_response": {"ok": True}},
    {"tool_name": "Edit", "tool_input": {"file_path": "app/db.py"}, "tool_response": {"ok": True}},
    {"tool_name": "Bash", "tool_input": {"command": "npm install"}, "tool_response": {"ok": True}},
    {"tool_name": "Bash", "tool_input": {"command": "npm test"}, "tool_response": {"ok": True}},
    {"tool_name": "Read", "tool_input": {"file_path": "README.md"}, "tool_response": {"ok": True}},
]

# PreToolUse guard-событие (заблокированная опасная операция) кладём напрямую в journal.jsonl
BLOCKED = [
    {"ts": "2026-08-07T12:00:00Z", "session_id": "sess-1", "cwd": ".",
     "command": "psql -c 'DROP TABLE users;'", "rules_matched": ["sql_drop"],
     "reasons": ["Удаление таблицы/базы/схемы (DROP)"], "decision": "ask"},
]


def run_hook(env, event):
    payload = dict(event)
    payload["session_id"] = "sess-1"
    subprocess.run(
        ["python3", JOURNAL_HOOK],
        input=json.dumps(payload), capture_output=True, text=True, env=env,
    )


def main():
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ)
        env["CLAUDE_PROJECT_DIR"] = tmp
        klyvo = os.path.join(tmp, ".klyvo")
        os.makedirs(klyvo, exist_ok=True)

        for ev in POST_EVENTS:
            run_hook(env, ev)

        log_path = os.path.join(klyvo, "session_log.jsonl")
        logged = [json.loads(l) for l in open(log_path, encoding="utf-8")]
        if len(logged) == len(POST_EVENTS):
            print(f"[OK] session_log записал все {len(POST_EVENTS)} события")
        else:
            print(f"[FAIL] ожидалось {len(POST_EVENTS)} записей, получено {len(logged)}")
            failures += 1

        with open(os.path.join(klyvo, "journal.jsonl"), "w", encoding="utf-8") as f:
            for b in BLOCKED:
                f.write(json.dumps(b, ensure_ascii=False) + "\n")

        result = subprocess.run(
            ["python3", RENDER, "--session", "sess-1", "--dir", klyvo],
            capture_output=True, text=True, env=env,
        )
        out = result.stdout
        print("\n----- рендер сводки -----")
        print(out)
        print("-------------------------")

        checks = [
            ("app/main.py — 2", "два изменения одного файла сгруппированы"),
            ("app/db.py — 1", "второй файл показан"),
            ("npm install", "команда показана"),
            ("Перехвачено опасных операций с данными: 1", "заблокированная операция учтена"),
            ("DROP TABLE", "опасная команда показана"),
        ]
        for needle, desc in checks:
            if needle in out:
                print(f"[OK] {desc}")
            else:
                print(f"[FAIL] не найдено ({desc}): {needle!r}")
                failures += 1

        # Read не должен попадать в «изменённые файлы»
        if "README.md — 1" in out:
            print("[FAIL] Read ошибочно попал в изменённые файлы")
            failures += 1
        else:
            print("[OK] Read не засчитан как изменение файла")

        # ── --export: секреты/cwd/абсолютные пути не должны попасть в файл ──
        with open(os.path.join(klyvo, "session_log.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "ts": "2026-08-07T12:05:00Z", "session_id": "sess-1",
                "kind": "command", "tool": "Bash",
                "detail": "curl -u admin:hunter2Secret https://api.example.com",
                "success": True,
            }, ensure_ascii=False) + "\n")
            f.write(json.dumps({
                "ts": "2026-08-07T12:06:00Z", "session_id": "sess-1",
                "kind": "edit", "tool": "Edit",
                "detail": "/home/ivan-petrov/work/acme-corp-private/src/db.py",
                "success": True,
            }, ensure_ascii=False) + "\n")
        with open(os.path.join(klyvo, "journal.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "ts": "2026-08-07T12:07:00Z", "session_id": "sess-1",
                "cwd": "/home/ivan-petrov/work/acme-corp-private",
                "command": 'psql "postgresql://admin:TOPSECRET@db.host/prod" -c "TRUNCATE orders;"',
                "rules_matched": ["sql_truncate"], "severities": ["critical"],
                "reasons": ["Опустошение таблицы (TRUNCATE)"], "decision": "deny",
            }, ensure_ascii=False) + "\n")

        export_path = os.path.join(tmp, "out.json")
        result = subprocess.run(
            ["python3", RENDER, "--export", export_path, "--dir", klyvo],
            capture_output=True, text=True, env=env,
        )
        exported = json.loads(open(export_path, encoding="utf-8").read())
        blob = json.dumps(exported, ensure_ascii=False)

        export_checks = [
            ("cwd" not in blob, "cwd отсутствует в экспорте целиком"),
            ("ivan-petrov" not in blob, "имя пользователя ОС из пути не попало в экспорт"),
            ("acme-corp-private" not in blob, "имя проекта/клиента из пути не попало в экспорт"),
            ("hunter2Secret" not in blob, "пароль из curl -u не попал в экспорт"),
            ("TOPSECRET" not in blob, "пароль из connection-string не попал в экспорт"),
            ("db.py" in blob, "имя файла (без каталогов) сохранено для контекста"),
            (exported.get("project_id") and len(exported["project_id"]) == 12, "есть псевдонимный project_id"),
            (os.path.abspath(klyvo) not in blob, "абсолютный путь проекта не попал в экспорт"),
        ]
        for cond, desc in export_checks:
            if cond:
                print(f"[OK] {desc}")
            else:
                print(f"[FAIL] {desc}")
                failures += 1

        if result.returncode != 0:
            print(f"[FAIL] --export завершился с кодом {result.returncode}: {result.stderr}")
            failures += 1

    print(f"\n{'ВСЕ ТЕСТЫ ПРОШЛИ' if failures == 0 else f'{failures} ПРОВАЛЕННЫХ ТЕСТОВ'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
