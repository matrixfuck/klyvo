#!/usr/bin/env python3
"""Тесты адаптера Cursor (beforeShellExecution)."""
import json
import os
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CURSOR_HOOK = os.path.join(REPO_ROOT, "adapters", "cursor_guard.py")

failures = 0


def check(desc, condition):
    global failures
    print(f"[{'OK' if condition else 'FAIL'}] {desc}")
    if not condition:
        failures += 1


def run(command, workspace_root):
    # Реальный payload beforeShellExecution: корень берётся из cwd, отдельного
    # поля workspace_roots в этом событии Cursor нет.
    payload = {
        "conversation_id": "conv-1",
        "generation_id": "gen-1",
        "model": "test",
        "command": command,
        "cwd": workspace_root,
        "sandbox": False,
        "hook_event_name": "beforeShellExecution",
    }
    r = subprocess.run(["python3", CURSOR_HOOK], input=json.dumps(payload),
                       capture_output=True, text=True)
    out = None
    if r.stdout.strip():
        try:
            out = json.loads(r.stdout)
        except json.JSONDecodeError:
            out = "INVALID"
    return out, r.returncode


with tempfile.TemporaryDirectory() as tmp:
    # критичная команда → permission deny (жёсткий блок) + сообщения
    out, code = run("psql -c \"DROP TABLE users\"", tmp)
    check("критичная: exit 0", code == 0)
    check("критичная: permission == deny", isinstance(out, dict) and out.get("permission") == "deny")
    check("критичная: есть user_message и agent_message (snake_case, как ждёт Cursor)",
          isinstance(out, dict) and out.get("user_message") and out.get("agent_message"))

    # warning-команда → permission ask (мягкое подтверждение)
    out_w, code_w = run("ALTER TABLE users DROP COLUMN email", tmp)
    check("warning: permission == ask", isinstance(out_w, dict) and out_w.get("permission") == "ask")

    # журнал записан в .klyvo проекта (workspace_root) с tool=cursor
    jpath = os.path.join(tmp, ".klyvo", "journal.jsonl")
    check("журнал записан в workspace_root/.klyvo", os.path.exists(jpath))
    if os.path.exists(jpath):
        entries = [json.loads(l) for l in open(jpath, encoding="utf-8").read().splitlines()]
        check("в журнале tool == cursor", all(e.get("tool") == "cursor" for e in entries))
        check("в журнале критичная команда deny сохранена",
              any("DROP TABLE" in e.get("command", "") and e.get("decision") == "deny" for e in entries))

    # безопасная команда → нет вывода, нет решения
    out, code = run("git status", tmp)
    check("безопасная: exit 0", code == 0)
    check("безопасная: нет вывода (нет навязанного решения)", out is None)

with tempfile.TemporaryDirectory() as tmp2:
    # config проекта (allowlist) учитывается
    os.makedirs(os.path.join(tmp2, ".klyvo"), exist_ok=True)
    with open(os.path.join(tmp2, ".klyvo", "config.json"), "w", encoding="utf-8") as f:
        json.dump({"allowlist": ["^scripts/reset\\.sh"]}, f)
    out, code = run("scripts/reset.sh && DROP TABLE t", tmp2)
    check("allowlist проекта учтён (нет решения)", out is None and code == 0)

print(f"\n{'ВСЕ ТЕСТЫ ПРОШЛИ' if failures == 0 else f'{failures} ПРОВАЛЕННЫХ ТЕСТОВ'}")
sys.exit(1 if failures else 0)
