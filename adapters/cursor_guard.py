#!/usr/bin/env python3
"""beforeShellExecution-хук для Cursor — тонкий адаптер над klyvo.adapter.

Формат Cursor: команда в поле `command` верхнего уровня, корень проекта в
`workspace_roots[0]`; ответ — {"permission": "allow|deny|ask", ...}. Модель
`ask` та же, что у Claude Code, — используем «мягкое» подтверждение.

Установка: см. tools/install_hooks.py --tool cursor (пишет .cursor/hooks.json).
"""
import json
import os
import sys

# Ядро правил рядом с этим файлом (репо klyvo) — работает при глобальной установке.
CODE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if CODE_ROOT not in sys.path:
    sys.path.insert(0, CODE_ROOT)

try:
    from klyvo.adapter import evaluate, decision_for, log_finding, reason_text
except Exception:
    sys.exit(0)  # fail open


def main():
    try:
        data = json.loads(sys.stdin.read())
    except json.JSONDecodeError:
        sys.exit(0)

    command = data.get("command", "")
    if not command:
        sys.exit(0)

    roots = data.get("workspace_roots") or []
    project_root = roots[0] if roots else (data.get("cwd") or os.getcwd())

    findings = evaluate(command, project_root)
    if not findings:
        # Нет находок — не навязываем решение, обычный поток разрешений Cursor.
        sys.exit(0)

    decision = decision_for(findings)  # critical → deny, warning → ask
    log_finding(project_root, command, findings, tool="cursor", decision=decision,
                session_id=data.get("conversation_id"), cwd=data.get("cwd"))

    reason = reason_text(findings, decision)
    print(json.dumps({
        "permission": decision,
        "userMessage": reason,
        "agentMessage": reason,
    }, ensure_ascii=False))
    sys.exit(0)


if __name__ == "__main__":
    main()
