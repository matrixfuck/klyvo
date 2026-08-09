#!/usr/bin/env python3
"""PreToolUse guard-хук для Claude Code и совместимых форков — тонкий адаптер.

Формат Claude Code (и его форков — DeepSeek-Code, Langcli, Crush и т.п.): команда
в tool_input.command; блокировка/подтверждение через
hookSpecificOutput.permissionDecision = "deny" | "ask".
"""
import json
import os
import sys

# Ядро правил лежит рядом с этим файлом (репо klyvo), независимо от того, над
# каким проектом сейчас работает агент — это позволяет ставить хук глобально.
CODE_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if CODE_ROOT not in sys.path:
    sys.path.insert(0, CODE_ROOT)

try:
    from klyvo.adapter import evaluate, decision_for, log_finding, reason_text
except Exception:
    sys.exit(0)  # fail open: баг в guard не должен ломать агента


def resolve_project_root(data):
    """Корень проекта для журнала/config.

    Claude Code задаёт CLAUDE_PROJECT_DIR, но форки (DeepSeek-Code и др.) её не
    ставят — поэтому падаем на cwd из payload, затем на текущую директорию.
    """
    return os.environ.get("CLAUDE_PROJECT_DIR") or data.get("cwd") or os.getcwd()


def main():
    try:
        data = json.loads(sys.stdin.read())
    except json.JSONDecodeError:
        sys.exit(0)

    command = data.get("tool_input", {}).get("command", "")
    if not command:
        sys.exit(0)

    project_root = resolve_project_root(data)
    findings = evaluate(command, project_root)
    if not findings:
        sys.exit(0)

    decision = decision_for(findings)  # critical → deny, warning → ask
    log_finding(project_root, command, findings, tool="claude-code", decision=decision,
                session_id=data.get("session_id"), cwd=data.get("cwd"))

    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason_text(findings, decision),
        }
    }, ensure_ascii=False))
    sys.exit(0)


if __name__ == "__main__":
    main()
