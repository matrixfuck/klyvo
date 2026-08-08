#!/usr/bin/env python3
"""PreToolUse guard-хук для Claude Code — тонкий адаптер над klyvo.adapter.

Формат Claude Code: команда в tool_input.command; блокировка/подтверждение
через hookSpecificOutput.permissionDecision = "ask".
"""
import json
import os
import sys

# Ядро правил лежит рядом с этим файлом (репо klyvo), независимо от того, над
# каким проектом сейчас работает агент — это позволяет ставить хук глобально.
CODE_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PROJECT_ROOT = os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd())

if CODE_ROOT not in sys.path:
    sys.path.insert(0, CODE_ROOT)

try:
    from klyvo.adapter import evaluate, decision_for, log_finding, reason_text
except Exception:
    sys.exit(0)  # fail open: баг в guard не должен ломать агента


def main():
    try:
        data = json.loads(sys.stdin.read())
    except json.JSONDecodeError:
        sys.exit(0)

    command = data.get("tool_input", {}).get("command", "")
    if not command:
        sys.exit(0)

    findings = evaluate(command, PROJECT_ROOT)
    if not findings:
        sys.exit(0)

    decision = decision_for(findings)  # critical → deny, warning → ask
    log_finding(PROJECT_ROOT, command, findings, tool="claude-code", decision=decision,
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
