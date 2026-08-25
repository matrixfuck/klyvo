#!/usr/bin/env python3
"""PreToolUse-хук для Codex CLI.

Ответ Codex — ПЛОСКИЙ JSON и только решение `deny`: парсер Codex строго отвергает
лишние поля, поэтому hookSpecificOutput-обёртку Claude Code здесь использовать
нельзя. `deny` — единственное, на что Codex реагирует; предупреждения (`ask`)
Codex не умеет, поэтому мы их пропускаем, но записываем в журнал.

Требует включённого флага в ~/.codex/config.toml:  [features] codex_hooks = true
Устанавливается через tools/install_hooks.py --tool codex.
"""
import json
import os
import sys

CODE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if CODE_ROOT not in sys.path:
    sys.path.insert(0, CODE_ROOT)

try:
    from klyvo.adapter import evaluate, decision_for, log_finding, reason_text
except Exception as e:
    sys.stderr.write(f"klyvo codex_guard: не удалось импортировать ядро ({e})\n")
    sys.exit(0)


def main():
    try:
        data = json.loads(sys.stdin.read())
    except ValueError:
        sys.exit(0)

    tool_input = data.get("tool_input") or {}
    command = tool_input.get("command") or data.get("command") or ""
    if not command:
        sys.exit(0)

    project_root = os.environ.get("CLAUDE_PROJECT_DIR") or data.get("cwd") or os.getcwd()
    try:
        findings = evaluate(command, project_root)
    except Exception as e:
        sys.stderr.write(f"klyvo codex_guard: ошибка детекции ({e})\n")
        sys.exit(0)
    if not findings:
        sys.exit(0)

    decision = decision_for(findings)  # deny | ask
    reason = reason_text(findings, decision)

    # Решение отдаём раньше журнала — блокировка не должна зависеть от записи.
    if decision == "deny":
        # Формат сверен с исходниками openai/codex: schema.rs, структура
        # PreToolUseHookSpecificOutputWire — camelCase, hookEventName обязателен,
        # и стоит deny_unknown_fields, поэтому ни одного лишнего ключа быть не
        # должно: любой посторонний ключ роняет разбор всего ответа, и команда
        # проходит как ни в чём не бывало.
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }, ensure_ascii=False))
        sys.stdout.flush()
    # warning → ничего не печатаем: Codex не умеет ask, команда пройдёт, но будет
    # записана в журнал ниже.

    try:
        log_finding(project_root, command, findings, tool="codex", decision=decision,
                    session_id=data.get("session_id"), cwd=data.get("cwd"))
    except Exception:
        pass

    sys.exit(0)


if __name__ == "__main__":
    main()
