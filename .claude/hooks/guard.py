#!/usr/bin/env python3
"""PreToolUse guard-хук для Claude Code и совместимых форков — тонкий адаптер.

Формат Claude Code (и его форков — DeepSeek-Code, Langcli, Crush и т.п.): команда
в tool_input.command; блокировка/подтверждение через
hookSpecificOutput.permissionDecision = "deny" | "ask".

Хук намеренно fail-open: собственная поломка не должна ломать работу агента. Но
молчаливый fail-open опаснее самой поломки — человек месяцами считает себя
защищённым, пока хук давно не работает. Поэтому каждый сбой записывается в
~/.klyvo/health.jsonl, попадает в сводку сессии и виден в `klyvo_rules.py doctor`.
"""
import json
import os
import sys

# Ядро правил лежит рядом с этим файлом (репо klyvo), независимо от того, над
# каким проектом сейчас работает агент — это позволяет ставить хук глобально.
CODE_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if CODE_ROOT not in sys.path:
    sys.path.insert(0, CODE_ROOT)


def report_broken(stage, err):
    """Записать сбой guard'а. Только stdlib и никакого stdout.

    Пишем сами, а не через klyvo/, потому что самый вероятный сбой — как раз
    поломка импорта пакета: зависеть от него тут нельзя. В stdout нельзя ни
    байта: агент разбирает его как ответ хука.
    """
    try:
        import datetime
        path = os.path.join(os.path.expanduser("~"), ".klyvo", "health.jsonl")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        rows = []
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                rows = [ln for ln in f.read().splitlines() if ln.strip()][-49:]
        rows.append(json.dumps({
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "stage": stage,
            "error": f"{type(err).__name__}: {err}"[:300],
            "code_root": CODE_ROOT,
        }, ensure_ascii=False))
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(rows) + "\n")
    except Exception:
        pass  # диагностика не имеет права ломать агента
    try:
        sys.stderr.write(
            "Klyvo: guard не смог отработать и пропустил команду без проверки "
            f"({stage}). Проверить: python3 {os.path.join(CODE_ROOT, 'klyvo_rules.py')} doctor\n"
        )
    except Exception:
        pass


try:
    from klyvo.adapter import evaluate, decision_for, log_finding, reason_text
except Exception as e:  # fail open: баг в guard не должен ломать агента
    report_broken("импорт ядра правил", e)
    sys.exit(0)


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
    try:
        findings = evaluate(command, project_root)
    except Exception as e:
        # Раньше исключение здесь роняло хук с трейсбеком. Команда всё равно
        # проходила, но пользователь хотя бы видел шум; теперь сбой ещё и
        # фиксируется, чтобы его было видно в сводке.
        report_broken("проверка команды", e)
        sys.exit(0)
    if not findings:
        sys.exit(0)

    decision = decision_for(findings)  # critical → deny, warning → ask
    reason = reason_text(findings, decision)

    # Решение печатаем ДО журналирования: блокировка не должна зависеть от того,
    # удалось ли записать журнал.
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }, ensure_ascii=False))
    sys.stdout.flush()

    try:
        log_finding(project_root, command, findings, tool="claude-code", decision=decision,
                    session_id=data.get("session_id"), cwd=data.get("cwd"))
    except Exception as e:
        report_broken("запись журнала", e)
    sys.exit(0)


if __name__ == "__main__":
    main()
