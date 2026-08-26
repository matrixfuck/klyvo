#!/usr/bin/env python3
"""beforeShellExecution-хук для Cursor — тонкий адаптер над klyvo.adapter.

Формат Cursor: команда в поле `command` верхнего уровня, корень воркспейса в
`workspace_roots` (список), рабочая директория в `cwd`. Ответ — ровно три поля:
{"permission": "allow|deny|ask", "user_message", "agent_message"}. Модель `ask`
та же, что у Claude Code, — «мягкое» подтверждение.

Отдаём ТОЛЬКО задокументированные поля. Раньше сюда добавлялись camelCase-дубли
«на случай иной версии формата» — но именно такая страховка и обнулила адаптер
Codex: там неизвестные поля отвергают весь ответ целиком. Лишнее поле не может
помочь и может стоить блокировки.

Код возврата держим нулевым. У Cursor `exit 2` документирован как эквивалент
deny, но версия, которая его не знает, обязана трактовать ненулевой код как
«хук упал» и пропустить команду. Ставка на два канала сразу тут не страхует, а
добавляет способ проиграть.

Cursor по умолчанию работает в режиме fail-open: если хук упал, вернул невалидный
JSON или ненулевой код — команда проходит. Поэтому решение печатаем раньше, чем
пишем журнал: сбой журналирования не должен снимать блокировку.

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
except Exception as e:  # fail-open, но со следом в stderr для отладки
    sys.stderr.write(f"klyvo cursor_guard: не удалось импортировать ядро ({e})\n")
    sys.exit(0)


def main():
    try:
        data = json.loads(sys.stdin.read())
    except ValueError:  # включает json.JSONDecodeError
        sys.exit(0)

    command = data.get("command", "")
    if not command:
        sys.exit(0)

    # Корень проекта берём из cwd; workspace_roots оставлен запасным вариантом
    # на случай, если будущие версии формата его добавят.
    roots = data.get("workspace_roots") or []
    project_root = (roots[0] if roots else None) or data.get("cwd") or os.getcwd()

    try:
        findings = evaluate(command, project_root)
    except Exception as e:
        sys.stderr.write(f"klyvo cursor_guard: ошибка детекции ({e})\n")
        sys.exit(0)  # не ломаем работу Cursor из-за сбоя правил

    if not findings:
        # Нет находок — не навязываем решение, обычный поток разрешений Cursor.
        sys.exit(0)

    decision = decision_for(findings)  # critical → deny, warning → ask
    reason = reason_text(findings, decision)

    # Сначала отдаём решение — блокировка не должна зависеть от журналирования.
    print(json.dumps({
        "permission": decision,
        "user_message": reason,
        "agent_message": reason,
    }, ensure_ascii=False))
    sys.stdout.flush()

    try:
        log_finding(project_root, command, findings, tool="cursor", decision=decision,
                    session_id=data.get("conversation_id"), cwd=data.get("cwd"))
    except Exception:
        pass  # журнал не критичен: решение уже отдано Cursor

    sys.exit(0)


if __name__ == "__main__":
    main()
