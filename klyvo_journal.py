#!/usr/bin/env python3
"""Человекочитаемая сводка сессии Klyvo.

Собирает из двух логов детерминированную сводку — без нейросети:
  .klyvo/session_log.jsonl  — все выполненные действия агента (PostToolUse)
  .klyvo/journal.jsonl      — перехваченные опасные DB-операции (PreToolUse)

Использование:
  python3 klyvo_journal.py            # последняя сессия
  python3 klyvo_journal.py --all      # все сессии
  python3 klyvo_journal.py --session <id>
"""
import argparse
import json
import os
import sys
from collections import Counter, OrderedDict


def klyvo_dir():
    base = os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd())
    return os.path.join(base, ".klyvo")


def read_jsonl(path):
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def latest_session(events):
    for e in reversed(events):
        if e.get("session_id"):
            return e["session_id"]
    return None


def render(actions, blocked, session_label):
    lines = []
    lines.append("═══ Сводка сессии Klyvo ═══")
    if session_label:
        lines.append(f"Сессия: {session_label}")

    times = [a["ts"] for a in actions if a.get("ts")] + [b["ts"] for b in blocked if b.get("ts")]
    if times:
        lines.append(f"Период: {min(times)} — {max(times)}")
    lines.append(f"Всего действий агента: {len(actions)}")
    lines.append("")

    # Изменённые файлы
    file_edits = Counter()
    for a in actions:
        if a.get("kind") in ("edit", "write") and a.get("detail"):
            file_edits[a["detail"]] += 1
    if file_edits:
        lines.append(f"Изменённые файлы ({len(file_edits)}):")
        for path, n in file_edits.most_common():
            word = "правка" if n == 1 else "правок" if n >= 5 else "правки"
            lines.append(f"  • {path} — {n} {word}")
        lines.append("")

    # Выполненные команды
    commands = [a["detail"] for a in actions if a.get("kind") == "command" and a.get("detail")]
    if commands:
        lines.append(f"Выполненные команды ({len(commands)}):")
        seen = OrderedDict()
        for c in commands:
            seen[c] = seen.get(c, 0) + 1
        for c, n in seen.items():
            suffix = f"  (×{n})" if n > 1 else ""
            oneline = c.replace("\n", " ⏎ ")
            if len(oneline) > 100:
                oneline = oneline[:97] + "..."
            lines.append(f"  • {oneline}{suffix}")
        lines.append("")

    # Заблокировано guard'ом
    if blocked:
        lines.append(f"⚠ Перехвачено опасных операций с данными: {len(blocked)}")
        for b in blocked:
            reasons = "; ".join(b.get("reasons", [])) or "опасная операция"
            oneline = b.get("command", "").replace("\n", " ⏎ ")
            if len(oneline) > 80:
                oneline = oneline[:77] + "..."
            lines.append(f"  • {oneline}")
            lines.append(f"    └ {reasons} — потребовано подтверждение")
        lines.append("")
    else:
        lines.append("⚠ Опасных операций с данными не перехвачено.")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Человекочитаемая сводка сессии Klyvo")
    parser.add_argument("--all", action="store_true", help="показать все сессии")
    parser.add_argument("--session", help="показать конкретную сессию по id")
    parser.add_argument("--dir", help="путь к .klyvo (по умолчанию из CLAUDE_PROJECT_DIR/cwd)")
    args = parser.parse_args(argv)

    base = args.dir or klyvo_dir()
    actions = read_jsonl(os.path.join(base, "session_log.jsonl"))
    blocked = read_jsonl(os.path.join(base, "journal.jsonl"))

    if not actions and not blocked:
        print("Журнал пуст — в этом проекте ещё не было действий агента с активным Klyvo.")
        return 0

    if args.all:
        label = "все сессии"
    else:
        target = args.session or latest_session(actions) or latest_session(blocked)
        label = target
        actions = [a for a in actions if a.get("session_id") == target]
        blocked = [b for b in blocked if b.get("session_id") == target]

    sys.stdout.write(render(actions, blocked, label))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
