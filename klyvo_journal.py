#!/usr/bin/env python3
"""Человекочитаемая сводка сессии Klyvo.

Собирает из двух логов детерминированную сводку — без нейросети:
  .klyvo/session_log.jsonl  — все выполненные действия агента (PostToolUse)
  .klyvo/journal.jsonl      — перехваченные опасные DB-операции (PreToolUse)

Использование:
  python3 klyvo_journal.py            # последняя сессия
  python3 klyvo_journal.py --all      # все сессии
  python3 klyvo_journal.py --session <id>
  python3 klyvo_journal.py --export   # обезличенный JSON для ручной отправки
                                       # (все сессии, если не сузить --session)
"""
import argparse
import datetime
import hashlib
import json
import os
import sys
from collections import Counter, OrderedDict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from klyvo.redact import redact
except Exception:  # экспорт не должен падать целиком из-за отсутствия klyvo/
    def redact(text):
        return text


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
            # Решение лежит в записи журнала. Раньше здесь стояла фраза про
            # подтверждение независимо от него, и жёсткая блокировка выглядела
            # в сводке так же, как обычный запрос — то есть сводка врала.
            outcome = ("заблокировано" if b.get("decision") == "deny"
                       else "потребовано подтверждение")
            lines.append(f"    └ {reasons} — {outcome}")
        lines.append("")
    else:
        lines.append("⚠ Опасных операций с данными не перехвачено.")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def project_id(base):
    """Стабильный псевдонимный ID проекта — необратимый хэш пути, не сам путь."""
    return hashlib.sha256(os.path.abspath(base).encode("utf-8")).hexdigest()[:12]


def sanitize_action(a):
    """Событие сессии для экспорта: путь файла — только имя, без каталогов."""
    kind = a.get("kind", "")
    detail = a.get("detail") or ""
    if kind == "command":
        detail = redact(detail)  # уже маскировалось при записи; второй проход — на случай старых логов
    elif detail:
        detail = redact(os.path.basename(detail))
    return {"ts": a.get("ts"), "kind": kind, "detail": detail, "success": a.get("success")}


def sanitize_block(b):
    """Перехваченная опасная команда для экспорта: без cwd, команда — под повторный redact()."""
    return {
        "ts": b.get("ts"),
        "tool": b.get("tool"),
        "command": redact(b.get("command", "")),
        "rules_matched": b.get("rules_matched", []),
        "severities": b.get("severities", []),
        "reasons": b.get("reasons", []),
        "decision": b.get("decision"),
    }


def export_bundle(actions, blocked, base):
    """Обезличенный снимок для ручной отправки: без cwd/абсолютных путей/секретов."""
    return {
        "klyvo_export_version": 1,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "project_id": project_id(base),
        "note": (
            "Локальный экспорт Klyvo, отправляется только вручную. Секреты и "
            "абсолютные пути замаскированы автоматически (best-effort, не "
            "100%-я гарантия) — просмотри файл перед отправкой."
        ),
        "actions": [sanitize_action(a) for a in actions],
        "blocked": [sanitize_block(b) for b in blocked],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Человекочитаемая сводка сессии Klyvo")
    parser.add_argument("--all", action="store_true", help="показать все сессии")
    parser.add_argument("--session", help="показать конкретную сессию по id")
    parser.add_argument("--dir", help="путь к .klyvo (по умолчанию из CLAUDE_PROJECT_DIR/cwd)")
    parser.add_argument(
        "--export", nargs="?", const="__default__", metavar="PATH",
        help="сохранить обезличенный JSON для ручной отправки (по умолчанию "
             "рядом с .klyvo; без --session выгружает все сессии сразу)",
    )
    args = parser.parse_args(argv)

    base = args.dir or klyvo_dir()
    actions = read_jsonl(os.path.join(base, "session_log.jsonl"))
    blocked = read_jsonl(os.path.join(base, "journal.jsonl"))

    if not actions and not blocked:
        print("Журнал пуст — в этом проекте ещё не было действий агента с активным Klyvo.")
        return 0

    if args.session:
        target = args.session
        label = target
        actions = [a for a in actions if a.get("session_id") == target]
        blocked = [b for b in blocked if b.get("session_id") == target]
    elif args.all or args.export is not None:
        label = "все сессии"
    else:
        target = latest_session(actions) or latest_session(blocked)
        label = target
        actions = [a for a in actions if a.get("session_id") == target]
        blocked = [b for b in blocked if b.get("session_id") == target]

    sys.stdout.write(render(actions, blocked, label))

    if args.export is not None:
        bundle = export_bundle(actions, blocked, base)
        if args.export == "__default__":
            stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            out_path = os.path.join(os.path.dirname(base) or ".", f"klyvo-export-{stamp}.json")
        else:
            out_path = args.export
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, ensure_ascii=False, indent=2)
        print(f"\nЭкспорт сохранён: {out_path}")
        print(f"Источник: {base}")
        print(f"({len(bundle['actions'])} действий, {len(bundle['blocked'])} перехватов — "
              "секреты и пути замаскированы. Просмотри файл, прежде чем отправлять.)")
        # Журнал действий и журнал перехватов лежат рядом и наполняются одними и теми же
        # хуками, поэтому пустота ровно одного из них почти всегда значит, что команду
        # запустили не из того каталога: .klyvo берётся из CLAUDE_PROJECT_DIR или cwd.
        # Без этой подсказки человек выгружает почти пустой бандл, заливает его в хаб,
        # видит там пусто и считает сломанным хаб.
        if bool(bundle["actions"]) != bool(bundle["blocked"]):
            missing = "действий" if not bundle["actions"] else "перехватов"
            print(f"\nВНИМАНИЕ: {missing} в этом каталоге нет вообще. Похоже, команда "
                  f"запущена не из того проекта.\nЖурнал берётся из CLAUDE_PROJECT_DIR "
                  f"или текущего каталога; укажи каталог явно: --dir ПУТЬ/.klyvo")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
